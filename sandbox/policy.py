"""Static syntax policy and shared primitive-value limits.

This module validates structure and configuration. Execution and checks on
resolved call targets remain in sandbox.interpreter.
"""

import ast
from dataclasses import dataclass
import math
from typing import Any

from sandbox.errors import _Stopped


@dataclass(frozen=True)
class Limits:
    """Bounds for one fresh execution; counters are never guest variables."""

    max_steps: int = 10_000
    max_output_chars: int = 4096
    max_collection_items: int = 1000
    max_int_bits: int = 4096
    max_source_bytes: int = 32_768
    max_ast_nodes: int = 4096
    max_call_depth: int = 32

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            minimum = 0 if name == "max_output_chars" else 1
            if type(value) is not int or value < minimum:
                raise ValueError(f"{name} must be an integer >= {minimum}")


_FORBIDDEN_NAMES = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "open",
        "input",
        "getattr",
        "setattr",
        "delattr",
        "globals",
        "locals",
        "vars",
        "dir",
        "type",
        "object",
        "super",
        "help",
        "breakpoint",
        "exit",
        "quit",
        "memoryview",
    }
)

_ALLOWED_NODES = frozenset(
    {
        ast.Module,
        ast.Expr,
        ast.Constant,
        ast.Name,
        ast.Load,
        ast.Store,
        ast.List,
        ast.Dict,
        ast.Assign,
        ast.AugAssign,
        ast.Subscript,
        ast.BinOp,
        ast.UnaryOp,
        ast.BoolOp,
        ast.Compare,
        ast.IfExp,
        ast.If,
        ast.For,
        ast.While,
        ast.Break,
        ast.Continue,
        ast.Pass,
        ast.FunctionDef,
        ast.arguments,
        ast.arg,
        ast.Return,
        ast.Call,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.FloorDiv,
        ast.Mod,
        ast.Pow,
        ast.LShift,
        ast.RShift,
        ast.BitAnd,
        ast.BitOr,
        ast.BitXor,
        ast.UAdd,
        ast.USub,
        ast.Invert,
        ast.Not,
        ast.And,
        ast.Or,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.Is,
        ast.IsNot,
        ast.In,
        ast.NotIn,
    }
)

MAX_NESTING_DEPTH = 64


def check_primitive(
    value: Any, limits: Limits, node: ast.AST | None = None
) -> bool:
    """Checks scalar bounds, returning False for non-primitive values."""
    value_type = type(value)
    if value_type not in (type(None), bool, int, float, str):
        return False
    if value_type is int and value.bit_length() > limits.max_int_bits:
        raise _Stopped("resource_limit", "Integer size limit exceeded", node)
    if value_type is float and not math.isfinite(value):
        raise _Stopped("resource_limit", "Non-finite numeric result", node)
    if value_type is str and len(value) > limits.max_source_bytes:
        raise _Stopped("resource_limit", "String size limit exceeded", node)
    return True


@dataclass(frozen=True)
class Policy:
    """Validates the complete AST before any submitted operation executes."""

    limits: Limits

    @staticmethod
    def stop(status: str, reason: str, node: ast.AST) -> None:
        raise _Stopped(status, reason, node)

    def validate(self, tree: ast.Module) -> None:
        """Checks the complete AST, including branches that will not execute."""
        pending = [(tree, 0, 0, 0)]
        count = 0
        while pending:
            node, depth, function_depth, loop_depth = pending.pop()
            count += 1
            if count > self.limits.max_ast_nodes or depth > MAX_NESTING_DEPTH:
                self.stop(
                    "resource_limit", "AST size or nesting limit exceeded", node
                )
            if isinstance(
                node,
                (
                    ast.Import,
                    ast.ImportFrom,
                    ast.Attribute,
                    ast.Global,
                    ast.Nonlocal,
                ),
            ):
                self.stop(
                    "policy_rejected",
                    f"{type(node).__name__} is prohibited",
                    node,
                )
            if type(node) not in _ALLOWED_NODES:
                self.stop(
                    "unsupported",
                    f"{type(node).__name__} is not supported",
                    node,
                )
            if isinstance(node, (ast.Name, ast.arg, ast.FunctionDef)):
                name = (
                    node.id
                    if isinstance(node, ast.Name)
                    else node.arg
                    if isinstance(node, ast.arg)
                    else node.name
                )
                if name.startswith("_") or name in _FORBIDDEN_NAMES:
                    self.stop(
                        "policy_rejected", "Reserved or prohibited name", node
                    )
            if isinstance(node, ast.Constant):
                if not check_primitive(node.value, self.limits, node):
                    self.stop(
                        "unsupported", "Value type is not supported", node
                    )
            if isinstance(node, ast.Call) and node.keywords:
                self.stop(
                    "unsupported", "Keyword arguments are not supported", node
                )
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self.validate_target(target)
            if isinstance(node, (ast.AugAssign, ast.For)):
                self.validate_target(node.target)
            if isinstance(node, ast.Dict) and any(
                key is None for key in node.keys
            ):
                self.stop(
                    "unsupported", "Dictionary unpacking is not supported", node
                )
            if isinstance(node, ast.Return) and not function_depth:
                self.stop("unsupported", "Return outside a function", node)
            if isinstance(node, (ast.Break, ast.Continue)) and not loop_depth:
                self.stop("unsupported", "Loop control outside a loop", node)
            if isinstance(node, ast.FunctionDef):
                args = node.args
                if (
                    node.decorator_list
                    or node.returns is not None
                    or getattr(node, "type_params", [])
                    or args.vararg
                    or args.kwarg
                    or args.kwonlyargs
                    or any(
                        arg.annotation is not None
                        for arg in args.posonlyargs + args.args
                    )
                ):
                    self.stop(
                        "unsupported",
                        "Only basic positional functions are supported",
                        node,
                    )
                names = [arg.arg for arg in args.posonlyargs + args.args]
                if len(names) != len(set(names)):
                    self.stop(
                        "unsupported", "Duplicate function argument", node
                    )
                # Defaults execute in the enclosing scope; the function body has
                # its own loop and return context.
                pending.append((args, depth + 1, function_depth, loop_depth))
                pending.extend(
                    (child, depth + 1, function_depth + 1, 0)
                    for child in reversed(node.body)
                )
                continue
            if isinstance(node, (ast.For, ast.While)):
                pending.extend(
                    (child, depth + 1, function_depth, loop_depth + 1)
                    for child in reversed(node.body)
                )
                pending.extend(
                    (child, depth + 1, function_depth, loop_depth)
                    for child in reversed(node.orelse)
                )
                headers = (
                    [node.iter, node.target]
                    if isinstance(node, ast.For)
                    else [node.test]
                )
                pending.extend(
                    (child, depth + 1, function_depth, loop_depth)
                    for child in headers
                )
                continue
            pending.extend(
                (child, depth + 1, function_depth, loop_depth)
                for child in reversed(list(ast.iter_child_nodes(node)))
            )

    def validate_target(self, node: ast.AST) -> None:
        if not isinstance(node, (ast.Name, ast.Subscript)):
            self.stop(
                "unsupported",
                "Only name and subscript assignment are supported",
                node,
            )
