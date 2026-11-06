"""A deliberately small Python AST interpreter with bounded runtime checks.

This module supplies language-level restrictions. A separate disposable worker
must supply hard wall-time and operating-system memory limits.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import math
import operator
import time
from typing import Any


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


class _Stopped(Exception):
    """An interpreter decision, distinct from a guest program exception."""

    def __init__(self, status: str, reason: str, node: ast.AST | None):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.node = node


class _Return(Exception):
    def __init__(self, value: Any):
        super().__init__()
        self.value = value


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


@dataclass(frozen=True)
class _Builtin:
    name: str


@dataclass
class _Scope:
    values: dict[str, Any] = field(default_factory=dict)
    parent: _Scope | None = None
    local_names: set[str] = field(default_factory=set)


@dataclass
class _Function:
    definition: ast.FunctionDef
    scope: _Scope
    names: list[str]
    defaults: list[Any]
    local_names: set[str]


_BUILTINS = {
    name: _Builtin(name)
    for name in ("len", "range", "sum", "abs", "min", "max", "print")
}
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
_NUMERIC = (bool, int, float)
_MAX_EVENTS = 128
_MAX_DEPTH = 64


class _Interpreter:
    """Owns trusted bookkeeping separately from the interpreted environment."""

    def __init__(self, limits: Limits):
        self.limits = limits
        self.steps = 0
        self.output_parts: list[str] = []
        self.output_chars = 0
        self.events: list[dict[str, Any]] = []
        self.call_depth = 0
        self.current_node: ast.AST | None = None

    def event(
        self, node: ast.AST | None, operation: str, decision: str, reason: str
    ) -> None:
        event = {
            "line": getattr(node, "lineno", None),
            "column": getattr(node, "col_offset", None),
            "operation": operation,
            "decision": decision,
            "reason": reason,
        }
        if len(self.events) < _MAX_EVENTS:
            self.events.append(event)
        elif decision != "allowed":
            # Keep the terminal failure even after a long sequence of calls.
            self.events[-1] = event

    def stop(
        self, status: str, reason: str, node: ast.AST | None = None
    ) -> None:
        raise _Stopped(status, reason, node or self.current_node)

    def tick(self, node: ast.AST | None = None) -> None:
        if node is not None:
            self.current_node = node
        if self.steps >= self.limits.max_steps:
            self.stop("resource_limit", "Execution step limit exceeded", node)
        self.steps += 1

    def validate(self, tree: ast.Module) -> None:
        """Checks the complete AST, including branches that will not execute."""
        pending = [(tree, 0, 0, 0)]
        count = 0
        while pending:
            node, depth, function_depth, loop_depth = pending.pop()
            count += 1
            if count > self.limits.max_ast_nodes or depth > _MAX_DEPTH:
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
                self.checked(node.value, node)
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

    def checked(self, value: Any, node: ast.AST | None = None) -> Any:
        value_type = type(value)
        if value_type is int and value.bit_length() > self.limits.max_int_bits:
            self.stop("resource_limit", "Integer size limit exceeded", node)
        if value_type is float and not math.isfinite(value):
            self.stop("resource_limit", "Non-finite numeric result", node)
        if value_type is str and len(value) > self.limits.max_source_bytes:
            self.stop("resource_limit", "String size limit exceeded", node)
        if (
            value_type in (list, dict, range)
            and len(value) > self.limits.max_collection_items
        ):
            self.stop("resource_limit", "Collection size limit exceeded", node)
        if value_type not in (
            type(None),
            bool,
            int,
            float,
            str,
            list,
            dict,
            range,
            _Builtin,
            _Function,
        ):
            self.stop("unsupported", "Value type is not supported", node)
        return value

    def lookup(self, name: str, scope: _Scope) -> Any:
        current: _Scope | None = scope
        while current is not None:
            if name in current.values:
                return current.values[name]
            if name in current.local_names:
                raise UnboundLocalError(
                    f"Local variable '{name}' is not assigned"
                )
            current = current.parent
        if name in _BUILTINS:
            return _BUILTINS[name]
        raise NameError(f"Name '{name}' is not defined")

    def read_subscript(self, node: ast.Subscript, scope: _Scope) -> Any:
        container = self.evaluate(node.value, scope)
        index = self.evaluate(node.slice, scope)
        if type(container) not in (list, dict, str, range):
            raise TypeError("Value does not support indexing")
        if type(container) is dict:
            self.check_key(index)
        elif type(index) not in (int, bool):
            raise TypeError("Sequence index must be an integer")
        return self.checked(container[index])

    def check_key(self, key: Any) -> None:
        if type(key) not in (type(None), bool, int, float, str):
            raise TypeError("Dictionary keys must be primitive values")

    def store(self, node: ast.AST, value: Any, scope: _Scope) -> None:
        self.checked(value)
        if isinstance(node, ast.Name):
            scope.values[node.id] = value
            return
        container = self.evaluate(node.value, scope)
        index = self.evaluate(node.slice, scope)
        if type(container) is list:
            if type(index) not in (int, bool):
                raise TypeError("List index must be an integer")
        elif type(container) is dict:
            self.check_key(index)
            if (
                index not in container
                and len(container) >= self.limits.max_collection_items
            ):
                self.stop(
                    "resource_limit", "Collection size limit exceeded", node
                )
        else:
            raise TypeError(
                "Only lists and dictionaries support item assignment"
            )
        container[index] = value

    def binary(self, op: ast.operator, left: Any, right: Any) -> Any:
        lt, rt = type(left), type(right)
        if isinstance(op, ast.Add) and lt is rt and lt in (list, str):
            maximum = (
                self.limits.max_collection_items
                if lt is list
                else self.limits.max_source_bytes
            )
            if len(left) + len(right) > maximum:
                self.stop("resource_limit", "Sequence size limit exceeded")
            return left + right
        if isinstance(op, ast.Mult) and (
            (lt in (list, str) and rt in (int, bool))
            or (rt in (list, str) and lt in (int, bool))
        ):
            sequence, repeat = (
                (left, right) if lt in (list, str) else (right, left)
            )
            maximum = (
                self.limits.max_collection_items
                if type(sequence) is list
                else self.limits.max_source_bytes
            )
            if len(sequence) * max(0, repeat) > maximum:
                self.stop("resource_limit", "Sequence size limit exceeded")
            return sequence * repeat
        if lt not in _NUMERIC or rt not in _NUMERIC:
            raise TypeError(
                "Arithmetic requires numbers or supported sequence operations"
            )
        if isinstance(
            op, (ast.LShift, ast.RShift, ast.BitAnd, ast.BitOr, ast.BitXor)
        ):
            if lt not in (int, bool) or rt not in (int, bool):
                raise TypeError("Bit operations require integers")
        if (
            isinstance(op, ast.Pow)
            and lt in (int, bool)
            and rt in (int, bool)
            and right >= 0
        ):
            lower_bits = max(0, abs(left).bit_length() - 1) * right + 1
            if lower_bits > self.limits.max_int_bits:
                self.stop("resource_limit", "Integer size limit exceeded")
        if isinstance(op, ast.LShift) and rt in (int, bool) and right >= 0:
            if (
                left != 0
                and abs(left).bit_length() + right > self.limits.max_int_bits
            ):
                self.stop("resource_limit", "Integer size limit exceeded")
            if left == 0:
                return 0
        operations = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.FloorDiv: operator.floordiv,
            ast.Mod: operator.mod,
            ast.Pow: operator.pow,
            ast.LShift: operator.lshift,
            ast.RShift: operator.rshift,
            ast.BitAnd: operator.and_,
            ast.BitOr: operator.or_,
            ast.BitXor: operator.xor,
        }
        return self.checked(operations[type(op)](left, right))

    def compare(self, op: ast.cmpop, left: Any, right: Any) -> bool:
        if isinstance(op, ast.Is):
            return left is right
        if isinstance(op, ast.IsNot):
            return left is not right
        if isinstance(op, (ast.In, ast.NotIn)):
            if type(right) is dict:
                self.check_key(left)
                result = left in right
            elif type(right) in (str, range):
                if type(left) not in (bool, int, float, str, type(None)):
                    raise TypeError("Unsupported membership value")
                result = left in right
            elif type(right) is list:
                result = any(
                    self.compare(ast.Eq(), left, item) for item in right
                )
            else:
                raise TypeError("Unsupported membership container")
            return not result if isinstance(op, ast.NotIn) else result
        # Conversion bounds recursive comparisons and rejects cyclic graphs.
        plain_left = self.plain(left, for_comparison=True)
        plain_right = self.plain(right, for_comparison=True)
        operations = {
            ast.Eq: operator.eq,
            ast.NotEq: operator.ne,
            ast.Lt: operator.lt,
            ast.LtE: operator.le,
            ast.Gt: operator.gt,
            ast.GtE: operator.ge,
        }
        return operations[type(op)](plain_left, plain_right)

    def evaluate(self, node: ast.AST, scope: _Scope) -> Any:
        self.tick(node)
        if isinstance(node, ast.Constant):
            return self.checked(node.value)
        if isinstance(node, ast.Name):
            return self.lookup(node.id, scope)
        if isinstance(node, ast.List):
            if len(node.elts) > self.limits.max_collection_items:
                self.stop("resource_limit", "Collection size limit exceeded")
            return [self.evaluate(item, scope) for item in node.elts]
        if isinstance(node, ast.Dict):
            result = {}
            for key_node, value_node in zip(node.keys, node.values):
                key = self.evaluate(key_node, scope)
                self.check_key(key)
                value = self.evaluate(value_node, scope)
                if (
                    key not in result
                    and len(result) >= self.limits.max_collection_items
                ):
                    self.stop(
                        "resource_limit", "Collection size limit exceeded"
                    )
                result[key] = value
            return result
        if isinstance(node, ast.Subscript):
            return self.read_subscript(node, scope)
        if isinstance(node, ast.BinOp):
            return self.binary(
                node.op,
                self.evaluate(node.left, scope),
                self.evaluate(node.right, scope),
            )
        if isinstance(node, ast.UnaryOp):
            value = self.evaluate(node.operand, scope)
            if isinstance(node.op, ast.Not):
                return not value
            if type(value) not in _NUMERIC:
                raise TypeError("Unary arithmetic requires a number")
            operations = {
                ast.UAdd: operator.pos,
                ast.USub: operator.neg,
                ast.Invert: operator.invert,
            }
            return self.checked(operations[type(node.op)](value))
        if isinstance(node, ast.BoolOp):
            for child in node.values:
                value = self.evaluate(child, scope)
                if isinstance(node.op, ast.And) and not value:
                    return value
                if isinstance(node.op, ast.Or) and value:
                    return value
            return value
        if isinstance(node, ast.Compare):
            left = self.evaluate(node.left, scope)
            for op, child in zip(node.ops, node.comparators):
                right = self.evaluate(child, scope)
                if not self.compare(op, left, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.IfExp):
            branch = (
                node.body if self.evaluate(node.test, scope) else node.orelse
            )
            return self.evaluate(branch, scope)
        if isinstance(node, ast.Call):
            function = self.evaluate(node.func, scope)
            args = [self.evaluate(arg, scope) for arg in node.args]
            if (
                type(function) is _Builtin
                and _BUILTINS.get(function.name) is function
            ):
                self.event(
                    node, f"call:{function.name}", "allowed", "Reviewed builtin"
                )
                return self.builtin(function.name, args)
            if type(function) is _Function:
                self.event(
                    node, "call:function", "allowed", "Interpreted function"
                )
                return self.call(function, args)
            self.stop(
                "policy_rejected",
                "Call target is not an approved function",
                node,
            )
        self.stop("internal_error", "Unexpected expression node", node)

    def local_names(self, definition: ast.FunctionDef) -> set[str]:
        names = {
            arg.arg
            for arg in definition.args.posonlyargs + definition.args.args
        }
        pending = list(definition.body)
        while pending:
            child = pending.pop()
            if isinstance(child, ast.FunctionDef):
                names.add(child.name)
                continue
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                names.add(child.id)
            pending.extend(ast.iter_child_nodes(child))
        return names

    def execute_block(self, statements: list[ast.stmt], scope: _Scope) -> None:
        for statement in statements:
            self.execute(statement, scope)

    def execute(self, node: ast.stmt, scope: _Scope) -> Any:
        self.tick(node)
        if isinstance(node, ast.Expr):
            return self.evaluate(node.value, scope)
        if isinstance(node, ast.Assign):
            value = self.evaluate(node.value, scope)
            for target in node.targets:
                self.store(target, value, scope)
        elif isinstance(node, ast.AugAssign):
            # Evaluate a subscript target exactly once, before the RHS.
            if isinstance(node.target, ast.Name):
                old = self.lookup(node.target.id, scope)
                value = self.binary(
                    node.op, old, self.evaluate(node.value, scope)
                )
                if type(old) is list and isinstance(
                    node.op, (ast.Add, ast.Mult)
                ):
                    old[:] = value
                    value = old
                self.store(node.target, value, scope)
            else:
                target = node.target
                container = self.evaluate(target.value, scope)
                index = self.evaluate(target.slice, scope)
                if type(container) not in (list, dict):
                    raise TypeError(
                        "Augmented assignment requires a list or dictionary"
                    )
                if type(container) is dict:
                    self.check_key(index)
                elif type(index) not in (int, bool):
                    raise TypeError("List index must be an integer")
                old = container[index]
                value = self.binary(
                    node.op, old, self.evaluate(node.value, scope)
                )
                if type(old) is list and isinstance(
                    node.op, (ast.Add, ast.Mult)
                ):
                    old[:] = value
                    value = old
                container[index] = value
        elif isinstance(node, ast.If):
            branch = (
                node.body if self.evaluate(node.test, scope) else node.orelse
            )
            self.execute_block(branch, scope)
        elif isinstance(node, (ast.For, ast.While)):
            broke = False
            if isinstance(node, ast.For):
                iterable = self.iterable(self.evaluate(node.iter, scope))
            else:
                iterable = None
            while True:
                self.tick(node)
                if isinstance(node, ast.While):
                    if not self.evaluate(node.test, scope):
                        break
                else:
                    try:
                        item = next(iterable)
                    except StopIteration:
                        break
                    self.store(node.target, item, scope)
                try:
                    self.execute_block(node.body, scope)
                except _Break:
                    broke = True
                    break
                except _Continue:
                    continue
            if not broke:
                self.execute_block(node.orelse, scope)
        elif isinstance(node, ast.FunctionDef):
            defaults = [
                self.evaluate(value, scope) for value in node.args.defaults
            ]
            names = [arg.arg for arg in node.args.posonlyargs + node.args.args]
            scope.values[node.name] = _Function(
                node, scope, names, defaults, self.local_names(node)
            )
        elif isinstance(node, ast.Return):
            raise _Return(
                self.evaluate(node.value, scope) if node.value else None
            )
        elif isinstance(node, ast.Break):
            raise _Break()
        elif isinstance(node, ast.Continue):
            raise _Continue()
        elif not isinstance(node, ast.Pass):
            self.stop("internal_error", "Unexpected statement node", node)
        return None

    def call(self, function: _Function, args: list[Any]) -> Any:
        minimum = len(function.names) - len(function.defaults)
        if not minimum <= len(args) <= len(function.names):
            raise TypeError("Incorrect number of positional arguments")
        if self.call_depth >= self.limits.max_call_depth:
            self.stop("resource_limit", "Function call depth limit exceeded")
        values = args + function.defaults[len(args) - minimum :]
        scope = _Scope(
            dict(zip(function.names, values)),
            function.scope,
            function.local_names,
        )
        self.call_depth += 1
        try:
            self.execute_block(function.definition.body, scope)
        except _Return as result:
            return result.value
        finally:
            self.call_depth -= 1
        return None

    def iterable(self, value: Any):
        if type(value) not in (list, dict, str, range):
            raise TypeError(
                "Only lists, dictionaries, strings, and ranges are iterable"
            )
        return iter(value)

    def builtin(self, name: str, args: list[Any]) -> Any:
        if name == "print":
            # Format incrementally without constructing an unbounded repr.
            for index, value in enumerate(args):
                if index:
                    self.write(" ")
                self.print_value(value, nested=False, seen=set(), depth=0)
            self.write("\n")
            return None
        if name == "range":
            if not 1 <= len(args) <= 3 or any(
                type(arg) not in (int, bool) for arg in args
            ):
                raise TypeError("range expects one to three integer arguments")
            start, stop, step = (
                (0, args[0], 1)
                if len(args) == 1
                else (args[0], args[1], args[2] if len(args) == 3 else 1)
            )
            if step == 0:
                raise ValueError("range step cannot be zero")
            count = (
                max(0, (stop - start + step - 1) // step)
                if step > 0
                else max(0, (start - stop - step - 1) // -step)
            )
            if count > self.limits.max_collection_items:
                self.stop("resource_limit", "Range size limit exceeded")
            return range(start, stop, step)
        if name in ("len", "abs"):
            if len(args) != 1:
                raise TypeError(f"{name} expects one argument")
            if name == "len":
                self.iterable(args[0])
                return self.checked(len(args[0]))
            if type(args[0]) not in _NUMERIC:
                raise TypeError("abs expects a number")
            return self.checked(abs(args[0]))
        if name == "sum":
            if not 1 <= len(args) <= 2:
                raise TypeError(
                    "sum expects an iterable and optional starting number"
                )
            total = args[1] if len(args) == 2 else 0
            if type(total) not in _NUMERIC:
                raise TypeError("sum start must be a number")
            for item in self.iterable(args[0]):
                self.tick()
                if type(item) not in _NUMERIC:
                    raise TypeError("sum items must be numbers")
                total = self.binary(ast.Add(), total, item)
            return total
        if name in ("min", "max"):
            if not args:
                raise TypeError(f"{name} expects at least one argument")
            values = self.iterable(args[0]) if len(args) == 1 else iter(args)
            try:
                result = next(values)
            except StopIteration:
                raise ValueError(f"{name} argument is empty") from None
            for value in values:
                self.tick()
                op = ast.Lt() if name == "min" else ast.Gt()
                if self.compare(op, value, result):
                    result = value
            return result
        self.stop("internal_error", "Unexpected builtin")

    def write(self, text: str) -> None:
        remaining = self.limits.max_output_chars - self.output_chars
        if len(text) > remaining:
            if remaining:
                self.output_parts.append(text[:remaining])
                self.output_chars += remaining
            self.stop("resource_limit", "Output character limit exceeded")
        self.output_parts.append(text)
        self.output_chars += len(text)

    def print_value(
        self, value: Any, *, nested: bool, seen: set[int], depth: int
    ) -> None:
        self.tick()
        if depth > _MAX_DEPTH:
            self.stop("resource_limit", "Value nesting limit exceeded")
        if type(value) in (type(None), bool, int, float, str):
            if type(value) is str and not nested:
                self.write(value)
            elif type(value) is int:
                # CPython's configurable decimal conversion limit must not turn
                # an otherwise bounded value into an interpreter failure.
                if value.bit_length() > 12_000:
                    self.stop(
                        "resource_limit", "Printed integer size limit exceeded"
                    )
                self.write(str(value))
            else:
                self.write(repr(value))
            return
        if type(value) is range:
            if (
                max(
                    value.start.bit_length(),
                    value.stop.bit_length(),
                    value.step.bit_length(),
                )
                > 12_000
            ):
                self.stop(
                    "resource_limit", "Printed integer size limit exceeded"
                )
            self.write(f"range({value.start}, {value.stop}, {value.step})")
            return
        if type(value) not in (list, dict):
            self.stop("policy_rejected", "Only data values may be printed")
        if id(value) in seen:
            self.write("[...]" if type(value) is list else "{...}")
            return
        seen.add(id(value))
        self.write("[" if type(value) is list else "{")
        entries = value.items() if type(value) is dict else enumerate(value)
        for index, (key, item) in enumerate(entries):
            if index:
                self.write(", ")
            if type(value) is dict:
                self.print_value(key, nested=True, seen=seen, depth=depth + 1)
                self.write(": ")
            self.print_value(item, nested=True, seen=seen, depth=depth + 1)
        self.write("]" if type(value) is list else "}")
        seen.remove(id(value))

    def plain(self, value: Any, *, for_comparison: bool = False) -> Any:
        """Copies bounded acyclic data into JSON-compatible return values."""
        seen: set[int] = set()
        count = 0

        def convert(item: Any, depth: int) -> Any:
            nonlocal count
            self.tick()
            count += depth > 0
            if count > self.limits.max_collection_items or depth > _MAX_DEPTH:
                self.stop(
                    "resource_limit",
                    "Returned data size or nesting limit exceeded",
                )
            if type(item) in (type(None), bool, int, float, str):
                return self.checked(item)
            if for_comparison and type(item) is range:
                return item
            if type(item) not in (list, dict, range):
                self.stop("policy_rejected", "Only plain data may be returned")
            if id(item) in seen:
                self.stop("policy_rejected", "Cyclic data cannot be returned")
            seen.add(id(item))
            if type(item) is dict:
                # JSON object keys are strings; rejecting other keys avoids
                # silently merging distinct Python keys during serialization.
                if not for_comparison and any(
                    type(key) is not str for key in item
                ):
                    self.stop(
                        "unsupported",
                        "Returned dictionary keys must be strings",
                    )
                result = {
                    key: convert(child, depth + 1)
                    for key, child in item.items()
                }
            else:
                result = [convert(child, depth + 1) for child in item]
            seen.remove(id(item))
            return result

        return convert(value, 0)


def run(code: str, *, limits: Limits | None = None) -> dict[str, Any]:
    """Interprets a supported program in a fresh environment.

    The last top-level expression is returned as plain data. Output, traversal,
    collection growth, numeric size, and function depth are bounded internally;
    hard process time and memory limits belong to the external worker harness.
    """
    started = time.monotonic()
    interpreter = _Interpreter(limits if limits is not None else Limits())
    value = None
    error = None
    status = "ok"
    try:
        if type(code) is not str:
            interpreter.stop("program_error", "Source must be a string")
        if len(code.encode("utf-8")) > interpreter.limits.max_source_bytes:
            interpreter.stop("resource_limit", "Source byte limit exceeded")
        tree = ast.parse(code)
        interpreter.validate(tree)
        scope = _Scope()
        last = None
        for statement in tree.body:
            result = interpreter.execute(statement, scope)
            last = result if isinstance(statement, ast.Expr) else None
        value = interpreter.plain(last)
    except _Stopped as stopped:
        status = stopped.status
        error = stopped.reason
        interpreter.event(
            stopped.node,
            type(stopped.node).__name__ if stopped.node else "execution",
            "rejected",
            stopped.reason,
        )
    except (SyntaxError, UnicodeError) as exception:
        status = "program_error"
        error = f"{type(exception).__name__}: Invalid Python source"
        interpreter.event(None, "parse", "rejected", error)
    except RecursionError:
        status = "resource_limit"
        error = "Interpreter recursion limit exceeded"
        interpreter.event(
            interpreter.current_node, "execution", "rejected", error
        )
    except (
        ArithmeticError,
        LookupError,
        TypeError,
        ValueError,
        NameError,
        RuntimeError,
    ) as exception:
        status = "program_error"
        error = f"{type(exception).__name__}: {exception}"
        interpreter.event(
            interpreter.current_node, "program", "failed", error[:256]
        )
    except Exception as exception:  # A bug must not expose host tracebacks.
        status = "internal_error"
        error = f"Internal interpreter error: {type(exception).__name__}"
        interpreter.event(
            interpreter.current_node, "execution", "failed", error
        )
    return {
        "status": status,
        "value": value if status == "ok" else None,
        "stdout": "".join(interpreter.output_parts),
        "steps": interpreter.steps,
        "events": interpreter.events,
        "error": error,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
    }
