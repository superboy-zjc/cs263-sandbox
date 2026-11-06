"""Public interpreter errors and private execution-control signals."""

import ast
from typing import Any


class InterpreterError(Exception):
    """Base exception for interpreter errors."""


class UndefinedVariableError(InterpreterError, NameError):
    """Raised when a variable does not exist."""


class UnsupportedOperationError(InterpreterError):
    """Raised when an operation is not supported."""


class SecurityViolationError(InterpreterError):
    """Raised when a security policy is violated."""


class ResourceLimitError(InterpreterError):
    """Raised when execution exceeds a configured resource bound."""


class _Stopped(Exception):
    """An interpreter decision, distinct from a guest program exception."""

    def __init__(self, status: str, reason: str, node: ast.AST | None):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.node = node


class _Return(Exception):
    """Carries a return value to the current interpreted function call."""

    def __init__(self, value: Any):
        super().__init__()
        self.value = value


class _Break(Exception):
    """Stops the nearest interpreted loop."""

    pass


class _Continue(Exception):
    """Advances the nearest interpreted loop to its next iteration."""

    pass
