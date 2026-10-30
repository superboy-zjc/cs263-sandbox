
class InterpreterError(Exception):
    """Base exception for interpreter errors."""
    pass


class UndefinedVariableError(InterpreterError):
    """Raised when a variable does not exist."""
    pass


class UnsupportedOperationError(InterpreterError):
    """Raised when an operation is not supported."""
    pass


class SecurityViolationError(InterpreterError):
    """Raised when a security policy is violated."""
    pass
