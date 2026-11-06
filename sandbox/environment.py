"""Lexical variable scopes for the sandbox's interpreted Python subset."""

from __future__ import annotations

from typing import Any

from sandbox.errors import UndefinedVariableError


class Environment:
    """Stores variables owned by one scope and resolves enclosing scopes.

    Assignments always affect this environment. A name declared local to a
    function must be assigned before it can be read, even if an enclosing scope
    contains a variable with the same name.
    """

    def __init__(
        self,
        variables: dict[str, Any] | None = None,
        parent: Environment | None = None,
        local_names: set[str] | None = None,
    ) -> None:
        """Creates a scope with its own copies of initial variables and names.

        Args:
            variables: Initial bindings for this scope. Values are not deep
                copied, so interpreted mutable objects preserve aliasing.
            parent: Enclosing lexical scope, if any.
            local_names: Names bound locally by a function's parameters or body.
        """
        self.variables = dict(variables) if variables is not None else {}
        self.parent = parent
        self.local_names = (
            set(local_names) if local_names is not None else set()
        )

    @property
    def values(self) -> dict[str, Any]:
        """Returns the same mutable bindings exposed by ``variables``."""
        return self.variables

    def set(self, name: str, value: Any) -> None:
        """Binds or updates a variable in this scope."""
        self.variables[name] = value

    def get(self, name: str) -> Any:
        """Resolves a name locally, then through enclosing lexical scopes.

        Raises:
            UnboundLocalError: A local name has no value in its owning scope.
            UndefinedVariableError: No scope contains or declares the name.
        """
        current: Environment | None = self
        while current is not None:
            if name in current.variables:
                return current.variables[name]
            if name in current.local_names:
                raise UnboundLocalError(
                    f"Local variable '{name}' is not assigned"
                )
            current = current.parent
        raise UndefinedVariableError(f"Variable '{name}' is not defined")
