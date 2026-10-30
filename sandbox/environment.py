
from sandbox.errors import UndefinedVariableError


class Environment:
    def __init__(self):
        self.variables = {}

    def set(self, name, value):
        self.variables[name] = value

    def get(self, name):
        if name not in self.variables:
            raise UndefinedVariableError(
                f"Variable '{name}' is not defined"
            )

        return self.variables[name]
