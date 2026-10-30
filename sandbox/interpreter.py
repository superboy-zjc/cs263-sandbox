
import ast

from sandbox.environment import Environment
from sandbox.errors import UnsupportedOperationError


class Interpreter:
    def __init__(self):
        self.environment = Environment()

    def eval_node(self, node):

        # Execute statements in a module
        if isinstance(node, ast.Module):
            for statement in node.body:
                self.eval_node(statement)

        # Handle assignment
        elif isinstance(node, ast.Assign):
            value = self.eval_node(node.value)

            for target in node.targets:
                if not isinstance(target, ast.Name):
                    raise UnsupportedOperationError(
                        "Unsupported assignment target"
                    )

                self.environment.set(target.id, value)

        #  Handle constants
        elif isinstance(node, ast.Constant):
            if type(node.value) not in (
                int, float, bool, str, type(None)
            ):
                raise UnsupportedOperationError(
                    "Unsupported constant"
                )

            return node.value

        # Read variables
        elif isinstance(node, ast.Name):
            if not isinstance(node.ctx, ast.Load):
                raise UnsupportedOperationError(
                    "Unsupported name context"
                )

            return self.environment.get(node.id)

        # Handle arithmetic operations
        elif isinstance(node, ast.BinOp):
            # Evaluate left and right expressions
            left = self.eval_node(node.left)
            right = self.eval_node(node.right)

            # Only allow numeric operands
            if type(left) not in (int, float) or type(right) not in (
                int, float
            ):
                raise UnsupportedOperationError(
                    "Unsupported operands"
                )

            # Addition
            if isinstance(node.op, ast.Add):
                return left + right

            # Subtraction
            elif isinstance(node.op, ast.Sub):
                return left - right

            # Multiplication
            elif isinstance(node.op, ast.Mult):
                return left * right

            # Division
            elif isinstance(node.op, ast.Div):
                return left / right

            # Reject unsupported operators
            else:
                raise UnsupportedOperationError(
                    f"Unsupported operator: {type(node.op).__name__}"
                )

        # Reject unsupported AST nodes
        else:
            raise UnsupportedOperationError(
                f"Unsupported AST node: {type(node).__name__}"
            )


# Main program
if __name__ == "__main__":

    source_code = """
x = 10
y = 20

addition = x + y
subtraction = y - x
multiplication = x * y
division = y / x
"""

    # Parse Python source into AST
    tree = ast.parse(source_code)

    # Create interpreter
    interpreter = Interpreter()

    interpreter.eval_node(tree)

    print(interpreter.environment.variables)



