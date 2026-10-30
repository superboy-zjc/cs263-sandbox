
import pytest

from sandbox.environment import Environment
from sandbox.errors import UndefinedVariableError


def test_set_and_get():
    env = Environment()

    env.set("x", 10)

    assert env.get("x") == 10


#  Update test
def test_update_variable():
    env = Environment()

    env.set("x", 10)
    env.set("x", 20)

    assert env.get("x") == 20


#  test: an undefined variable
def test_undefined_variable():
    env = Environment()

    with pytest.raises(
        UndefinedVariableError,
        match="Variable 'y' is not defined"
    ):
        env.get("y")
