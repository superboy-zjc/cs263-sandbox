"""Checks the original environment API and lexical function-scope behavior."""

import pytest

from sandbox.environment import Environment
from sandbox.errors import InterpreterError, UndefinedVariableError


def test_set_and_get():
    env = Environment()

    env.set("x", 10)

    assert env.get("x") == 10


def test_update_variable():
    env = Environment()

    env.set("x", 10)
    env.set("x", 20)

    assert env.get("x") == 20


def test_undefined_variable():
    env = Environment()

    with pytest.raises(
        UndefinedVariableError, match="Variable 'y' is not defined"
    ):
        env.get("y")


def test_undefined_variable_preserves_project_and_name_error_hierarchy():
    with pytest.raises(UndefinedVariableError) as error:
        Environment().get("missing")

    assert isinstance(error.value, InterpreterError)
    assert isinstance(error.value, NameError)
    assert str(error.value) == "Variable 'missing' is not defined"


def test_enclosing_scope_lookup_and_local_assignment():
    parent = Environment({"outer": 3, "shared_name": 4})
    child = Environment(parent=parent)

    assert child.get("outer") == 3
    child.set("shared_name", 8)

    assert child.get("shared_name") == 8
    assert parent.get("shared_name") == 4
    assert "outer" not in child.variables


def test_lexical_lookup_uses_the_original_parent_environment():
    parent = Environment({"value": 1})
    child = Environment(parent=parent)
    grandchild = Environment(parent=child)

    parent.set("value", 2)

    assert grandchild.get("value") == 2


def test_unassigned_local_does_not_fall_back_to_parent():
    parent = Environment({"value": 5})
    child = Environment(parent=parent, local_names={"value"})

    with pytest.raises(UnboundLocalError, match="Local variable 'value'"):
        child.get("value")

    child.set("value", None)

    assert child.get("value") is None
    assert parent.get("value") == 5


def test_unassigned_enclosing_local_stops_more_distant_lookup():
    outer = Environment({"value": 5})
    middle = Environment(parent=outer, local_names={"value"})
    inner = Environment(parent=middle)

    with pytest.raises(UnboundLocalError):
        inner.get("value")


def test_initial_bindings_and_names_have_fresh_ownership():
    mutable_value = [1]
    bindings = {"value": mutable_value}
    names = {"local"}
    env = Environment(bindings, local_names=names)

    bindings["external"] = 4
    names.add("later")
    env.set("own", 2)

    assert "external" not in env.variables
    assert "own" not in bindings
    assert "later" not in env.local_names
    assert env.get("value") is mutable_value


def test_fresh_instances_do_not_reuse_bindings_or_declared_locals():
    first = Environment(local_names={"first_only"})
    second = Environment()
    first.set("answer", 42)

    assert second.variables == {}
    assert second.local_names == set()
    with pytest.raises(UndefinedVariableError):
        second.get("answer")


def test_values_property_aliases_the_original_variables_api():
    env = Environment({"value": 1})

    assert env.values is env.variables
    env.values["value"] = 2

    assert env.get("value") == 2
