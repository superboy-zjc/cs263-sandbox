"""Adapter unit tests; mocked executors are not baseline execution evidence."""

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from sandbox.evaluation import reference


class FakePrintContainer:
    """Inert fixture representing the original container's data-only field."""

    def __init__(self, value=""):
        self.value = value


class ReferenceAdapterTest(unittest.TestCase):
    """Exercise the adapter contract without executing submitted Python."""

    def test_executor_is_fresh_and_uses_unmodified_upstream_configuration(self):
        instances = []

        class FakeExecutor:
            def __init__(self, **kwargs):
                self.configuration = kwargs
                self.tools = None
                self.code = None
                self.state = {}
                instances.append(self)

            def send_tools(self, tools):
                self.tools = tools

            def __call__(self, code):
                self.code = code
                return SimpleNamespace(
                    output={"answer": (42, None)}, logs="hi\n"
                )

        with mock.patch.object(
            reference,
            "_load_executor",
            return_value=(FakeExecutor, FakePrintContainer),
        ):
            first = reference.run(
                "opaque source; never executed",
                limits={"max_output_chars": 100},
            )
            second = reference.run("another opaque source")

        self.assertEqual(first["status"], "ok")
        self.assertEqual(first["value"], {"answer": [42, None]})
        self.assertEqual(first["stdout"], "hi\n")
        self.assertIsNone(first["steps"])
        self.assertIsNone(first["error"])
        self.assertEqual(first["reference_commit"], reference.REFERENCE_COMMIT)
        self.assertEqual(len(instances), 2)
        self.assertIsNot(instances[0], instances[1])
        self.assertEqual(instances[0].tools, {})
        self.assertEqual(
            instances[0].configuration,
            {
                "additional_authorized_imports": [],
                "max_print_outputs_length": 100,
                "timeout_seconds": None,
            },
        )
        self.assertEqual(second["status"], "ok")

    def test_execution_error_is_not_a_security_verdict(self):
        executor_type = mock.Mock()
        executor_type.return_value.state = {
            "_print_outputs": FakePrintContainer("before error\n")
        }
        executor_type.return_value.side_effect = ValueError(
            "upstream execution message"
        )
        with mock.patch.object(
            reference,
            "_load_executor",
            return_value=(executor_type, FakePrintContainer),
        ):
            result = reference.run("opaque source")
        self.assertEqual(result["status"], "program_error")
        self.assertEqual(
            result["error"], "ValueError: upstream execution message"
        )
        self.assertEqual(result["stdout"], "before error\n")
        self.assertIsNone(result["value"])

    def test_non_plain_output_is_output_error(self):
        executor_type = mock.Mock()
        executor_type.return_value.state = {}
        executor_type.return_value.return_value = SimpleNamespace(
            output=object(), logs=""
        )
        with mock.patch.object(
            reference,
            "_load_executor",
            return_value=(executor_type, FakePrintContainer),
        ):
            result = reference.run("opaque source")
        self.assertEqual(result["status"], "output_error")
        self.assertTrue(result["error"].startswith("OutputValidationError:"))

    def test_invalid_limits_fail_before_execution(self):
        for limits in ({"max_int_bits": True}, {"max_output_chars": 0}, []):
            with self.subTest(limits=limits):
                with mock.patch.object(
                    reference, "_load_executor"
                ) as load_executor:
                    result = reference.run("opaque source", limits=limits)
                load_executor.assert_not_called()
                self.assertEqual(result["status"], "infrastructure_error")

    def test_error_formatting_does_not_call_custom_str(self):
        class UnprintableError(Exception):
            def __str__(self):
                raise AssertionError("Custom exception conversion was called.")

        self.assertEqual(
            reference._error_text(UnprintableError("plain message")),
            "UnprintableError: plain message",
        )


class PlainResultTest(unittest.TestCase):
    """Check that output conversion does not invoke arbitrary object methods."""

    def test_nested_plain_values_are_copied(self):
        source = {"items": [1, 2.5, True, None, "text"], "tuple": (3,)}
        result = reference._plain_result(source, {})
        self.assertEqual(
            result, {"items": [1, 2.5, True, None, "text"], "tuple": [3]}
        )
        self.assertIsNot(source, result)
        self.assertIsNot(source["items"], result["items"])

    def test_non_finite_values_and_non_string_keys_are_rejected(self):
        for value in (float("nan"), float("inf"), float("-inf"), {1: "value"}):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(reference.OutputValidationError):
                    reference._plain_result(value, {})

    def test_objects_and_subclasses_are_rejected_without_repr(self):
        class Unprintable:
            def __repr__(self):
                raise AssertionError("Custom repr was called.")

        class CustomList(list):
            def __iter__(self):
                raise AssertionError("Custom iteration was called.")

        class CustomInteger(int):
            pass

        for value in (Unprintable(), CustomList(), CustomInteger(1)):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(reference.OutputValidationError):
                    reference._plain_result(value, {})

    def test_value_size_limits_are_enforced(self):
        examples = (
            (256, {"max_int_bits": 8}),
            ([1, 2], {"max_collection_items": 1}),
            ("long", {"max_output_chars": 3}),
        )
        for value, limits in examples:
            with self.subTest(limits=limits):
                with self.assertRaises(reference.OutputValidationError):
                    reference._plain_result(value, limits)

    def test_cycles_and_deep_values_are_rejected(self):
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(reference.OutputValidationError):
            reference._plain_result(cycle, {})
        deep = 0
        for _ in range(34):
            deep = [deep]
        with self.assertRaises(reference.OutputValidationError):
            reference._plain_result(deep, {})

    def test_aggregate_result_budget_is_enforced(self):
        with self.assertRaises(reference.OutputValidationError):
            reference._plain_result(["x" * 1000] * 100, {})


class ReferenceProvenanceTest(unittest.TestCase):
    """Check fail-closed provenance handling using local inert fixture files."""

    def test_wrong_distribution_version_is_rejected(self):
        distribution = SimpleNamespace(version="0.0.0")
        with mock.patch.object(
            reference.metadata, "distribution", return_value=distribution
        ):
            with self.assertRaisesRegex(RuntimeError, "version"):
                reference._load_executor()

    def test_changed_source_is_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "local_python_executor.py"
            source.write_text(
                "# inert fixture, not upstream code\n", encoding="utf-8"
            )
            distribution = SimpleNamespace(
                version=reference.REFERENCE_VERSION,
                locate_file=lambda _: source,
            )
            with mock.patch.object(
                reference.metadata, "distribution", return_value=distribution
            ):
                with mock.patch.object(
                    reference.importlib, "import_module"
                ) as import_module:
                    with self.assertRaisesRegex(RuntimeError, "does not match"):
                        reference._load_executor()
                import_module.assert_not_called()


if __name__ == "__main__":
    unittest.main()
