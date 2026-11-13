"""Correctness, policy, and accounting checks for the AST interpreter."""

import ast
from dataclasses import FrozenInstanceError
import json
import unittest

from sandbox.errors import (
    ResourceLimitError,
    SecurityViolationError,
    UndefinedVariableError,
    UnsupportedOperationError,
)
from sandbox.interpreter import Interpreter, Limits, run


class OriginalInterfaceTest(unittest.TestCase):
    """Keep the original package's Interpreter and Environment usable."""

    def test_original_assignment_demo(self):
        interpreter = Interpreter()
        tree = ast.parse(
            "x = 10\ny = 20\naddition = x + y\nsubtraction = y - x\n"
            "multiplication = x * y\ndivision = y / x"
        )
        self.assertIsNone(interpreter.eval_node(tree))
        self.assertEqual(
            interpreter.environment.variables,
            {
                "x": 10,
                "y": 20,
                "addition": 30,
                "subtraction": 10,
                "multiplication": 200,
                "division": 2.0,
            },
        )

    def test_original_instance_preserves_its_environment(self):
        interpreter = Interpreter()
        interpreter.eval_node(ast.parse("x = 10"))
        interpreter.eval_node(ast.parse("y = x + 5"))
        self.assertEqual(interpreter.environment.get("y"), 15)
        self.assertEqual(
            interpreter.eval_node(ast.Name(id="x", ctx=ast.Load())), 10
        )
        self.assertEqual(interpreter.eval_node(ast.Constant(value=7)), 7)

    def test_missing_variable_keeps_original_error(self):
        interpreter = Interpreter()
        with self.assertRaises(UndefinedVariableError):
            interpreter.eval_node(ast.Name(id="missing", ctx=ast.Load()))
        self.assertEqual(interpreter.events[-1]["decision"], "failed")
        self.assertEqual(run("missing")["status"], "program_error")

    def test_ast_entry_point_does_not_bypass_policy(self):
        interpreter = Interpreter()
        with self.assertRaises(SecurityViolationError):
            interpreter.eval_node(ast.parse("x = 1\nimport math"))
        self.assertEqual(interpreter.environment.variables, {})
        self.assertEqual(interpreter.events[-1]["decision"], "rejected")
        with self.assertRaises(UnsupportedOperationError):
            interpreter.eval_node(ast.parse("class Example:\n    pass"))

    def test_ast_entry_point_enforces_resource_limits(self):
        interpreter = Interpreter(Limits(max_steps=10))
        with self.assertRaises(ResourceLimitError):
            interpreter.eval_node(ast.parse("while True:\n    pass"))

    def test_structured_run_uses_fresh_environment(self):
        self.assertEqual(run("x = 1")["status"], "ok")
        self.assertEqual(run("x")["status"], "program_error")


class InterpreterTest(unittest.TestCase):
    def assert_value(self, code, expected, **kwargs):
        result = run(code, **kwargs)
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["value"], expected)
        json.dumps(result, allow_nan=False)
        return result

    def test_arithmetic_and_short_circuit(self):
        self.assert_value("(2 + 3 * 4) == 14 and (True or missing)", True)
        self.assert_value("0 and missing", 0)
        self.assert_value("7 if 1 < 2 < 3 else missing", 7)

    def test_assignment_is_not_an_implicit_return(self):
        self.assert_value("answer = 42", None)
        self.assert_value("answer = 42\nanswer", 42)
        self.assert_value("def answer():\n    value = 42\nanswer()", None)

    def test_loops_break_continue_and_else(self):
        self.assert_value(
            "total = 0\nfor item in range(6):\n"
            "    if item == 2:\n        continue\n"
            "    if item == 5:\n        break\n"
            "    total += item\nelse:\n    total = 100\ntotal",
            8,
        )
        self.assert_value(
            "x = 0\nwhile x < 3:\n    x += 1\nelse:\n    x += 4\nx", 7
        )
        self.assert_value(
            "x = 0\nfor item in []:\n    pass\nelse:\n    x = 9\nx", 9
        )

    def test_function_defaults_evaluate_at_definition(self):
        self.assert_value(
            "x = 3\ndef f(a=x, b=4):\n    return a + b\nx = 100\nf()", 7
        )
        self.assert_value("def f(a, b=4, c=5):\n    return a+b+c\nf(1, 2)", 8)

    def test_lexical_scope_and_argument_errors(self):
        self.assert_value(
            "def outer(x):\n    def inner(y):\n        return x+y\n"
            "    return inner(4)\nouter(3)",
            7,
        )
        for code in (
            "def f(a):\n    return a\nf()",
            "def f(a):\n    return a\nf(1, 2)",
            "x=8\ndef f():\n    y=x\n    x=4\n    return y\nf()",
        ):
            with self.subTest(code=code):
                self.assertEqual(run(code)["status"], "program_error")

    def test_recursive_function_and_call_depth(self):
        code = (
            "def f(n):\n    if n == 0:\n        return 1\n"
            "    return n*f(n-1)\nf(5)"
        )
        self.assert_value(code, 120)
        result = run(code, limits=Limits(max_call_depth=3))
        self.assertEqual(result["status"], "resource_limit")

    def test_reviewed_builtin_aliases_keep_identity(self):
        self.assert_value("measure = len\nmeasure([1,2,3])", 3)
        result = self.assert_value("emit = print\nemit('hello', 3)", None)
        self.assertEqual(result["stdout"], "hello 3\n")
        self.assertTrue(
            any(
                event["operation"] == "call:print" for event in result["events"]
            )
        )
        self.assertEqual(run("f = 3\nf()")["status"], "policy_rejected")

    def test_reviewed_builtins_and_ranges(self):
        self.assert_value(
            "sum(range(5), 10) + abs(-2) + min(4,3) + max([1,6])", 31
        )
        self.assert_value("range(5, -2, -2)", [5, 3, 1, -1])
        self.assert_value("range(0) == []", False)
        self.assert_value(
            "range(3)", [0, 1, 2], limits=Limits(max_collection_items=3)
        )

    def test_lists_dictionaries_and_aliases(self):
        self.assert_value(
            "x = [1, 2]\ny = x\nx += [3]\nx[0] = 4\n"
            "d = {'answer': y}\nd['answer']",
            [4, 2, 3],
        )
        self.assert_value("{1: 2} == {1: 2}", True)
        self.assert_value("2 in [1, 2] and 'x' in {'x': 3}", True)

    def test_augmented_subscript_evaluates_index_once(self):
        self.assert_value(
            "calls = [0]\ndef index():\n    calls[0] += 1\n    return 0\n"
            "x=[2]\nx[index()] += 3\n[x[0], calls[0]]",
            [5, 1],
        )

    def test_policy_validation_precedes_any_execution(self):
        for code in (
            "print('before')\nimport os",
            "if False:\n    x = [].append",
            "x = 1\nx.real",
            "eval('1')",
            "_operations_count = 0",
            "_print_outputs = 'fake'",
        ):
            with self.subTest(code=code):
                result = run(code)
                self.assertEqual(result["status"], "policy_rejected", result)
                self.assertEqual(result["stdout"], "")
                self.assertEqual(result["steps"], 0)
                self.assertEqual(result["events"][-1]["decision"], "rejected")

    def test_unsupported_constructs_and_invalid_control_flow(self):
        for code in (
            "class Thing:\n    pass",
            "[x for x in range(3)]",
            "lambda x: x",
            "print('x', end='')",
            "a, b = [1,2]",
            "return 1",
            "break",
            "for x in []:\n    pass\nelse:\n    break",
            "def f(*args):\n    return 1",
            "f'{1}'",
        ):
            with self.subTest(code=code):
                self.assertEqual(run(code)["status"], "unsupported", code)

    def test_no_fuzzy_name_resolution_or_state_reuse(self):
        self.assertEqual(run("answer=4\nanswe")["status"], "program_error")
        self.assert_value("answer=4\nanswer", 4)
        self.assertEqual(run("answer")["status"], "program_error")

    def test_step_budget_and_bounded_events(self):
        result = run("while True:\n    print('x')", limits=Limits(max_steps=30))
        self.assertEqual(result["status"], "resource_limit")
        self.assertEqual(result["steps"], 30)
        result = run("for x in range(200):\n    len([])")
        self.assertEqual(result["status"], "ok")
        self.assertLessEqual(len(result["events"]), 128)
        result = run("for x in range(200):\n    len([])\n1/0")
        self.assertEqual(len(result["events"]), 128)
        self.assertEqual(result["events"][-1]["decision"], "failed")

    def test_incremental_output_limit(self):
        result = run("print('abcdef')", limits=Limits(max_output_chars=3))
        self.assertEqual(result["status"], "resource_limit")
        self.assertEqual(result["stdout"], "abc")
        result = run("print('x')", limits=Limits(max_output_chars=0))
        self.assertEqual(result["stdout"], "")
        self.assertEqual(result["status"], "resource_limit")

    def test_resource_checks_before_allocation(self):
        for code in ("2**100", "1<<100", "[0]*100", "range(100)", "'a'*100"):
            with self.subTest(code=code):
                result = run(
                    code,
                    limits=Limits(
                        max_int_bits=16,
                        max_collection_items=8,
                        max_source_bytes=64,
                    ),
                )
                self.assertEqual(result["status"], "resource_limit", result)
        self.assertEqual(run("1e309")["status"], "resource_limit")

    def test_builtin_intermediate_results_obey_integer_bound(self):
        # A discarded or truth-tested builtin result must still be checked;
        # checking only the final returned value would miss this case.
        result = run(
            "if len([True, True]):\n    print('reached')",
            limits=Limits(max_int_bits=1),
        )
        self.assertEqual(result["status"], "resource_limit")
        self.assertEqual(result["stdout"], "")
        self.assertEqual(result["error"], "Integer size limit exceeded")

    def test_source_ast_and_nested_result_bounds(self):
        self.assertEqual(
            run("1" * 30, limits=Limits(max_source_bytes=20))["status"],
            "resource_limit",
        )
        self.assertEqual(
            run("[1,2,3]", limits=Limits(max_ast_nodes=3))["status"],
            "resource_limit",
        )
        result = run(
            "x=[0]\nfor i in range(10):\n    x=[x,x]\nx",
            limits=Limits(max_collection_items=20),
        )
        self.assertEqual(result["status"], "resource_limit")

    def test_cycles_and_function_outputs_are_not_plain_data(self):
        for code in ("x=[0]\nx[0]=x\nx", "len", "def f():\n    pass\nf"):
            with self.subTest(code=code):
                self.assertEqual(run(code)["status"], "policy_rejected")
        result = run("x=[0]\nx[0]=x\nprint(x)")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["stdout"], "[[...]]\n")

    def test_program_errors_are_separate_from_policy_decisions(self):
        for code in ("1/0", "[][0]", "len(2)", "1.0 << 2", "range(1, 2, 0)"):
            with self.subTest(code=code):
                result = run(code)
                self.assertEqual(result["status"], "program_error", result)
                self.assertIsNone(result["value"])
                self.assertNotIn("Traceback", result["error"])
        self.assertEqual(run("(")["status"], "program_error")

    def test_result_schema_and_limits(self):
        result = self.assert_value("42", 42)
        self.assertEqual(
            set(result),
            {
                "status",
                "value",
                "stdout",
                "steps",
                "events",
                "error",
                "elapsed_ms",
            },
        )
        self.assertGreaterEqual(result["elapsed_ms"], 0)
        with self.assertRaises(FrozenInstanceError):
            Limits().max_steps = 2
        for kwargs in ({"max_steps": 0}, {"max_int_bits": True}):
            with self.assertRaises(ValueError):
                Limits(**kwargs)
    def test_slice_reads(self):
        examples = (
            ("[10,20,30,40][1:3]", [20, 30]),
            ("[10,20,30][:2]", [10, 20]),
            ("[10,20,30][-2:]", [20, 30]),
            ("[10,20,30][::2]", [10, 30]),
            ("[10,20,30][::-1]", [30, 20, 10]),
            ("[10,20,30][1:99]", [20, 30]),
            ("[10,20,30][2:1]", []),
            ("'hello'[1:4]", "ell"),
            ("'hello'[::-1]", "olleh"),
            ("start=1\n[10,20,30][start:start+2]", [20, 30]),
        )
        for code, expected in examples:
            with self.subTest(code=code):
                self.assert_value(code, expected)

    def test_slice_reads(self):
        examples = (
            ("[10,20,30,40][1:3]", [20, 30]),
            ("[10,20,30][:2]", [10, 20]),
            ("[10,20,30][-2:]", [20, 30]),
            ("[10,20,30][::2]", [10, 30]),
            ("[10,20,30][::-1]", [30, 20, 10]),
            ("[10,20,30][1:99]", [20, 30]),
            ("[10,20,30][2:1]", []),
            ("'hello'[1:4]", "ell"),
            ("'hello'[::-1]", "olleh"),
            ("start=1\n[10,20,30][start:start+2]", [20, 30]),
        )
        for code, expected in examples:
            with self.subTest(code=code):
                self.assert_value(code, expected)

    def test_slice_errors(self):
        for code in (
            "[1,2,3][::0]",
            "[1,2,3]['x':]",
            "{'x':1}[:]",
            "range(3)[:]",
        ):
            with self.subTest(code=code):
                self.assertEqual(
                    run(code)["status"], "program_error"
                )
    def test_slice_assignment_rejected_before_execution(self):
        for operation in ("x[1:2]=[9]", "x[1:2]+=[9]"):
            with self.subTest(operation=operation):
                result = run(
                    "print('before')\nx=[1,2,3]\n" + operation)
                self.assertEqual(result["status"], "unsupported")
                self.assertEqual(result["stdout"], "")
                self.assertEqual(result["steps"], 0)

    def test_slice_returns_a_shallow_copy(self):
        self.assert_value(
            "x=[[1],2,3]\ny=x[:]\n"
            "y[1]=9\ny[0][0]=8\n[x,y]",
            [[[8], 2, 3], [[8], 9, 3]],
        )


if __name__ == "__main__":
    unittest.main()
