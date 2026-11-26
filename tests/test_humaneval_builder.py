"""Tests for deterministic, non-executing HumanEval suite construction."""

import ast

from scripts import build_humaneval_suite


def _record(number):
    return {
        "task_id": f"HumanEval/{number}",
        "entry_point": "double",
        "prompt": (
            "from typing import List\n"
            "import math\n\n"
            "def double(value: int) -> int:\n"
        ),
        "canonical_solution": "    return value * 2\n",
        "test": (
            "def check(candidate):\n"
            f"    assert candidate({number}) == {number * 2}\n"
        ),
    }


def test_build_suite_selects_and_partitions_before_execution():
    suite = build_humaneval_suite.build_suite(
        [_record(number) for number in range(40)]
    )

    cases = suite["cases"]
    expected_ids = [
        record["task_id"]
        for record in sorted(
            [_record(number) for number in range(40)],
            key=build_humaneval_suite._selection_key,
        )[: build_humaneval_suite.SAMPLE_SIZE]
    ]
    assert [
        case["provenance"]["source_locator"] for case in cases
    ] == expected_ids
    assert [case["partition"] for case in cases[:20]] == [
        "development"
    ] * 20
    assert [case["partition"] for case in cases[20:]] == ["heldout"] * 10


def test_case_removes_only_type_syntax_and_preserves_runtime_import():
    case = build_humaneval_suite._case(_record(4), 1)
    tree = ast.parse(case["code"])

    imports = [node for node in tree.body if isinstance(node, ast.Import)]
    function = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef)
    )
    assert [alias.name for alias in imports[0].names] == ["math"]
    assert function.args.args[0].annotation is None
    assert function.returns is None
    assert case["expected"]["value"] == [8]
    assert ast.unparse(tree.body[-1]) == "[double(4)]"


def test_extract_check_accepts_boolean_identity_without_execution():
    assertion = ast.parse("assert candidate([1], 1) is True").body[0]

    call, expected = build_humaneval_suite._extract_check(assertion)

    assert ast.unparse(call) == "candidate([1], 1)"
    assert expected is True
