"""Tests for benchmark planning and command-line validation."""

import argparse
from pathlib import Path
from unittest import mock

import pytest

from sandbox.evaluation import cli


@pytest.mark.parametrize("value", ["0", "101", "not-an-integer"])
def test_repetition_count_rejects_invalid_values(value):
    with pytest.raises(argparse.ArgumentTypeError):
        cli._repetition_count(value)


def test_repeated_benchmark_counterbalances_executor_order(tmp_path):
    output = Path(tmp_path) / "results.jsonl"
    case = {
        "id": "case",
        "category": "benign",
        "code": "1",
        "expected": {"status": "ok", "value": 1},
    }

    def result(*args, **kwargs):
        return {
            "executor": args[1],
            "trial": {
                "index": kwargs["trial_index"],
                "count": kwargs["trial_count"],
            },
            "observed": {"status": "ok"},
            "matches_expected": True,
            "controller_errors": [],
        }

    with (
        mock.patch.object(
            cli.harness, "load_cases", return_value=([case], "x")
        ),
        mock.patch.object(cli.harness, "resolve_image", return_value="image"),
        mock.patch.object(
            cli.harness, "run_case", side_effect=result
        ) as run_case,
    ):
        exit_code = cli.main(
            [
                "benchmark",
                "--repetitions",
                "2",
                "--output",
                str(output),
            ]
        )

    assert exit_code == 0
    assert [
        (call.args[1], call.kwargs["trial_index"])
        for call in run_case.call_args_list
    ] == [
        ("prototype", 1),
        ("reference", 1),
        ("reference", 2),
        ("prototype", 2),
    ]


def test_compatibility_mismatch_is_measurement_not_cli_failure(tmp_path):
    output = Path(tmp_path) / "results.jsonl"
    cases = [
        {
            "id": "development",
            "category": "compatibility",
            "partition": "development",
            "code": "1",
            "expected": {"status": "ok", "value": 1},
        },
        {
            "id": "heldout",
            "category": "compatibility",
            "partition": "heldout",
            "code": "2",
            "expected": {"status": "ok", "value": 2},
        },
    ]

    def result(*args, **kwargs):
        return {
            "executor": args[1],
            "observed": {"status": "unsupported"},
            "matches_expected": False,
            "controller_errors": [],
        }

    with (
        mock.patch.object(
            cli.harness, "load_cases", return_value=(cases, "x")
        ),
        mock.patch.object(cli.harness, "resolve_image", return_value="image"),
        mock.patch.object(
            cli.harness, "run_case", side_effect=result
        ) as run_case,
    ):
        exit_code = cli.main(
            [
                "benchmark",
                "--partition",
                "development",
                "--executor",
                "prototype",
                "--output",
                str(output),
            ]
        )

    assert exit_code == 0
    assert run_case.call_count == 1
    assert run_case.call_args.args[0]["id"] == "development"
