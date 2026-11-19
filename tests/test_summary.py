"""Tests for bounded evaluation-result summaries."""

import json
from pathlib import Path

import pytest

from sandbox.evaluation import summary


def _record(executor, status, *, attack_success=None):
    oracle = (
        None
        if attack_success is None
        else {"kind": "canary_exposure", "attack_success": attack_success}
    )
    return {
        "executor": executor,
        "observed": {"status": status, "worker_elapsed_ms": 2.0},
        "matches_expected": status == "policy_rejected",
        "attack_oracle": oracle,
        "cleanup_ok": True,
        "controller_errors": [],
        "execution_wall_ms": 5.0,
    }


def test_summarize_separates_oracles_from_expectations():
    report = summary.summarize(
        [
            _record("prototype", "policy_rejected", attack_success=False),
            _record("reference", "program_error", attack_success=False),
            _record("reference", "wall_timeout", attack_success=True),
        ]
    )

    prototype = report["executors"]["prototype"]
    reference = report["executors"]["reference"]
    assert prototype["expectation_matches"] == 1
    assert prototype["observed_attack_successes"] == 0
    assert reference["expectation_mismatches"] == 2
    assert reference["observed_attack_successes"] == 1
    assert reference["statuses"] == {"program_error": 1, "wall_timeout": 1}


def test_load_records_rejects_invalid_or_empty_files(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        summary.load_records(empty)

    invalid = tmp_path / "invalid.jsonl"
    invalid.write_text(json.dumps({"executor": "prototype"}) + "\n")
    with pytest.raises(ValueError, match="schema"):
        summary.load_records(invalid)


def test_load_records_reads_valid_lines(tmp_path):
    path = Path(tmp_path) / "results.jsonl"
    records = [_record("prototype", "policy_rejected")]
    path.write_text("".join(json.dumps(record) + "\n" for record in records))

    assert summary.load_records(path) == records
