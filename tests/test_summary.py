"""Tests for bounded evaluation-result summaries."""

import json
from pathlib import Path

import pytest

from sandbox.evaluation import summary


def _record(
    executor,
    status,
    *,
    attack_success=None,
    case_id="case",
    elapsed_ms=2.0,
    category="benign",
    partition=None,
    matches_expected=None,
    technique_class=None,
    source_family=None,
    source_kind=None,
    variant_group=None,
):
    oracle = (
        None
        if attack_success is None
        else {"kind": "canary_exposure", "attack_success": attack_success}
    )
    return {
        "case_id": case_id,
        "category": category,
        "partition": partition,
        "executor": executor,
        "observed": {
            "status": status,
            "elapsed_ms": elapsed_ms,
            "worker_elapsed_ms": elapsed_ms + 1,
            "peak_memory_kib": 100,
        },
        "matches_expected": (
            status == "policy_rejected"
            if matches_expected is None
            else matches_expected
        ),
        "attack_oracle": oracle,
        "technique_class": technique_class,
        "source_family": source_family,
        "source_kind": source_kind,
        "variant_group": variant_group,
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


def test_summarize_reports_distributions_and_cases():
    report = summary.summarize(
        [
            _record("prototype", "ok", case_id="first", elapsed_ms=1.0),
            _record("prototype", "ok", case_id="first", elapsed_ms=2.0),
            _record("prototype", "ok", case_id="first", elapsed_ms=9.0),
        ]
    )

    prototype = report["executors"]["prototype"]
    distribution = prototype["measurements"]["executor_elapsed_ms"]
    assert distribution == {
        "records": 3,
        "minimum": 1.0,
        "median": 2.0,
        "mean": 4.0,
        "p95": 9.0,
        "maximum": 9.0,
    }
    assert prototype["cases"]["first"]["records"] == 3


def test_summarize_distinguishes_attack_variants_from_groups():
    metadata = {
        "technique_class": "indirect_attribute_access",
        "source_family": "smolagents_security_tests",
        "source_kind": "sandbox_regression",
        "variant_group": "warnings_sys_indirect",
    }
    report = summary.summarize(
        [
            _record(
                "prototype",
                "policy_rejected",
                category="attack",
                case_id="map",
                attack_success=False,
                **metadata,
            ),
            _record(
                "prototype",
                "policy_rejected",
                category="attack",
                case_id="partial",
                attack_success=False,
                **metadata,
            ),
        ]
    )

    composition = report["attack_suite_composition"]
    assert composition["case_variants"] == 2
    assert composition["variant_groups"] == 1
    assert composition["technique_classes"] == 1
    assert composition["source_families"] == 1
    assert composition["metadata_complete"] is True
    assert composition["by_technique_class"] == {
        "indirect_attribute_access": {
            "case_variants": 2,
            "variant_groups": 1,
            "source_families": 1,
        }
    }


def test_summarize_reports_compatibility_outcomes_by_partition():
    report = summary.summarize(
        [
            _record(
                "prototype",
                "ok",
                case_id="correct",
                category="compatibility",
                partition="development",
                matches_expected=True,
            ),
            _record(
                "prototype",
                "ok",
                case_id="wrong",
                category="compatibility",
                partition="development",
                matches_expected=False,
            ),
            _record(
                "prototype",
                "unsupported",
                case_id="unsupported",
                category="compatibility",
                partition="heldout",
                matches_expected=False,
            ),
        ]
    )

    compatibility = report["executors"]["prototype"]["compatibility"]
    assert compatibility == {
        "records": 3,
        "cases": 3,
        "exact_matches": 1,
        "outcomes": {
            "exact_match": 1,
            "unsupported": 1,
            "wrong_output": 1,
        },
        "partitions": {
            "development": {
                "records": 2,
                "exact_matches": 1,
                "outcomes": {"exact_match": 1, "wrong_output": 1},
            },
            "heldout": {
                "records": 1,
                "exact_matches": 0,
                "outcomes": {"unsupported": 1},
            },
        },
    }


def test_summarize_exposes_mixed_input_conditions():
    first = _record("prototype", "ok", case_id="first")
    first.update(
        {
            "image_id": "sha256:first",
            "suite_sha256": "a" * 64,
            "trial": {"index": 1, "count": 1},
        }
    )
    second = _record("reference", "ok", case_id="second")
    second.update(
        {
            "image_id": "sha256:second",
            "suite_sha256": "b" * 64,
            "trial": {"index": 1, "count": 2},
        }
    )

    conditions = summary.summarize([first, second])["input_conditions"]

    assert conditions["image_ids"] == ["sha256:first", "sha256:second"]
    assert conditions["suite_sha256"] == ["a" * 64, "b" * 64]
    assert conditions["trial_counts"] == [1, 2]
    assert conditions["mixed_images"] is True
    assert conditions["mixed_suites"] is True
    assert conditions["balanced_case_counts"] is False


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
