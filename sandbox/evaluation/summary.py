"""Summarize bounded JSON Lines evaluation records."""

from collections import Counter
import json
import math
from pathlib import Path
import statistics
from typing import Any


MAX_RECORDS = 10_000
MAX_RECORD_BYTES = 1_048_576


def _mean(values: list[float]) -> float | None:
    if not values:
        return None
    return round(math.fsum(values) / len(values), 3)


def _distribution(values: list[float]) -> dict[str, float | int | None]:
    """Return bounded descriptive statistics using nearest-rank P95."""
    if not values:
        return {
            "records": 0,
            "minimum": None,
            "median": None,
            "mean": None,
            "p95": None,
            "maximum": None,
        }
    ordered = sorted(values)
    p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return {
        "records": len(ordered),
        "minimum": round(ordered[0], 3),
        "median": round(statistics.median(ordered), 3),
        "mean": _mean(ordered),
        "p95": round(ordered[p95_index], 3),
        "maximum": round(ordered[-1], 3),
    }


def _finite_values(records: list[dict[str, Any]], *path: str) -> list[float]:
    """Read finite, exact numeric measurements from nested result fields."""
    values = []
    for record in records:
        value: Any = record
        for name in path:
            if type(value) is not dict:
                value = None
                break
            value = value.get(name)
        if type(value) in (int, float) and math.isfinite(value):
            values.append(value)
    return values


def _measurements(records: list[dict[str, Any]]) -> dict[str, dict]:
    """Summarize executor, worker, container, and memory measurements."""
    return {
        "executor_elapsed_ms": _distribution(
            _finite_values(records, "observed", "elapsed_ms")
        ),
        "worker_elapsed_ms": _distribution(
            _finite_values(records, "observed", "worker_elapsed_ms")
        ),
        "execution_wall_ms": _distribution(
            _finite_values(records, "execution_wall_ms")
        ),
        "elapsed_wall_ms": _distribution(
            _finite_values(records, "elapsed_wall_ms")
        ),
        "peak_memory_kib": _distribution(
            _finite_values(records, "observed", "peak_memory_kib")
        ),
    }


def _compatibility_outcome(record: dict[str, Any]) -> str:
    """Classify an external benign case without hiding wrong output values."""
    if record.get("matches_expected") is True:
        return "exact_match"
    status = record["observed"]["status"]
    if status == "ok":
        return "wrong_output"
    return status


def _compatibility_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize compatibility records by partition and observed outcome."""
    selected = [
        record
        for record in records
        if record.get("category") == "compatibility"
    ]
    partitions = {}
    for partition in sorted(
        {
            record.get("partition")
            for record in selected
            if type(record.get("partition")) is str
        }
    ):
        partition_records = [
            record
            for record in selected
            if record.get("partition") == partition
        ]
        partitions[partition] = {
            "records": len(partition_records),
            "exact_matches": sum(
                record.get("matches_expected") is True
                for record in partition_records
            ),
            "outcomes": dict(
                sorted(
                    Counter(
                        _compatibility_outcome(record)
                        for record in partition_records
                    ).items()
                )
            ),
        }
    return {
        "records": len(selected),
        "cases": len({record["case_id"] for record in selected}),
        "exact_matches": sum(
            record.get("matches_expected") is True for record in selected
        ),
        "outcomes": dict(
            sorted(
                Counter(
                    _compatibility_outcome(record) for record in selected
                ).items()
            )
        ),
        "partitions": partitions,
    }


def _attack_suite_composition(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Describe attack-corpus composition without implying a coverage rate."""
    metadata_fields = (
        "technique_class",
        "source_family",
        "source_kind",
        "variant_group",
    )
    cases: dict[str, dict[str, str]] = {}
    conflicts = set()
    incomplete = set()
    for record in records:
        if record.get("category") != "attack":
            continue
        case_id = record["case_id"]
        metadata = {
            field: record.get(field)
            for field in metadata_fields
            if type(record.get(field)) is str
        }
        if len(metadata) != len(metadata_fields):
            incomplete.add(case_id)
            continue
        if case_id in cases and cases[case_id] != metadata:
            conflicts.add(case_id)
            continue
        cases[case_id] = metadata

    by_class = {}
    for technique_class in sorted(
        {metadata["technique_class"] for metadata in cases.values()}
    ):
        selected = [
            metadata
            for metadata in cases.values()
            if metadata["technique_class"] == technique_class
        ]
        by_class[technique_class] = {
            "case_variants": len(selected),
            "variant_groups": len(
                {metadata["variant_group"] for metadata in selected}
            ),
            "source_families": len(
                {metadata["source_family"] for metadata in selected}
            ),
        }

    return {
        "case_variants": len(cases),
        "variant_groups": len(
            {metadata["variant_group"] for metadata in cases.values()}
        ),
        "technique_classes": len(
            {metadata["technique_class"] for metadata in cases.values()}
        ),
        "source_families": len(
            {metadata["source_family"] for metadata in cases.values()}
        ),
        "source_kinds": len(
            {metadata["source_kind"] for metadata in cases.values()}
        ),
        "metadata_complete": not incomplete and not conflicts,
        "incomplete_case_ids": sorted(incomplete),
        "conflicting_case_ids": sorted(conflicts),
        "by_technique_class": by_class,
    }


def _input_conditions(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Expose fingerprints that must agree before comparing measurements."""
    image_ids = sorted(
        {
            record["image_id"]
            for record in records
            if type(record.get("image_id")) is str
        }
    )
    suite_hashes = sorted(
        {
            record["suite_sha256"]
            for record in records
            if type(record.get("suite_sha256")) is str
        }
    )
    trial_counts = sorted(
        {
            record["trial"]["count"]
            for record in records
            if type(record.get("trial")) is dict
            and type(record["trial"].get("count")) is int
        }
    )
    executors = sorted({record["executor"] for record in records})
    case_counts = {
        executor: dict(
            sorted(
                Counter(
                    record["case_id"]
                    for record in records
                    if record["executor"] == executor
                ).items()
            )
        )
        for executor in executors
    }
    balanced = bool(case_counts) and all(
        counts == next(iter(case_counts.values()))
        for counts in case_counts.values()
    )
    return {
        "image_ids": image_ids,
        "suite_sha256": suite_hashes,
        "trial_counts": trial_counts,
        "mixed_images": len(image_ids) > 1,
        "mixed_suites": len(suite_hashes) > 1,
        "balanced_case_counts": balanced,
        "case_counts": case_counts,
    }


def load_records(path: Path) -> list[dict[str, Any]]:
    """Load bounded result records without interpreting submitted source."""
    records = []
    with path.open("rb") as stream:
        for line_number, line in enumerate(stream, start=1):
            if line_number > MAX_RECORDS:
                raise ValueError("Result file exceeds the record limit.")
            if len(line) > MAX_RECORD_BYTES:
                raise ValueError(
                    f"Result record {line_number} exceeds the size limit."
                )
            try:
                record = json.loads(line)
            except (ValueError, UnicodeError, RecursionError) as error:
                raise ValueError(
                    f"Result record {line_number} is invalid JSON."
                ) from error
            if (
                type(record) is not dict
                or type(record.get("executor")) is not str
                or type(record.get("case_id")) is not str
                or type(record.get("observed")) is not dict
                or type(record["observed"].get("status")) is not str
            ):
                raise ValueError(
                    f"Result record {line_number} has an invalid schema."
                )
            records.append(record)
    if not records:
        raise ValueError("Result file is empty.")
    return records


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate outcomes while keeping regressions and oracles separate."""
    executors: dict[str, dict[str, Any]] = {}
    for executor in sorted({record["executor"] for record in records}):
        selected = [
            record for record in records if record["executor"] == executor
        ]
        statuses = Counter(record["observed"]["status"] for record in selected)
        oracle_records = [
            record
            for record in selected
            if type(record.get("attack_oracle")) is dict
        ]
        successful_attack_records = [
            record
            for record in oracle_records
            if record["attack_oracle"].get("attack_success") is True
        ]
        worker_times = _finite_values(
            selected, "observed", "worker_elapsed_ms"
        )
        execution_times = _finite_values(selected, "execution_wall_ms")
        case_summaries = {}
        for case_id in sorted({record["case_id"] for record in selected}):
            case_records = [
                record for record in selected if record["case_id"] == case_id
            ]
            case_summaries[case_id] = {
                "records": len(case_records),
                "statuses": dict(
                    sorted(
                        Counter(
                            record["observed"]["status"]
                            for record in case_records
                        ).items()
                    )
                ),
                "measurements": _measurements(case_records),
            }
        executors[executor] = {
            "records": len(selected),
            "statuses": dict(sorted(statuses.items())),
            "expectation_matches": sum(
                record.get("matches_expected") is True for record in selected
            ),
            "expectation_mismatches": sum(
                record.get("matches_expected") is False for record in selected
            ),
            "attack_oracles": len(oracle_records),
            "observed_attack_successes": sum(
                record["attack_oracle"].get("attack_success") is True
                for record in oracle_records
            ),
            "affected_attack_variant_groups": sorted(
                {
                    record["variant_group"]
                    for record in successful_attack_records
                    if type(record.get("variant_group")) is str
                }
            ),
            "affected_attack_technique_classes": sorted(
                {
                    record["technique_class"]
                    for record in successful_attack_records
                    if type(record.get("technique_class")) is str
                }
            ),
            "cleanup_failures": sum(
                record.get("cleanup_ok") is not True for record in selected
            ),
            "inspection_retries": sum(
                type(record.get("inspection")) is dict
                and record["inspection"].get("attempts", 0) > 1
                for record in selected
            ),
            "cleanup_retries": sum(
                type(record.get("cleanup")) is dict
                and record["cleanup"].get("attempts", 0) > 1
                for record in selected
            ),
            "records_with_controller_errors": sum(
                bool(record.get("controller_errors")) for record in selected
            ),
            "worker_timing_records": len(worker_times),
            "mean_worker_elapsed_ms": _mean(worker_times),
            "execution_timing_records": len(execution_times),
            "mean_execution_wall_ms": _mean(execution_times),
            "compatibility": _compatibility_summary(selected),
            "measurements": _measurements(selected),
            "cases": case_summaries,
        }
    return {
        "schema_version": 1,
        "input_conditions": _input_conditions(records),
        "attack_suite_composition": _attack_suite_composition(records),
        "executors": executors,
    }
