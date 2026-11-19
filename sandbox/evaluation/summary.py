"""Summarize bounded JSON Lines evaluation records."""

from collections import Counter
import json
import math
from pathlib import Path
from typing import Any


MAX_RECORDS = 10_000
MAX_RECORD_BYTES = 1_048_576


def _mean(values: list[float]) -> float | None:
    if not values:
        return None
    return round(math.fsum(values) / len(values), 3)


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
        worker_times = [
            record["observed"]["worker_elapsed_ms"]
            for record in selected
            if type(record["observed"].get("worker_elapsed_ms"))
            in (int, float)
            and math.isfinite(record["observed"]["worker_elapsed_ms"])
        ]
        execution_times = [
            record["execution_wall_ms"]
            for record in selected
            if type(record.get("execution_wall_ms")) in (int, float)
            and math.isfinite(record["execution_wall_ms"])
        ]
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
            "cleanup_failures": sum(
                record.get("cleanup_ok") is not True for record in selected
            ),
            "records_with_controller_errors": sum(
                bool(record.get("controller_errors")) for record in selected
            ),
            "worker_timing_records": len(worker_times),
            "mean_worker_elapsed_ms": _mean(worker_times),
            "execution_timing_records": len(execution_times),
            "mean_execution_wall_ms": _mean(execution_times),
        }
    return {"schema_version": 1, "executors": executors}
