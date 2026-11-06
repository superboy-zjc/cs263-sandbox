"""Command-line interface for isolated executor comparisons."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from sandbox.evaluation import harness


def main(argv: list[str] | None = None) -> int:
    """Run a smoke suite and write one JSON Lines record per execution."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["benchmark"])
    parser.add_argument(
        "--cases", type=Path, default=Path("benchmarks/cases.json")
    )
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument(
        "--executor", action="append", choices=["prototype", "reference"]
    )
    parser.add_argument("--image", default="cs263-sandbox:baseline")
    parser.add_argument("--wall-seconds", type=float, default=5.0)
    parser.add_argument("--memory-mib", type=int, default=256)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        settings = harness.Settings(
            image=args.image,
            wall_seconds=args.wall_seconds,
            memory_mib=args.memory_mib,
        )
        cases, suite_hash = harness.load_cases(args.cases)
        if args.case_ids:
            requested = set(args.case_ids)
            known = {case["id"] for case in cases}
            if requested - known:
                raise ValueError(
                    "Unknown case IDs: " + ", ".join(requested - known)
                )
            cases = [case for case in cases if case["id"] in requested]
        executors = list(
            dict.fromkeys(args.executor or ["prototype", "reference"])
        )
        image_id = harness.resolve_image(settings.image)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        output = args.output or Path(f"results/baseline-{timestamp}.jsonl")
        output.parent.mkdir(parents=True, exist_ok=True)
        summaries = {executor: Counter() for executor in executors}
        failed_prototype = False
        infrastructure_failed = False
        with output.open("x", encoding="utf-8") as stream:
            for executor in executors:
                for case in cases:
                    record = harness.run_case(
                        case, executor, image_id, settings, suite_hash
                    )
                    stream.write(json.dumps(record, allow_nan=False) + "\n")
                    stream.flush()
                    status = record["observed"]["status"]
                    summaries[executor][status] += 1
                    if (
                        executor == "prototype"
                        and not record["matches_expected"]
                    ):
                        failed_prototype = True
                    if (
                        status
                        in {
                            "infrastructure_error",
                            "protocol_error",
                            "crashed",
                            "internal_error",
                            "protocol_limit",
                        }
                        or record["controller_errors"]
                    ):
                        infrastructure_failed = True
                    print(
                        f"{executor:9} {case['id']}: {status}; "
                        f"matches expectation={record['matches_expected']}",
                        flush=True,
                    )
        print(f"Results: {output}")
        print(json.dumps(summaries, sort_keys=True))
        print(
            "Expectation matches are regression checks, not escape-rate scores."
        )
        return 1 if failed_prototype or infrastructure_failed else 0
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
