"""Command-line interface for isolated executor comparisons."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from sandbox.evaluation import harness, summary


def _repetition_count(value: str) -> int:
    """Parse a bounded number of fresh-container repetitions."""
    try:
        count = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if count < 1 or count > 100:
        raise argparse.ArgumentTypeError("must be between 1 and 100")
    return count


def main(argv: list[str] | None = None) -> int:
    """Run a smoke suite and write one JSON Lines record per execution."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["benchmark", "summarize"])
    parser.add_argument("result_file", nargs="?", type=Path)
    parser.add_argument(
        "--cases", type=Path, default=Path("benchmarks/cases.json")
    )
    parser.add_argument("--case", action="append", dest="case_ids")
    parser.add_argument(
        "--partition", choices=sorted(harness.COMPATIBILITY_PARTITIONS)
    )
    parser.add_argument(
        "--executor", action="append", choices=["prototype", "reference"]
    )
    parser.add_argument("--image", default="cs263-sandbox:baseline")
    parser.add_argument("--wall-seconds", type=float, default=5.0)
    parser.add_argument("--memory-mib", type=int, default=256)
    parser.add_argument(
        "--repetitions",
        type=_repetition_count,
        default=1,
        help="run each executor/case pair in this many fresh containers",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "summarize":
            if args.result_file is None:
                raise ValueError("summarize requires a JSON Lines result file.")
            report = summary.summarize(summary.load_records(args.result_file))
            print(json.dumps(report, allow_nan=False, indent=2, sort_keys=True))
            return 0
        if args.result_file is not None:
            raise ValueError(
                "benchmark does not accept a result-file argument."
            )
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
        if args.partition:
            cases = [
                case
                for case in cases
                if case.get("partition") == args.partition
            ]
            if not cases:
                raise ValueError(
                    f"No cases use the {args.partition} partition."
                )
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
            for trial_index in range(1, args.repetitions + 1):
                trial_executors = (
                    executors
                    if trial_index % 2 == 1
                    else list(reversed(executors))
                )
                for case in cases:
                    for executor in trial_executors:
                        record = harness.run_case(
                            case,
                            executor,
                            image_id,
                            settings,
                            suite_hash,
                            trial_index=trial_index,
                            trial_count=args.repetitions,
                        )
                        stream.write(
                            json.dumps(record, allow_nan=False) + "\n"
                        )
                        stream.flush()
                        status = record["observed"]["status"]
                        summaries[executor][status] += 1
                        if (
                            executor == "prototype"
                            and case["category"] != "compatibility"
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
                        trial = (
                            f" [{trial_index}/{args.repetitions}]"
                            if args.repetitions > 1
                            else ""
                        )
                        print(
                            f"{executor:9} {case['id']}{trial}: {status}; "
                            "matches expectation="
                            f"{record['matches_expected']}",
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
