# Repeated performance evaluation

This experiment measures repeated cold execution of six bounded benign
workloads. It is intended to replace single-run smoke timings with a reproducible
initial distribution. It does not yet measure warm throughput, broad Python
compatibility, or performance on a resource-constrained target device.

## Workloads and execution order

`benchmarks/performance.json` contains project-authored workloads for arithmetic
loops, indexed list updates, dictionary lookups with branches, stepped string
slices, user-defined function calls, and nested list traversal. Each workload
has an explicit expected value and output.

Each executor/workload pair runs 20 times, for 240 records. Every record uses a
fresh Docker container. Trials are interleaved by workload, and executor order is
reversed on alternating trials. This balances which executor runs first instead
of running all prototype measurements before all reference measurements.

Reproduce the experiment from the repository root:

```sh
docker build -f containers/Dockerfile -t cs263-sandbox:baseline .
python3 -m sandbox benchmark \
  --cases benchmarks/performance.json \
  --repetitions 20 \
  --output results/performance.jsonl
python3 -m sandbox summarize results/performance.jsonl
```

The command limits repetitions to 100. Result records include the trial index
and count. The summary reports sample counts, minimum, median, mean,
nearest-rank P95, and maximum, both overall and by workload.

## Measurement boundaries

- `executor_elapsed_ms` is executor-specific diagnostic timing. The two
  implementations start this timer at different internal boundaries, so it must
  not be used for a direct comparison.
- `worker_elapsed_ms` begins before executor-specific imports and initialization
  in the isolated worker and ends after execution and result conversion. This is
  the main cold worker comparison.
- `execution_wall_ms` measures Docker startup and the controller's wait for the
  worker response. It excludes the later inspect and cleanup steps.
- `elapsed_wall_ms` additionally includes container inspection and cleanup.
- `peak_memory_kib` is the worker process's Linux high-water resident memory. It
  includes imports but is not aggregate container memory.

All cases use the same image, one CPU, 256 MiB of container memory, no network,
no host mounts, a read-only root filesystem, and a five-second controller
deadline.

## Final result

The accepted run on 2026-11-25 used performance-suite SHA-256
`c6f9e7c517d64a6bd7bf8b985f291675f604ba2379cb55bedbce26bccf9c7838`
and image ID
`sha256:0a803aa41de9ee8c671537c2b31237d87c291b6ed58fbc1fff5f9802f7d7f202`.
The accepted JSON Lines file had SHA-256
`e5f104c03ed26f458ecdb635c3e1e73f7f3b62c912c2a41986aead42fd76b5f4`.
Both executors produced the expected value and output in all 120 records. No
container inspection, cleanup, or controller error occurred, and no evaluation
container remained after the run.

| Measurement | Prototype median | Prototype P95 | Reference median | Reference P95 | Reference/prototype median |
| --- | ---: | ---: | ---: | ---: | ---: |
| Cold worker time | 33.255 ms | 70.247 ms | 339.833 ms | 555.934 ms | 10.22x |
| Docker execution wall time | 618.044 ms | 1,002.534 ms | 955.636 ms | 1,644.345 ms | 1.55x |
| Worker peak memory | 22,332 KiB | 22,348 KiB | 56,228 KiB | 56,412 KiB | 2.52x |

Across these workloads, the prototype therefore had lower cold worker time,
Docker execution wall time, and worker-process memory. Docker startup accounts
for much of the wall-clock measurement, so the wall-time ratio is smaller than
the worker-time ratio. These ratios describe this image and workload set only;
they are not general Python performance claims.

## Excluded runs and infrastructure hardening

Two early complete 20-repetition runs on a pre-compatibility image were excluded.
In the first, one otherwise successful record failed to remove its stopped
container on the initial attempt. In the second, one otherwise successful record
could not inspect container state on the initial attempt. The recorded program
outputs were correct, but infrastructure evidence was incomplete.

Those observations led to bounded controller retries for exact container
inspection and removal. Each operation now makes at most three attempts with
short delays and records the attempt count and bounded diagnostics. A recovered
transient failure remains visible in the record; failure after all attempts is a
controller error and makes the benchmark command fail.

After the implementation was frozen, the first final-image run was also
excluded: 239 records completed normally, but one prototype function-call
record reached the five-second outer deadline after 17 earlier successful
trials. Its exact container was inspected and removed, with no controller error
or residual container. The complete 20-repetition experiment was restarted
under the same limits rather than replacing the one measurement. The second
final-image run is the accepted result above. Excluded JSON Lines files remain
local evidence and are not combined with the accepted run.

## Limitations

The workloads are small, project-authored, and deliberately remain inside the
prototype's supported subset. They do not represent general Python programs or
an independently sourced application corpus. Fresh containers measure cold
initialization rather than steady-state throughput, and worker memory includes
different import graphs. The experiment ran on one machine and date, not on an
IoT or other resource-constrained target. Future evaluation should add an
independently sourced benign corpus, a warm-execution mode with an explicit state
reset boundary, multiple machines or architectures, and enough repetitions for
confidence intervals where appropriate.
