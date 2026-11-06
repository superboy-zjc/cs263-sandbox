# Initial evaluation

The first experiment compares our restricted AST interpreter with the unchanged
[smolagents executor at commit 96f33fa](https://github.com/huggingface/smolagents/blob/96f33faaf028479119ec8d34507b47694cf14e34/src/smolagents/local_python_executor.py).
Its complete upstream package is installed in the evaluation image. The source
archive checksum, installed executor checksum, and base-image digest are verified
or pinned. Runtime dependency versions are fixed in
`containers/reference-constraints.txt`; wheels can differ by architecture. The
image retains dependency manifests, and each run records package versions and
the resolved image ID.

## What the smoke suite measures

The 15 cases are written for this project: eight check benign execution or Python
semantics, four check our intended restriction policy, and three check resource
budgets. They are a starting point for regression testing. They do not represent
a published escape corpus, establish a security guarantee, or measure resistance
to prompt injection.

Each case has an explicit expected result under our initial policy. Report both
the actual executor outcome and whether that expectation matched. The reference
retains its own imports, builtins, and operation limits; it is not silently
reconfigured to match our smaller subset. For example, allowing `import math` is
a deliberate reference capability and is not evidence of an escape. Upstream
exceptions remain `program_error`; the adapter does not guess which exceptions
constitute security-policy decisions.

Result conversion is a separate measurement boundary. `output_error` means the
returned object cannot be represented in the bounded plain-data protocol. It
does not mean that the executor prevented the preceding computation or side
effects. `wall_timeout`, `oom_killed`, and `protocol_limit` identify external
controller outcomes and must not be counted as language-policy rejections.

## Reproduction and measurement

Both executors use the same Docker image and outer limits, with a fresh container
for every case. Default limits are five seconds of wall time, 256 MiB of memory,
one CPU, and 64 processes. No application credentials or host directories are
passed into the container. The supervisor also bounds response and stderr data
retained on the host, kills overdue containers, and records removal failures.

`elapsed_ms` is executor-specific diagnostic timing and should not be compared
as a uniform metric. `worker_elapsed_ms` includes cold interpreter/adapter imports,
executor initialization, execution, and result conversion for both implementations.
`execution_wall_ms` includes Docker startup and waiting; `elapsed_wall_ms` also
includes inspection and cleanup. `peak_memory_kib` is the worker process's
high-water resident memory from Linux `getrusage`, including imports. It is not
an aggregate memory measurement of the entire container and is sampled before
the final JSON response is encoded.

These are single-run smoke measurements, not performance estimates. Repeated
trials, warm execution, representative workloads, and ARM-device measurements
remain future evaluation work. Because the image includes the reference's
dependencies, its size is not a measurement of the standalone prototype's
deployment footprint.

## Observability and limitations

Prototype records include bounded events for reviewed calls and the terminal
rejection or failure, with source locations and reasons. Steps account for
execution, reviewed builtin iteration, formatting, and result traversal; they
are not directly comparable with the reference's AST counter. The adapter emits
only its own phases and reports reference steps as unavailable. It does not
invent policy traces for the upstream executor.

Future attack evaluation needs independently observed success conditions, such
as access to a designated test resource that is reachable within containment but
forbidden by the language policy. This avoids letting outer isolation hide a
missing interpreter check. Related payload variants should stay together when
forming development and held-out splits. Record provenance, adaptations, policy
assumptions, exclusions, and both security and compatibility outcomes.
