# Lightweight Python Sandboxing with a Restricted AST Interpreter

## Abstract

This project asks whether an interpreter-level Python policy can reject unsafe
operations before they reach host capabilities while using fewer resources than
a broader Python executor. We implemented a restricted abstract-syntax-tree
(AST) interpreter with complete-tree validation, runtime checks on resolved call
targets and exact-type methods, private execution budgets, plain-data result
conversion, and structured rejection evidence. A Docker controller supplies an
independent process, filesystem, network, time, and memory boundary for the
experiments; it is not counted as part of the language policy.

On 36 sourced attack cases, the prototype had zero observed attack successes:
none of 27 disclosure attempts emitted the canary, and all nine availability
attempts were stopped internally or rejected before outer containment
intervened. The corpus contains 31 related variant groups across 16
project-defined mechanism classes; this result still covers only the declared
cases and oracles. On a deterministic 30-task HumanEval adaptation, the prototype
matched 15/20 development tasks and 4/10 tasks whose runtime outcomes were held
out until the implementation was frozen. On six project-authored workloads run
20 times per executor in fresh containers, the pinned reference used 10.22
times the prototype's median cold worker time, 1.55 times its median Docker
execution wall time, and 2.52 times its median worker peak memory. These
measurements show a concrete security--compatibility--cost tradeoff on one
machine; they do not establish general Python security or IoT suitability.

## 1. Problem and scope

AI agents may generate code after consuming untrusted content. If generated
source is executed with ordinary Python authority, a prompt-level compromise can
become file, process, credential, or network access. Virtual machines and
containers can place a strong boundary around that execution, but a deployment
may also want to reject dangerous language operations early and avoid starting
a guest operating system for each small computation.

The research question is therefore narrow: **how much security observability
and execution-cost reduction can a small interpreter-based Python subset provide,
and what compatibility does that restriction sacrifice?** The work contributes
an implementation and an evaluation protocol, not a proof that Python can be
made safe inside a shared process.

The adversary controls the submitted source. Relevant goals are reaching a
capability absent from the language policy, disclosing a designated container
resource, exhausting CPU, memory, or output capacity, and confusing result
classification. The prototype intentionally receives no modules, arbitrary
Python objects, file handles, callbacks, or other host capabilities. Native
extensions, container escape, hardware side channels, and attacks without an
observable effect are outside the measured threat model.

## 2. Sandboxing approaches

Sandbox layers protect different interfaces and should not be treated as
interchangeable.

| Layer | Boundary | Strength and cost | Relevance here |
| --- | --- | --- | --- |
| Virtual machine or microVM | A hypervisor separates the workload behind a guest kernel and virtual devices. | Strong isolation and broad Linux compatibility, with a guest kernel and configured guest memory. Firecracker reports about 150 ms minimum startup and about 3 MiB of non-shared VMM memory in its evaluated configuration; the latter is not total microVM memory. | Appropriate for a high-assurance outer boundary, but still has fixed per-guest costs. |
| Linux container | Namespaces isolate process, mount, and network views; capabilities and seccomp reduce authority; cgroups account for and limit resources. | Lower startup cost and higher density than a VM, but containers share the host kernel and depend on daemon and profile configuration. | Useful experimental containment. It can hide a missing language check, so the language policy needs its own oracle. |
| Process and OS policy | Address spaces, users, namespaces, syscall filters, and resource controllers constrain one process. gVisor inserts a user-space application kernel between the program and host system calls. | Near-native CPU work is possible, while syscall interposition and extra state add overhead and may reduce compatibility. The Linux documentation explicitly states that seccomp alone is not a complete sandbox. | Covers failures, parsing costs, and operations missed by interpreter counters. |
| Language or interpreter policy | A validator or interpreter decides which syntax, values, calls, and capabilities exist. | Fine-grained decisions can happen before allocation or host calls, but the trusted base includes the interpreter and every exposed wrapper; a smaller language loses compatibility. | The prototype's main subject. It is a candidate additional layer, not a universal replacement for OS isolation. |

The comparison is grounded in the
[Firecracker paper](https://www.usenix.org/conference/nsdi20/presentation/agache),
[Docker security documentation](https://docs.docker.com/engine/security/), the
Linux documentation for
[seccomp](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
and [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html), and the
[gVisor security](https://gvisor.dev/docs/architecture_guide/security/) and
[performance](https://gvisor.dev/docs/architecture_guide/performance/) models.
The project has no ARM, microcontroller, energy, or warm resident-interpreter
measurements. Language-level control is therefore only an engineering candidate
for resource-constrained environments in this study.

## 3. Existing Python sandbox designs

[RestrictedPython](https://github.com/zopefoundation/RestrictedPython) compiles
a restricted subset and rewrites operations to caller-provided guards. This
retains CPython execution but makes the caller's globals, builtins, import
policy, and reachable objects part of the boundary. Its maintainers explicitly
state that it is not by itself a sandbox or secured environment.

[PyPy's sandbox](https://doc.pypy.org/sandbox.html) takes a different approach:
a translated interpreter serializes external operations to an outer controller,
which supplies virtual files and other services. This supports a broader Python
language behind a process boundary, but the official documentation describes
the published implementation as old and unmaintained and primarily tested with
PyPy 2.

[Asteval](https://lmfit.github.io/asteval/) is closer to this project. It walks
Python AST nodes against a separate symbol table and excludes imports, classes,
dynamic attribute functions, and dangerous dunder access by default. Its
[safety documentation](https://lmfit.github.io/asteval/safety.html) describes it
as safer than `eval`, not completely safe against malicious code.

The pinned
[smolagents `LocalPythonExecutor`](https://github.com/huggingface/smolagents/blob/96f33faaf028479119ec8d34507b47694cf14e34/src/smolagents/local_python_executor.py)
is the experimental reference because it is an AST interpreter intended for
agent-generated Python. It supports a broader set of Python operations and
calls real Python callables that pass its policy. The upstream
[security policy](https://github.com/huggingface/smolagents/blob/main/SECURITY.md)
does not present local execution as a complete isolation boundary. This project
compares behavior and resource use with that fixed version; it does not claim
the reference represents CPython or a security baseline.

The design difference pursued here is narrow but explicit: submitted AST nodes
are never compiled or passed to `eval` or `exec`; approved callables and methods
remain internal tokens; runtime dispatch checks their identity and owning exact
type; and returned data is copied through a bounded plain-data protocol. Hard
time and memory protection still belongs to the outer process boundary.

## 4. Prototype design

### 4.1 Static validation

Before any submitted statement executes, the policy walks the complete AST and
enforces node, name, target, nesting, and node-count rules. Imports, reflection,
dynamic evaluation, classes, exception handling, lambda expressions, arbitrary
keyword arguments, private names, and unreviewed attributes are rejected.
Reviewing all branches prevents an invalid operation from being hidden behind a
condition that happens to be false during one run.

Attribute syntax is allowed only as the direct target of a call using a reviewed
method name. This static rule is not the final authorization: runtime dispatch
also requires an exact list, tuple, or string and returns an internal method
token rather than a Python bound method.

### 4.2 Runtime interpretation

The interpreter implements plain scalars, lists, tuples, dictionaries, bounded
slice reads, assignments and unpacking, arithmetic and comparisons, conditions,
loops, functions, list comprehensions, and immediately materialized generator
expressions. Its builtins are small wrappers rather than objects copied from
`builtins`. User functions are interpreter-owned records with lexical
environments. An alias remains safe because permission follows the resolved
internal token rather than its variable name.

Every returned or compared structure is traversed with size, depth, cycle, key,
number, and type checks. Arbitrary objects and function values cannot cross the
result boundary. A successful result contains only JSON-compatible plain data,
captured output, execution counters, and diagnostic events.

### 4.3 Resource control

Private state enforces 10,000 interpreter steps, 4,096 output characters, 1,000
collection or range items, 4,096-bit integers, 32,768 source bytes, 4,096 AST
nodes, syntax depth 64, and function-call depth 32. Wrappers check growth before
list mutation, joining, splitting, repetition, slicing, ranges, and large integer
operations where practical. These counters are not guest variables and cannot
be reset by interpreted assignments.

Step counting cannot bound every host operation or interpreter defect. Each
evaluation therefore runs in a fresh Docker container with no network or host
mount, a read-only root filesystem, an unprivileged user, dropped capabilities,
`no-new-privileges`, PID and file-descriptor limits, one CPU, 256 MiB of memory,
and an external deadline. The controller bounds its own pipe buffers, inspects
the exact container, retries inspection and removal at most three times, and
records cleanup evidence. The base image and reference source are pinned and
runtime versions are recorded, although online build tooling and platform wheels
mean the image is not claimed to be byte-for-byte reproducible.

## 5. Evaluation method

The accepted compatibility and performance experiments used image
`sha256:0a803aa41de9ee8c671537c2b31237d87c291b6ed58fbc1fff5f9802f7d7f202`.
The expanded attack experiment used
`sha256:128da983471829f9e0f29551a093c73b2232499e0d5cf29bd07bd220c602ca71`,
which adds the corpus metadata validation and coverage summary without changing
the interpreter or policy implementation. Each record retains its resolved
image ID, and each executor/case pair used a fresh container.

### 5.1 Attack cases and independent oracles

The 36-case corpus draws from current RestrictedPython, asteval, and smolagents
security tests; fixed JailCTF Pyjailbreaker and challenge repositories; and two
published sandbox discussions. It contains 31 related variant groups, 16
mechanism classes, seven source families, and three source kinds. Per-case
metadata includes an immutable source where available, locator, inspected-source
SHA-256, license note, and safe adaptation. The loader rejects duplicate
payloads and inconsistent group classification.

Twenty-seven cases attempt direct capability access, dynamic evaluation,
namespace or importer recovery, object-graph and frame traversal, formatter and
higher-order indirection, transitive modules, AST validation gaps, or name
filter bypass. The controller creates a fresh random canary, places it inside
the container, removes it from the worker environment, and scans raw output for
the exact value. Nine cases exercise nontermination, recursion, output, numeric,
collection, string, or malformed-code-object availability threats; success
means a declared outer condition occurred. Executor status labels are not
attack oracles. Syntax variants count as variants, not independent mechanisms.

### 5.2 Independent benign compatibility

The compatibility generator verifies the official compressed
[HumanEval dataset](https://github.com/openai/human-eval/blob/b9453e8f1865df0a0057a1383767caa400acfbcf/data/HumanEval.jsonl.gz)
hash, ranks all 164 task IDs by a fixed SHA-256 rule, and selects 30 before
execution. It removes only `typing` imports and function annotations, then
statically converts exact literal or Boolean upstream assertions into final
function calls. The generator never executes upstream code on the host. The
official HumanEval module itself warns that its reliability guard is
[not a security sandbox](https://github.com/openai/human-eval/blob/master/human_eval/execution.py).

The first 20 selected tasks form the development partition and guided bounded
language additions. The remaining ten runtime outcomes were unseen until the
implementation was frozen, although an aggregate syntax inventory had examined
the full dataset. The held-out result is therefore the primary evidence of
generalization. This is a fixed HumanEval adaptation, not official pass@1 or the
complete upstream test suite.

### 5.3 Repeated performance

Six project-authored cases exercise arithmetic loops, list updates, dictionary
lookup, string slicing, function calls, and nested data. Every executor/case
pair runs 20 times, giving 240 records. Trials are interleaved by workload and
executor order reverses on alternating trials. The main comparable measures are
cold worker elapsed time, Docker execution wall time, and worker-process peak
resident memory. Executor-internal timers start at different boundaries and are
reported only as diagnostics.

## 6. Results

### 6.1 Security observations

| Executor | Cases | Canary disclosures | Availability successes | Observed statuses |
| --- | ---: | ---: | ---: | --- |
| Prototype | 36 | 0 | 0 | 25 `policy_rejected`, 8 `resource_limit`, 3 `unsupported` |
| Pinned reference | 36 | 0 | 6 | 30 `program_error`, 4 `oom_killed`, 2 `wall_timeout` |

Neither executor emitted the canary. The six reference successes were all
availability outcomes: oversized integer power, range materialization, list
repetition, and string repetition reached the container memory limit; unbounded
output and an exponent tower reached the controller deadline. The prototype
stopped all nine availability attempts internally or rejected their syntax
before outer containment. Zero observed prototype successes means only that
these payloads did not satisfy their declared oracles. Most capability cases
were rejected statically, and the suite has no integrity oracle, blind attack
partition, or claim to exhaust unknown techniques.

### 6.2 Compatibility

| Executor | Development | Runtime-outcome held out | Descriptive total |
| --- | ---: | ---: | ---: |
| Prototype | 15/20 | 4/10 | 19/30 |
| Pinned reference | 20/20 | 9/10 | 29/30 |

All 19 prototype `ok` results exactly matched expected value and output; there
were no wrong successful answers. The other outcomes were two policy rejections,
three unsupported programs, four internal resource limits, and two ordinary
program errors. The held-out misses expose the cost of the smaller language:
keyword arguments and reviewed builtins remain incomplete, while recursive
canonical programs can exceed the step budget. The reference miss rejected an
upstream use of `bin`, confirming that it is also a restricted comparison
executor.

The 75% development and 40% held-out rates should not be pooled into a claimed
independent 63.3% rate. The total describes this sample; 4/10 is the outcome not
used to select features, and its small denominator gives a coarse estimate.

### 6.3 Performance

| Measurement | Prototype median / P95 | Reference median / P95 | Reference/prototype median |
| --- | ---: | ---: | ---: |
| Cold worker time | 33.255 / 70.247 ms | 339.833 / 555.934 ms | 10.22x |
| Docker execution wall time | 618.044 / 1,002.534 ms | 955.636 / 1,644.345 ms | 1.55x |
| Worker peak memory | 22,332 / 22,348 KiB | 56,228 / 56,412 KiB | 2.52x |

All 240 accepted records matched their expected results. The worker-time and
memory differences include different import graphs and supported feature sets.
Docker startup compresses the wall-time ratio. The numbers support a lower-cost
claim only for these cold, small, project-authored workloads on this machine.
They do not measure warm throughput, energy, deployment image size, ARM, or a
resource-constrained device.

## 7. Observability and validity

The final accepted attack, compatibility, and performance experiments contain
372 execution records. Every record includes case, suite, source, and resolved
image fingerprints; executor and partition; effective limits; expected and
observed status, value, and output; bounded runtime events with source location
and reason; interpreter steps where available; worker and wall timing; worker
peak memory; Docker exit and OOM state; inspection and removal attempts; and any
controller errors. Attack records additionally contain source provenance,
source-artifact hashes, corpus grouping fields, and an independent oracle
result.

The summary command keeps expectation matches, attack-oracle successes, and
compatibility outcomes separate. It reports attack variants separately from
variant groups, mechanism classes, source families, and source kinds. It also
reports distributions rather than only means and exposes unique image IDs,
suite hashes, repetition counts, and per-executor case counts, flagging mixed or
unbalanced inputs. All 372 accepted containers were inspected and removed with
no retry, cleanup failure, controller error, or residual evaluation container.

This observability supports audit and diagnosis, but it does not fix sampling
bias or missing attacks. Raw JSON Lines results are ignored by Git and remain
local; the repository retains exact suite hashes, image IDs, accepted result
hashes where recorded, aggregate tables, adaptation rules, and reproduction
commands. A stronger artifact release would publish the accepted raw records
and machine description.

## 8. Limitations and future work

- Thirty-six sourced payloads across 31 variant groups and 16 project-defined
  classes demonstrate broader public-technique sampling, not an escape-rate
  estimate, complete state-of-the-art denominator, or proof. Add a blind attack
  partition, integrity oracles, and cases adjacent to newly allowed methods and
  comprehensions.
- The compatibility sample has only ten runtime-outcome-held-out tasks and uses
  statically extractable exact checks from canonical solutions. Evaluate larger,
  independently chosen applications and keep a larger blind partition.
- Generator expressions are immediately materialized, and several Python
  constructs and builtins remain intentionally incomplete. This is a language
  subset rather than a conforming Python implementation.
- Performance uses cold containers and project-authored supported cases. Add a
  warm worker with a proven state-reset boundary, external workloads, confidence
  intervals, and several machines or architectures.
- Run on the intended edge or IoT target and measure memory, latency, energy,
  persistent footprint, and the cost of the outer isolation actually available
  there.
- Expand Docker integration tests to cover OOM, protocol overflow, and canary
  bootstrap paths continuously, not only through experimental runs.

## 9. Conclusion

The project demonstrates a concrete middle layer between unrestricted local
Python execution and operating-system containment. Complete-AST validation,
identity-based call dispatch, exact-type method wrappers, bounded plain-data
conversion, and private resource counters produced explicit decisions before
the tested payloads reached host capabilities. The final measurements also show
the price: only 4 of 10 runtime-outcome-held-out benign tasks matched, even
though the narrow supported workloads used less cold worker time and memory than
the broader reference.

The appropriate interpretation is defense in depth. The interpreter can reduce
exposed language capability, reject expensive operations early, and explain its
decisions. A process, container, microVM, or comparable outer boundary must
still cover parser cost, interpreter defects, native runtime failures, and
unknown attacks. The project's strongest result is therefore not “Python is
safe,” but a reproducible account of which operations were allowed or rejected,
which attacks met an independent success condition, which benign tasks remained
compatible, what resources were measured, and where the evidence stops.
