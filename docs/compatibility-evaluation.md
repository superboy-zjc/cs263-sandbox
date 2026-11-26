# Independent benign compatibility evaluation

The project-authored smoke and performance cases are useful regression tests,
but they cannot show how much ordinary Python the prototype accepts. This
experiment therefore derives a fixed sample from OpenAI's
[HumanEval](https://github.com/openai/human-eval) dataset. HumanEval supplies
hand-written programming tasks, canonical solutions, and functional checks. It
is a correctness corpus, not a security corpus.

## Dataset pin and deterministic split

The source artifact is pinned to upstream commit
`b9453e8f1865df0a0057a1383767caa400acfbcf`. Its compressed SHA-256 is
`b796127e635a67f93fb35c04f4cb03cf06f38c8072ee7cee8833d7bee06979ef`,
and it contains 164 unique tasks. HumanEval is distributed under the MIT
license; the upstream notice is retained in `third_party/HUMANEVAL_LICENSE`.

`scripts/build_humaneval_suite.py` ranks every task by
`SHA-256("cs263-humaneval-compatibility-v1" + NUL + task_id)`. The first 30
tasks form the sample. Ranks 1--20 are the development partition, and ranks
21--30 are held out. This rule selected both partitions before any executor
result was observed; it does not select tasks according to prototype support.
The syntax inventory covered all upstream tasks before execution, so “held out”
here means that its runtime outcomes did not guide implementation; it is not a
claim that the task syntax was hidden from the implementer.

The generator parses the upstream source and test code as data. It never
executes either on the host. For each selected task it:

1. removes only `typing` imports and function annotations, which are type-only
   syntax in these canonical programs;
2. retains runtime imports, attribute calls, comprehensions, tuples, keyword
   arguments, and other operational syntax;
3. statically extracts official assertions of the form `candidate(...) == x`,
   `candidate(...) is x`, `candidate(...)`, or `not candidate(...)` when all
   inputs and the exact result are literals representable by the bounded result
   protocol; and
4. replaces those assertions with one final list of calls to the canonical
   function, while recording the upstream task and assertion line numbers.

All 30 deterministically selected tasks had at least one extractable check. The
committed generated suite is `benchmarks/humaneval.json`, with SHA-256
`7c5c52485a7be44809a9b4c7fe63b610c636d742cd8da108709837bbd98e2c4a`.
The official HumanEval runner warns that generated Python must not be executed
without robust sandboxing. In this project, canonical programs run only through
the same disposable container controller used by the other evaluations.

## Reproduction

Download the exact upstream artifact, rebuild the derived suite, then run the
development and held-out partitions separately:

```sh
curl -fL \
  -o /tmp/HumanEval.jsonl.gz \
  https://raw.githubusercontent.com/openai/human-eval/b9453e8f1865df0a0057a1383767caa400acfbcf/data/HumanEval.jsonl.gz
python3 scripts/build_humaneval_suite.py /tmp/HumanEval.jsonl.gz
docker build -f containers/Dockerfile -t cs263-sandbox:baseline .
python3 -m sandbox benchmark \
  --cases benchmarks/humaneval.json \
  --partition development \
  --wall-seconds 15 \
  --output results/humaneval-development.jsonl
python3 -m sandbox benchmark \
  --cases benchmarks/humaneval.json \
  --partition heldout \
  --wall-seconds 15 \
  --output results/humaneval-heldout.jsonl
```

Compatibility mismatches are measurements rather than harness failures, so
they do not make the benchmark command exit unsuccessfully. Infrastructure or
controller failures still do. `python -m sandbox summarize` reports exact
matches and failure classifications by partition.

## Development and evaluation protocol

The first development run used the earlier narrow interpreter and a five-second
outer deadline. It passed 1 of 20 prototype cases; the reference passed 19, with
one outer timeout. Only the development outcomes were then used to add bounded
tuple handling and unpacking, direct allowlisted methods on exact list, string,
and tuple values, list and generator comprehensions, and reviewed conversion and
sequence builtins. Imports, arbitrary attributes, dynamic evaluation, arbitrary
callables, and unbounded collection growth remained prohibited. Increasing the
outer deadline to 15 seconds let the reference complete the larger first task;
it did not change the prototype's internal 10,000-step limit.

After tests and attack regressions passed, the implementation was frozen. The
held-out partition was then run once and was not used for further changes.
That first run produced 4/10 exact prototype matches. A later code audit found
an unrelated comprehension-scope error not exposed by these task outcomes; after
fixing it, both partitions and the attack suite were rerun on the final image and
produced the same outcome counts.

## Result

The final runs on 2026-11-25 used image ID
`sha256:0a803aa41de9ee8c671537c2b31237d87c291b6ed58fbc1fff5f9802f7d7f202`.
The accepted development and held-out JSON Lines files had SHA-256 values
`2d966ed6576ce5c8d8cefe3144eb8e324cdccf4956c5c4025f0244d31be62d4c`
and
`2fdf2dfebe498c645fd9eca822c1b962a750cdeb0b45036b23dfe8a1bfe97b28`,
respectively.

| Executor | Development exact | Held-out exact | Overall exact | Other outcomes |
| --- | ---: | ---: | ---: | --- |
| Prototype | 15/20 (75.0%) | 4/10 (40.0%) | 19/30 (63.3%) | 2 policy rejections, 3 unsupported, 4 resource limits, 2 program errors |
| Pinned reference | 20/20 (100%) | 9/10 (90.0%) | 29/30 (96.7%) | 1 program error |

The prototype produced no wrong `ok` result: all 19 successful executions
matched the expected value and output exactly. Development misses were two
prohibited runtime imports, one unsupported lambda, and two computations that
exceeded the interpreter step budget. Held-out misses exposed unsupported
keyword arguments, missing reviewed `tuple` and `all` builtins, and recursive
programs that exceeded the step budget. These categories distinguish policy
choices and resource limits from incorrect answers.

The reference miss was HumanEval/116. Its policy rejected the canonical use of
`bin`, so this comparison executor is also a restricted Python implementation
rather than a CPython compatibility oracle. The expected outputs come from the
upstream checks, not from reference-executor behavior.

All 60 final execution containers were inspected and removed. There were no
inspection retries, cleanup retries, cleanup failures, or controller errors.
Every JSON Lines record retains the partition, upstream provenance, source and
suite hashes, image ID, expected and observed result, terminal event and source
location, step count, timing, peak worker memory, container state, and cleanup
evidence.

## Limitations

This experiment evaluates 30 canonical solutions, not arbitrary benign Python
programs. It uses the exact literal and Boolean subset of upstream assertions,
so it does not claim full HumanEval pass rates. Removing type-only syntax makes
the experiment about runtime language compatibility; it does not measure
annotation support. A single deterministic sample has sampling error, and a
ten-task held-out partition gives only a coarse estimate. The development score
is expected to be optimistic because it guided implementation; the held-out
drop shows why both numbers must be reported. Finally, functional correctness
does not establish security, and the cold-container measurements in the
performance experiment do not establish suitability for a particular IoT
device.
