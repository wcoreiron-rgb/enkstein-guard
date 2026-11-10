# Security history component profiling

`tools/profile_security_history.py` is a bounded, synthetic component diagnostic
for `SecurityHistoryStore.recent` and `SecurityHistoryStore.record`. It is not a
deployment benchmark, a capacity result, or production-acceptance evidence.

Running the command without `--run` prints a complete plan and performs no
temporary-store or output allocation:

```console
PYTHONPATH=src python tools/profile_security_history.py
```

The plan records the normalized arguments, fixture size and construction mode,
exact public request counts, output paths, and hard scope limits. Parameters are
restricted to 1–16 actors, 16–256 history rows per actor, at most 4,096 total
rows, and 1–100 iterations. Each iteration makes one `recent` call and one
`record` call per actor.

## Explicit diagnostic run

Use a new output directory for every run. The tool refuses an existing output
directory so an older report or cProfile file cannot be overwritten.

```console
PYTHONPATH=src python tools/profile_security_history.py \
  --run --actors 2 --per-actor-history 16 --iterations 1 \
  --output-dir verification/history-component-profiler/example-run
```

Every execution creates the database and key inside a new
`TemporaryDirectory`; there are no database-path or key-path arguments. The
fixture is filled through public `record` calls by default, then the exact
record count and all authenticated rows are verified before timing begins. A
second complete verification runs after timing. Temporary keys, ciphertexts,
context payloads, actor identifiers, and tokens are never included in the JSON
report.

For larger fixtures, `--bulk-seed` opts into faster diagnostic-only setup. It
first creates one valid public record per actor, then uses the existing store
encoder and active synthetic-store key to create additional authenticated
SQLite rows. The complete fixture must still pass the normal store verification
before profiling. This mode is synthetic fixture construction, not real warmup
and not deployment acceptance.

The exclusive output directory contains:

- `history-component.prof`: raw cProfile statistics for the public timed calls.
- `history-component.json`: exact parameters and call counts, elapsed time,
  structured top functions, fixture verification, Python runtime, package
  version, source/package locations and SHA-256 digests, and an explicit
  synthetic-component evidence classification.

Reports distinguish a package imported from `site-packages`/`dist-packages`
(`installed_distribution`) from a directly imported checkout or staging tree
(`source_tree`). Compare results only when the parameters, runtime, source
location, version, and digests are the intended ones. Timing has no pass/fail
threshold and must not be cited as service latency, deployment behavior, or
production capacity.
