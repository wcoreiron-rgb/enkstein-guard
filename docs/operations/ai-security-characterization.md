# AI security path capacity characterization

This harness measures the configured AI inspection path on one
production-profile Guard host. It is a characterization tool, not a production
acceptance suite, SLO, or live-model robustness test.

It reuses the production deployment topology:

- Guard has no network interface and runs under its production UID.
- The independent egress proxy owns the only network path.
- Agents are networkless, have distinct UIDs and credentials, and are split
  evenly across tenants `a` and `b`.
- Each tenant has a fixed business model and fixed security-inspection model on
  the local synthetic TLS upstream.
- Business and inspector connectors use separate tenant-bound credentials.
- Internal inspector routes are never granted to agents.
- The characterization-only TLS fixture atomically publishes bounded cumulative
  counters. It never persists request bodies or header values; credential
  observations are represented only by bounded SHA-256 hash-count buckets.

No public provider or live model is contacted.

## Plan first

The command defaults to plan mode. Plan mode validates the complete product
configuration and prints bounded parameters without invoking Docker:

```sh
ENKSTEIN_POLICY_PACK=/nonexistent/guard-stage-tests \
PYTHONPATH=src:tests \
python deployment/characterize_ai_security.py
```

`--plan` is an explicit synonym for the default. The small defaults are:

- 2 actors, one per tenant;
- 16 retained history records per actor and capacity 32;
- 16 warmup calls per actor;
- 10 measured seconds at 2 offered requests/second/actor;
- at most 4 in-flight requests per actor.

Bounds are deliberately finite: actor count must be even from 2 through 64,
per-actor history 16 through 256, global history capacity is exactly
`actors × per_actor_history` and at most 100,000, duration is 1 through 600
seconds, rate is 0.1 through 3 requests/second/actor with at least one offered
call, and per-actor in-flight work is 1 through 16.

The plan includes the canonical configuration digest, actor allocation and
UIDs, derived warmup and offered measurement calls, fixed models, and the four
separate credential names. It always states:

```json
{"production_accepted": false, "live_model_robustness": false}
```

## Explicit execution

Only `--run` may create containers. Root review and a matching candidate wheel
and image are prerequisites:

```sh
python deployment/characterize_ai_security.py \
  --run \
  --actors 2 \
  --per-actor-history 16 \
  --duration 10 \
  --rate-per-actor 2 \
  --max-inflight 4
```

The harness creates a random Compose project whose name starts with `egai`.
Cleanup invokes `docker compose down --volumes --remove-orphans` only for that
project and removes only its private run directory. It never prunes Docker,
changes the global context, starts a VM, or removes resources belonging to
another run.

## Warmup gate

The harness first starts all configured agents with the fixed-count warmup
phase. Warmup uses only ordinary benign calls to the protected tenant business
route. Every request has a unique request ID; there are no retries and no direct
database insertion or history seeding.

Measurement does not begin unless all of these are observed:

1. every actor process exits normally and reports exactly its configured
   offered and actual warmup calls;
2. every actor reports at least `per_actor_history` successful calls;
3. `service status` reports `security_history.records` equal to the exact
   configured global capacity;
4. the strict upstream-counter delta reports inspector calls, business calls,
   successful calls, and actual calls all equal, with zero unknown requests.

Failure of any gate leaves `complete=false`, records the error, preserves the
partial warmup evidence, skips measurement, and still performs project-local
cleanup.

## Measured phase and report

After the warmup gate, all agents offer their configured bounded rate for the
fixed duration. The networkless load fixture reports, without retrying:

- offered and actual calls;
- every response/client-error status and count;
- successful and error calls;
- p50, p95, p99, maximum, and per-request values for total client latency,
  semaphore queue time, and Guard RPC time separately. Total client latency
  starts before waiting for an in-flight slot;
- the requested offered window and any post-window drain time. A measured phase
  remains alive through at least the configured offered duration even if all
  calls finish earlier.

The harness keeps warmup and measurement sections separate. It also records:

- actor count and per-tenant allocation;
- confirmed warmup history occupancy;
- strict cumulative synthetic-upstream snapshots and nonnegative phase deltas
  for inspector, business, unknown, fixed-model, and bounded header-hash counts;
- Guard and egress process RSS, threads, file descriptors, state size and
  archive size through the existing production harness sampler;
- service/store status after warmup and measurement;
- exact candidate identity from the existing evidence header: wheel and
  installed-package digests, image ID, dependency lock comparison, preserved
  configuration hash and policy version, plus source/test/tool/deployment
  revision digests.

Missing summaries, early agent exits, offered/actual mismatches, status errors,
missing store occupancy, unavailable metrics, and harness exceptions remain
explicit. The harness does not silently retry requests, infer missing counts,
or manufacture zeros for absent results.

The report may be complete even when non-OK measured statuses are observed;
those statuses are exposed at top level as `observed_errors` and
`observed_error_counts` and are characterization data, not an acceptance
verdict. Measurement completeness additionally requires business calls to
equal successful calls, inspector calls to fall between successful and actual
calls, zero unknown calls, and at least one observed inspector call. Review
the offered-versus-actual counts, latency distribution, inspector/business call
ratio, process/store samples, and environment identity together. Do not convert
these observations into production SLOs without a separately reviewed target
and acceptance process.

The JSON report always keeps `production_accepted=false` and
`live_model_robustness=false`, including a complete run with no observed
errors. The counters file is measurement evidence, not an audit log; it retains
neither prompts nor responses.

## Scope limitations

- Synthetic local TLS upstream with immediate deterministic responses; provider
  WAN latency and real-model behavior are excluded.
- Single-host production profile only; no HA, active-active, or multi-host claim.
- The retained-history window is full at measurement start, but this is not a
  multi-day endurance or retention test.
- No claim about semantic attack detection, production acceptance, customer
  workloads, or live-model robustness.

The synthetic upstream fsyncs its counters before every response. Reported
latency includes that measurement overhead and both synthetic model calls; it
is not an isolated Guard processing-time measurement. A full history means
the configured actor windows are full, not that every supported storage limit
has been exercised.
