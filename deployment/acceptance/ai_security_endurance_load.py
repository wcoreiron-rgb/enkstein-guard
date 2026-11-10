"""Fixed, networkless load actor for the synthetic AI endurance harness.

Every offered call receives one fresh request ID and is attempted once.  The
actor emits bounded 60-second progress records and one final summary.  A sparse
one-millisecond histogram preserves enough information to recompute p95/p99
without printing one record per request.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
from pathlib import Path
import time

from enkstein_guard.outcomes import new_request_id
from enkstein_guard.service import guarded_request


SOCKET = "/run/guard/guard.sock"
RATE_PER_ACTOR = 2
WARMUP_CALLS = 64
MAX_INFLIGHT = 4
FULL_DURATION_SECONDS = 10_800
MIN_SMOKE_DURATION_SECONDS = 30
WINDOW_SECONDS = 60
RPC_TIMEOUT_SECONDS = 70
DRAIN_TIMEOUT_SECONDS = 75
MAX_HISTOGRAM_MS = 120_000


class Histogram:
    """Sparse, bounded millisecond histogram with deterministic percentiles."""

    def __init__(self):
        self.buckets: dict[int, int] = {}
        self.count = 0
        self.maximum_ms: float | None = None

    def add(self, value):
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError("invalid_latency")
        bucket = min(MAX_HISTOGRAM_MS, int(math.ceil(value)))
        self.buckets[bucket] = self.buckets.get(bucket, 0) + 1
        self.count += 1
        self.maximum_ms = value if self.maximum_ms is None else max(self.maximum_ms, value)

    def percentile(self, fraction):
        if not self.count:
            return None
        rank = min(self.count, max(1, int(math.ceil(fraction * self.count))))
        seen = 0
        for bucket, count in sorted(self.buckets.items()):
            seen += count
            if seen >= rank:
                return float(bucket)
        raise RuntimeError("invalid_histogram")

    def report(self):
        return {
            "unit": "milliseconds_ceiling",
            "maximum_bucket_ms": MAX_HISTOGRAM_MS,
            "count": self.count,
            "buckets": [[bucket, self.buckets[bucket]] for bucket in sorted(self.buckets)],
        }


def scheduled_count(duration_seconds):
    if (type(duration_seconds) is not int
            or not MIN_SMOKE_DURATION_SECONDS <= duration_seconds <= FULL_DURATION_SECONDS):
        raise ValueError("invalid_endurance_duration")
    return duration_seconds * RATE_PER_ACTOR


def benign_payload(phase, actor, sequence):
    if phase not in ("warmup", "measurement") or not actor:
        raise ValueError("invalid_endurance_payload")
    return {
        "messages": [{
            "role": "user",
            "content": "endurance:%s actor:%s sequence:%d benign synthetic request"
                       % (phase, actor, sequence),
        }],
        "max_tokens": 32,
    }


class Load:
    def __init__(self, args):
        self.args = validate_args(args)
        self.token = Path(args.token_file).read_text().strip()
        if not self.token:
            raise ValueError("missing_agent_token")
        self.semaphore = asyncio.Semaphore(MAX_INFLIGHT)
        self.request_ids: set[str] = set()
        self.statuses: dict[str, int] = {}
        self.total = Histogram()
        self.queue = Histogram()
        self.rpc = Histogram()
        self.window_values: list[float] = []
        self.window_statuses: dict[str, int] = {}
        self.window_started = time.monotonic()
        self.windows_emitted = 0

    async def one(self, sequence):
        total_started = time.perf_counter()
        async with self.semaphore:
            acquired = time.perf_counter()
            request_id = new_request_id()
            if request_id in self.request_ids:
                status = "client_error:duplicate_request_id"
                finished = time.perf_counter()
            else:
                self.request_ids.add(request_id)
                try:
                    response = await guarded_request(
                        SOCKET, self.token, self.args.route,
                        benign_payload(self.args.phase, self.args.actor, sequence),
                        request_id=request_id, timeout=RPC_TIMEOUT_SECONDS)
                    status = str(response.get("status", "missing_status"))
                    if response.get("reason"):
                        status += ":" + str(response["reason"])
                except Exception as error:
                    status = "client_error:" + type(error).__name__
                finished = time.perf_counter()
        total_ms = (finished - total_started) * 1000
        queue_ms = (acquired - total_started) * 1000
        rpc_ms = (finished - acquired) * 1000
        self.total.add(total_ms)
        self.queue.add(queue_ms)
        self.rpc.add(rpc_ms)
        self.window_values.append(total_ms)
        self.statuses[status] = self.statuses.get(status, 0) + 1
        self.window_statuses[status] = self.window_statuses.get(status, 0) + 1

    def flush_window(self, *, force=False):
        now = time.monotonic()
        elapsed = now - self.window_started
        if not force and elapsed < WINDOW_SECONDS:
            return
        values = sorted(self.window_values)

        def percentile(fraction):
            if not values:
                return None
            index = min(len(values) - 1, max(0, int(math.ceil(fraction * len(values))) - 1))
            return round(values[index], 3)

        print(json.dumps({
            "type": "window",
            "phase": self.args.phase,
            "actor": self.args.actor,
            "window_index": self.windows_emitted,
            "seconds": round(elapsed, 3),
            "requests": len(values),
            "statuses": dict(sorted(self.window_statuses.items())),
            "p95_ms": percentile(0.95),
            "p99_ms": percentile(0.99),
            "max_ms": round(max(values), 3) if values else None,
        }, sort_keys=True), flush=True)
        self.windows_emitted += 1
        self.window_values = []
        self.window_statuses = {}
        self.window_started = now

    async def run(self):
        offered = WARMUP_CALLS if self.args.phase == "warmup" else scheduled_count(
            self.args.duration)
        started = time.monotonic()
        tasks = []
        for sequence in range(offered):
            due = started + sequence / RATE_PER_ACTOR
            await asyncio.sleep(max(0, due - time.monotonic()))
            tasks.append(asyncio.create_task(self.one(sequence)))
            if self.args.phase == "measurement":
                self.flush_window()
        offered_finished = time.monotonic()
        done, pending = await asyncio.wait(tasks, timeout=DRAIN_TIMEOUT_SECONDS)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        completed = time.monotonic()
        if self.args.phase == "measurement":
            window_end = started + self.args.duration
            await asyncio.sleep(max(0, window_end - completed))
            completed = time.monotonic()
            self.flush_window(force=True)
            offered_window = self.args.duration
            drain = max(0, completed - window_end)
        else:
            offered_window = drain = None
        actual = sum(self.statuses.values())
        successful = self.statuses.get("ok", 0)
        result = {
            "type": "summary",
            "phase": self.args.phase,
            "actor": self.args.actor,
            "offered_calls": offered,
            "actual_calls": actual,
            "successful_calls": successful,
            "error_calls": actual - successful,
            "statuses": dict(sorted(self.statuses.items())),
            "unique_request_ids": len(self.request_ids),
            "pending_cancelled": len(pending),
            "elapsed_seconds": round(completed - started, 3),
            "offered_schedule_seconds": round(offered_finished - started, 3),
            "offered_window_seconds": offered_window,
            "drain_seconds": round(drain, 3) if drain is not None else None,
            "configured_max_inflight": MAX_INFLIGHT,
            "retries": 0,
            "real_model_robustness": False,
            "synthetic_counter_fsync_overhead": True,
        }
        for name, histogram in (("total", self.total), ("queue", self.queue), ("rpc", self.rpc)):
            result.update({
                name + "_p95_ms": histogram.percentile(0.95),
                name + "_p99_ms": histogram.percentile(0.99),
                name + "_max_ms": (round(histogram.maximum_ms, 3)
                                    if histogram.maximum_ms is not None else None),
                name + "_histogram": histogram.report(),
            })
        print(json.dumps(result, sort_keys=True), flush=True)


def parser():
    result = argparse.ArgumentParser()
    result.add_argument("--phase", choices=("warmup", "measurement"), required=True)
    result.add_argument("--actor", required=True)
    result.add_argument("--route", required=True)
    result.add_argument("--token-file", default="/run/agent-token")
    result.add_argument("--duration", type=int, default=FULL_DURATION_SECONDS)
    return result


def validate_args(args):
    if (type(args.actor) is not str or not args.actor or len(args.actor) > 128
            or type(args.route) is not str or not args.route or len(args.route) > 256
            or args.phase not in ("warmup", "measurement")):
        raise ValueError("invalid_endurance_load_parameters")
    scheduled_count(args.duration)
    return args


def main(argv=None):
    asyncio.run(Load(parser().parse_args(argv)).run())


if __name__ == "__main__":
    main()
