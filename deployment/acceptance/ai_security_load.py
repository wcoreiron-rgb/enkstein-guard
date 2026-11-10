"""Networkless agent load for AI-path capacity characterization.

One invocation performs either a fixed-count warmup or a bounded rate-driven
measurement. Every call uses a new request ID; there are no retries.
"""
import argparse
import asyncio
import json
import math
import os
from pathlib import Path
import time


os.environ["ENKSTEIN_POLICY_PACK"] = "/nonexistent/guard-stage-tests"

from enkstein_guard.outcomes import new_request_id  # noqa: E402
from enkstein_guard.service import guarded_request  # noqa: E402


SOCKET = "/run/guard/guard.sock"


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    position = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return round(ordered[position], 2)


def scheduled_count(duration, rate):
    if (type(duration) not in (int, float) or not math.isfinite(duration) or not 1 <= duration <= 600
            or type(rate) not in (int, float) or not math.isfinite(rate) or not 0.1 <= rate <= 3):
        raise ValueError("invalid_measurement_bounds")
    count = int(math.floor(duration * rate))
    if count < 1:
        raise ValueError("measurement_offers_no_calls")
    return count


def benign_payload(phase, actor, sequence):
    if phase not in ("warmup", "measurement"):
        raise ValueError("invalid_phase")
    return {"messages": [{"role": "user", "content":
            "characterization:%s actor:%s sequence:%d benign synthetic request"
            % (phase, actor, sequence)}], "max_tokens": 32}


def _latency_summary(prefix, values):
    return {
        prefix + "_p50_ms": percentile(values, 0.50),
        prefix + "_p95_ms": percentile(values, 0.95),
        prefix + "_p99_ms": percentile(values, 0.99),
        prefix + "_max_ms": round(max(values), 2) if values else None,
        prefix + "_latencies_ms": [round(value, 3) for value in values],
    }


def summary(phase, actor, offered, total_latencies, queue_latencies,
            rpc_latencies, statuses, elapsed, offered_window, drain):
    actual = sum(statuses.values())
    errors = sum(count for status, count in statuses.items() if status != "ok")
    result = {
        "type": "summary",
        "phase": phase,
        "actor": actor,
        "offered_calls": offered,
        "actual_calls": actual,
        "successful_calls": statuses.get("ok", 0),
        "error_calls": errors,
        "statuses": dict(sorted(statuses.items())),
        "elapsed_seconds": round(elapsed, 3),
        "offered_window_seconds": (round(offered_window, 3)
                                   if offered_window is not None else None),
        "drain_seconds": round(drain, 3) if drain is not None else None,
        "production_accepted": False,
        "live_model_robustness": False,
    }
    result.update(_latency_summary("total", total_latencies))
    result.update(_latency_summary("queue", queue_latencies))
    result.update(_latency_summary("rpc", rpc_latencies))
    return result


class Load:
    def __init__(self, args):
        self.args = args
        self.token = Path(args.token_file).read_text().strip()
        if not self.token:
            raise ValueError("missing_agent_token")
        self.statuses = {}
        self.total_latencies = []
        self.queue_latencies = []
        self.rpc_latencies = []
        self.request_ids = set()
        self.semaphore = asyncio.Semaphore(args.max_inflight)

    async def one(self, sequence):
        total_started = time.perf_counter()
        async with self.semaphore:
            acquired = time.perf_counter()
            request_id = new_request_id()
            if request_id in self.request_ids:
                raise RuntimeError("duplicate_request_id")
            self.request_ids.add(request_id)
            rpc_started = time.perf_counter()
            try:
                response = await guarded_request(
                    SOCKET, self.token, self.args.route,
                    benign_payload(self.args.phase, self.args.actor, sequence),
                    request_id=request_id, timeout=70)
                status = response.get("status", "missing_status")
                if response.get("reason"):
                    status += ":" + str(response["reason"])
            except Exception as error:
                status = "client_error:" + type(error).__name__
            finished = time.perf_counter()
            self.total_latencies.append((finished - total_started) * 1000)
            self.queue_latencies.append((acquired - total_started) * 1000)
            self.rpc_latencies.append((finished - rpc_started) * 1000)
            self.statuses[status] = self.statuses.get(status, 0) + 1

    async def run(self):
        started = time.monotonic()
        if self.args.phase == "warmup":
            offered = self.args.warmup_count
        else:
            offered = scheduled_count(self.args.duration, self.args.rate)
        tasks = []
        for sequence in range(offered):
            due = started + sequence / self.args.rate
            await asyncio.sleep(max(0, due - time.monotonic()))
            tasks.append(asyncio.create_task(self.one(sequence)))
        await asyncio.gather(*tasks)
        completed = time.monotonic()
        if self.args.phase == "measurement":
            window_end = started + self.args.duration
            await asyncio.sleep(max(0, window_end - completed))
            finished = time.monotonic()
            offered_window = self.args.duration
            drain = max(0, completed - window_end)
        else:
            finished = completed
            offered_window = drain = None
        elapsed = finished - started
        print(json.dumps(summary(self.args.phase, self.args.actor, offered,
                                 self.total_latencies, self.queue_latencies,
                                 self.rpc_latencies, self.statuses, elapsed,
                                 offered_window, drain),
                         sort_keys=True), flush=True)


def parser():
    result = argparse.ArgumentParser()
    result.add_argument("--phase", choices=("warmup", "measurement"), required=True)
    result.add_argument("--actor", required=True)
    result.add_argument("--route", required=True)
    result.add_argument("--token-file", default="/run/agent-token")
    result.add_argument("--warmup-count", type=int, default=16)
    result.add_argument("--duration", type=float, default=10)
    result.add_argument("--rate", type=float, default=2)
    result.add_argument("--max-inflight", type=int, default=4)
    return result


def validate_args(args):
    if (not args.actor or len(args.actor) > 128 or not args.route or len(args.route) > 256
            or type(args.warmup_count) is not int or not 16 <= args.warmup_count <= 256
            or type(args.max_inflight) is not int or not 1 <= args.max_inflight <= 16):
        raise ValueError("invalid_load_parameters")
    scheduled_count(args.duration, args.rate)
    return args


def main(argv=None):
    args = validate_args(parser().parse_args(argv))
    asyncio.run(Load(args).run())


if __name__ == "__main__":
    main()
