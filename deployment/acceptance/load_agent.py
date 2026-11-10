"""Untrusted load-generating agent for production-profile capacity and soak runs.

Runs in a network-less agent container under its own UID with its own
credential and reaches only the Guard socket. Prints one JSON line per window
and a final summary line. Every model request carries a unique "rid:<id>"
marker so the synthetic upstream can count executions per request.

  load_agent.py --plan '<json>' --duration S (--rate R | --concurrency C) [--window 60]
                [--dedup-probes 20] [--max-inflight 4] [--slow-every N --slow-ms M]

--slow-every N makes every N-th chat request one the synthetic upstream answers
after M ms, so that executed requests are in flight when the harness kills Guard.

plan: [{"route": name, "kind": "chat" | "chat_sensitive" | "retrieval", "weight": n}, ...]
"""
import argparse
import asyncio
from collections import deque
import json
from pathlib import Path
import random
import time

from enkstein_guard.outcomes import new_request_id
from enkstein_guard.service import guarded_request

SOCKET = "/run/guard/guard.sock"


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))], 2)


def payload(kind, request_id, sequence, slow_ms=None):
    marker = request_id.split("-", 1)[1]
    if kind == "retrieval":
        return {"query": "outage runbook steps %d" % (sequence % 7), "top_k": 3}
    text = "Summarize case %d rid:%s" % (sequence, marker)
    if kind == "chat_sensitive":
        text += " for customer user%d@example.com" % (sequence % 500)
    if slow_ms:
        text = "delay_ms:%d %s" % (slow_ms, text)
    return {"messages": [{"role": "user", "content": text}], "max_tokens": 64}


class Load:
    def __init__(self, args):
        self.args = args
        self.token = Path("/run/agent-token").read_text().strip()
        plan = json.loads(args.plan)
        self.routes = [(entry["route"], entry["kind"]) for entry in plan for _ in range(entry.get("weight", 1))]
        self.window_started = time.time()
        self.window, self.all_latencies, self.statuses = [], [], {}
        self.window_statuses = {}
        self.by_route = {}
        # Dedup probes resubmit recent completed IDs (still inside the request
        # window); expired probes resubmit the earliest ones, which a long run
        # has archived, so Guard must refuse them.
        self.completed = deque(maxlen=2000)
        self.earliest = []
        self.lost = []
        self.sequence = 0
        self.chats = 0
        self.slow = 0
        self.inflight = 0
        self.max_inflight_seen = 0

    async def one(self):
        route, kind = random.choice(self.routes)
        self.sequence += 1
        request_id = new_request_id()
        slow = None
        if kind != "retrieval":
            self.chats += 1
            if self.args.slow_every and self.chats % self.args.slow_every == 0:
                slow = self.args.slow_ms
                self.slow += 1
        body = payload(kind, request_id, self.sequence, slow)
        self.inflight += 1
        self.max_inflight_seen = max(self.max_inflight_seen, self.inflight)
        started = time.perf_counter()
        try:
            response = await guarded_request(SOCKET, self.token, route, body, request_id=request_id, timeout=70)
            status = response.get("status")
            if status == "busy" and response.get("reason"):
                status = "busy:" + response["reason"]
        except Exception as error:
            status = "client_error:" + type(error).__name__
        finally:
            self.inflight -= 1
        elapsed = (time.perf_counter() - started) * 1000
        self.window.append(elapsed)
        self.all_latencies.append(elapsed)
        self.statuses[status] = self.statuses.get(status, 0) + 1
        self.window_statuses[status] = self.window_statuses.get(status, 0) + 1
        route_counts = self.by_route.setdefault(route, {})
        route_counts[status] = route_counts.get(status, 0) + 1
        if status == "ok":
            self.completed.append((route, request_id, body))
            if len(self.earliest) < 50:
                self.earliest.append((route, request_id, body))
        if status.startswith("client_error") and len(self.lost) < 5000:
            # Response lost (for example the service was killed): the request may
            # or may not have executed, so it is resubmitted with the same ID.
            self.lost.append((route, request_id, body))
        return status

    def flush(self, force=False):
        now = time.time()
        if not force and now - self.window_started < self.args.window:
            return
        print(json.dumps({"type": "window", "t": int(now), "seconds": round(now - self.window_started, 1),
                          "requests": len(self.window), "statuses": self.window_statuses,
                          "p50_ms": percentile(self.window, .5), "p95_ms": percentile(self.window, .95),
                          "p99_ms": percentile(self.window, .99),
                          "max_ms": round(max(self.window), 1) if self.window else None}), flush=True)
        self.window, self.window_statuses, self.window_started = [], {}, now

    async def run(self):
        deadline = time.monotonic() + self.args.duration
        tasks = set()
        if self.args.rate:
            interval, next_at = 1 / self.args.rate, time.monotonic()
            while time.monotonic() < deadline:
                if len(tasks) < self.args.max_inflight:
                    task = asyncio.ensure_future(self.one())
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)
                next_at += interval
                self.flush()
                await asyncio.sleep(max(0, next_at - time.monotonic()))
        else:
            async def worker():
                while time.monotonic() < deadline:
                    status = await self.one()
                    self.flush()
                    if status and status.startswith("busy"):
                        # A real client backs off when told the service is busy.
                        await asyncio.sleep(self.args.busy_backoff)
            await asyncio.gather(*(worker() for _ in range(self.args.concurrency)))
        await asyncio.gather(*tasks, return_exceptions=True)
        self.flush(force=True)
        async def resubmit(items):
            counts = {}
            for route, request_id, body in items:
                for attempt in range(30):
                    try:
                        response = await guarded_request(SOCKET, self.token, route, body, request_id=request_id,
                                                         timeout=70)
                        status = response.get("status")
                        if status == "busy":
                            await asyncio.sleep(0.5)
                            continue
                        if response.get("reason"):
                            status += ":" + response["reason"]
                        break
                    except Exception as error:
                        status = "client_error:" + type(error).__name__
                        await asyncio.sleep(1)
                counts[status] = counts.get(status, 0) + 1
            return counts
        recent = list(self.completed)
        probes = await resubmit(random.sample(recent, min(self.args.dedup_probes, len(recent))))
        expired = await resubmit(self.earliest[:self.args.expired_probes]) if self.args.expired_probes else {}
        lost = await resubmit(self.lost) if self.args.resubmit_lost else {}
        print(json.dumps({"type": "summary", "requests": sum(self.statuses.values()), "statuses": self.statuses,
                          "p50_ms": percentile(self.all_latencies, .5), "p95_ms": percentile(self.all_latencies, .95),
                          "p99_ms": percentile(self.all_latencies, .99),
                          "max_ms": round(max(self.all_latencies), 1) if self.all_latencies else None,
                          "max_inflight": self.max_inflight_seen, "dedup_probes": probes, "expired_probes": expired,
                          "lost_responses": len(self.lost), "lost_resubmitted": lost, "by_route": self.by_route,
                          "slow_requests": self.slow,
                          **({"latencies_ms": [round(v, 2) for v in self.all_latencies]}
                             if self.args.emit_latencies else {})}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--rate", type=float)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--window", type=float, default=60)
    parser.add_argument("--dedup-probes", type=int, default=20)
    parser.add_argument("--max-inflight", type=int, default=4)
    parser.add_argument("--resubmit-lost", action="store_true")
    parser.add_argument("--emit-latencies", action="store_true")
    parser.add_argument("--busy-backoff", type=float, default=0.05)
    parser.add_argument("--slow-every", type=int, default=0)
    parser.add_argument("--expired-probes", type=int, default=0)
    parser.add_argument("--slow-ms", type=int, default=2000)
    asyncio.run(Load(parser.parse_args()).run())


if __name__ == "__main__":
    main()
