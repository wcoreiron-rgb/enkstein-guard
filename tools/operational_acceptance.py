"""Measure operational acceptance against docs/operations/capacity-targets.json.

Runs a development-profile Guard service as a separate process with audit,
time-bound outcome tracking, sensitivity and local-prompt controls and a
synthetic fixture connector. Results are merged into --output so groups can
run in separate invocations. Targets are read, never modified; every target
reports pass/fail with the measured values, including misses.

Groups: sustained (T-01, T-07), burst (T-02, T-08, T-09), vault (T-03),
state (T-04, T-05, T-06).
"""
import argparse
import asyncio
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return round(ordered[index], 2)


def config(root, tenants=4):
    routes, agents = [], []
    for number in range(1, tenants + 1):
        tenant = "t%d" % number
        routes += [
            {"name": tenant + ".comment", "tenant": tenant, "operation": "ticket.update", "resource": "ticket",
             "destination": "ticket-service", "connector": "echo", "clearance": "confidential", "produces": "internal",
             "task_boundaries": [{"principal": "bot-" + tenant, "workflow": "work", "fields": [
                 {"path": ["ticket"], "kind": "str", "max_length": 32}, {"path": ["comment"], "kind": "str", "max_length": 2000}]}]},
            {"name": tenant + ".lookup", "tenant": tenant, "operation": "lookup", "resource": "crm", "destination": "crm",
             "connector": "echo", "clearance": "confidential", "privacy": "tokenize"},
            {"name": tenant + ".update", "tenant": tenant, "operation": "update", "resource": "crm", "destination": "crm",
             "connector": "echo", "clearance": "restricted", "privacy": "restore"},
            {"name": tenant + ".slow", "tenant": tenant, "operation": "batch", "resource": "batch",
             "destination": "batch", "connector": "slow", "clearance": "confidential"}]
        agents.append({"id": "agent-" + tenant, "tenant": tenant, "principal": "bot-" + tenant, "task": "work",
                       "clearance": "confidential",
                       "routes": [tenant + ".comment", tenant + ".lookup", tenant + ".update", tenant + ".slow"]})
    return {"schema_version": 2, "profile": "development",
            "paths": {"state_directory": str(root / "state"), "key_directory": str(root / "keys"),
                      "socket": str(root / "sock/guard.sock"), "admin_socket": str(root / "admin/admin.sock"),
                      "archive_directory": str(root / "archive")},
            "service": {"max_connections": 32, "transport_timeout_seconds": 1, "request_timeout_seconds": 30},
            # Sized per docs/operations/capacity-planning.md:
            # capacity >= peak_rps * (archive_age + archive_interval).
            "outcomes": {"capacity": 200000, "max_request_age_seconds": 3600},
            "retention": {"outcome_archive_age_seconds": 7200},
            "vault": {"max_entries": 10000, "token_ttl_seconds": 3600},
            "tenants": [{"id": "t%d" % n} for n in range(1, tenants + 1)],
            "connectors": [{"name": "echo", "type": "fixture", "behavior": "echo"},
                           {"name": "slow", "type": "fixture", "behavior": "slow"}],
            "routes": routes, "agents": agents}


class Environment:
    def __init__(self, root):
        self.root = Path(root)
        self.config_path = self.root / "config.json"
        self.process = None

    def cli(self, *args):
        result = subprocess.run([sys.executable, "-m", "enkstein_guard", "--config", str(self.config_path), *args],
                                capture_output=True, text=True, timeout=600)
        return result.returncode, json.loads(result.stdout.strip().splitlines()[-1])

    def prepare(self):
        if not self.config_path.exists():
            for name in ("sock", "admin"):
                (self.root / name).mkdir(mode=0o700, parents=True, exist_ok=True)
            self.config_path.write_text(json.dumps(config(self.root)))
            code, payload = self.cli("init")
            assert code == 0, payload
            self.tokens = {}
            for number in range(1, 5):
                path = self.root / ("agent-t%d.token" % number)
                code, payload = self.cli("agent", "issue", "--agent", "agent-t%d" % number, "--output", str(path))
                assert code == 0, payload
        self.tokens = {"t%d" % n: (self.root / ("agent-t%d.token" % n)).read_text().strip() for n in range(1, 5)}
        return self

    def start(self):
        started = time.monotonic()
        self.process = subprocess.Popen([sys.executable, "-m", "enkstein_guard", "--config", str(self.config_path),
                                         "service", "start"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        code, payload = self.cli("service", "wait-ready", "--timeout", "120")
        assert code == 0, payload
        return time.monotonic() - started

    def stop(self):
        if self.process is not None:
            self.cli("service", "stop")
            self.process.communicate(timeout=120)
            self.process = None

    def rss_mib(self):
        try:
            for line in Path("/proc/%d/status" % self.process.pid).read_text().splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
        except OSError:
            return None

    @property
    def socket(self):
        return str(self.root / "sock/guard.sock")


async def one(env, tenant, route, payload, latencies, statuses, *, request_id=True):
    from enkstein_guard.outcomes import new_request_id
    from enkstein_guard.service import guarded_request
    started = time.perf_counter()
    try:
        response = await guarded_request(env.socket, env.tokens[tenant], route, payload,
                                         request_id=new_request_id() if request_id else None, timeout=30)
        status = response.get("status")
    except Exception:
        response, status = None, "client_error"
    latencies.append((time.perf_counter() - started) * 1000)
    statuses[status] = statuses.get(status, 0) + 1
    return response


async def sustained(env, rate, duration, rss):
    latencies, statuses, tasks = [], {}, []
    interval = 1 / rate
    started = time.perf_counter()
    count = 0
    next_sample = started
    while time.perf_counter() - started < duration:
        tenant = "t%d" % (count % 4 + 1)
        tasks.append(asyncio.ensure_future(one(env, tenant, tenant + ".comment",
                                               {"ticket": "INC-%d" % count, "comment": "synthetic load %d" % count},
                                               latencies, statuses)))
        count += 1
        if time.perf_counter() >= next_sample:
            value = env.rss_mib()
            if value:
                rss.append(value)
            next_sample += 1
        target = started + count * interval
        await asyncio.sleep(max(0, target - time.perf_counter()))
    await asyncio.gather(*tasks)
    elapsed = time.perf_counter() - started
    return {"requests": count, "elapsed_seconds": round(elapsed, 1), "achieved_rps": round(count / elapsed, 2),
            "p50_ms": percentile(latencies, .5), "p95_ms": percentile(latencies, .95), "p99_ms": percentile(latencies, .99),
            "max_ms": round(max(latencies), 2), "statuses": statuses}


async def burst(env, clients, duration, rss):
    latencies, statuses = [], {}
    stop = time.perf_counter() + duration

    async def worker(number):
        tenant = "t%d" % (number % 4 + 1)
        sequence = 0
        while time.perf_counter() < stop:
            await one(env, tenant, tenant + ".comment", {"ticket": "B-%d" % number, "comment": "burst %d" % sequence},
                      latencies, statuses)
            sequence += 1

    async def sampler():
        while time.perf_counter() < stop:
            value = env.rss_mib()
            if value:
                rss.append(value)
            await asyncio.sleep(1)

    await asyncio.gather(sampler(), *(worker(n) for n in range(clients)))
    return {"clients": clients, "requests": sum(statuses.values()), "statuses": statuses,
            "p95_ms": percentile(latencies, .95), "p99_ms": percentile(latencies, .99)}


async def exhaustion(env):
    from enkstein_guard.service import guarded_request
    results = {}
    idle = [await asyncio.open_unix_connection(env.socket) for _ in range(40)]
    await asyncio.sleep(0.2)
    latencies, statuses = [], {}
    await one(env, "t1", "t1.comment", {"ticket": "X", "comment": "during flood"}, latencies, statuses)
    results["during_flood_statuses"] = statuses
    for reader, writer in idle:
        writer.close()
    started = time.perf_counter()
    recovered = None
    while time.perf_counter() - started < 10:
        latencies, statuses = [], {}
        await one(env, "t1", "t1.comment", {"ticket": "X", "comment": "after flood"}, latencies, statuses)
        if statuses.get("ok"):
            recovered = time.perf_counter() - started
            break
        await asyncio.sleep(0.05)
    results["recovery_seconds"] = round(recovered, 3) if recovered is not None else None
    reader, writer = await asyncio.open_unix_connection(env.socket, limit=4_000_000)
    try:
        writer.write(b'{"credential":"x","route":"t1.comment","payload":{"x":"' + b"a" * 2_000_000 + b'"}}\n')
        await writer.drain()
        oversized = json.loads(await reader.readline()).get("status")
    except (ConnectionError, ValueError):
        oversized = "connection_closed_by_guard"
    finally:
        writer.close()
    results["oversized_frame_status"] = oversized
    latencies, statuses = [], {}
    await one(env, "t1", "t1.comment", {"ticket": "X", "comment": "alive"}, latencies, statuses)
    results["service_alive_after_oversized"] = bool(statuses.get("ok"))
    return results


async def slow_dependencies(env):
    latencies, statuses = [], {}
    response = await one(env, "t1", "t1.slow", {"job": "x"}, latencies, statuses)
    transport = {"timeout_seconds": 1, "observed_ms": round(latencies[0], 1), "status": response and response.get("status")}
    from enkstein_guard.contracts import Action, ControlResult
    from enkstein_guard.runtime import AccessDenied, GuardRuntime, Principal, Route

    async def slow_control(operation):
        await asyncio.sleep(5)
        return ControlResult("slow", operation.context.tenant_id, operation.context.operation_id, Action.ALLOW)

    async def transport_fn(operation):
        return {}

    token = "acceptance-" + "x" * 40
    runtime = GuardRuntime(credentials={token: Principal("t", "p", "a", frozenset({"r"}))},
                           routes=(Route("r", "op", "res", "dest", "t", ("slow",), transport_fn),),
                           controls={"slow": slow_control}, audit=lambda event: None, control_timeout=0.2)
    started = time.perf_counter()
    try:
        await runtime.execute(token, "r", {})
        denied = False
    except AccessDenied:
        denied = True
    control = {"timeout_seconds": 0.2, "observed_ms": round((time.perf_counter() - started) * 1000, 1), "denied": denied}
    return {"transport": transport, "control": control}


def populate_vault(env, per_tenant):
    from enkstein_guard.host import StateLayout, vault_limits
    from enkstein_guard.productconfig import load
    from enkstein_guard.vault import LocalVault, Scope
    cfg = load(env.config_path)
    vault = LocalVault(*StateLayout(cfg).vault, **vault_limits(cfg))
    for number in range(1, 5):
        tenant = "t%d" % number
        scope = Scope(tenant, "bot-" + tenant, "agent-" + tenant, "service-session")
        for batch in range(0, per_tenant, 128):
            values = tuple("synthetic-%s-%d@example.com" % (tenant, i) for i in range(batch, min(per_tenant, batch + 128)))
            vault.put_many(values, scope, ("crm",), ttl=3600)
    return vault.usage()


async def vault_group(env):
    latencies, statuses = [], {}
    references = []
    for number in range(200):
        tenant = "t%d" % (number % 4 + 1)
        response = await one(env, tenant, tenant + ".lookup", {"email": "user%d@example.com" % number, "note": "x"},
                             latencies, statuses)
        if tenant == "t1" and response and response.get("status") == "ok":
            references.append(response["result"]["payload"]["email"])
    cross = {"attempts": 0, "succeeded": 0}
    for reference in references[:20]:
        for tenant in ("t2", "t3"):
            l2, s2 = [], {}
            response = await one(env, tenant, tenant + ".update", {"email": reference}, l2, s2)
            cross["attempts"] += 1
            cross["succeeded"] += int(bool(response) and response.get("status") == "ok")
    own = {}
    await one(env, "t1", "t1.update", {"email": references[0]}, [], own)
    return {"tokenizing_requests": 200, "p95_ms": percentile(latencies, .95), "statuses": statuses,
            "cross_tenant_restore": cross, "own_tenant_restore_statuses": own}


def bulk_audit(env, target):
    from cryptography.fernet import Fernet
    from enkstein_guard.host import StateLayout
    from enkstein_guard.productconfig import load
    database, key = StateLayout(load(env.config_path)).audit
    cipher = Fernet(key.read_bytes())
    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute("SELECT sequence, record FROM events ORDER BY sequence DESC LIMIT 1").fetchall()
        sequence, head = (rows[0][0], hashlib.sha256(rows[0][1]).hexdigest()) if rows else (0, "0" * 64)
        batch = []
        while sequence < target:
            sequence += 1
            record = {"sequence": sequence, "previous": head, "time_ns": time.time_ns(),
                      "event": {"outcome": "authorized", "operation_id": secrets.token_hex(16), "tenant_id": "t1",
                                "route": "t1.comment", "decision": "allow", "reason_codes": ["controls_evaluated"]}}
            encrypted = cipher.encrypt(json.dumps(record, sort_keys=True).encode())
            head = hashlib.sha256(encrypted).hexdigest()
            batch.append((sequence, encrypted))
        connection.executemany("INSERT INTO events VALUES (?, ?)", batch)
        connection.commit()
    return sequence


def bulk_outcomes(ledger, count, issued_at):
    ids = []
    with closing(sqlite3.connect(ledger.database)) as connection:
        rows = []
        counts = {}
        for number in range(count):
            tenant = "t%d" % (number % 4 + 1)
            request_id = "%010d-%s" % (issued_at, secrets.token_urlsafe(18))
            from enkstein_guard.runtime import Principal
            principal = Principal(tenant, "bot-" + tenant, "agent-" + tenant, frozenset())
            name, digest = ledger.binding(principal, request_id, tenant + ".comment", {"n": number})
            tenant_hash = hashlib.sha256(tenant.encode()).hexdigest()
            rows.append((name, ledger._encode({"id": name, "digest": digest, "state": "completed",
                                                "generation": "bulk", "tenant_hash": tenant_hash,
                                                "issued_at": issued_at}), issued_at, tenant_hash))
            counts[tenant_hash] = counts.get(tenant_hash, 0) + 1
            if number < 50:
                ids.append((tenant, request_id, number))
        # Ledger schema 3: the issuance time and tenant hash are also indexed columns.
        connection.executemany("INSERT INTO outcomes (id, record, issued_at, tenant_hash) VALUES (?, ?, ?, ?)", rows)
        for tenant_hash, used in counts.items():
            connection.execute("INSERT INTO tenant_counts VALUES (?, ?) ON CONFLICT(tenant_hash) DO UPDATE SET used=used+?",
                               (tenant_hash, used, used))
        connection.commit()
    return ids


def state_group(env, results):
    from enkstein_guard.audit import DurableAudit
    from enkstein_guard.host import StateLayout
    from enkstein_guard.outcomes import OutcomeLedger, new_request_id
    from enkstein_guard.productconfig import load
    from enkstein_guard.runtime import Principal
    cfg = load(env.config_path)
    layout = StateLayout(cfg)
    total = bulk_audit(env, 100_000)
    started = time.perf_counter()
    audit = DurableAudit(*layout.audit, full_verify_every=cfg["audit"]["full_verify_every"])
    open_seconds = time.perf_counter() - started
    latencies = []
    for number in range(500):
        started = time.perf_counter()
        audit({"outcome": "acceptance", "operation_id": str(number)})
        latencies.append((time.perf_counter() - started) * 1000)
    started = time.perf_counter()
    audit.verify()
    verify_seconds = time.perf_counter() - started
    old = int(time.time()) - 40 * 86400
    # T-05 exactly as defined: a ledger of capacity 10000 holding 9000 records.
    t05 = env.root / "t05"
    if t05.exists():
        import shutil
        shutil.rmtree(t05)
    t05.mkdir(mode=0o700)
    OutcomeLedger.initialize(t05 / "data/outcomes.sqlite3", t05 / "keys/outcomes.key", maximum=10000)
    ledger = OutcomeLedger(t05 / "data/outcomes.sqlite3", t05 / "keys/outcomes.key", maximum=10000, time_bound=True,
                           max_request_age=3600)
    archived_ids = bulk_outcomes(ledger, 9000, old)
    ledger.configure_tenants(["t1", "t2", "t3", "t4"])
    usage_before = ledger.usage()
    outcome_latencies = []
    for number in range(200):
        tenant = "t%d" % (number % 4 + 1)
        principal = Principal(tenant, "bot-" + tenant, "agent-" + tenant, frozenset())
        started = time.perf_counter()
        name, state = ledger.begin(principal, new_request_id(), tenant + ".comment", {"n": number})
        ledger.finish(name, "completed")
        outcome_latencies.append((time.perf_counter() - started) * 1000)
    # Informational: the service ledger filled towards its configured 200000.
    service_ledger = OutcomeLedger(*layout.outcomes, maximum=cfg["outcomes"]["capacity"], time_bound=True,
                                   max_request_age=cfg["outcomes"]["max_request_age_seconds"])
    fill = max(0, 180000 - service_ledger.usage()["records"])
    bulk_outcomes(service_ledger, fill, old)
    service_ledger = OutcomeLedger(*layout.outcomes, maximum=cfg["outcomes"]["capacity"], time_bound=True,
                                   max_request_age=cfg["outcomes"]["max_request_age_seconds"])
    service_ledger.configure_tenants(["t1", "t2", "t3", "t4"])
    large = []
    for number in range(100):
        principal = Principal("t1", "bot-t1", "agent-t1", frozenset())
        started = time.perf_counter()
        name, state = service_ledger.begin(principal, new_request_id(), "t1.comment", {"n": number})
        service_ledger.finish(name, "completed")
        large.append((time.perf_counter() - started) * 1000)
    started_ready = env.start()
    status_before = env.cli("service", "status")[1]
    env.stop()
    started = time.perf_counter()
    archive = audit.archive(layout.archive, keep=cfg["retention"]["audit_archive_keep_events"])
    archive_seconds = time.perf_counter() - started
    archived = ledger.archive(t05, before=int(time.time()) - 30 * 86400)
    service_archive = service_ledger.archive(layout.archive, before=int(time.time()) - 30 * 86400)
    rejected = 0
    for tenant, request_id, number in archived_ids:
        principal = Principal(tenant, "bot-" + tenant, "agent-" + tenant, frozenset())
        try:
            ledger.begin(principal, request_id, tenant + ".comment", {"n": number})
        except Exception:
            rejected += 1
    results["T-04"] = {"active_events_before": total + 500, "open_full_verify_seconds": round(open_seconds, 2),
                       "append_p95_ms": percentile(latencies, .95), "full_verify_seconds": round(verify_seconds, 2),
                       "archive_seconds": round(archive_seconds, 2), "archived_events": archive["archived"]}
    results["T-05"] = {"records_before": usage_before["records"], "capacity": usage_before["maximum"],
                       "begin_finish_p95_ms": percentile(outcome_latencies, .95), "archived": archived["archived"],
                       "archived_ids_probed": len(archived_ids), "archived_ids_accepted": len(archived_ids) - rejected,
                       "informational_service_ledger": {"records": 180000, "capacity": cfg["outcomes"]["capacity"],
                                                        "begin_finish_p95_ms": percentile(large, .95),
                                                        "archived": service_archive["archived"]}}
    results["T-06"] = {"ready_seconds": round(started_ready, 2), "audit_events": status_before["audit"]["active_events"],
                       "outcome_records": status_before["outcomes"]["records"],
                       "vault_live_entries": status_before["vault"]["live_entries"]}


def evaluate(targets, results):
    verdicts = {}
    def check(target_id, ok, measured):
        verdicts[target_id] = {"passed": bool(ok), "measured": measured}
    t = {item["id"]: item for item in targets["targets"]}
    if "T-01" in results:
        r = results["T-01"]
        unexpected = sum(v for k, v in r["statuses"].items() if k != "ok") / max(1, r["requests"])
        check("T-01", r["elapsed_seconds"] >= t["T-01"]["min_duration_seconds"] and r["achieved_rps"] >= t["T-01"]["offered_rps"] * 0.95
              and r["p50_ms"] <= t["T-01"]["p50_ms_max"] and r["p95_ms"] <= t["T-01"]["p95_ms_max"]
              and r["p99_ms"] <= t["T-01"]["p99_ms_max"] and unexpected <= t["T-01"]["unexpected_error_rate_max"], r)
    if "T-02" in results:
        r = results["T-02"]
        check("T-02", set(r["statuses"]) <= {"ok", "busy"} and results.get("service_crashes", 0) == 0, r)
    if "T-03" in results:
        r = results["T-03"]
        check("T-03", r["vault_live_entries_before"] >= t["T-03"]["live_entries_min"] and r["p95_ms"] <= t["T-03"]["tokenizing_request_p95_ms_max"]
              and r["cross_tenant_restore"]["succeeded"] == 0 and set(r["statuses"]) == {"ok"}, r)
    if "T-04" in results:
        r = results["T-04"]
        check("T-04", r["active_events_before"] >= t["T-04"]["active_events"] and r["append_p95_ms"] <= t["T-04"]["append_p95_ms_max"]
              and r["full_verify_seconds"] <= t["T-04"]["full_verify_seconds_max"]
              and r["archive_seconds"] <= t["T-04"]["archive_seconds_max"], r)
    if "T-05" in results:
        r = results["T-05"]
        check("T-05", r["records_before"] >= t["T-05"]["records"] and r["capacity"] == t["T-05"]["capacity"]
              and r["begin_finish_p95_ms"] <= t["T-05"]["begin_finish_p95_ms_max"] and r["archived_ids_accepted"] == 0, r)
    if "T-06" in results:
        check("T-06", results["T-06"]["ready_seconds"] <= t["T-06"]["ready_seconds_max"], results["T-06"])
    if "T-07" in results:
        check("T-07", results["T-07"]["max_rss_mib"] is not None and results["T-07"]["max_rss_mib"] <= t["T-07"]["guard_rss_mib_max"], results["T-07"])
    if "T-08" in results:
        r = results["T-08"]
        check("T-08", r["recovery_seconds"] is not None and r["recovery_seconds"] <= t["T-08"]["recovery_seconds_max"]
              and r["service_alive_after_oversized"] and set(r["during_flood_statuses"]) <= {"busy", "ok"}, r)
    if "T-09" in results:
        r = results["T-09"]
        check("T-09", r["transport"]["observed_ms"] <= r["transport"]["timeout_seconds"] * 1000 + t["T-09"]["transport_timeout_slack_ms_max"]
              and r["transport"]["status"] == "execution_or_audit_failed_outcome_unknown" and r["control"]["denied"]
              and r["control"]["observed_ms"] <= r["control"]["timeout_seconds"] * 1000 + t["T-09"]["control_timeout_slack_ms_max"], r)
    # Every defined target gets a verdict: a target whose group did not run (or
    # crashed) is not met, so a partial run never reads as all targets passed.
    for target_id in t:
        verdicts.setdefault(target_id, {"passed": False, "measured": None, "not_run": True})
    return {target_id: verdicts[target_id] for target_id in t}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--group", choices=("sustained", "burst", "vault", "state"), required=True)
    parser.add_argument("--work", required=True, help="Persistent work directory shared by groups")
    parser.add_argument("--output", required=True)
    parser.add_argument("--duration", type=float, default=300)
    args = parser.parse_args()
    targets = json.loads((ROOT / "docs/operations/capacity-targets.json").read_text())
    output = Path(args.output)
    report = json.loads(output.read_text()) if output.exists() else {"results": {}}
    results = report["results"]
    env = Environment(args.work).prepare()
    rss = []
    try:
        if args.group == "sustained":
            env.start()
            results["T-01"] = asyncio.run(sustained(env, targets["targets"][0]["offered_rps"], args.duration, rss))
            results["T-07"] = {"max_rss_mib": round(max(rss), 1) if rss else None, "samples": len(rss), "during": "T-01"}
        elif args.group == "burst":
            env.start()
            results["T-02"] = asyncio.run(burst(env, 32, 60, rss))
            results["T-07_burst"] = {"max_rss_mib": round(max(rss), 1) if rss else None, "samples": len(rss)}
            results["T-08"] = asyncio.run(exhaustion(env))
            results["T-09"] = asyncio.run(slow_dependencies(env))
            results["service_crashes"] = 0 if env.process.poll() is None else 1
        elif args.group == "vault":
            usage = populate_vault(env, 2000)
            env.start()
            outcome = asyncio.run(vault_group(env))
            outcome["vault_live_entries_before"] = usage["live_entries"]
            outcome["max_rss_mib"] = env.rss_mib()
            results["T-03"] = outcome
        else:
            state_group(env, results)
    finally:
        env.stop()
    if "T-07_burst" in results and "T-07" in results and results["T-07_burst"]["max_rss_mib"]:
        results["T-07"]["max_rss_mib"] = max(results["T-07"]["max_rss_mib"] or 0, results["T-07_burst"]["max_rss_mib"])
        results["T-07"]["during"] = "T-01,T-02"
    # Container runs receive the executed image's identity and the Docker
    # engine from tools/run_operational_acceptance_container.sh, which resolves
    # the tag once and runs that image ID.
    sys.path.insert(0, str(ROOT / "tools"))
    import evidence
    identity = json.loads(Path(os.environ["GUARD_IMAGE_INFO"]).read_text()) if os.environ.get("GUARD_IMAGE_INFO") else None
    header = evidence.header("operational-acceptance", configurations=[evidence.configuration(
        env.config_path, preserve=(output.parent / "configurations", "operational-acceptance-container.guard.json"))],
        image_info=identity["image"] if identity else None)
    if identity:
        header["environment"]["docker_engine"] = identity.get("docker_engine")
    report.update({"evidence": header, "version": __import__("enkstein_guard").__version__,
                   "python": platform.python_version(),
                   "platform": platform.platform(), "cpu_count": os.cpu_count(),
                   "image": identity["image"]["reference"] if identity else None,
                   "image_id": identity["image"]["id"] if identity else None,
                   "targets_defined_at": targets["defined_at"], "targets_sha256": hashlib.sha256(
                       (ROOT / "docs/operations/capacity-targets.json").read_bytes()).hexdigest(),
                   "scope": "Single-host development profile on one OS user; synthetic fixture connector; "
                            "multi-UID peer-bound fairness is container acceptance only.",
                   "verdicts": evaluate(targets, results)})
    report["passed"] = all(verdict["passed"] for verdict in report["verdicts"].values())
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v["passed"] for k, v in report["verdicts"].items()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
