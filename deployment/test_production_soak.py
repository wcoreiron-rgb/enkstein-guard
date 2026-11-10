"""Multi-hour soak through the production-linux-peer-bound deployment with
scheduled retention. Targets: docs/operations/soak-targets.json, committed
before measurement. Samples processes, stores and retention every minute,
triggers one operator retention run mid-way, and checks integrity at the end.
Writes verification/0.5.0rc2/production-soak.json (and a progress file during
the run under .local-deploy so an interrupted soak still leaves its samples).

Usage: GUARD_TEST_IMAGE=enkstein-guard:0.5.0rc2 python deployment/test_production_soak.py [--duration S]
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from production_harness import (ROOT, AgentRun, Deployment, capacity_config, participation, percentile,  # noqa: E402
                                plan_for, write_report)

TARGETS = ROOT / "docs/operations/soak-targets.json"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, help="override (harness check only; not evidence)")
    options = parser.parse_args()
    targets = json.loads(TARGETS.read_text())
    target = {item["id"]: item["requirements"] for item in targets["targets"]}
    retention = targets["retention_configuration"]
    duration = options.duration or targets["load"]["duration_seconds"]
    evidence_run = options.duration is None
    config = capacity_config(rate=retention["max_requests_per_second"], capacity=retention["outcome_capacity"],
                             archive_age=retention["outcome_archive_age_seconds"],
                             archive_interval=retention["outcome_archive_interval_seconds"],
                             audit_threshold=retention["audit_archive_threshold_events"],
                             audit_keep=retention["audit_archive_keep_events"],
                             audit_interval=retention["audit_archive_interval_seconds"],
                             vault_interval=retention["vault_purge_interval_seconds"],
                             token_ttl=retention["token_ttl_seconds"])
    deployment = Deployment(config, label="soak", upstream_mode="count")
    progress = deployment.run.parent / ("soak-progress-%s.jsonl" % deployment.project)
    report = {"targets": str(TARGETS.relative_to(ROOT)), "targets_sha256": hashlib.sha256(TARGETS.read_bytes()).hexdigest(),
              "targets_defined_at": targets["defined_at"], "duration_seconds": duration,
              "harness_check_only": not evidence_run, "samples": [], "verdicts": {}}
    try:
        report["ready"] = deployment.up()
        report["evidence"] = deployment.header("production-soak")
        rate = targets["load"]["requests_per_second_per_agent"]
        # Agents' output is read while they run (AgentRun): a three-hour summary
        # would otherwise fill the pipe and keep them from exiting.
        processes = {agent["id"]: AgentRun(deployment.agent(agent["id"], [
            "--plan", json.dumps(plan_for(agent["id"][0])), "--duration", str(duration), "--rate", str(rate),
            "--window", "60", "--emit-latencies", "--dedup-probes", "50",
            "--expired-probes", str(target["S-07"]["expired_probes_per_agent"])])) for agent in config["agents"]}
        started = time.time()
        interval = targets["sampling"]["interval_seconds"]
        operator_run = None
        while any(process.poll() is None for process in processes.values()):
            sample = deployment.sample()
            status = deployment.status() or {}
            sample["status"] = {key: status.get(key) for key in ("outcomes", "audit", "vault", "retention",
                                                                 "tracked_requests", "unsettled_outcomes",
                                                                 "audit_event_failures", "rate_limit")}
            sample["upstream"] = deployment.upstream_stats()
            sample["elapsed"] = round(time.time() - started, 1)
            report["samples"].append(sample)
            with open(progress, "a") as stream:
                stream.write(json.dumps(sample) + "\n")
            if operator_run is None and time.time() - started > duration / 2:
                code, payload = deployment.guard_cli("retention", "run", "--store", "vault", check=False)
                operator_run = {"exit": code, "status": payload.get("status"), "elapsed": sample["elapsed"]}
            time.sleep(interval)
        results = {agent: run.result(1800) for agent, run in processes.items()}
        report["operator_retention_run"] = operator_run
        statuses, latencies, windows, probes, refused_probes = {}, [], [], {}, {}
        for agent, result in results.items():
            summary = result["summary"] or {}
            for key, value in summary.get("statuses", {}).items():
                statuses[key] = statuses.get(key, 0) + value
            latencies += summary.get("latencies_ms", [])
            windows += [dict(window, agent=agent) for window in result["windows"]]
            for key, value in summary.get("dedup_probes", {}).items():
                probes[key] = probes.get(key, 0) + value
            for key, value in summary.get("expired_probes", {}).items():
                refused_probes[key] = refused_probes.get(key, 0) + value
            if result["returncode"]:
                report.setdefault("agent_errors", {})[agent] = result["stderr"]
        final = deployment.status() or {}
        code, audit = deployment.guard_cli("audit", "verify", "--with-archives", check=False, timeout=1800)
        archives_code, archives = deployment.guard_cli("outcomes", "verify-archives", check=False, timeout=1800)
        upstream = deployment.upstream_stats() or {}
        last = deployment.sample()
        report.update(statuses=statuses, requests=sum(statuses.values()), p50_ms=percentile(latencies, .5),
                      p95_ms=percentile(latencies, .95), p99_ms=percentile(latencies, .99),
                      window_p99_ms_max=max((w["p99_ms"] or 0 for w in windows), default=None), windows=windows,
                      dedup_probes=probes, expired_probes=refused_probes, upstream=upstream,
                      audit_verify={"exit": code, **audit},
                      outcome_archives={"exit": archives_code, **archives},
                      final_status={key: final.get(key) for key in ("outcomes", "audit", "vault", "retention",
                                                                     "tracked_requests", "unsettled_outcomes",
                                                                     "audit_event_failures")},
                      final_sample=last)

        def series(path):
            values = []
            for sample in report["samples"]:
                node = sample
                for key in path:
                    node = node.get(key) if isinstance(node, dict) else None
                if isinstance(node, (int, float)):
                    values.append((sample["elapsed"], node))
            return values

        rss = series(("guard", "process", "rss_kib"))
        fds = series(("guard", "process", "fds"))
        threads = series(("guard", "process", "threads"))
        egress_rss = series(("egress", "process", "rss_kib"))
        state = series(("guard", "paths", "/state", "bytes"))
        archive_bytes = series(("guard", "paths", "/archive", "bytes"))
        records = series(("status", "outcomes", "records"))
        active = series(("status", "audit", "active_events"))
        live = series(("status", "vault", "live_entries"))
        expired = series(("status", "vault", "expired_entries"))
        hour = 3600
        first_hour = [v for t, v in rss if t <= hour] or [v for _, v in rss[:5]]
        last_hour = [v for t, v in rss if t >= (rss[-1][0] - hour)] if rss else []
        two_hour = [v for t, v in state if t <= 2 * hour]
        retention_final = final.get("retention") or {}
        non_ok = sum(v for k, v in statuses.items() if k != "ok")
        tracked = final.get("tracked_requests") or 0
        # Every agent must have run the whole soak (measurement rule).
        ran = participation(results, [agent["id"] for agent in config["agents"]],
                            minimum_requests=int(0.95 * rate * duration))
        report["participation"] = ran
        report["verdicts"] = {
            "S-01": {"passed": ran["complete"] and bool(statuses) and non_ok <= target["S-01"]["non_ok_statuses_max"],
                     "measured": {"agents_complete": ran["complete"], "requests": sum(statuses.values()),
                                  "non_ok": non_ok, "statuses": statuses}},
            "S-02": {"passed": bool(latencies) and report["p95_ms"] <= target["S-02"]["p95_ms_max"]
                     and report["p99_ms"] <= target["S-02"]["p99_ms_max"]
                     and (report["window_p99_ms_max"] or 0) <= target["S-02"]["window_p99_ms_max"],
                     "measured": {"p50_ms": report["p50_ms"], "p95_ms": report["p95_ms"], "p99_ms": report["p99_ms"],
                                  "window_p99_ms_max": report["window_p99_ms_max"]}},
            "S-03": {"passed": bool(rss) and max(v for _, v in rss) / 1024 <= target["S-03"]["guard_rss_mib_max"]
                     and (max(last_hour) - max(first_hour)) / 1024 <= target["S-03"]["last_hour_max_over_first_hour_max_mib"]
                     and max((v for _, v in egress_rss), default=0) / 1024 <= target["S-03"]["egress_rss_mib_max"],
                     "measured": {"guard_rss_mib_max": round(max((v for _, v in rss), default=0) / 1024, 1),
                                  "first_hour_max_mib": round(max(first_hour, default=0) / 1024, 1),
                                  "last_hour_max_mib": round(max(last_hour, default=0) / 1024, 1),
                                  "egress_rss_mib_max": round(max((v for _, v in egress_rss), default=0) / 1024, 1)}},
            "S-04": {"passed": bool(fds) and max(v for _, v in fds) - fds[0][1] <= target["S-04"]["guard_fds_over_first_sample_max"]
                     and max(v for _, v in threads) <= target["S-04"]["guard_threads_max"],
                     "measured": {"fds_first": fds[0][1] if fds else None, "fds_max": max((v for _, v in fds), default=None),
                                  "threads_max": max((v for _, v in threads), default=None)}},
            "S-05": {"passed": bool(records) and max(v for _, v in records) <= target["S-05"]["outcome_records_max"]
                     and max(v for _, v in active) <= target["S-05"]["audit_active_events_max"]
                     and max(v for _, v in live) <= target["S-05"]["vault_live_entries_max"]
                     and max((v for _, v in expired), default=0) <= target["S-05"]["vault_expired_entries_max"]
                     and max(v for _, v in state) <= target["S-05"]["state_bytes_max"]
                     and (not two_hour or state[-1][1] <= target["S-05"]["state_bytes_end_over_two_hour_mark_max_factor"]
                          * max(two_hour)),
                     "measured": {"outcome_records_max": max((v for _, v in records), default=None),
                                  "audit_active_events_max": max((v for _, v in active), default=None),
                                  "vault_live_entries_max": max((v for _, v in live), default=None),
                                  "vault_expired_entries_max": max((v for _, v in expired), default=None),
                                  "state_bytes_max": max((v for _, v in state), default=None),
                                  "state_bytes_two_hour_mark": max(two_hour, default=None),
                                  "state_bytes_end": state[-1][1] if state else None}},
            "S-06": {"passed": (retention_final.get("outcomes", {}).get("runs_with_records", 0)
                                >= target["S-06"]["outcome_archive_runs_with_records_min"]
                                and retention_final.get("audit", {}).get("runs_with_records", 0)
                                >= target["S-06"]["audit_archive_runs_with_records_min"]
                                and retention_final.get("vault", {}).get("runs", 0)
                                >= target["S-06"]["vault_purge_runs_min"]
                                and sum(retention_final.get(name, {}).get("failures", 0)
                                        for name in ("outcomes", "audit", "vault", "settlement"))
                                <= target["S-06"]["retention_failures_max"]),
                     "measured": {name: {key: retention_final.get(name, {}).get(key)
                                         for key in ("runs", "runs_with_records", "records_total", "failures", "max_seconds")}
                                  for name in ("outcomes", "audit", "vault", "settlement")}},
            "S-07": {"passed": code == 0 and archives_code == 0 and archives.get("verified") is True
                     and upstream.get("duplicate_markers", 1) <= target["S-07"]["upstream_duplicate_markers_max"]
                     and set(probes) == {target["S-07"]["dedup_probe_status"]}
                     # IDs archived hours ago are refused, never executed again.
                     and sum(refused_probes.values()) == target["S-07"]["expired_probes_per_agent"] * len(config["agents"])
                     and set(refused_probes) <= set(target["S-07"]["expired_probe_statuses"]),
                     "measured": {"audit_verify_exit": code, "outcome_archives": archives,
                                  "duplicate_markers": upstream.get("duplicate_markers"), "dedup_probes": probes,
                                  "expired_probes": refused_probes}},
            "S-08": {"passed": bool(archive_bytes) and tracked > 0
                     and archive_bytes[-1][1] / tracked <= target["S-08"]["archive_bytes_per_tracked_request_max"],
                     "measured": {"archive_bytes_end": archive_bytes[-1][1] if archive_bytes else None,
                                  "tracked_requests": tracked,
                                  "bytes_per_tracked_request": round(archive_bytes[-1][1] / tracked, 1)
                                  if archive_bytes and tracked else None}}}
    except Exception as error:
        report["error"] = deployment.redact(str(error))[-3000:]
        report["diagnostic_logs"] = deployment.logs()
    finally:
        deployment.down()
    report["passed"] = (len(report["verdicts"]) == len(target) and all(v["passed"] for v in report["verdicts"].values())
                        and "error" not in report and evidence_run)
    write_report("production-soak.json" if evidence_run else "production-soak-harness-check.json", report)
    print(json.dumps({"passed": report["passed"], "verdicts": {k: v["passed"] for k, v in report["verdicts"].items()},
                      "error": report.get("error")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
