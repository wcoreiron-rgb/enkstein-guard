"""Full-disk and failed-write acceptance in the production-linux-peer-bound
deployment. Guard's state and archive volumes are small tmpfs filesystems
(deployment/acceptance/compose.diskfull.yaml), filled from inside the Guard
container while requests run. Checks fail-closed refusal before dispatch,
unknown-outcome reporting for work already dispatched, duplicate suppression,
behaviour across a restart while full, recovery after space is freed, and a
full archive volume during retention. Writes verification/0.5.0rc2/production-disk-full.json.
"""
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from production_harness import ROOT, Deployment, capacity_config, plan_for, write_report  # noqa: E402

CALL = r"""
import asyncio, json, sys
from pathlib import Path
from enkstein_guard.outcomes import new_request_id
from enkstein_guard.service import guarded_request
token = Path("/run/agent-token").read_text().strip()
route, request_id, text, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
async def main():
    statuses = []
    for number in range(count):
        rid = request_id if request_id != "new" else new_request_id()
        body = {"messages": [{"role": "user", "content": text.replace("{rid}", rid.split("-", 1)[1]) + " n%d" % number}]}
        try:
            response = await guarded_request("/run/guard/guard.sock", token, route, body, request_id=rid, timeout=60)
            statuses.append(response.get("status") + (":" + response["reason"] if response.get("reason") else ""))
        except Exception as error:
            statuses.append("client_error:" + type(error).__name__)
    print(json.dumps(statuses))
asyncio.run(main())
"""


def main():
    # Sized per the ledger rule (40 req/s x 4,200 s x 1.1 <= 200,000); the tmpfs
    # volumes, not the ledger capacity, are what fill up.
    config = capacity_config(rate=40, capacity=200000, archive_age=3600, archive_interval=300, max_request_age=600,
                             audit_threshold=1000, audit_keep=100, audit_interval=86400, vault_interval=86400)
    config["service"]["transport_timeout_seconds"] = 30
    deployment = Deployment(config, label="diskfull", upstream_mode="count",
                            overlays=[ROOT / "deployment/acceptance/compose.diskfull.yaml"])
    agent = config["agents"][0]
    checks, details = {}, {}

    def call(route, request_id, text, count=1, background=False):
        command = [*deployment.base, "run", "--rm", "--no-deps", "-T", "--user", "%d:10001" % agent["uid"],
                   "-v", str(deployment.run / "credentials" / (agent["id"] + ".token")) + ":/run/agent-token:ro",
                   "--entrypoint", "python", "agent", "-c", CALL, route, request_id, text, str(count)]
        process = subprocess.Popen(command, env=deployment.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if background:
            return process
        return finish(process)

    def finish(process):
        out, err = process.communicate(timeout=300)
        lines = [line for line in out.splitlines() if line.startswith("[")]
        return json.loads(lines[-1]) if lines else ["no_result:" + deployment.redact(err[-300:])]

    def fill(path):
        result = deployment.compose("exec", "-T", "state-holder", "sh", "-c",
                                    "cat /dev/zero > %s/filler 2>/dev/null; df -k %s | tail -1" % (path, path),
                                    check=False, timeout=300)
        return result.stdout.strip()

    def free(path):
        return deployment.compose("exec", "-T", "state-holder", "rm", "-f", path + "/filler", check=False).returncode

    def ready_code():
        return deployment.guard_cli("service", "ready", "--timeout", "3", check=False, timeout=60)[0]

    try:
        deployment.up(before=("state-holder",))
        report_evidence = deployment.header("production-disk-full")
        checks["baseline_ok"] = call("a.model-plain", "new", "baseline rid:{rid}") == ["ok"]
        # 1. Work already dispatched when the disk fills: outcome unknown, never replayed.
        inflight_id = "%010d-%s" % (int(time.time()), "inflightdiskfull0000001")
        pending = call("a.model-plain", inflight_id, "delay_ms:4000 rid:{rid}", background=True)
        time.sleep(2.0)
        details["state_df_when_full"] = fill("/state")
        details["in_flight"] = finish(pending)
        checks["in_flight_reported_outcome_unknown"] = details["in_flight"] == ["execution_or_audit_failed_outcome_unknown"]
        time.sleep(2.5)  # the upstream publishes its counters every second
        before = deployment.upstream_stats()
        details["in_flight_retry_while_full"] = call("a.model-plain", inflight_id, "delay_ms:4000 rid:{rid}")
        checks["in_flight_retry_not_replayed"] = details["in_flight_retry_while_full"] == ["outcome_unknown_no_replay"]
        # 2. New work while full is refused before dispatch.
        details["new_while_full"] = call("a.model-plain", "new", "new while full rid:{rid}", count=5)
        details["tokenized_while_full"] = call("a.model", "new", "customer jane@example.com rid:{rid}")
        time.sleep(2.5)
        after = deployment.upstream_stats()
        refused = {"request_tracking_unavailable_or_conflict:tracking_unavailable",
                   "unavailable_no_execution:audit_unavailable", "unavailable_no_execution:vault_unavailable"}
        checks["new_work_refused_before_dispatch"] = (set(details["new_while_full"] + details["tokenized_while_full"])
                                                      <= refused)
        checks["nothing_dispatched_while_full"] = bool(before and after) and after["requests"] == before["requests"]
        checks["not_ready_while_full"] = ready_code() != 0
        code, doctor = deployment.guard_cli("doctor", check=False, timeout=120)
        details["doctor_warnings_while_full"] = [w.get("code") for w in doctor.get("warnings", [])]
        # The operator is told: event writes are failing and a final state is
        # waiting to be written.
        checks["doctor_warns_while_full"] = {"service_events_lost", "outcome_states_pending_write"} <= set(
            details["doctor_warnings_while_full"])
        # 3. Restart while full: refuses to start (fail closed), recovers once space is freed.
        deployment.compose("kill", "guard", check=False)
        deployment.compose("up", "-d", "--no-color", "guard", check=False)
        time.sleep(15)
        checks["restart_while_full_not_ready"] = ready_code() != 0
        details["guard_state_after_restart_attempt"] = deployment.compose(
            "ps", "-a", "--format", "json", "guard", check=False).stdout.strip()[-600:]
        checks["space_freed"] = free("/state") == 0
        started = time.time()
        try:
            deployment.wait_ready(timeout=180)
            details["ready_seconds_after_free"] = round(time.time() - started, 1)
            checks["ready_after_free"] = True
        except RuntimeError:
            checks["ready_after_free"] = False
        # 4. After recovery: still never replayed; new work runs.
        details["in_flight_retry_after_recovery"] = call("a.model-plain", inflight_id, "delay_ms:4000 rid:{rid}")
        checks["in_flight_still_not_replayed"] = details["in_flight_retry_after_recovery"] == ["outcome_unknown_no_replay"]
        details["after_recovery"] = call("a.model-plain", "new", "after recovery rid:{rid}", count=3)
        checks["new_work_after_recovery"] = details["after_recovery"] == ["ok"] * 3
        stats = deployment.upstream_stats() or {}
        details["upstream"] = stats
        checks["no_request_executed_twice"] = stats.get("max_executions_per_marker", 2) <= 1
        code, listed = deployment.guard_cli("outcomes", "list", "--state", "uncertain", check=False)
        checks["in_flight_recorded_uncertain"] = code == 0 and len(listed.get("records", [])) >= 1
        code, _ = deployment.guard_cli("audit", "verify", check=False)
        checks["audit_chain_intact_after_full_disk"] = code == 0
        # 5. Full archive volume during retention: requests continue, the job
        #    fails and is reported, no partial segment remains, then it succeeds.
        # Enough audit events to pass the archive threshold, paced under every
        # agent's rate share (each admitted request writes two audit events).
        processes = [deployment.agent(item["id"], ["--plan", json.dumps(plan_for(item["id"][0], sensitive=0, retrieval=0)),
                                                  "--duration", "20", "--rate", "8", "--window", "60"])
                     for item in config["agents"]]
        loads = [Deployment.collect(process, 300)["summary"] or {} for process in processes]
        details["load_for_audit_threshold"] = [load.get("statuses") for load in loads]
        code, status = deployment.guard_cli("service", "status", check=False)
        details["audit_active_before_retention"] = (status.get("audit") or {}).get("active_events")
        details["archive_df_when_full"] = fill("/archive")
        listing_before = deployment.compose("exec", "-T", "state-holder", "ls", "/archive", check=False).stdout.split()
        code, failed = deployment.guard_cli("retention", "run", "--store", "audit", check=False, timeout=600)
        details["retention_while_archive_full"] = {"exit": code, "error": failed.get("error")}
        checks["retention_failure_reported"] = code != 0 and failed.get("error") == "audit_archive_failed"
        checks["requests_unaffected_by_full_archive"] = call("a.model-plain", "new", "archive full rid:{rid}") == ["ok"]
        listing_after = deployment.compose("exec", "-T", "state-holder", "ls", "/archive", check=False).stdout.split()
        checks["no_partial_segment_left"] = sorted(listing_after) == sorted(listing_before)
        free("/archive")
        code, archived = deployment.guard_cli("retention", "run", "--store", "audit", check=False, timeout=600)
        details["retention_after_free"] = {"exit": code, "archived": (archived.get("last_result") or {}).get("archived")}
        checks["retention_succeeds_after_free"] = code == 0 and (archived.get("last_result") or {}).get("archived", 0) > 0
        code, _ = deployment.guard_cli("audit", "verify", "--with-archives", check=False)
        checks["audit_chain_with_archives_verified"] = code == 0
        code, status = deployment.guard_cli("service", "status", check=False)
        details["final_status"] = {key: status.get(key) for key in ("audit_event_failures", "unsettled_outcomes",
                                                                  "retention", "outcomes", "audit")}
        report = {"evidence": report_evidence, "checks": checks, "details": details, "passed": all(checks.values()),
                  "scope": "Guard state (16-24 MiB) and archive (8 MiB) tmpfs volumes inside the Docker VM; synthetic "
                           "credentials and upstream; production profile with separate UIDs and the egress proxy."}
    except Exception as error:
        report = {"checks": checks, "details": details, "passed": False,
                  "error": deployment.redact(str(error))[-3000:], "diagnostic_logs": deployment.logs()}
    finally:
        deployment.down()
    write_report("production-disk-full.json", report)
    print(json.dumps({"passed": report["passed"], "failed": [k for k, v in checks.items() if not v],
                      "error": report.get("error")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
