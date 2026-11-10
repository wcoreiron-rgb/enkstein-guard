"""Shared harness for production-profile container acceptance runs.

Brings up deployment/compose.production.yaml plus the acceptance overlay (a
synthetic TLS upstream reachable only from the egress network) as a disposable
Compose project, initializes Guard state with synthetic credentials, runs
network-less agent containers under their own UIDs, samples Guard and egress
processes, and tears everything down. Only the project's own containers and
volumes are removed. Nothing here contacts a real provider.
"""
import datetime
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "deployment"))
import evidence  # noqa: E402
from test_production_profile import certificates  # noqa: E402

IMAGE = os.environ.get("GUARD_TEST_IMAGE", evidence.IMAGE_TAG)
EVIDENCE = Path(os.environ.get("GUARD_EVIDENCE_DIR", evidence.EVIDENCE_DIR))
NETWORKS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

SAMPLE = r"""
import json, os, sys
match = sys.argv[1].encode()
result = {"process": None, "paths": {}}
for pid in os.listdir("/proc"):
    if not pid.isdigit() or int(pid) in (os.getpid(), os.getppid()):
        continue
    try:
        argv = open("/proc/%s/cmdline" % pid, "rb").read().split(b"\0")
        if not any(match == item for item in argv) or b"python" not in argv[0] and b"enkstein" not in argv[0]:
            continue
        fields = dict(line.split(":", 1) for line in open("/proc/%s/status" % pid).read().splitlines() if ":" in line)
        result["process"] = {"pid": int(pid), "rss_kib": int(fields["VmRSS"].split()[0]),
                             "threads": int(fields["Threads"]), "fds": len(os.listdir("/proc/%s/fd" % pid))}
        break
    except (OSError, KeyError, ValueError):
        continue
for path in sys.argv[2:]:
    total, files = 0, {}
    for root, _, names in os.walk(path):
        for name in names:
            try:
                size = os.path.getsize(os.path.join(root, name))
            except OSError:
                continue
            total += size
            files[os.path.relpath(os.path.join(root, name), path)] = size
    result["paths"][path] = {"bytes": total, "files": len(files),
                             "largest": sorted(files.items(), key=lambda item: -item[1])[:8]}
print(json.dumps(result))
"""


def capacity_config(*, rate, capacity, archive_age, archive_interval, max_request_age=1800, audit_threshold=50000,
                    audit_keep=5000, audit_interval=300, vault_interval=60, token_ttl=600, agents_per_tenant=2):
    """Production-profile configuration with two tenants, real connector types only."""
    tenants = ("a", "b")
    connectors, routes, agents = [], [], []
    uid = 11001
    for tenant in tenants:
        connectors.append({"name": "model-" + tenant, "type": "chat_completions",
                           "endpoint": "https://upstream.acceptance.test/v1/chat/completions",
                           "model": "synthetic-model", "credential": "key-" + tenant, "authentication": "x-api-key",
                           "ca_file": "/bootstrap/ca.pem", "timeout_seconds": 20,
                           "data_domain": "acceptance-upstream"})
        routes += [
            {"name": tenant + ".model", "tenant": tenant, "operation": "model.call", "connector": "model-" + tenant,
             "clearance": "internal", "produces": "internal", "privacy": "tokenize"},
            {"name": tenant + ".model-plain", "tenant": tenant, "operation": "model.call",
             "connector": "model-" + tenant, "clearance": "internal", "produces": "internal"},
            {"name": tenant + ".kb", "tenant": tenant, "operation": "retrieve", "connector": "kb",
             "clearance": "internal"}]
        for number in range(1, agents_per_tenant + 1):
            agents.append({"id": "%s%d" % (tenant, number), "tenant": tenant, "principal": "%s-bot%d" % (tenant, number),
                           "uid": uid, "clearance": "internal", "groups": ["support"],
                           "routes": [tenant + ".model", tenant + ".model-plain", tenant + ".kb"]})
            uid += 1
    connectors.append({"name": "kb", "type": "retrieval_local", "collection": "kb"})
    return {
        "schema_version": 2, "profile": "production-linux-peer-bound", "deployment": {"guard_uid": 10001},
        "paths": {"state_directory": "/state", "key_directory": "/state-keys", "socket": "/run/guard/guard.sock",
                  "admin_socket": "/run/guard-admin/admin.sock", "archive_directory": "/archive"},
        "service": {"socket_group": 10001, "max_connections": 32, "per_peer_connections": 4,
                    "max_requests_per_second": rate, "transport_timeout_seconds": 20, "request_timeout_seconds": 60},
        "vault": {"max_entries": 50000, "max_bytes": 67108864, "token_ttl_seconds": token_ttl},
        "outcomes": {"capacity": capacity, "max_request_age_seconds": max_request_age},
        "retention": {"outcome_archive_age_seconds": archive_age, "outcome_archive_interval_seconds": archive_interval,
                      "audit_archive_threshold_events": audit_threshold, "audit_archive_keep_events": audit_keep,
                      "audit_archive_interval_seconds": audit_interval, "vault_purge_interval_seconds": vault_interval},
        "tenants": [{"id": tenant} for tenant in tenants],
        "backend_inventory": {"schema_version": 1, "backends": [{
            "backend_id": "acceptance-upstream", "account_id": "synthetic-shared",
            "data_domain": "acceptance-upstream", "tenants": list(tenants),
            "hosts": ["https://upstream.acceptance.test"]}]},
        "connectors": connectors, "routes": routes, "agents": agents, "approvers": [],
        "egress": {"mode": "proxy", "socket": "/run/guard-egress/egress.sock", "client_uids": [10001],
                   "socket_group": 10003, "max_connections": 128,
                   "allow": [{"host": "upstream.acceptance.test", "port": 443, "addresses": NETWORKS}]}}


def plan_for(tenant, *, chat=5, sensitive=2, plain=1, retrieval=2):
    """Request mix for one agent: tokenized chat, chat with a sensitive value,
    untokenized chat and retrieval, by weight."""
    return [entry for entry in (
        {"route": tenant + ".model", "kind": "chat", "weight": chat},
        {"route": tenant + ".model", "kind": "chat_sensitive", "weight": sensitive},
        {"route": tenant + ".model-plain", "kind": "chat", "weight": plain},
        {"route": tenant + ".kb", "kind": "retrieval", "weight": retrieval}) if entry["weight"]]


class Deployment:
    def __init__(self, config, *, label, overlays=(), upstream_mode="count", project_prefix="egrc2"):
        local = ROOT / ".local-deploy"
        local.mkdir(exist_ok=True, mode=0o700)
        self.config = config
        self.run = local / ("%s-%s" % (label, secrets.token_hex(5)))
        self.run.mkdir(mode=0o700)
        (self.run / "bootstrap").mkdir(mode=0o755)
        (self.run / "credentials").mkdir(mode=0o777)
        (self.run / "credentials").chmod(0o777)
        self.config_path = self.run / "bootstrap/guard.json"
        self.config_path.write_text(json.dumps(config, indent=2))
        self.config_path.chmod(0o444)
        documents = [{"doc_id": "kb-%d" % n, "title": "Runbook %d" % n,
                      "content": "Outage runbook steps %d: restart the ticket service." % n,
                      "label": "internal", "groups": ["support"]} for n in range(20)]
        for tenant in {t["id"] for t in config["tenants"]}:
            path = self.run / "bootstrap" / ("docs-%s.jsonl" % tenant)
            path.write_text("".join(json.dumps(item) + "\n" for item in documents))
            path.chmod(0o444)
        certificates(self.run)
        self.secrets = {c["credential"]: "synthetic-%s-%s" % (c["credential"], secrets.token_hex(8))
                        for c in config["connectors"] if c["type"] == "chat_completions"}
        self.project = project_prefix + secrets.token_hex(4)
        self.env = {**os.environ, "GUARD_IMAGE": IMAGE, "GUARD_AGENT_IMAGE": IMAGE,
                    "GUARD_BOOTSTRAP_DIR": str(self.run / "bootstrap"),
                    "GUARD_ACCEPTANCE_DIR": str(ROOT / "deployment/acceptance"),
                    "GUARD_UPSTREAM_DIR": str(self.run / "upstream"),
                    "GUARD_AGENT_TOKEN_FILE": str(self.run / "credentials/placeholder.token"),
                    "UPSTREAM_MODE": upstream_mode}
        (self.run / "credentials/placeholder.token").write_text("placeholder")
        files = [ROOT / "deployment/compose.production.yaml", ROOT / "deployment/acceptance/compose.acceptance.yaml",
                 *overlays]
        self.base = ["docker", "compose", "-p", self.project] + [item for path in files for item in ("-f", str(path))]

    # -- compose helpers ------------------------------------------------------
    def redact(self, text):
        for value in self.secrets.values():
            text = text.replace(value, "[redacted]")
        return text

    def compose(self, *args, stdin=None, check=True, timeout=900):
        result = subprocess.run([*self.base, *args], env=self.env, input=stdin, capture_output=True, text=True,
                                timeout=timeout)
        if check and result.returncode:
            raise RuntimeError("compose %s failed: %s" % (args[:3], self.redact(result.stderr[-2000:])))
        return result

    def guard_cli(self, *args, stdin=None, check=True, exec_=True, timeout=900):
        command = ["exec", "-T", "guard", "enkstein-guard"] if exec_ else [
            "run", "--rm", "--no-deps", "-T", "-v", str(self.run / "credentials") + ":/credentials", "guard"]
        result = self.compose(*command, "--config", "/bootstrap/guard.json", *args, stdin=stdin, check=False,
                              timeout=timeout)
        lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
        payload = json.loads(lines[-1]) if lines else {"status": "no_output", "stderr": self.redact(result.stderr[-500:])}
        if check and result.returncode:
            raise RuntimeError("guard cli %s failed: %s" % (args[:2], json.dumps(payload)[:2000]))
        return result.returncode, payload

    def wait_ready(self, timeout=120):
        deadline = time.time() + timeout
        while time.time() < deadline:
            code, payload = self.guard_cli("service", "ready", "--timeout", "3", check=False)
            if code == 0:
                return payload
            time.sleep(1)
        raise RuntimeError("guard_not_ready: " + self.redact(self.compose("logs", "--no-color", "guard", "egress",
                                                                          check=False).stdout[-3000:]))

    def up(self, *, before=()):
        if before:
            self.compose("up", "-d", "--no-color", *before)
        self.compose("up", "--no-color", "initialize", "capture-init")
        self.guard_cli("init", exec_=False)
        for agent in self.config["agents"]:
            self.guard_cli("agent", "issue", "--agent", agent["id"], "--output", "/credentials/%s.token" % agent["id"],
                           exec_=False)
            (self.run / "credentials" / (agent["id"] + ".token")).chmod(0o444)
        if any(c["type"] == "retrieval_local" and c["collection"] == "kb"
               for c in self.config["connectors"]):
            for tenant in {t["id"] for t in self.config["tenants"]}:
                self.guard_cli("retrieval", "ingest", "--tenant", tenant, "--collection", "kb",
                               "--file", "/bootstrap/docs-%s.jsonl" % tenant, exec_=False)
        for connector in self.config["connectors"]:
            if connector["type"] != "chat_completions":
                continue
            routes = [r for r in self.config["routes"] if r["connector"] == connector["name"]]
            args = ["connector", "secret-set", "--name", connector["credential"], "--tenant", routes[0]["tenant"],
                    "--destination", "upstream.acceptance.test"]
            for route in routes:
                args += ["--route", route["name"]]
            self.guard_cli(*args, "--value-file", "-", stdin=self.secrets[connector["credential"]] + "\n", exec_=False)
        self.compose("up", "-d", "--no-color", "egress", "upstream", "guard")
        return self.wait_ready()

    def agent(self, agent_id, script_args, *, extra_env=None):
        """Start a load agent container for ``agent_id`` (its own UID and credential)."""
        agent = next(a for a in self.config["agents"] if a["id"] == agent_id)
        command = [*self.base, "run", "--rm", "--no-deps", "-T", "--user", "%d:10001" % agent["uid"],
                   "-v", str(ROOT / "deployment/acceptance/load_agent.py") + ":/load_agent.py:ro",
                   "-v", str(self.run / "credentials" / (agent_id + ".token")) + ":/run/agent-token:ro"]
        for key, value in (extra_env or {}).items():
            command += ["-e", "%s=%s" % (key, value)]
        command += ["--entrypoint", "python", "agent", "/load_agent.py", *script_args]
        return subprocess.Popen(command, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    @staticmethod
    def collect(process, timeout):
        stdout, stderr = process.communicate(timeout=timeout)
        lines = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
        summary = next((line for line in reversed(lines) if line.get("type") == "summary"), None)
        return {"windows": [line for line in lines if line.get("type") == "window"], "summary": summary,
                "returncode": process.returncode, "stderr": stderr[-1500:] if process.returncode else ""}

    def sample(self):
        """Guard and egress process figures plus state/archive volume sizes."""
        result = {"t": time.time()}
        guard = self.compose("exec", "-T", "guard", "python", "-c", SAMPLE, "start", "/state", "/archive",
                             check=False, timeout=60)
        egress = self.compose("exec", "-T", "egress", "python", "-c", SAMPLE, "serve", check=False, timeout=60)
        for name, run in (("guard", guard), ("egress", egress)):
            lines = [line for line in run.stdout.splitlines() if line.startswith("{")]
            result[name] = json.loads(lines[-1]) if lines else None
        return result

    def status(self):
        code, payload = self.guard_cli("service", "status", check=False, timeout=120)
        return payload if code == 0 else None

    def upstream_stats(self, *, settle=True):
        """Upstream counters once they stop changing (published every second)."""
        previous = None
        for _ in range(30):
            out = self.compose("exec", "-T", "upstream", "cat", "/capture/stats.json", check=False, timeout=60).stdout
            try:
                current = json.loads(out)
            except ValueError:
                current = None
            if not settle or (current and previous and current["requests"] == previous["requests"]
                              and current["updated"] != previous["updated"]):
                return current
            previous = current
            time.sleep(1.2)
        return previous

    def header(self, report):
        code, shown = self.guard_cli("config", "show", check=False)
        policy = shown.get("policy_version") if code == 0 else None
        return evidence.header(report, configurations=[evidence.configuration(
            self.config_path, name="guard.json", policy_version=policy,
            preserve=(EVIDENCE / "configurations", report + ".guard.json"))], image_info=evidence.image(IMAGE))

    def logs(self):
        return self.redact(self.compose("logs", "--no-color", "guard", "egress", "upstream", check=False).stdout[-6000:])

    def down(self):
        self.compose("down", "--volumes", "--remove-orphans", check=False)
        shutil.rmtree(self.run, ignore_errors=True)


class AgentRun:
    """A started load agent whose output is read while it runs. Without this a
    long run fills the pipe (summary with latencies) and `docker compose run`
    cannot exit, so a caller waiting for the exit would wait forever."""

    def __init__(self, process):
        self.process, self.out, self.err = process, [], []
        self.threads = [threading.Thread(target=self._pump, args=(process.stdout, self.out), daemon=True),
                        threading.Thread(target=self._pump, args=(process.stderr, self.err), daemon=True)]
        for thread in self.threads:
            thread.start()

    @staticmethod
    def _pump(stream, sink):
        for line in iter(stream.readline, ""):
            sink.append(line)

    def poll(self):
        return self.process.poll()

    def result(self, timeout):
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=60)
        for thread in self.threads:
            thread.join(timeout=60)
        stdout, stderr = "".join(self.out), "".join(self.err)
        lines = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
        summary = next((line for line in reversed(lines) if line.get("type") == "summary"), None)
        return {"windows": [line for line in lines if line.get("type") == "window"], "summary": summary,
                "returncode": self.process.returncode, "stderr": stderr[-1500:] if self.process.returncode else ""}


def participation(results, expected, *, minimum_requests=1):
    """Every launched agent must have exited 0 and reported a summary with at
    least ``minimum_requests`` requests; a phase in which an agent failed or
    did not run is not a result."""
    agents = {}
    for agent in expected:
        result = results.get(agent) or {}
        summary = result.get("summary") or {}
        agents[agent] = {"returncode": result.get("returncode"), "summary": bool(result.get("summary")),
                         "requests": summary.get("requests", 0)}
    complete = bool(agents) and all(item["returncode"] == 0 and item["summary"]
                                    and item["requests"] >= minimum_requests for item in agents.values())
    return {"agents": agents, "minimum_requests": minimum_requests, "complete": complete}


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))], 2)


def write_report(name, report):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    report.setdefault("generated_at", datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"))
    (EVIDENCE / name).write_text(json.dumps(report, indent=2) + "\n")
    return EVIDENCE / name
