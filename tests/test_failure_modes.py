"""Failed writes and full disks: fail closed before dispatch, report unknown
outcomes after dispatch, never replay, recover without restart.

Store failures are injected at the storage layer (the same exception types a
full disk produces); ``StateVolumeFullTests`` fills a real size-limited tmpfs
(Linux user + mount namespace) under a running service.
"""
import asyncio
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

from enkstein_guard.audit import AuditError, DurableAudit
from enkstein_guard.host import GuardHost, RateLimiter, StateLayout, initialize_state
from enkstein_guard.identities import IdentityStore
from enkstein_guard.outcomes import OutcomeError, OutcomeLedger, new_request_id
from enkstein_guard.productconfig import validate
from enkstein_guard.runtime import Principal
from enkstein_guard.sensitivity import TaintError, TaintStore
from enkstein_guard.service import guarded_request
from enkstein_guard.vault import LocalVault, VaultError

from test_host import DECLARED, make_config

FULL = sqlite3.OperationalError("database or disk is full")


class FailureHarness(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-fail-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("sock", "admin"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "declared.txt").write_text(DECLARED)
        self.config_path = self.root / "config.json"
        self.config_path.write_text(json.dumps(self.make()))
        self.config = validate(json.loads(self.config_path.read_text()), source=str(self.config_path))
        initialize_state(self.config)
        store = IdentityStore(*StateLayout(self.config).identities)
        store.issue("agent", "agent-a", self.root / "agent-a.token")
        self.token = (self.root / "agent-a.token").read_text().strip()
        self.host = await GuardHost(self.config).start()
        self.addAsyncCleanup(self.stop)

    def make(self):
        return make_config(self.root)

    async def stop(self):
        if self.host is not None:
            await self.host.stop()
            self.host = None

    async def restart(self):
        await self.stop()
        self.host = await GuardHost(self.config).start()

    async def call(self, route, payload, request_id=None):
        return await guarded_request(self.config["paths"]["socket"], self.token, route, payload,
                                     request_id=request_id or new_request_id())

    def outcomes_of(self, route):
        return [event.get("outcome") for _, _, event in self.host.components.audit.events()
                if event.get("route") == route and "operation_id" in event]

    def ledger_state(self, request_id, route, payload):
        principal = Principal("tenant-a", "support-bot", "agent-a", frozenset())
        name, _ = OutcomeLedger.binding(principal, request_id, route, payload)
        return self.host.components.outcomes.state(name)


class PreDispatchFailureTests(FailureHarness):
    COMMENT = {"ticket": "INC-42", "comment": "status update"}

    async def test_ledger_write_failure_rejects_before_dispatch(self):
        ledger = self.host.components.outcomes
        with mock.patch.object(OutcomeLedger, "_connect", side_effect=FULL):
            result = await self.call("ticket.comment", self.COMMENT)
        self.assertEqual((result["status"], result["reason"]),
                         ("request_tracking_unavailable_or_conflict", "tracking_unavailable"))
        self.assertEqual(self.outcomes_of("ticket.comment"), [])  # no control ran, nothing dispatched
        self.assertEqual(ledger.usage()["records"], 0)
        self.assertEqual((await self.call("ticket.comment", self.COMMENT))["status"], "ok")

    async def test_audit_failure_before_dispatch_is_not_a_denial_or_unknown(self):
        request_id = new_request_id()
        original = DurableAudit.__call__

        def failing(audit, event):
            if event.get("outcome") == "authorized":
                raise AuditError("audit_write_failed")
            return original(audit, event)

        with mock.patch.object(DurableAudit, "__call__", failing):
            result = await self.call("ticket.comment", self.COMMENT, request_id)
        self.assertEqual((result["status"], result["reason"]), ("unavailable_no_execution", "audit_unavailable"))
        self.assertNotIn("transport_completed", self.outcomes_of("ticket.comment"))
        # Nothing was sent, so the same ID may be submitted again once storage recovers.
        self.assertIsNone(self.ledger_state(request_id, "ticket.comment", self.COMMENT))
        self.assertEqual((await self.call("ticket.comment", self.COMMENT, request_id))["status"], "ok")
        self.assertEqual(self.outcomes_of("ticket.comment").count("transport_completed"), 1)

    async def test_vault_failure_during_tokenization_sends_nothing(self):
        payload = {"email": "jane@example.com", "note": "x"}
        request_id = new_request_id()
        with mock.patch.object(LocalVault, "put_many", side_effect=VaultError("vault_write_failed")):
            result = await self.call("crm.lookup", payload, request_id)
        self.assertEqual((result["status"], result["reason"]), ("unavailable_no_execution", "vault_unavailable"))
        self.assertIn("preparation_unavailable_no_execution", self.outcomes_of("crm.lookup"))
        self.assertNotIn("transport_completed", self.outcomes_of("crm.lookup"))
        self.assertEqual((await self.call("crm.lookup", payload, request_id))["status"], "ok")

    async def test_policy_refusal_of_payload_stays_a_denial(self):
        result = await self.call("crm.lookup", {"amount": 4111111111111111})
        self.assertEqual(result["status"], "denied")

    async def test_denial_with_failing_ledger_is_still_reported_as_denied(self):
        request_id = new_request_id()
        payload = {"ticket": "INC-99", "comment": "outside the task boundary"}
        with mock.patch.object(OutcomeLedger, "finish", side_effect=OutcomeError("tracking_unavailable")):
            first = await self.call("ticket.comment", payload, request_id)
            again = await self.call("ticket.comment", payload, request_id)
        self.assertEqual((first["status"], again["status"]), ("denied", "denied"))
        self.host.run_retention("settlement")
        self.assertEqual(self.ledger_state(request_id, "ticket.comment", payload), "denied")


class PostDispatchFailureTests(FailureHarness):
    COMMENT = {"ticket": "INC-42", "comment": "status update"}

    async def test_unrecorded_completion_is_released_never_replays_and_recovers(self):
        request_id = new_request_id()
        original = OutcomeLedger.finish

        def failing(ledger, name, state):
            if state == "completed":
                raise OutcomeError("tracking_unavailable")
            return original(ledger, name, state)

        with mock.patch.object(OutcomeLedger, "finish", failing):
            first = await self.call("ticket.comment", self.COMMENT, request_id)
            again = await self.call("ticket.comment", self.COMMENT, request_id)
            status = self.host.status()
        # The action completed: its result is released even though the ledger
        # could not record it yet; the identifier still never replays.
        self.assertEqual(first["status"], "ok")
        self.assertEqual(again["status"], "completed_no_replay")
        self.assertEqual(status["unsettled_outcomes"], 1)
        self.host.run_retention("settlement")  # storage recovered: the pending state is written
        self.assertEqual(self.ledger_state(request_id, "ticket.comment", self.COMMENT), "completed")
        self.assertEqual(self.host.status()["unsettled_outcomes"], 0)
        self.assertEqual((await self.call("ticket.comment", self.COMMENT, request_id))["status"], "completed_no_replay")
        self.assertEqual(self.outcomes_of("ticket.comment").count("transport_completed"), 1)

    async def test_unwritten_state_becomes_uncertain_after_restart(self):
        request_id = new_request_id()
        with mock.patch.object(OutcomeLedger, "finish", side_effect=OutcomeError("tracking_unavailable")):
            first = await self.call("ticket.comment", self.COMMENT, request_id)
        self.assertEqual(first["status"], "ok")
        await self.restart()  # the unwritten state is lost; the record is uncertain after restart
        self.assertEqual((await self.call("ticket.comment", self.COMMENT, request_id))["status"],
                         "outcome_unknown_no_replay")
        self.assertEqual(self.ledger_state(request_id, "ticket.comment", self.COMMENT), "uncertain")

    async def test_audit_failure_after_dispatch_is_unknown(self):
        request_id = new_request_id()
        original = DurableAudit.__call__

        def failing(audit, event):
            if event.get("outcome") == "transport_completed":
                raise AuditError("audit_write_failed")
            return original(audit, event)

        with mock.patch.object(DurableAudit, "__call__", failing):
            first = await self.call("ticket.comment", self.COMMENT, request_id)
        self.assertEqual(first["status"], "execution_or_audit_failed_outcome_unknown")
        self.assertEqual((await self.call("ticket.comment", self.COMMENT, request_id))["status"],
                         "outcome_unknown_no_replay")
        self.assertEqual(self.outcomes_of("ticket.comment").count("authorized"), 1)
        self.host.components.audit.verify()

    async def test_taint_write_failure_withholds_the_response(self):
        request_id = new_request_id()
        payload = {"ticket": "INC-42", "comment": "customer jane@example.com"}
        with mock.patch.object(TaintStore, "raise_to", side_effect=TaintError("taint_store_write_failed")):
            first = await self.call("ticket.comment", payload, request_id)
        self.assertEqual((first["status"], first["reason"]), ("response_withheld", "taint_unavailable"))
        self.assertNotIn("jane@example.com", json.dumps(first))
        self.assertEqual((await self.call("ticket.comment", payload, request_id))["status"], "completed_no_replay")


class ConnectorSaturationTests(FailureHarness):
    async def test_saturated_connector_is_refused_before_dispatch_not_unknown(self):
        import enkstein_guard.host as host_module
        from enkstein_guard.runtime import UnavailableBeforeDispatch
        request_id = new_request_id()
        payload = {"ticket": "INC-42", "comment": "busy"}
        original = host_module._fixture

        def saturated(behavior, timeout, delay=1):
            async def transport(operation):
                raise UnavailableBeforeDispatch("connector_busy")
            return transport

        await self.stop()
        with mock.patch.object(host_module, "_fixture", saturated):
            self.host = await GuardHost(self.config).start()
            result = await self.call("ticket.comment", payload, request_id)
        self.assertEqual((result["status"], result["reason"]), ("unavailable_no_execution", "connector_busy"))
        self.assertIn("transport_unavailable_no_execution", self.outcomes_of("ticket.comment"))
        self.assertIsNone(self.ledger_state(request_id, "ticket.comment", payload))  # the ID stays usable
        await self.restart()
        self.assertEqual((await self.call("ticket.comment", payload, request_id))["status"], "ok")

class ClientRefusalTests(unittest.IsolatedAsyncioTestCase):
    async def test_refused_client_receives_busy_even_after_sending_a_large_frame(self):
        from enkstein_guard.contracts import Action, ControlResult
        from enkstein_guard.runtime import GuardRuntime, Route
        from enkstein_guard.service import GuardService

        async def allow(operation):
            return ControlResult("c", operation.context.tenant_id, operation.context.operation_id, Action.ALLOW)

        async def transport(operation):
            return {}

        with tempfile.TemporaryDirectory(prefix="eg-refuse-") as temp:
            directory = Path(temp) / "sock"
            directory.mkdir(mode=0o700)
            token = "refusal-test-" + "t" * 40
            runtime = GuardRuntime(credentials={token: Principal("t", "p", "a", frozenset({"r"}))},
                                   routes=(Route("r", "op", "res", "dest", "t", ("c",), transport),),
                                   controls={"c": allow}, audit=lambda event: None)
            service = await GuardService(runtime, directory / "s.sock", max_connections=1).start()
            try:
                holder = await asyncio.open_unix_connection(str(directory / "s.sock"))  # takes the only slot
                await asyncio.sleep(0.05)
                for _ in range(5):
                    response = await guarded_request(directory / "s.sock", token, "r", {"blob": "x" * 900_000},
                                                     timeout=10)
                    self.assertEqual(response, {"status": "busy"})
                holder[1].close()
            finally:
                await service.close()


class TransportFailureCodeTests(unittest.TestCase):
    def test_bounded_transport_refuses_beyond_its_slots(self):
        import threading
        from enkstein_guard.blocking import BoundedBlockingTransport
        from enkstein_guard.runtime import UnavailableBeforeDispatch
        transport = BoundedBlockingTransport(1)
        release = threading.Event()

        async def scenario():
            first = asyncio.ensure_future(transport.run(release.wait, 5))
            await asyncio.sleep(0.05)
            with self.assertRaises(UnavailableBeforeDispatch):
                await transport.run(lambda: None)
            release.set()
            await first
            self.assertIsNone(await transport.run(lambda: None))  # the slot is released afterwards
        asyncio.run(scenario())

    def test_provider_failures_carry_fixed_reason_codes(self):
        import socket
        import ssl
        from urllib.error import HTTPError, URLError
        from enkstein_guard.egress import EgressDenied
        from enkstein_guard.providers import failure_code
        cases = [(EgressDenied("egress_denied_503"), "egress_denied_503"),
                 (URLError(ssl.SSLError("bad")), "provider_tls_failed"),
                 (URLError(socket.timeout("t")), "provider_timeout"),
                 (URLError(ConnectionRefusedError()), "provider_connection_failed"),
                 (HTTPError("https://x", 503, "busy", {}, None), "provider_http_503"),
                 (ValueError(), "provider_response_invalid")]
        for error, code in cases:
            self.assertEqual(failure_code(error), code)


class ArchiveFailureTests(unittest.TestCase):
    def test_failed_segment_writes_leave_no_partial_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "archive"
            archive.mkdir(mode=0o700)
            clock = [time.time()]
            ledger = OutcomeLedger.initialize(root / "o/o.sqlite3", root / "k/o.key", maximum=100,
                                              time_bound=True, max_request_age=60, clock=lambda: clock[0])
            ledger.configure_tenants(["t"])
            principal = Principal("t", "p", "a", frozenset({"r"}))
            for number in range(5):
                name, _ = ledger.begin(principal, new_request_id(clock[0]), "r", {"n": number})
                ledger.finish(name, "completed")
            clock[0] += 3600
            with mock.patch("enkstein_guard.outcomes.os.fsync", side_effect=OSError(28, "No space left on device")):
                with self.assertRaises(OutcomeError):
                    ledger.archive(archive, before=int(clock[0]) - 120)
            self.assertEqual(list(archive.iterdir()), [])
            self.assertEqual(ledger.usage()["records"], 5)
            self.assertEqual(ledger.archive(archive, before=int(clock[0]) - 120)["archived"], 5)
            audit = DurableAudit.initialize(root / "a/a.sqlite3", root / "k/a.key")
            for number in range(30):
                audit({"event": "e", "outcome": "e", "count": number})
            before = sorted(archive.iterdir())
            with mock.patch("enkstein_guard.audit.os.fsync", side_effect=OSError(28, "No space left on device")):
                with self.assertRaises(AuditError):
                    audit.archive(archive, keep=5)
            self.assertEqual(sorted(archive.iterdir()), before)
            self.assertEqual(audit.summary()["active_events"], 30)
            self.assertEqual(audit.archive(archive, keep=5, batch=10)["files"], 3)
            audit.verify(archives=archive)


class ChunkedArchiveTests(unittest.TestCase):
    def test_outcome_archive_chunks_advance_cutoff_and_keep_uncertain(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "archive"
            archive.mkdir(mode=0o700)
            start = time.time()
            clock = [start]
            ledger = OutcomeLedger.initialize(root / "o/o.sqlite3", root / "k/o.key", maximum=1000,
                                              time_bound=True, max_request_age=600, clock=lambda: clock[0])
            ledger.configure_tenants(["t"])
            principal = Principal("t", "p", "a", frozenset({"r"}))
            ids = []
            for number in range(25):
                request_id = new_request_id(start - 500 + number)
                name, _ = ledger.begin(principal, request_id, "r", {"n": number})
                ledger.finish(name, "uncertain" if number in (3, 17) else "completed")
                ids.append((request_id, name))
            clock[0] = start + 1000
            result = ledger.archive(archive, before=int(start) - 400, batch=4)
            self.assertEqual((result["archived"], result["retained_unreconciled"]), (23, 2))
            self.assertEqual(result["cutoff"], int(start) - 400)
            self.assertGreaterEqual(result["files"], 5)
            self.assertEqual(sum(item["records"] for item in ledger.archives()), 23)
            self.assertEqual(ledger.usage()["records"], 2)
            # Unreconciled records outlive the sizing horizon and are counted for diagnostics.
            self.assertEqual(ledger.usage()["retained_below_cutoff"], 2)
            with self.assertRaises(OutcomeError) as caught:
                ledger.begin(principal, ids[0][0], "r", {"n": 0})
            self.assertEqual(str(caught.exception), "request_id_expired")
            ledger.resolve(ids[3][1], "not_executed")
            again = ledger.archive(archive, before=int(start) - 400)
            self.assertEqual((again["archived"], again["retained_unreconciled"]), (1, 1))
            self.assertEqual(ledger.usage()["retained_below_cutoff"], 1)
            # Nothing due: no new segment file.
            files = len(list(archive.iterdir()))
            ledger.archive(archive, before=int(start) - 400)
            self.assertEqual(len(list(archive.iterdir())), files)
            self.assertTrue(ledger.verify_archives(archive)["verified"])
            # A request still in flight in this process is never archived, even
            # when uncertain records are explicitly included.
            in_flight, _ = ledger.begin(principal, new_request_id(clock[0] - 550), "r", {"n": "late"})
            clock[0] += 200
            ledger.archive(archive, before=int(clock[0]) - 700, include_uncertain=True)
            self.assertEqual(ledger.state(in_flight), "executing")
            ledger.finish(in_flight, "completed")
            # Removing a segment row is detected against the authenticated counter.
            with sqlite3.connect(root / "o/o.sqlite3") as connection:
                connection.execute("DELETE FROM archives WHERE sequence=(SELECT min(sequence) FROM archives)")
            problems = ledger.verify_archives(archive)["problems"]
            self.assertIn("segment_count_mismatch", [item["problem"] for item in problems])


class RateLimitTests(unittest.TestCase):
    def test_per_agent_share_and_refill(self):
        now = [0.0]
        limiter = RateLimiter(4, ["a", "b"], clock=lambda: now[0])
        self.assertEqual(limiter.share, 2)
        allowed = sum(limiter.allow("a") for _ in range(10))
        self.assertEqual(allowed, 4)  # burst of two seconds of share
        self.assertTrue(limiter.allow("b"))  # another agent's share is untouched
        now[0] += 1.0
        self.assertEqual(sum(limiter.allow("a") for _ in range(10)), 2)
        self.assertTrue(RateLimiter(None, ["a"]).allow("a"))


class RateLimitedServiceTests(FailureHarness):
    def make(self):
        data = make_config(self.root)
        data["service"]["max_requests_per_second"] = 2
        return data

    async def test_rate_limited_requests_are_neither_tracked_nor_executed(self):
        results = [await self.call("ticket.comment", {"ticket": "INC-42", "comment": "n%d" % n}) for n in range(8)]
        statuses = [r["status"] for r in results]
        self.assertIn("busy", statuses)
        self.assertTrue(all(r.get("reason") == "rate_limited" for r in results if r["status"] == "busy"))
        executed = statuses.count("ok")
        self.assertEqual(self.host.components.outcomes.usage()["records"], executed)
        self.assertEqual(self.outcomes_of("ticket.comment").count("transport_completed"), executed)
        self.assertEqual(self.host.status()["rate_limit"]["rate_limited"], statuses.count("busy"))


class ScheduledRetentionTests(FailureHarness):
    def make(self):
        data = make_config(self.root)
        data["outcomes"] = {"max_request_age_seconds": 600}
        data["retention"] = {"outcome_archive_age_seconds": 3600, "audit_archive_threshold_events": 1000,
                             "audit_archive_keep_events": 100}
        data["vault"] = {"token_ttl_seconds": 1}
        return data

    async def test_jobs_archive_outcomes_and_audit_and_purge_vault(self):
        for number in range(6):
            self.assertEqual((await self.call("ticket.comment", {"ticket": "INC-42", "comment": "c%d" % number}))["status"],
                             "ok")
        self.assertEqual((await self.call("crm.lookup", {"email": "jane@example.com", "note": "x"}))["status"], "ok")
        ledger = self.host.components.outcomes
        real = time.time()
        ledger._clock = lambda: real + 4000
        status = self.host.run_retention("outcomes")
        self.assertIsNone(status["last_error"])
        self.assertEqual(status["last_result"]["archived"], 7)
        self.assertEqual(ledger.usage()["records"], 0)
        for number in range(1200):
            self.host.event("synthetic_load", count=number)
        status = self.host.run_retention("audit")
        self.assertIsNone(status["last_error"])
        self.assertGreater(status["last_result"]["archived"], 0)
        self.host.components.audit.verify(archives=self.host.components.layout.archive)
        await asyncio.sleep(1.1)
        self.assertGreaterEqual(self.host.run_retention("vault")["last_result"]["purged"], 1)
        response = await self.host.admin("retention.run", {"store": "vault"})
        self.assertEqual(response["status"], "ok")
        self.assertEqual(self.host.status()["retention"]["outcomes"]["runs"], 1)

    async def test_schedule_runs_without_operator_action(self):
        retention = self.host.config.data["retention"]
        retention.update(vault_purge_interval_seconds=1, outcome_archive_interval_seconds=1,
                         audit_archive_interval_seconds=1)
        await self.restart()
        await asyncio.sleep(3.5)
        status = self.host.status()["retention"]
        self.assertGreaterEqual(min(status[name]["runs"] for name in ("vault", "outcomes", "audit")), 1)

    async def test_failed_job_is_reported_and_retried(self):
        with mock.patch.object(OutcomeLedger, "archive", side_effect=OutcomeError("outcome_archive_failed")):
            status = self.host.run_retention("outcomes")
        self.assertEqual((status["last_error"], status["failures"]), ("outcome_archive_failed", 1))
        self.assertIsNone(self.host.run_retention("outcomes")["last_error"])


ENOSPC_SCRIPT = textwrap.dedent("""
    import asyncio, json, os, subprocess, sys
    from pathlib import Path
    sys.path.insert(0, sys.argv[2])
    from test_host import make_config
    from enkstein_guard.host import GuardHost, StateLayout, initialize_state
    from enkstein_guard.identities import IdentityStore
    from enkstein_guard.outcomes import OutcomeLedger, new_request_id
    from enkstein_guard.productconfig import validate
    from enkstein_guard.runtime import Principal
    from enkstein_guard.service import guarded_request

    GuardHost.EVENT_FAILURE_WINDOW = 0.5
    root = Path(sys.argv[1])
    volume = root / "volume"
    volume.mkdir(parents=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=4m,mode=0700", "tmpfs", str(volume)], check=True)
    for name in ("sock", "admin"):
        (root / name).mkdir(mode=0o700)
    (root / "declared.txt").write_text("cobalt orchard")
    data = make_config(root)
    data["paths"].update(state_directory=str(volume / "state"), archive_directory=str(volume / "archive"))
    data["connectors"].append({"name": "delayed", "type": "fixture", "behavior": "delay", "delay_seconds": 1.5})
    data["routes"].append({"name": "ticket.delayed", "tenant": "tenant-a", "operation": "ticket.update",
                           "resource": "ticket", "destination": "delay-service", "connector": "delayed",
                           "clearance": "confidential"})
    data["agents"][0]["routes"].append("ticket.delayed")
    config = validate(data)
    initialize_state(config)
    IdentityStore(*StateLayout(config).identities).issue("agent", "agent-a", root / "agent.token")
    token = (root / "agent.token").read_text().strip()
    results = {}

    async def call(route, payload, request_id=None):
        return await guarded_request(config["paths"]["socket"], token, route, payload,
                                     request_id=request_id or new_request_id())

    def fill():
        with open(volume / "filler", "wb") as stream:
            try:
                while True:
                    stream.write(b"\\0" * 65536)
                    stream.flush()
            except OSError as error:
                return error.errno

    async def main():
        host = await GuardHost(config).start()
        try:
            comment = {"ticket": "INC-42", "comment": "before"}
            results["before"] = (await call("ticket.comment", comment))["status"]
            # A request already dispatched when the disk fills: its outcome cannot be recorded.
            delayed_id, delayed = new_request_id(), {"job": "in flight"}
            pending = asyncio.ensure_future(call("ticket.delayed", delayed, delayed_id))
            await asyncio.sleep(0.4)
            results["fill_errno"] = fill()
            results["in_flight_when_full"] = (await pending)["status"]
            results["in_flight_retry_while_full"] = (await call("ticket.delayed", delayed, delayed_id))["status"]
            full = [await call("ticket.comment", {"ticket": "INC-42", "comment": "full %d" % n}) for n in range(5)]
            results["while_full"] = sorted({r["status"] + ":" + r.get("reason", "") for r in full})
            results["lookup_while_full"] = (await call("crm.lookup", {"email": "jane@example.com", "note": "x"}))["status"]
            results["ready_while_full"] = host.ready()["ready"]
            retained_id = new_request_id()
            results["retry_id_while_full"] = (await call("ticket.comment", comment, retained_id))["status"]
            (volume / "filler").unlink()
            await asyncio.sleep(0.6)
            host.run_retention("settlement")
            results["after_free"] = (await call("ticket.comment", {"ticket": "INC-42", "comment": "after"}))["status"]
            results["retry_id_after_free"] = (await call("ticket.comment", comment, retained_id))["status"]
            results["in_flight_retry_after_free"] = (await call("ticket.delayed", delayed, delayed_id))["status"]
            principal = Principal("tenant-a", "support-bot", "agent-a", frozenset())
            name, _ = OutcomeLedger.binding(principal, delayed_id, "ticket.delayed", delayed)
            results["in_flight_ledger_state"] = host.components.outcomes.state(name)
            results["delayed_dispatches"] = sum(1 for _, _, e in host.components.audit.events()
                                                if e.get("route") == "ticket.delayed" and e.get("outcome") == "authorized")
            results["audit_verified"] = bool(host.components.audit.verify())
            results["ready_after_free"] = host.ready()["ready"]
            results["lost_events"] = host.status()["audit_event_failures"]
        finally:
            await host.stop()
        host = await GuardHost(config).start()
        try:
            results["after_restart"] = (await call("ticket.comment", {"ticket": "INC-42", "comment": "restart"}))["status"]
            results["in_flight_after_restart"] = (await call("ticket.delayed", delayed, delayed_id))["status"]
        finally:
            await host.stop()

    asyncio.run(main())
    print(json.dumps(results))
""")


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("unshare") and shutil.which("mount"),
                     "Linux user and mount namespaces")
class StateVolumeFullTests(unittest.TestCase):
    def test_full_tmpfs_state_volume_fails_closed_then_recovers(self):
        with tempfile.TemporaryDirectory(prefix="eg-enospc-") as temp:
            script = Path(temp) / "enospc.py"
            script.write_text(ENOSPC_SCRIPT)
            import enkstein_guard
            env = dict(os.environ, PYTHONPATH=os.pathsep.join(
                [str(Path(enkstein_guard.__file__).resolve().parent.parent), str(Path(__file__).resolve().parent)]))
            run = subprocess.run(["unshare", "-rm", sys.executable, str(script), str(Path(temp) / "run"),
                                  str(Path(__file__).resolve().parent)],
                                 capture_output=True, text=True, timeout=120, env=env)
            if run.returncode and "Operation not permitted" in run.stderr:
                self.skipTest("user namespaces unavailable")
            self.assertEqual(run.returncode, 0, run.stderr[-3000:])
            results = json.loads(run.stdout.strip().splitlines()[-1])
        self.assertEqual(results["before"], "ok")
        self.assertEqual(results["fill_errno"], 28)
        # Dispatched before the disk filled: unknown outcome, never replayed, never re-executed.
        self.assertEqual(results["in_flight_when_full"], "execution_or_audit_failed_outcome_unknown")
        self.assertEqual(results["in_flight_retry_while_full"], "outcome_unknown_no_replay")
        self.assertEqual(results["in_flight_retry_after_free"], "outcome_unknown_no_replay")
        self.assertEqual(results["in_flight_ledger_state"], "uncertain")
        self.assertEqual(results["delayed_dispatches"], 1)
        self.assertEqual(results["in_flight_after_restart"], "outcome_unknown_no_replay")
        # New work while full is refused before dispatch.
        self.assertTrue(set(results["while_full"]) <= {"request_tracking_unavailable_or_conflict:tracking_unavailable",
                                                        "unavailable_no_execution:audit_unavailable"}, results)
        self.assertIn(results["lookup_while_full"], ("request_tracking_unavailable_or_conflict", "unavailable_no_execution"))
        self.assertFalse(results["ready_while_full"])
        self.assertIn(results["retry_id_while_full"], ("request_tracking_unavailable_or_conflict", "unavailable_no_execution"))
        # Recovery without restart; an ID refused while full runs once afterwards.
        self.assertEqual(results["after_free"], "ok")
        self.assertEqual(results["retry_id_after_free"], "ok")
        self.assertTrue(results["audit_verified"])
        self.assertTrue(results["ready_after_free"])
        self.assertGreater(results["lost_events"], 0)  # best-effort service events lost while full are counted
        self.assertEqual(results["after_restart"], "ok")
