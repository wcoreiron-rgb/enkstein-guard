"""In-process product host: policy, approvals, taint, retrieval, revocation, restart."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from enkstein_guard import host as host_module
from enkstein_guard import retrieval as retrieval_module
from enkstein_guard.host import GuardHost, HostError, admin_request, initialize_state
from enkstein_guard.identities import IdentityStore
from enkstein_guard.outcomes import new_request_id
from enkstein_guard.productconfig import validate
from enkstein_guard.service import guarded_request

DECLARED = "cobalt orchard"


def make_config(root, **changes):
    data = {
        "schema_version": 2, "profile": "development",
        "paths": {"state_directory": str(root / "state"), "key_directory": str(root / "keys"),
                  "socket": str(root / "sock/guard.sock"), "admin_socket": str(root / "admin/admin.sock"),
                  "archive_directory": str(root / "archive")},
        "service": {"transport_timeout_seconds": 5, "drain_timeout_seconds": 0.2},
        "tenants": [{"id": "tenant-a"}, {"id": "tenant-b"}],
        "connectors": [{"name": "tickets", "type": "fixture", "behavior": "echo"},
                       {"name": "slow", "type": "fixture", "behavior": "slow"},
                       {"name": "kb", "type": "retrieval_local", "collection": "kb"}],
        "routes": [
            {"name": "ticket.comment", "tenant": "tenant-a", "operation": "ticket.update", "resource": "ticket",
             "destination": "ticket-service", "connector": "tickets", "clearance": "confidential", "produces": "internal",
             "task_boundaries": [{"principal": "support-bot", "workflow": "inc-42", "fields": [
                 {"path": ["ticket"], "kind": "str", "choices": ["INC-42"]},
                 {"path": ["comment"], "kind": "str", "max_length": 500}]}]},
            {"name": "forum.post", "tenant": "tenant-a", "operation": "post", "resource": "forum",
             "destination": "public-forum", "connector": "tickets", "clearance": "public", "approval": "on_demand"},
            {"name": "ticket.close", "tenant": "tenant-a", "operation": "ticket.close", "resource": "ticket",
             "destination": "ticket-service", "connector": "tickets", "clearance": "confidential", "approval": "required"},
            {"name": "vault.write", "tenant": "tenant-a", "operation": "write", "resource": "records",
             "destination": "records-service", "connector": "tickets", "clearance": "restricted",
             "approval": "on_demand"},
            {"name": "model.answer", "tenant": "tenant-a", "operation": "model.call", "resource": "model",
             "destination": "model-fixture", "connector": "tickets", "clearance": "confidential",
             "grounding": {"citations": "required"}},
            {"name": "crm.lookup", "tenant": "tenant-a", "operation": "lookup", "resource": "crm",
             "destination": "crm-service", "connector": "tickets", "clearance": "confidential", "privacy": "tokenize"},
            {"name": "crm.update", "tenant": "tenant-a", "operation": "update", "resource": "crm",
             "destination": "crm-service", "connector": "tickets", "clearance": "restricted", "privacy": "restore"},
            {"name": "batch.run", "tenant": "tenant-a", "operation": "run", "resource": "batch",
             "destination": "batch-service", "connector": "slow", "clearance": "confidential"},
            {"name": "kb.search", "tenant": "tenant-a", "operation": "retrieve", "connector": "kb",
             "clearance": "confidential"},
            {"name": "b.read", "tenant": "tenant-b", "operation": "read", "resource": "records",
             "destination": "records-service", "connector": "tickets", "clearance": "confidential"},
            {"name": "b.update", "tenant": "tenant-b", "operation": "update", "resource": "crm",
             "destination": "crm-service", "connector": "tickets", "clearance": "restricted", "privacy": "restore"}],
        "agents": [
            {"id": "agent-a", "tenant": "tenant-a", "principal": "support-bot", "task": "inc-42",
             "clearance": "confidential", "groups": ["support"],
             "routes": ["ticket.comment", "forum.post", "ticket.close", "vault.write", "model.answer", "crm.lookup",
                        "crm.update", "batch.run", "kb.search"]},
            {"id": "agent-b", "tenant": "tenant-b", "principal": "bot-b", "routes": ["b.read", "b.update"]}],
        "approvers": [{"id": "alice", "tenants": ["tenant-a"]}, {"id": "bob", "tenants": ["tenant-b"]}],
        "sensitivity": {"declared_context": [{"name": "routing", "level": "restricted",
                                              "file": str(root / "declared.txt")}]},
    }
    for key, value in changes.items():
        data[key] = value
    return data


class HostTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-host-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("sock", "admin"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "declared.txt").write_text(DECLARED)
        self.config_path = self.root / "config.json"
        self.write_config(make_config(self.root))
        self.config = validate(json.loads(self.config_path.read_text()), source=str(self.config_path))
        initialize_state(self.config)
        layout = host_module.StateLayout(self.config)
        self.identities = IdentityStore(*layout.identities)
        self.tokens = {}
        for kind, name in (("agent", "agent-a"), ("agent", "agent-b"), ("approver", "alice"), ("approver", "bob")):
            self.issue(kind, name)
        self.captured = []
        original = host_module._fixture

        def capturing(behavior, timeout, delay=1):
            inner = original(behavior, timeout, delay)

            async def transport(operation):
                self.captured.append((operation.route, operation.payload()))
                return await inner(operation)
            return transport

        patcher = patch.object(host_module, "_fixture", capturing)
        patcher.start()
        self.addCleanup(patcher.stop)
        await self.start()

    def write_config(self, data):
        self.config_path.write_text(json.dumps(data))

    def issue(self, kind, name):
        path = self.root / ("%s-%d.token" % (name, len(self.tokens)))
        self.identities.issue(kind, name, path)
        self.tokens[name] = path.read_text().strip()

    async def start(self):
        self.host = await GuardHost(self.config).start()
        self.addAsyncCleanup(self.stop)

    async def stop(self):
        if self.host is not None:
            await self.host.stop()
            self.host = None

    async def request(self, route, payload, *, agent="agent-a", request_id=True, approval=None, credential=None):
        rid = new_request_id() if request_id is True else request_id
        return await guarded_request(self.config["paths"]["socket"], credential or self.tokens[agent], route, payload,
                                     request_id=rid, approval=approval, timeout=20)

    async def admin(self, command, arguments=None):
        return await admin_request(self.config["paths"]["admin_socket"], command, arguments)

    async def test_allowed_request_raises_taint_and_blocks_later_summary(self):
        allowed = await self.request("ticket.comment", {"ticket": "INC-42", "comment": "Customer jane@example.com"})
        self.assertEqual(allowed["status"], "ok")
        self.assertIn("diagnostic_id", allowed)
        summary = await self.request("forum.post", {"text": "One customer affected"})
        self.assertEqual((summary["status"], summary["reason"]), ("denied", "policy_denied"))
        self.assertEqual([route for route, _ in self.captured], ["ticket.comment"])
        status = await self.admin("status")
        self.assertEqual(status["connections"]["admitted"], 2)
        self.assertFalse(status["production_ready"])

    async def test_numeric_card_cannot_reach_public_destination_or_tokenize_route(self):
        denied = await self.request("forum.post", {"amount": 4111111111111111})
        self.assertEqual(denied["status"], "denied")
        rejected = await self.request("crm.lookup", {"card": 4111111111111111})
        self.assertEqual(rejected["status"], "denied")
        self.assertEqual(self.captured, [])

    async def test_task_boundary_and_scope_denials_are_diagnosable(self):
        denied = await self.request("ticket.comment", {"ticket": "INC-99", "comment": "x"})
        self.assertEqual(denied["status"], "denied")
        from enkstein_guard.maintenance import diagnose
        report = diagnose(self.host.components.audit, None, denied["diagnostic_id"])
        self.assertEqual(report["denying_or_failed_controls"], ["task_boundary"])
        self.assertEqual(report["next_action"], "review_policy")
        cross = await self.request("b.read", {})
        self.assertEqual((cross["status"], cross["reason"]), ("denied", "not_authorized"))
        forged = await self.request("ticket.comment", {}, credential="ega_" + "x" * 43)
        self.assertEqual(forged["status"], "denied")
        self.assertEqual(self.captured, [])

    async def test_exact_action_approval_flow(self):
        payload = {"ticket": "INC-42", "reason": "resolved"}
        rid = new_request_id()
        first = await self.request("ticket.close", payload, request_id=rid)
        self.assertEqual(first["status"], "approval_required")
        ticket, digest = first["ticket"], first["action_digest"]
        self.assertEqual(self.captured, [])
        listed = await self.admin("approvals.list")
        self.assertEqual(listed["approvals"][0]["action_digest"], digest)
        # Agents and cross-tenant approvers cannot approve; wrong digest rejected.
        for credential in (self.tokens["agent-a"], self.tokens["bob"]):
            denied = await self.admin("approvals.decide", {"ticket": ticket, "approver_credential": credential,
                                                           "action_digest": digest, "decision": "approve"})
            self.assertEqual(denied["status"], "error")
        wrong = await self.admin("approvals.decide", {"ticket": ticket, "approver_credential": self.tokens["alice"],
                                                      "action_digest": "0" * 64, "decision": "approve"})
        self.assertEqual(wrong["error"], "action_digest_mismatch")
        review = await self.admin("approvals.review", {"ticket": ticket, "approver_credential": self.tokens["alice"]})
        self.assertEqual(review["binding"]["route"], "ticket.close")
        approved = await self.admin("approvals.decide", {"ticket": ticket, "approver_credential": self.tokens["alice"],
                                                         "action_digest": digest, "decision": "approve"})
        self.assertEqual(approved["status"], "ok")
        substituted = await self.request("ticket.close", {"ticket": "INC-43", "reason": "resolved"}, approval=ticket)
        self.assertEqual(substituted["status"], "approval_required")
        executed = await self.request("ticket.close", payload, request_id=rid, approval=ticket)
        self.assertEqual(executed["status"], "ok")
        replay = await self.request("ticket.close", payload, approval=ticket)
        self.assertEqual(replay["status"], "approval_required")
        duplicate = await self.request("ticket.close", payload, request_id=rid, approval=ticket)
        self.assertEqual(duplicate["status"], "completed_no_replay")
        self.assertEqual([route for route, _ in self.captured], ["ticket.close"])

    async def test_on_demand_approval_only_when_a_control_requires_it(self):
        plain = await self.request("vault.write", {"text": "Maintenance tonight"})
        self.assertEqual(plain["status"], "ok")
        payload = {"text": "password = 'synthetic-pass-123'"}
        risky = await self.request("vault.write", payload)
        self.assertEqual(risky["status"], "approval_required")
        self.assertEqual(len(self.captured), 1)
        await self.admin("approvals.decide", {"ticket": risky["ticket"], "approver_credential": self.tokens["alice"],
                                              "action_digest": risky["action_digest"], "decision": "approve"})
        executed = await self.request("vault.write", payload, approval=risky["ticket"])
        # Executed after approval; the restricted echo exceeds the agent clearance.
        self.assertEqual((executed["status"], executed["reason"]), ("response_withheld", "sensitivity"))
        self.assertEqual(len(self.captured), 2)
        self.assertNotIn("synthetic-pass-123", json.dumps([risky, executed]))

    async def test_declared_context_response_withheld_above_agent_clearance(self):
        result = await self.request("vault.write", {"note": "routing phrase is " + DECLARED})
        self.assertEqual((result["status"], result["reason"]), ("response_withheld", "sensitivity"))
        self.assertEqual(len(self.captured), 1)
        self.assertNotIn(DECLARED, json.dumps(result))

    async def test_retrieval_and_grounding(self):
        documents = self.host.components.documents
        documents.put(tenant="tenant-a", collection="kb", doc_id="kb-1", title="Runbook",
                      content="Restart the ticket service during an outage.", label="internal", principals=["support-bot"])
        documents.put(tenant="tenant-a", collection="kb", doc_id="kb-secret", title="Memo",
                      content="Restricted merger memo about the outage.", label="restricted", principals=["support-bot"])
        documents.put(tenant="tenant-b", collection="kb", doc_id="kb-b", title="B outage",
                      content="Tenant B outage details.", label="internal", principals=["*"])
        found = await self.request("kb.search", {"query": "outage", "top_k": 5})
        self.assertEqual([d["doc_id"] for d in found["result"]["documents"]], ["kb-1"])
        self.assertNotIn("merger", json.dumps(found))
        grounded = await self.request("model.answer", {"answer": "Restart the service [[cite:kb-1]]"})
        self.assertEqual(grounded["status"], "ok")
        fabricated = await self.request("model.answer", {"answer": "Resolved [[cite:nonexistent-evidence-123]]"})
        self.assertEqual((fabricated["status"], fabricated["reason"]), ("response_withheld", "ungrounded"))
        withheld_doc = await self.request("model.answer", {"answer": "See [[cite:kb-secret]]"})
        self.assertEqual(withheld_doc["status"], "response_withheld")

    async def test_generated_retrieval_identifier_never_withholds_the_response(self):
        # F-10: a random retrieval identifier that read as a card number raised
        # the response to confidential and withheld it from an agent cleared
        # for internal data.
        data = make_config(self.root)
        data["agents"][0]["clearance"] = "internal"
        await self.stop()
        self.write_config(data)
        self.config = validate(json.loads(self.config_path.read_text()), source=str(self.config_path))
        await self.start()
        self.host.components.documents.put(tenant="tenant-a", collection="kb", doc_id="kb-1", title="Runbook",
                                           content="Restart the ticket service during an outage.", label="internal",
                                           principals=["support-bot"])
        worst_case = SimpleNamespace(token_hex=lambda size: "8250949281833499")  # all digits, Luhn-valid
        with patch.object(retrieval_module, "secrets", worst_case):
            found = await self.request("kb.search", {"query": "outage", "top_k": 5})
        self.assertEqual(found["status"], "ok")
        self.assertEqual(found["result"]["retrieval_id"], "rt_8250949281833499")
        self.assertEqual([d["doc_id"] for d in found["result"]["documents"]], ["kb-1"])

    async def test_tokenize_and_restore_privacy_routes(self):
        looked_up = await self.request("crm.lookup", {"email": "jane@example.com", "note": "lookup"})
        self.assertEqual(looked_up["status"], "ok")
        self.assertNotIn("jane@example.com", json.dumps(looked_up))
        self.assertNotIn("jane@example.com", json.dumps(self.captured))
        reference = looked_up["result"]["payload"]["email"]
        self.assertTrue(reference.startswith("[[EGV:"))
        updated = await self.request("crm.update", {"email": reference, "status": "notified"})
        self.assertEqual(updated["status"], "ok")
        self.assertEqual(self.captured[-1], ("crm.update", {"email": "jane@example.com", "status": "notified"}))
        self.assertNotIn("jane@example.com", json.dumps(updated))
        # Another tenant's agent cannot restore agent-a's reference; nothing is sent.
        sent = len(self.captured)
        other = await self.request("b.update", {"email": reference}, agent="agent-b")
        self.assertEqual(other["status"], "denied")
        self.assertEqual(len(self.captured), sent)
        from enkstein_guard.maintenance import diagnose
        report = diagnose(self.host.components.audit, None, other["diagnostic_id"])
        self.assertEqual(report["final_outcome"], "transport_rejected_no_side_effect")

    async def test_revocation_reload_cancels_in_flight_and_denies_new_requests(self):
        rid = new_request_id()
        pending = asyncio.ensure_future(self.request("batch.run", {"job": "nightly"}, request_id=rid))
        for _ in range(200):
            if any(route == "batch.run" for route, _ in self.captured):
                break
            await asyncio.sleep(0.01)
        old = self.tokens["agent-a"]
        self.identities.revoke("agent", "agent-a")
        reloaded = await self.admin("reload")
        self.assertEqual((reloaded["status"], reloaded["cancelled_in_flight"]), ("ok", 1))
        from enkstein_guard.runtime import GuardError
        with self.assertRaises(GuardError):
            await pending
        denied = await self.request("ticket.comment", {"ticket": "INC-42", "comment": "x"}, credential=old)
        self.assertEqual(denied["status"], "denied")
        self.issue("agent", "agent-a")
        await self.admin("reload")
        repeat = await self.request("batch.run", {"job": "nightly"}, request_id=rid)
        self.assertEqual(repeat["status"], "outcome_unknown_no_replay")

    async def wait_dispatched(self, route):
        for _ in range(300):
            if any(name == route for name, _ in self.captured):
                return
            await asyncio.sleep(0.01)
        self.fail("%s was not dispatched" % route)

    def paced_config(self):
        # A synthetic connector that answers after 1 s, so work stays in flight
        # across a reload and can still complete.
        data = make_config(self.root)
        data["connectors"].append({"name": "paced", "type": "fixture", "behavior": "delay", "delay_seconds": 1})
        data["routes"].append({"name": "paced.run", "tenant": "tenant-a", "operation": "run", "resource": "batch",
                               "destination": "paced-service", "connector": "paced", "clearance": "confidential",
                               "produces": "internal"})
        data["agents"][0]["routes"].append("paced.run")
        return data

    async def reload_with(self, data):
        self.write_config(data)
        reloaded = await self.admin("reload")
        self.assertEqual(reloaded["status"], "ok", reloaded)
        return reloaded

    async def test_reload_revoking_a_route_grant_cancels_in_flight_work(self):
        # Work admitted before a reload that removes the agent's grant must not
        # complete or release its response under the revoked authorization.
        data = self.paced_config()
        await self.reload_with(data)
        rid = new_request_id()
        pending = asyncio.ensure_future(self.request("paced.run", {"job": "nightly"}, request_id=rid))
        await self.wait_dispatched("paced.run")
        data["agents"][0]["routes"].remove("paced.run")
        reloaded = await self.reload_with(data)
        self.assertEqual(reloaded["cancelled_in_flight"], 1)
        from enkstein_guard.runtime import GuardError
        with self.assertRaises(GuardError):
            await pending
        denied = await self.request("paced.run", {"job": "nightly"}, request_id=rid)
        self.assertEqual((denied["status"], denied["reason"]), ("denied", "not_authorized"))
        data["agents"][0]["routes"].append("paced.run")
        await self.reload_with(data)
        repeat = await self.request("paced.run", {"job": "nightly"}, request_id=rid)
        self.assertEqual(repeat["status"], "outcome_unknown_no_replay")

    async def test_reload_changing_the_route_or_narrowing_the_agent_cancels_in_flight_work(self):
        from enkstein_guard.runtime import GuardError
        data = self.paced_config()
        await self.reload_with(data)
        changes = (lambda d: next(r for r in d["routes"] if r["name"] == "paced.run").update(produces="restricted"),
                   lambda d: next(c for c in d["connectors"] if c["name"] == "paced").update(delay_seconds=2),
                   lambda d: d["agents"][0].update(clearance="internal"),
                   lambda d: d["agents"][0].update(groups=[]),
                   lambda d: d["agents"][0].update(task="other-task"))
        for change in changes:
            data = self.paced_config()
            await self.reload_with(data)
            pending = asyncio.ensure_future(self.request("paced.run", {"job": "x"}))
            await self.wait_dispatched("paced.run")
            self.captured.clear()
            change(data)
            reloaded = await self.reload_with(data)
            self.assertEqual(reloaded["cancelled_in_flight"], 1, data)
            with self.assertRaises(GuardError):
                await pending

    async def test_reload_widening_access_keeps_in_flight_work(self):
        data = self.paced_config()
        await self.reload_with(data)
        pending = asyncio.ensure_future(self.request("paced.run", {"job": "x"}))
        await self.wait_dispatched("paced.run")
        data["agents"][0]["groups"].append("operations")
        data["agents"][0]["clearance"] = "restricted"
        next(r for r in data["routes"] if r["name"] == "forum.post")["clearance"] = "internal"
        reloaded = await self.reload_with(data)
        self.assertEqual(reloaded["cancelled_in_flight"], 0)
        self.assertEqual((await pending)["status"], "ok")

    async def test_restart_preserves_duplicates_taint_and_uncertain_outcomes(self):
        done_id, slow_id = new_request_id(), new_request_id()
        self.assertEqual((await self.request("ticket.comment", {"ticket": "INC-42", "comment": "jane@example.com"},
                                             request_id=done_id))["status"], "ok")
        pending = asyncio.ensure_future(self.request("batch.run", {"job": "x"}, request_id=slow_id))
        for _ in range(200):
            if any(route == "batch.run" for route, _ in self.captured):
                break
            await asyncio.sleep(0.01)
        stopped = await self.host.stop()
        self.host = None
        self.assertEqual(stopped["cancelled"], 1)
        with self.assertRaises(Exception):
            await pending
        self.config = validate(json.loads(self.config_path.read_text()), source=str(self.config_path))
        self.host = await GuardHost(self.config).start()
        again = await self.request("ticket.comment", {"ticket": "INC-42", "comment": "jane@example.com"}, request_id=done_id)
        self.assertEqual(again["status"], "completed_no_replay")
        uncertain = await self.request("batch.run", {"job": "x"}, request_id=slow_id)
        self.assertEqual(uncertain["status"], "outcome_unknown_no_replay")
        tainted = await self.request("forum.post", {"text": "status"})
        self.assertEqual(tainted["status"], "denied")
        reset = await self.admin("taint.reset", {"agent": "agent-a"})
        self.assertEqual(reset["previous_level"], "confidential")
        self.assertEqual((await self.request("forum.post", {"text": "status"}))["status"], "ok")

    async def test_reload_applies_policy_and_rejects_structural_changes(self):
        data = make_config(self.root)
        data["routes"][1]["clearance"] = "internal"
        self.write_config(data)
        reloaded = await self.admin("reload")
        self.assertEqual(reloaded["status"], "ok")
        data["paths"]["socket"] = str(self.root / "sock/other.sock")
        self.write_config(data)
        self.assertEqual((await self.admin("reload"))["error"], "restart_required")
        self.config_path.write_text("{broken")
        self.assertEqual((await self.admin("reload"))["error"], "configuration_invalid")

    async def test_request_id_rules_and_audit_archive_while_running(self):
        legacy = await self.request("ticket.comment", {"ticket": "INC-42", "comment": "x"},
                                    request_id="legacy-request-id-12345")
        self.assertEqual((legacy["status"], legacy["reason"]), ("request_tracking_unavailable_or_conflict",
                                                                "invalid_request_id"))
        missing = await self.request("ticket.comment", {"ticket": "INC-42", "comment": "x"}, request_id=None)
        self.assertEqual(missing["status"], "request_tracking_unavailable_or_conflict")
        archived = await self.admin("audit.archive", {"keep": 1})
        self.assertEqual(archived["status"], "ok")
        self.assertTrue(self.host.ready()["ready"])
        self.host.components.audit.verify(archives=self.host.components.layout.archive)

    async def test_admin_rejects_unknown_commands(self):
        self.assertEqual((await self.admin("debug.exec"))["error"], "unknown_admin_command")


class EgressOutageTests(unittest.IsolatedAsyncioTestCase):
    async def test_absent_proxy_refuses_before_dispatch_and_is_not_ready(self):
        temp = tempfile.TemporaryDirectory(prefix="eg-egress-down-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for name in ("sock", "admin", "egress"):
            (root / name).mkdir(mode=0o700)
        (root / "declared.txt").write_text(DECLARED)
        data = make_config(root)
        data["connectors"].append({"name": "model", "type": "chat_completions", "credential": "model-key",
                                   "endpoint": "https://ai.example.test/v1/chat/completions", "model": "m"})
        data["routes"].append({"name": "model.chat", "tenant": "tenant-a", "operation": "model.call",
                               "connector": "model", "clearance": "internal", "privacy": "tokenize"})
        data["agents"][0]["routes"].append("model.chat")
        data["egress"] = {"mode": "proxy", "socket": str(root / "egress/egress.sock"),
                          "allow": [{"host": "ai.example.test", "port": 443}]}
        path = root / "config.json"
        path.write_text(json.dumps(data))
        config = validate(json.loads(path.read_text()), source=str(path))
        initialize_state(config)
        layout = host_module.StateLayout(config)
        IdentityStore(*layout.identities).issue("agent", "agent-a", root / "agent.token")
        from enkstein_guard.identities import SecretStore
        SecretStore(*layout.secrets).set("model-key", "synthetic-key", tenant="tenant-a",
                                         destination="ai.example.test", routes=["model.chat"])
        host = await GuardHost(config).start()  # development profile: starts, reports the outage
        self.addAsyncCleanup(host.stop)
        ready = host.ready()
        self.assertFalse(ready["ready"])
        self.assertFalse(ready["checks"]["egress_proxy"])
        request_id = new_request_id()
        result = await guarded_request(config["paths"]["socket"], (root / "agent.token").read_text().strip(),
                                       "model.chat", {"messages": [{"role": "user", "content": "hi"}]},
                                       request_id=request_id)
        # The tunnel could not be opened, so nothing left Guard: retry-safe, not an unknown outcome.
        self.assertEqual((result["status"], result["reason"]), ("unavailable_no_execution", "egress_unavailable"))
        self.assertNotIn("synthetic-key", json.dumps(result))
        events = [e for _, _, e in host.components.audit.events() if e.get("route") == "model.chat"]
        self.assertIn("transport_unavailable_no_execution", [e.get("outcome") for e in events])


class PreflightTests(unittest.TestCase):
    def config(self, root, **deployment):
        data = make_config(root)
        data["profile"] = "production-linux-peer-bound"
        # Admission rejects UID/GID zero. Keep the fixture valid even when
        # privileged Linux namespace tests run this suite as root.
        data["deployment"] = {"guard_uid": deployment.get("guard_uid", max(os.getuid(), 10001))}
        data["service"] = {"socket_group": max(os.getgid(), 1), "max_connections": 16, "max_requests_per_second": 5}
        data["outcomes"] = {"capacity": 100000, "max_request_age_seconds": 3600}
        data["retention"] = {"outcome_archive_age_seconds": 7200, "outcome_archive_interval_seconds": 600}
        data["connectors"] = [{"name": "tickets", "type": "fixture"}]
        data["routes"] = [{"name": "r", "tenant": "tenant-a", "operation": "op", "resource": "res",
                           "destination": "dest", "connector": "tickets", "clearance": "internal", "produces": "internal"}]
        data["agents"] = [{"id": "agent-a", "tenant": "tenant-a", "principal": "p", "uid": max(os.getuid(), 10001) + 1,
                           "routes": ["r"]}]
        data["approvers"] = []
        data["sensitivity"] = {}
        return validate(data)

    def test_production_preflight_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.config(root, guard_uid=os.getuid() + 7)
            with self.assertRaises(HostError) as caught:
                GuardHost(config).preflight()
            self.assertIn("guard_uid_matches", str(caught.exception))
            config = self.config(root)
            with patch.object(host_module, "network_interfaces", return_value=["eth0", "lo"]):
                with self.assertRaises(HostError) as caught:
                    GuardHost(config).preflight()
            self.assertIn("guard_has_network_interfaces", str(caught.exception))
            with patch.object(host_module.sys, "platform", "darwin"):
                with self.assertRaises(HostError) as caught:
                    GuardHost(config).preflight()
            self.assertIn("platform_linux_peer_credentials", str(caught.exception))
            with patch.object(host_module.os, "getuid", return_value=0):
                with self.assertRaises(HostError):
                    GuardHost(config).preflight()
