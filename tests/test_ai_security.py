import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

os.environ["ENKSTEIN_POLICY_PACK"] = "/nonexistent/guard-stage-tests"

from enkstein_guard.ai_security import AISecurityControl, action_digest
from enkstein_guard.contracts import (
    Action, ControlResult, SecurityContext, Status, combine_results,
)
from enkstein_guard.privacy import Tokenizer
from enkstein_guard.providers import BrokeredChatProvider
from enkstein_guard.runtime import Operation
from enkstein_guard.security_assessment import (
    AssessmentError, ChatSecurityAnalyzer, InspectionBoundaryError,
    SecurityAssessment,
)
from enkstein_guard.security_context import SecurityHistoryError, SecurityHistoryStore
from enkstein_guard.identities import SecretBroker, SecretStore
from enkstein_guard.vault import LocalVault, Scope


class Analyzer:
    def __init__(self, *, decision="allow", risk="low", confidence=0.95,
                 signals=(), error=None, fixed=None):
        self.decision = decision
        self.risk = risk
        self.confidence = confidence
        self.signals = signals
        self.error = error
        self.fixed = fixed
        self.calls = []

    async def analyze(self, operation, context, digest):
        self.calls.append((operation, context, digest))
        if self.error is not None:
            raise self.error
        if self.fixed is not None:
            return self.fixed
        return SecurityAssessment(1, digest, self.decision, self.risk,
                                  self.confidence, tuple(self.signals))


class FakeAssessment:
    schema_version = 1
    action_digest = "a" * 64
    decision = "allow"
    risk = "low"
    confidence = 1
    signals = ()


class AISecurityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-ai-security-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.vault = LocalVault.initialize(root / "vault/data.sqlite3",
                                           root / "vault/key.json")
        self.history = SecurityHistoryStore.initialize(
            root / "history/data.sqlite3", root / "history/key")
        self.tokenizer = Tokenizer(self.vault)

    def operation(self, *, payload=None, tenant="tenant-a", principal="operator",
                  agent="agent-a", workflow="workflow-a", operation_id="operation-a",
                  route="ticket.write", resource="support-ticket",
                  destination="internal-service", policy="policy-1"):
        payload = {} if payload is None else payload
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        context = SecurityContext(tenant, principal, agent, workflow, operation_id,
                                  "ticket.update", policy)
        return Operation(context, route, resource, destination, encoded,
                         hashlib.sha256(encoded.encode()).hexdigest())

    @staticmethod
    def inspector(target):
        context = SecurityContext(
            target.context.tenant_id, "guard-security", "guard-security",
            "security-inspection", target.context.operation_id + ":inspection",
            "security.assess", "security-policy-1")
        return Operation(context, "__internal.ai-security", "security-model",
                         "security-provider", "{}", hashlib.sha256(b"{}").hexdigest())

    def control(self, analyzer, *, failure_action="deny", name="ai_security.engine",
                context_for=None):
        return AISecurityControl(
            analyzer=analyzer, inspector_operation_for=self.inspector,
            tokenizer=self.tokenizer, history=self.history,
            context_for=context_for, confidence_threshold=0.7,
            failure_action=failure_action, name=name)

    async def test_raw_identity_payload_numeric_and_metadata_are_private(self):
        prior = self.operation(
            principal="person@example.test", operation_id="prior",
            route="history-person@example.test")
        prior_assessment = SecurityAssessment(
            1, "b" * 64, "deny", "medium", 0.9, ("tool_misuse",))
        self.history.record(prior, prior_assessment, Action.DENY)
        analyzer = Analyzer()
        target = self.operation(
            principal="person@example.test",
            route="route-person@example.test",
            resource="resource-person@example.test",
            policy="policy-person@example.test",
            payload={"email": "secret@example.test", "card": 4111111111111111})
        result = await self.control(analyzer)(target)
        self.assertEqual(result.action, Action.ALLOW)
        visible = json.dumps(analyzer.calls[0][1], sort_keys=True)
        for raw in ("person@example.test", "secret@example.test",
                    "4111111111111111", "route-person@example.test",
                    "resource-person@example.test", "history-person@example.test"):
            self.assertNotIn(raw, visible)
        self.assertIn("[[EGV:", visible)
        self.assertIn("actor_ref", analyzer.calls[0][1])
        self.assertNotIn("principal_id", analyzer.calls[0][1])
        self.assertEqual(analyzer.calls[0][0].context.tenant_id, target.context.tenant_id)

    async def test_payload_identity_assertions_cannot_override_trusted_binding(self):
        analyzer = Analyzer()
        operation = self.operation(payload={
            "tenant_id": "tenant-admin", "principal_id": "root",
            "agent_id": "agent-admin", "route": "admin.delete",
        })
        result = await self.control(analyzer)(operation)
        self.assertEqual(result.action, Action.ALLOW)
        context, digest = analyzer.calls[0][1], analyzer.calls[0][2]
        self.assertNotEqual(context["actor_ref"], "root")
        self.assertEqual(digest, action_digest(operation))

    async def test_prepared_reference_becomes_opaque_without_restore_or_payload_change(self):
        prepared_scope = Scope(
            "tenant-a", "host-session", "protected-chat", "prepared-operation")
        native = self.vault.put(
            "synthetic private value", prepared_scope, ("business-service",))
        unminted = "[[EGV:" + "f" * 64 + "]]"
        payload = {"message": f"Review {native} then compare {unminted} before sending"}
        operation = self.operation(payload=payload)
        original_json = operation.payload_json
        analyzer = Analyzer()
        with mock.patch.object(self.vault, "restore", wraps=self.vault.restore) as restore:
            result = await self.control(analyzer)(operation)
        self.assertEqual(result.action, Action.ALLOW)
        restore.assert_not_called()
        inspected = analyzer.calls[0][1]["target_payload"]["message"]
        self.assertIn("Review protected-reference:", inspected)
        self.assertIn("then compare protected-reference:", inspected)
        self.assertIn("before sending", inspected)
        self.assertNotIn(native, inspected)
        self.assertNotIn(unminted, inspected)
        self.assertNotIn("synthetic private value", json.dumps(analyzer.calls[0][1]))
        self.assertEqual(operation.payload_json, original_json)
        self.assertEqual(operation.payload(), payload)

    async def test_malformed_reference_prefix_denies_without_analysis_or_rewrite(self):
        payload = {"message": "Review [[EGV:not-a-native-reference]] before sending"}
        operation = self.operation(payload=payload)
        analyzer = Analyzer()
        with mock.patch.object(self.vault, "restore", wraps=self.vault.restore) as restore:
            result = await self.control(analyzer)(operation)
        self.assertEqual((result.action, result.status), (Action.DENY, Status.ERROR))
        self.assertEqual(analyzer.calls, [])
        restore.assert_not_called()
        self.assertEqual(operation.payload(), payload)

    async def test_distinct_internal_route_may_share_provider_destination(self):
        analyzer = Analyzer()
        operation = self.operation(destination="security-provider")
        result = await self.control(analyzer)(operation)
        self.assertEqual(result.action, Action.ALLOW)
        self.assertNotEqual(analyzer.calls[0][0].route, operation.route)

    async def test_real_broker_receives_original_trusted_internal_context(self):
        root = Path(self.temp.name)
        secrets = SecretStore.initialize(
            root / "secrets/data.sqlite3", root / "secrets/key")
        secrets.set(
            "security-api", "synthetic-provider-key", tenant="tenant-a",
            destination="api.example.com", routes=("__internal.ai-security",))
        provider = BrokeredChatProvider(
            endpoint="https://api.example.com/v1/chat/completions",
            allowed_hosts={"api.example.com"}, model="security-model",
            broker=SecretBroker(secrets), credential_name="security-api")
        captured = []

        class Response:
            status = 200

            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self, size):
                return self.body

        class Opener:
            def open(self, request, timeout):
                request_body = json.loads(request.data)
                user = json.loads(request_body["messages"][1]["content"])
                assessment = {
                    "schema_version": 1,
                    "action_digest": user["action_digest"],
                    "decision": "allow",
                    "risk": "low",
                    "confidence": 0.99,
                    "signals": [],
                }
                response = {"choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": json.dumps(assessment)},
                    "finish_reason": "stop",
                }]}
                captured.append((request, request_body))
                return Response(json.dumps(response).encode())

        provider._opener = Opener()

        def internal(target):
            context = SecurityContext(
                target.context.tenant_id, "guard-security", "guard-security",
                "security-inspection", target.context.operation_id,
                "security.assess", "security-policy-1")
            return Operation(
                context, "__internal.ai-security", "security-model",
                "api.example.com", "{}", hashlib.sha256(b"internal").hexdigest())

        control = AISecurityControl(
            analyzer=ChatSecurityAnalyzer(provider),
            inspector_operation_for=internal, tokenizer=self.tokenizer,
            history=self.history, name="ai_security.brokered")
        target = self.operation(
            principal="person@example.test", agent="sensitive-agent",
            workflow="sensitive-workflow",
            payload={"email": "private@example.test"})
        result = await control(target)
        self.assertEqual(result.action, Action.ALLOW)
        request, body = captured[0]
        serialized = json.dumps(body)
        for raw in ("person@example.test", "sensitive-agent",
                    "sensitive-workflow", "private@example.test",
                    "synthetic-provider-key"):
            self.assertNotIn(raw, serialized)
        self.assertIn("[[EGV:", serialized)
        self.assertEqual(request.get_header("Authorization"),
                         "Bearer synthetic-provider-key")

    async def test_operation_id_prevents_assessment_replay(self):
        one = self.operation(operation_id="operation-one")
        two = self.operation(operation_id="operation-two")
        self.assertNotEqual(action_digest(one), action_digest(two))
        stale = SecurityAssessment(1, action_digest(one), "allow", "low", 1, ())
        result = await self.control(Analyzer(fixed=stale))(two)
        self.assertEqual(result.action, Action.DENY)

    async def test_fake_and_malformed_assessment_use_explicit_fallback(self):
        operation = self.operation()
        fake = await self.control(Analyzer(fixed=FakeAssessment()),
                                  failure_action="require_approval")(operation)
        outage = await self.control(Analyzer(error=TimeoutError()),
                                    failure_action="require_approval")(operation)
        self.assertEqual(fake.action, Action.REQUIRE_APPROVAL)
        self.assertEqual(outage.action, Action.REQUIRE_APPROVAL)

    async def test_inspection_boundary_denial_cannot_become_approval_fallback(self):
        operation = self.operation()
        boundary = await self.control(
            Analyzer(error=InspectionBoundaryError()),
            failure_action="require_approval")(operation)
        ordinary = await self.control(
            Analyzer(error=AssessmentError()),
            failure_action="require_approval")(operation)
        self.assertEqual((boundary.action, boundary.status),
                         (Action.DENY, Status.ERROR))
        self.assertEqual((ordinary.action, ordinary.status),
                         (Action.REQUIRE_APPROVAL, Status.OK))

    async def test_low_confidence_high_critical_and_model_deny_restrictions(self):
        operation = self.operation()
        low = await self.control(
            Analyzer(confidence=0.2), failure_action="require_approval")(operation)
        high = await self.control(Analyzer(
            risk="high", signals=("tool_misuse",)))(self.operation(operation_id="high"))
        critical = await self.control(Analyzer(
            risk="critical", signals=("destructive_action",)))(
                self.operation(operation_id="critical"))
        denied = await self.control(Analyzer(
            decision="deny", risk="low"))(self.operation(operation_id="deny"))
        self.assertEqual(low.action, Action.REQUIRE_APPROVAL)
        self.assertEqual(high.action, Action.REQUIRE_APPROVAL)
        self.assertEqual(critical.action, Action.DENY)
        self.assertEqual(denied.action, Action.DENY)

    async def test_vault_and_history_failure_always_deny(self):
        operation = self.operation()
        with mock.patch.object(self.history, "recent",
                               side_effect=SecurityHistoryError("synthetic")):
            history = await self.control(
                Analyzer(), failure_action="require_approval")(operation)
        with mock.patch.object(self.tokenizer, "tokenize", side_effect=RuntimeError("synthetic")):
            vault = await self.control(
                Analyzer(), failure_action="require_approval")(operation)
        self.assertEqual((history.action, history.status), (Action.DENY, Status.ERROR))
        self.assertEqual((vault.action, vault.status), (Action.DENY, Status.ERROR))

    async def test_history_write_failure_denies_before_returning_allow(self):
        operation = self.operation()
        with mock.patch.object(self.history, "record",
                               side_effect=SecurityHistoryError("synthetic")):
            result = await self.control(Analyzer())(operation)
        self.assertEqual((result.action, result.status), (Action.DENY, Status.ERROR))

    async def test_repeated_prior_denials_escalate_and_record_signal(self):
        operation = self.operation()
        for index in range(3):
            assessment = SecurityAssessment(
                1, f"{index:064x}", "deny", "medium", 0.9, ("tool_misuse",))
            self.history.record(
                self.operation(operation_id=f"prior-{index}"), assessment, Action.DENY)
        result = await self.control(Analyzer())(operation)
        self.assertEqual(result.action, Action.REQUIRE_APPROVAL)
        latest = self.history.recent(operation, limit=1)[0]
        self.assertIn("suspicious_sequence", latest.signals)

    async def test_deterministic_deny_remains_authoritative_in_combination(self):
        operation = self.operation()
        ai = await self.control(Analyzer(), name="ai_security.engine")(operation)
        deterministic = ControlResult(
            "policy", operation.context.tenant_id,
            operation.context.operation_id, Action.DENY)
        combined = combine_results(
            operation.context, (ai, deterministic),
            required_controls=("ai_security.engine", "policy"))
        self.assertEqual(combined.action, Action.DENY)

    async def test_invalid_inspector_or_sensitivity_context_fails_closed(self):
        operation = self.operation()
        same_route = lambda target: Operation(
            target.context, target.route, "model", "provider", "{}", target.digest)
        invalid_inspector = AISecurityControl(
            analyzer=Analyzer(), inspector_operation_for=same_route,
            tokenizer=self.tokenizer, history=self.history)
        invalid_context = self.control(
            Analyzer(), context_for=lambda target: {"level": "secret-prose"})
        self.assertEqual((await invalid_inspector(operation)).action, Action.DENY)
        self.assertEqual((await invalid_context(operation)).action, Action.DENY)


if __name__ == "__main__":
    unittest.main()
