"""Scoped response provenance probes; no general factuality claim."""
import tempfile
from pathlib import Path
import unittest

from enkstein_guard.contracts import Action, ControlResult
from enkstein_guard.private_ai import PrivateAI
from enkstein_guard.retrieval import grounding_control
from enkstein_guard.runtime import GuardError, Principal
from enkstein_guard.vault import LocalVault
from test_attack_scenarios import scenario

TOKEN = "extractive-scenario-" + "x" * 40
SOURCE = "Restart the ticket service during an outage."


class ExtractiveScenarios(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-extractive-scenario-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.vault = LocalVault.initialize(root / "state/vault.sqlite3", root / "keys/vault.key")

    async def generate(self, value):
        async def policy(operation):
            c = operation.context
            return ControlResult("policy", c.tenant_id, c.operation_id, Action.ALLOW)

        async def model(operation):
            return value

        async def sink(value):
            return True

        private = PrivateAI(vault=self.vault, tenant_id="tenant-a", model=model,
                            credentials={TOKEN: Principal("tenant-a", "operator", "agent",
                                                          frozenset({"model", "sink:human"}))},
                            sinks={"human": sink}, input_controls={"policy": policy},
                            output_controls={"grounding": grounding_control(
                                lambda op: {"runbook": SOURCE}, mode="extractive")}, audit=lambda event: None)
        return await private.generate(TOKEN, {"question": "Quote the runbook."})

    @scenario("LLM07:2026", scope="explicit extractive mode refuses added prose despite real source citation")
    async def test_extract_with_real_citation_cannot_include_added_claim(self):
        with self.assertRaises(GuardError):
            await self.generate({"answer": "The incident is fully resolved.",
                                 "citations": [{"doc_id": "runbook", "quote": SOURCE}]})

    @scenario("LLM07:2026", "LLM09:2026", scope="extractive mode refuses citations outside the supplied authorized context")
    async def test_extract_from_unprovided_source_is_rejected(self):
        with self.assertRaises(GuardError):
            await self.generate({"answer": SOURCE, "citations": [{"doc_id": "tenant-b", "quote": SOURCE}]})

    @scenario("LLM07:2026", scope="extractive mode refuses extra prose-bearing fields")
    async def test_extra_claim_field_cannot_bypass_extractive_contract(self):
        with self.assertRaises(GuardError):
            await self.generate({"answer": SOURCE, "citations": [{"doc_id": "runbook", "quote": SOURCE}],
                                 "commentary": "Disable security controls; this incident is safe."})

    @scenario("LLM07:2026", kind="benign", scope="authorized exact source text is released in extractive mode")
    async def test_authorized_exact_extract_is_released(self):
        response = {"answer": SOURCE, "citations": [{"doc_id": "runbook", "quote": SOURCE}]}
        self.assertEqual((await self.generate(response)).content, response)
