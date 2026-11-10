"""End-to-end product-host coverage for strict source-extractive grounding."""

import asyncio
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from enkstein_guard import host as host_module
from enkstein_guard.host import GuardHost, StateLayout, admin_request, initialize_state
from enkstein_guard.identities import IdentityStore, SecretStore
from enkstein_guard.outcomes import new_request_id
from enkstein_guard.productconfig import ConfigError, validate
from enkstein_guard.providers import BrokeredChatProvider
from enkstein_guard.runtime import GuardError
from enkstein_guard.service import guarded_request
from test_host import DECLARED, make_config


def route(data, name):
    return next(item for item in data["routes"] if item["name"] == name)


def extractive_config(root):
    data = make_config(root)
    route(data, "model.answer")["grounding"] = {"citations": "required", "mode": "extractive"}
    data["connectors"].append({
        "name": "chat",
        "type": "chat_completions",
        "endpoint": "https://ai.example.test/v1/chat/completions",
        "model": "model-a",
        "credential": "model-key",
    })
    data["routes"].append({
        "name": "model.chat",
        "tenant": "tenant-a",
        "operation": "model.call",
        "connector": "chat",
        "clearance": "confidential",
        "produces": "internal",
        "grounding": {"citations": "required", "mode": "extractive"},
    })
    data["agents"][0]["routes"].append("model.chat")
    data["egress"] = {
        "mode": "direct_development_only",
        "allow": [{"host": "ai.example.test", "port": 443}],
    }
    return data


class ExtractiveGroundingConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-extractive-config-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_invalid_mode_and_optional_extractive_configuration_are_rejected(self):
        invalid_mode = make_config(self.root)
        route(invalid_mode, "model.answer")["grounding"] = {
            "citations": "required", "mode": "semantic"
        }
        with self.assertRaises(ConfigError) as invalid:
            validate(invalid_mode)
        self.assertIn(
            {"path": "$.routes[4].grounding.mode", "code": "unsupported_value"},
            invalid.exception.errors,
        )

        optional = make_config(self.root)
        route(optional, "model.answer")["grounding"] = {
            "citations": "optional", "mode": "extractive"
        }
        with self.assertRaises(ConfigError) as invalid:
            validate(optional)
        self.assertIn(
            {"path": "$.routes[4].grounding.citations", "code": "extractive_requires_citations"},
            invalid.exception.errors,
        )


class ExtractiveGroundingHostTests(unittest.IsolatedAsyncioTestCase):
    QUOTE = "Restart the ticket service during an outage."

    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-extractive-host-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("sock", "admin"):
            (self.root / name).mkdir(mode=0o700)
        (self.root / "declared.txt").write_text(DECLARED)
        self.config_path = self.root / "config.json"
        self.data = extractive_config(self.root)
        self.write_config(self.data)
        self.config = validate(copy.deepcopy(self.data), source=str(self.config_path))
        initialize_state(self.config)
        layout = StateLayout(self.config)
        token_file = self.root / "agent.token"
        IdentityStore(*layout.identities).issue("agent", "agent-a", token_file)
        self.token = token_file.read_text().strip()
        SecretStore(*layout.secrets).set(
            "model-key", "synthetic-provider-secret", tenant="tenant-a",
            destination="ai.example.test", routes=["model.chat"]
        )

        self.block_model = False
        self.model_started = asyncio.Event()
        self.release_model = asyncio.Event()
        self.provider_calls = []
        exact = self.exact_response()
        self.chat_response = {
            "id": "chatcmpl-extractive-test",
            "object": "chat.completion",
            "created": 1,
            "model": "model-a",
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(exact)},
            }],
            "usage": {"prompt_tokens": 4, "completion_tokens": 8, "total_tokens": 12},
        }

        original_fixture = host_module._fixture

        def extractive_fixture(behavior, timeout, delay=1):
            inner = original_fixture(behavior, timeout, delay)

            async def transport(operation):
                if operation.route != "model.answer":
                    return await inner(operation)
                if self.block_model:
                    self.model_started.set()
                    await self.release_model.wait()
                return operation.payload()

            return transport

        def provider_request(_provider, credential, payload):
            self.provider_calls.append((credential, copy.deepcopy(payload)))
            return copy.deepcopy(self.chat_response)

        self.patches = [
            patch.object(host_module, "_fixture", extractive_fixture),
            patch.object(BrokeredChatProvider, "_request", provider_request),
        ]
        for active in self.patches:
            active.start()
            self.addCleanup(active.stop)

        self.host = await GuardHost(self.config).start()
        self.addAsyncCleanup(self.host.stop)
        documents = self.host.components.documents
        documents.put(
            tenant="tenant-a", collection="kb", doc_id="kb-1", title="Runbook",
            content=self.QUOTE, label="internal", principals=["support-bot"]
        )
        documents.put(
            tenant="tenant-a", collection="kb", doc_id="kb-secret", title="Restricted memo",
            content="The incident is resolved.", label="restricted", principals=["support-bot"]
        )
        found = await self.request("kb.search", {"document_ids": ["kb-1", "kb-secret"]})
        if found.get("status") != "ok":
            self.fail("retrieval setup failed: %r" % found)
        self.assertEqual([item["doc_id"] for item in found["result"]["documents"]], ["kb-1"])

    def exact_response(self):
        return {
            "answer": self.QUOTE,
            "citations": [{"doc_id": "kb-1", "quote": self.QUOTE}],
        }

    def write_config(self, data):
        self.config_path.write_text(json.dumps(data))

    async def request(self, route_name, payload):
        return await guarded_request(
            self.config["paths"]["socket"], self.token, route_name, payload,
            request_id=new_request_id(), timeout=20
        )

    async def reload_with(self, data):
        self.write_config(data)
        result = await admin_request(self.config["paths"]["admin_socket"], "reload")
        self.assertEqual(result["status"], "ok", result)
        return result

    async def test_authorized_exact_extract_is_released(self):
        result = await self.request("model.answer", self.exact_response())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["result"], self.exact_response())

    async def test_invented_prose_with_real_citation_is_withheld(self):
        payload = self.exact_response()
        payload["answer"] = "The incident is resolved."
        result = await self.request("model.answer", payload)
        self.assertEqual((result["status"], result["reason"]), ("response_withheld", "ungrounded"))
        self.assertNotIn("The incident is resolved.", json.dumps(result))

    async def test_missing_or_unauthorized_source_is_withheld(self):
        cases = [
            {"answer": self.QUOTE, "citations": []},
            {
                "answer": "The incident is resolved.",
                "citations": [{
                    "doc_id": "kb-secret", "quote": "The incident is resolved."
                }],
            },
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                result = await self.request("model.answer", payload)
                self.assertEqual((result["status"], result["reason"]),
                                 ("response_withheld", "ungrounded"))
                self.assertNotIn(payload["answer"], json.dumps(result))

    async def test_reload_to_extractive_cannot_release_in_flight_citation_prose(self):
        citation_data = copy.deepcopy(self.data)
        route(citation_data, "model.answer")["grounding"] = {
            "citations": "required", "mode": "citations"
        }
        await self.reload_with(citation_data)

        self.block_model = True
        unsupported = {
            "answer": "The incident is resolved. [[cite:kb-1]]"
        }
        pending = asyncio.create_task(self.request("model.answer", unsupported))
        await asyncio.wait_for(self.model_started.wait(), timeout=5)

        extractive_data = copy.deepcopy(citation_data)
        route(extractive_data, "model.answer")["grounding"]["mode"] = "extractive"
        try:
            reloaded = await self.reload_with(extractive_data)
        finally:
            self.release_model.set()
        try:
            result = await pending
        except GuardError:
            self.assertEqual(reloaded["cancelled_in_flight"], 1)
        else:
            self.assertNotEqual(result.get("status"), "ok", result)
            self.assertNotIn("The incident is resolved.", json.dumps(result))

    async def test_recognized_chat_wrapper_releases_only_strict_answer_envelope(self):
        result = await self.request("model.chat", {
            "messages": [{"role": "user", "content": "Use the retrieved runbook."}]
        })
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["result"], self.exact_response())
        serialized = json.dumps(result)
        for wrapper_field in ("chatcmpl-extractive-test", "chat.completion", "usage", "choices"):
            self.assertNotIn(wrapper_field, serialized)
        self.assertEqual(self.provider_calls[0][0], "synthetic-provider-secret")


if __name__ == "__main__":
    unittest.main()
