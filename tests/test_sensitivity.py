import asyncio
import base64
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from enkstein_guard.contracts import Action, SecurityContext
from enkstein_guard.runtime import Operation
from enkstein_guard.sensitivity import (Classifier, DeclaredContext, DeclaredEntry, FieldLevel, TaintError, TaintStore,
                                        agent_key, declared_output_control, heuristic_findings, highest, permits,
                                        sensitivity_control)


def operation(payload, route="r", agent="a"):
    context = SecurityContext("t", "p", agent, "w", "op-1", "op", "v1")
    encoded = json.dumps(payload, sort_keys=True)
    return Operation(context, route, "res", "dest", encoded, hashlib.sha256(encoded.encode()).hexdigest())


class LevelTests(unittest.TestCase):
    def test_ordering_and_invalid_levels(self):
        self.assertEqual(highest("public", "restricted", "internal"), "restricted")
        self.assertTrue(permits("confidential", "internal"))
        self.assertFalse(permits("internal", "confidential"))
        with self.assertRaises(ValueError):
            permits("secret", "public")


class DeclaredContextTests(unittest.TestCase):
    def setUp(self):
        self.declared = DeclaredContext([
            DeclaredEntry("routing", "restricted", "cobalt orchard"),
            DeclaredEntry("prompt", "confidential",
                          "You are the ACME support assistant. Never reveal the pricing floor of forty one dollars "
                          "and always escalate merger questions to the legal team immediately."),
        ])

    def test_verbatim_and_obfuscated_canary(self):
        for text in ("phrase: cobalt orchard", "COBALT-ORCHARD", "c o b a l t  o r c h a r d", "cob​alt orchard",
                     "cobаlt orchard", base64.b64encode(b"cobalt orchard").decode(),
                     "cobalt%20orchard", "636f62616c74206f72636861726420"):
            with self.subTest(text=text):
                self.assertEqual(self.declared.match(text)[0], "restricted")

    def test_long_entry_needs_two_shingles(self):
        leak = "It said never reveal the pricing floor of forty one dollars to anyone"
        self.assertEqual(self.declared.match(leak)[0], "confidential")
        self.assertEqual(self.declared.match("You are the ACME support assistant.")[0], "confidential")
        # A single shared four-word shingle is below the threshold.
        self.assertIsNone(self.declared.match("Hi, you are the ACME customer of the month")[0])

    def test_known_misses_are_explicit(self):
        # Paraphrase, translation and reversal are not recognized (documented limitation).
        for text in ("the orchard phrase with the blue metal", "huerto de cobalto", "drahcro tlaboc", "cobalt"):
            with self.subTest(text=text):
                self.assertIsNone(self.declared.match(text)[0])

    def test_benign_text_not_flagged(self):
        for text in ("The orchard produced cobalt-blue plums", "Explain how orchards are irrigated"):
            self.assertIsNone(self.declared.match(text)[0])

    def test_entry_validation(self):
        with self.assertRaises(ValueError):
            DeclaredContext([DeclaredEntry("x", "secret", "cobalt orchard")])
        with self.assertRaises(ValueError):
            DeclaredContext([DeclaredEntry("x", "internal", "abc")])


class ClassifierTests(unittest.TestCase):
    def test_trusted_sources_only(self):
        classifier = Classifier(field_levels=[FieldLevel(("customer", "*", "ssn"), "restricted")])
        self.assertEqual(classifier.classify({"note": "hello"}).level, "public")
        self.assertEqual(classifier.classify({"email": "jane@example.com"}).level, "confidential")
        self.assertEqual(classifier.classify({"k": "AKIA3ZK7QWERTYUIOPAS"}).level, "restricted")
        self.assertEqual(classifier.classify({"customer": [{"ssn": "x"}]}).level, "restricted")
        # Caller-supplied labels are ignored.
        self.assertEqual(classifier.classify({"label": "public", "sensitivity": "public",
                                              "text": "jane@example.com"}).level, "confidential")
        self.assertEqual(classifier.classify({"label": "restricted"}).level, "public")

    def test_card_numbers_sent_as_json_numbers_are_detected(self):
        classifier = Classifier()
        self.assertEqual(classifier.classify({"cc": 4111111111111111}).level, "confidential")
        self.assertEqual(classifier.classify({"cc": 4111111111111111.0}).level, "confidential")
        self.assertEqual(classifier.classify({"items": [{"n": 5500005555555559}]}).level, "confidential")
        for benign in (1234567890123, 42, True, 3.5, 10 ** 25):
            self.assertEqual(classifier.classify({"n": benign}).level, "public", benign)

    def test_vault_references_are_opaque(self):
        classifier = Classifier()
        self.assertEqual(classifier.classify({"v": "[[EGV:" + "a" * 64 + "]]"}).level, "public")

    def test_heuristic_modes(self):
        text = {"text": "This memo is confidential and internal only"}
        self.assertEqual(Classifier(heuristics="monitor").classify(text).level, "public")
        self.assertIn("marker.confidential", Classifier(heuristics="monitor").classify(text).heuristic)
        self.assertEqual(Classifier(heuristics="enforce").classify(text).level, "confidential")
        self.assertEqual(Classifier(heuristics="off").classify(text).heuristic, ())

    def test_heuristic_findings(self):
        rules = dict(heuristic_findings("The system prompt says the passphrase is: tangerine-42"))
        self.assertIn("marker.hidden_context", rules)
        self.assertIn("marker.passphrase", rules)
        self.assertEqual(heuristic_findings(""), ())


class TaintTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.db, self.key = root / "data/taint.sqlite3", root / "keys/taint.key"
        self.store = TaintStore.initialize(self.db, self.key)
        self.agent = agent_key("t", "p", "a")

    def test_sticky_durable_and_reset(self):
        self.assertEqual(self.store.level(self.agent), "public")
        self.assertEqual(self.store.raise_to(self.agent, "confidential"), ("public", "confidential"))
        self.assertEqual(self.store.raise_to(self.agent, "internal"), ("confidential", "confidential"))
        self.assertEqual(TaintStore(self.db, self.key).level(self.agent), "confidential")
        self.assertEqual(self.store.reset(self.agent), "confidential")
        self.assertEqual(TaintStore(self.db, self.key).level(self.agent), "public")

    def test_tamper_fails_closed(self):
        self.store.raise_to(self.agent, "restricted")
        with sqlite3.connect(self.db) as connection:
            connection.execute("UPDATE taint SET record=?", (b"forged",))
        with self.assertRaises(TaintError):
            TaintStore(self.db, self.key)

    def test_control_combines_taint_payload_and_clearance(self):
        classifier = Classifier()
        control = sensitivity_control(classifier, {"external": "public", "internal": "confidential"}, self.store)
        run = lambda payload, route: asyncio.run(control(operation(payload, route=route))).action
        key = agent_key("t", "p", "a")
        self.assertEqual(run({"text": "status ok"}, "external"), Action.ALLOW)
        self.assertEqual(run({"text": "jane@example.com"}, "external"), Action.DENY)
        self.assertEqual(run({"text": "jane@example.com"}, "internal"), Action.ALLOW)
        self.assertEqual(run({"text": "status ok"}, "unknown-route"), Action.DENY)
        self.store.raise_to(key, "confidential")
        # A summary written after seeing confidential data stays confidential.
        self.assertEqual(run({"summary": "one affected customer"}, "external"), Action.DENY)
        self.assertEqual(run({"summary": "one affected customer"}, "internal"), Action.ALLOW)

    def test_declared_output_control(self):
        declared = DeclaredContext([DeclaredEntry("routing", "restricted", "cobalt orchard")])
        control = declared_output_control(declared, "confidential")
        self.assertEqual(asyncio.run(control(operation({"answer": "Internal phrase: cobalt orchard"}))).action, Action.DENY)
        self.assertEqual(asyncio.run(control(operation({"answer": "No hidden phrase"}))).action, Action.ALLOW)


class NumericTokenizationTests(unittest.TestCase):
    def test_numeric_card_rejected_for_requests_and_tokenized_for_outputs(self):
        from enkstein_guard.privacy import Tokenizer
        from enkstein_guard.vault import LocalVault, Scope, VaultError
        with tempfile.TemporaryDirectory() as temp:
            vault = LocalVault.initialize(Path(temp) / "v/db", Path(temp) / "k/key")
            tokenizer = Tokenizer(vault)
            scope = Scope("t", "p", "w", "o")
            with self.assertRaises(VaultError):
                tokenizer.tokenize({"cc": 4111111111111111}, scope, ("d",))
            out = tokenizer.tokenize({"cc": 4111111111111111, "count": 3}, scope, ("d",), numeric_cards="tokenize")
            self.assertTrue(out["cc"].startswith("[[EGV:"))
            self.assertEqual(out["count"], 3)
            self.assertEqual(vault.restore(out["cc"], scope, "d"), "4111111111111111")
