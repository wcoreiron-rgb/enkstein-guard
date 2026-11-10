"""Document-level retrieval authorization and citation grounding checks.

Authorization uses only the authenticated identity in the trusted
SecurityContext and Guard-owned document records (tenant, ACL and label).
Backend-returned metadata, agent-supplied identity, labels or permissions are
ignored. The local store pre-filters by authorization before ranking, so
result counts and ordering never depend on documents the caller cannot read.

Grounding verifies that cited documents were actually retrieved for the caller
and that quoted spans occur in them. It does not verify that a claim is true
or entailed by the cited text.
"""
from __future__ import annotations

from collections import OrderedDict
from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time

from cryptography.fernet import Fernet

from .contracts import Action, ControlResult
from .runtime import AccessDenied, RejectedBeforeDispatch
from .sensitivity import agent_key, normalize, permits, rank
from .vault import _check_private

_ID = re.compile(r"[A-Za-z0-9._:/-]{1,128}")
_NAME = re.compile(r"[A-Za-z0-9._@:-]{1,128}")
STOPWORDS = frozenset("a an and are as at be by for from has have in is it its of on or that the this to was were "
                      "will with what which who how why when where do does did can could should would".split())


class RetrievalError(Exception):
    pass


@dataclass(frozen=True)
class Document:
    tenant: str
    collection: str
    doc_id: str
    title: str
    content: str
    label: str
    principals: frozenset
    groups: frozenset
    digest: str


def _validate_document(tenant, collection, doc_id, title, content, label, principals, groups, max_bytes):
    for value in (tenant, collection):
        if not isinstance(value, str) or not _NAME.fullmatch(value):
            raise RetrievalError("invalid_document_scope")
    if not isinstance(doc_id, str) or not _ID.fullmatch(doc_id):
        raise RetrievalError("invalid_document_id")
    if not isinstance(title, str) or len(title) > 512 or not isinstance(content, str) or not content:
        raise RetrievalError("invalid_document_content")
    if len(content.encode()) > max_bytes:
        raise RetrievalError("document_too_large")
    try:
        rank(label)
    except ValueError:
        raise RetrievalError("invalid_document_label") from None
    for collection_value in (principals, groups):
        if type(collection_value) not in (list, tuple, set, frozenset) or len(collection_value) > 256 or any(
                not isinstance(item, str) or not (item == "*" or _NAME.fullmatch(item)) for item in collection_value):
            raise RetrievalError("invalid_document_acl")
    if not principals and not groups:
        raise RetrievalError("document_acl_required")


class DocumentStore:
    """Encrypted Guard-owned records: content, tenant, ACL and label."""

    @classmethod
    def initialize(cls, database, key_file, **limits):
        database, key_file = Path(database), Path(key_file)
        if database.exists() or key_file.exists() or database == key_file:
            raise RetrievalError("document_store_exists")
        for parent in (database.parent, key_file.parent):
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _check_private(parent, directory=True)
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        key = Fernet.generate_key()
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("CREATE TABLE identity (record BLOB NOT NULL)")
            connection.execute("INSERT INTO identity VALUES (?)", (Fernet(key).encrypt(b"guard-documents-v1"),))
            connection.execute("CREATE TABLE documents (doc_key TEXT PRIMARY KEY, record BLOB NOT NULL)")
            connection.commit()
        return cls(database, key_file, **limits)

    def __init__(self, database, key_file, *, max_documents=10000, max_document_bytes=262_144):
        if type(max_documents) is not int or not 1 <= max_documents <= 100_000:
            raise ValueError("invalid_document_limit")
        if type(max_document_bytes) is not int or not 1 <= max_document_bytes <= 1_048_576:
            raise ValueError("invalid_document_size_limit")
        self.database, self.key_file = Path(database), Path(key_file)
        for path in (self.database, self.key_file):
            _check_private(path.parent, directory=True)
            _check_private(path)
        self._cipher = Fernet(self.key_file.read_bytes())
        self.max_documents, self.max_document_bytes = max_documents, max_document_bytes
        self._lock = threading.RLock()
        self._generation = 0
        with closing(self._connect()):
            pass

    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=5)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            row = connection.execute("SELECT record FROM identity").fetchall()
            if len(row) != 1 or self._cipher.decrypt(row[0][0]) != b"guard-documents-v1":
                raise ValueError()
            return connection
        except Exception:
            connection.close()
            raise RetrievalError("document_store_integrity_failed") from None

    @staticmethod
    def _key(tenant, collection, doc_id):
        return hashlib.sha256(json.dumps([tenant, collection, doc_id]).encode()).hexdigest()

    def _decode(self, key, encrypted):
        try:
            record = json.loads(self._cipher.decrypt(encrypted))
            if record["key"] != key:
                raise ValueError()
            return Document(record["tenant"], record["collection"], record["doc_id"], record["title"],
                            record["content"], record["label"], frozenset(record["principals"]),
                            frozenset(record["groups"]), record["digest"])
        except Exception:
            raise RetrievalError("document_store_integrity_failed") from None

    def put(self, *, tenant, collection, doc_id, content, label, title="", principals=(), groups=(), replace=False):
        _validate_document(tenant, collection, doc_id, title, content, label, principals, groups,
                           self.max_document_bytes)
        key = self._key(tenant, collection, doc_id)
        digest = hashlib.sha256(content.encode()).hexdigest()
        record = {"key": key, "tenant": tenant, "collection": collection, "doc_id": doc_id, "title": title,
                  "content": content, "label": label, "principals": sorted(principals), "groups": sorted(groups),
                  "digest": digest, "updated_at": int(time.time())}
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            exists = connection.execute("SELECT 1 FROM documents WHERE doc_key=?", (key,)).fetchone()
            if exists and not replace:
                raise RetrievalError("document_exists")
            if not exists and connection.execute("SELECT count(*) FROM documents").fetchone()[0] >= self.max_documents:
                raise RetrievalError("document_capacity_reached")
            connection.execute("INSERT INTO documents VALUES (?, ?) ON CONFLICT(doc_key) DO UPDATE SET record=excluded.record",
                               (key, self._cipher.encrypt(json.dumps(record).encode())))
            connection.commit()
            self._generation += 1
        return digest

    def remove(self, tenant, collection, doc_id):
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            removed = connection.execute("DELETE FROM documents WHERE doc_key=?",
                                         (self._key(tenant, collection, doc_id),)).rowcount
            connection.commit()
            self._generation += 1
        return bool(removed)

    def get(self, tenant, collection, doc_id):
        if not isinstance(doc_id, str) or not _ID.fullmatch(doc_id):
            return None
        key = self._key(tenant, collection, doc_id)
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute("SELECT record FROM documents WHERE doc_key=?", (key,)).fetchone()
        return self._decode(key, row[0]) if row else None

    def documents(self, tenant, collection):
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute("SELECT doc_key, record FROM documents").fetchall()
        result = [self._decode(key, record) for key, record in rows]
        return tuple(sorted((d for d in result if d.tenant == tenant and d.collection == collection),
                            key=lambda d: d.doc_id))

    def listing(self, tenant, collection):
        """Operator view without content."""
        return [{"doc_id": d.doc_id, "label": d.label, "digest": d.digest, "principals": len(d.principals),
                 "groups": len(d.groups)} for d in self.documents(tenant, collection)]

    @property
    def generation(self):
        return self._generation


def authorized(document, *, tenant, principal, agent, groups, clearance):
    return (document is not None and document.tenant == tenant
            and ("*" in document.principals or principal in document.principals
                 or ("agent:" + agent) in document.principals or bool(document.groups & groups))
            and permits(clearance, document.label))


class RetrievalAuthorizer:
    """Authorize candidates from any backend against trusted records.

    Only ``doc_id`` (and optionally ``content`` for an integrity check) is read
    from a candidate; tenant, ACL and label always come from ``lookup``.
    Returned documents carry the trusted record content, never backend text.
    """

    def __init__(self, lookup):
        if not callable(lookup):
            raise ValueError("document_lookup_required")
        self._lookup = lookup

    def authorize(self, candidates, *, tenant, principal, agent, groups, clearance, collection):
        allowed, withheld, seen = [], 0, set()
        for candidate in candidates:
            doc_id = candidate.get("doc_id") if type(candidate) is dict else None
            if not isinstance(doc_id, str) or doc_id in seen:
                withheld += 1
                continue
            seen.add(doc_id)
            document = self._lookup(tenant, collection, doc_id)
            content = candidate.get("content")
            if (not authorized(document, tenant=tenant, principal=principal, agent=agent, groups=groups,
                               clearance=clearance)
                    or (content is not None and hashlib.sha256(str(content).encode()).hexdigest() != document.digest)):
                withheld += 1
                continue
            allowed.append(document)
        return allowed, withheld


def new_retrieval_id():
    """Opaque identifier of one retrieval, returned to the agent.

    Guard classifies every response before releasing it. A bare random hex
    value is sometimes all digits and Luhn-valid (about 4 in 100,000), which the
    payment-card detector reports as a card number, and the response would then
    be withheld from an agent cleared below the detector level. The prefix
    keeps the identifier a single word of letters, digits and underscores, so no
    built-in detector can match any part of it.
    """
    return "rt_" + secrets.token_hex(8)


class RetrievalLedger:
    """Recent per-agent retrieval sets used by grounding checks; in memory."""

    def __init__(self, *, ttl=900, max_agents=1024, max_documents_per_agent=256):
        self.ttl, self._max_agents, self._max_docs = ttl, max_agents, max_documents_per_agent
        self._sets = OrderedDict()
        self._lock = threading.Lock()

    def record(self, key, documents):
        now = time.monotonic()
        with self._lock:
            entry = self._sets.pop(key, OrderedDict())
            for document in documents:
                entry.pop(document.doc_id, None)
                entry[document.doc_id] = (document.content, now + self.ttl)
            while len(entry) > self._max_docs:
                entry.popitem(last=False)
            self._sets[key] = entry
            while len(self._sets) > self._max_agents:
                self._sets.popitem(last=False)
        return new_retrieval_id()

    def allowed(self, key):
        now = time.monotonic()
        with self._lock:
            entry = self._sets.get(key, {})
            return {doc_id: content for doc_id, (content, expires) in entry.items() if expires > now}


def _terms(text):
    return [word for word in normalize(text).split() if word not in STOPWORDS and len(word) > 1]


class LocalRetrieval:
    """Route transport over the local DocumentStore with pre-authorization.

    Payload: {"query": str, "top_k": int} or {"document_ids": [str, ...]}.
    ``agents`` maps agent IDs to (groups, clearance) from trusted configuration.
    """

    def __init__(self, store: DocumentStore, *, collection, agents, ledger: RetrievalLedger,
                 max_results=5, max_chars=4000, on_release=None):
        if not _NAME.fullmatch(collection) or type(max_results) is not int or not 1 <= max_results <= 20:
            raise ValueError("invalid_retrieval_configuration")
        self.store, self.collection, self.ledger = store, collection, ledger
        self._agents = {agent: (frozenset(groups), clearance) for agent, (groups, clearance) in agents.items()}
        for _, clearance in self._agents.values():
            rank(clearance)
        self.max_results, self.max_chars = max_results, max_chars
        self._on_release = on_release
        self._cache = {}
        self._lock = threading.Lock()

    def _index(self, tenant):
        with self._lock:
            cached = self._cache.get(tenant)
            if cached and cached[0] == self.store.generation:
                return cached[1]
            documents = self.store.documents(tenant, self.collection)
            postings = {}
            for position, document in enumerate(documents):
                counts = {}
                for term in _terms(document.title + " " + document.content):
                    counts[term] = counts.get(term, 0) + 1
                for term, count in counts.items():
                    postings.setdefault(term, []).append((position, count))
            index = (documents, postings)
            self._cache[tenant] = (self.store.generation, index)
            return index

    async def call(self, operation):
        context = operation.context
        if context.agent_id not in self._agents:
            raise RejectedBeforeDispatch("retrieval_identity_unknown")
        groups, clearance = self._agents[context.agent_id]
        payload = operation.payload()
        identity = dict(tenant=context.tenant_id, principal=context.principal_id, agent=context.agent_id,
                        groups=groups, clearance=clearance)
        documents, postings = self._index(context.tenant_id)
        if set(payload) == {"query", "top_k"} or set(payload) == {"query"}:
            query, top_k = payload["query"], payload.get("top_k", self.max_results)
            if not isinstance(query, str) or not 0 < len(query) <= 2048 or type(top_k) is not int or not 1 <= top_k <= self.max_results:
                raise RejectedBeforeDispatch("invalid_retrieval_request")
            visible = {position for position, document in enumerate(documents)
                       if authorized(document, **identity)}
            scores = {}
            if visible:
                for term in set(_terms(query)):
                    hits = [(p, c) for p, c in postings.get(term, ()) if p in visible]
                    if not hits:
                        continue
                    idf = math.log(1 + len(visible) / len(hits))
                    for position, count in hits:
                        scores[position] = scores.get(position, 0.0) + idf * (1 + math.log(count))
            ranked = sorted(scores, key=lambda p: (-scores[p], documents[p].doc_id))[:top_k]
            selected = [documents[p] for p in ranked]
        elif set(payload) == {"document_ids"}:
            ids = payload["document_ids"]
            if type(ids) is not list or not 1 <= len(ids) <= self.max_results or any(not isinstance(i, str) for i in ids):
                raise RejectedBeforeDispatch("invalid_retrieval_request")
            authorizer = RetrievalAuthorizer(self.store.get)
            selected, _ = authorizer.authorize([{"doc_id": i} for i in ids], collection=self.collection, **identity)
        else:
            raise RejectedBeforeDispatch("invalid_retrieval_request")
        key = agent_key(context.tenant_id, context.principal_id, context.agent_id)
        retrieval_id = self.ledger.record(key, selected)
        if self._on_release is not None:
            self._on_release(selected)
        return {"retrieval_id": retrieval_id, "documents": [
            {"doc_id": d.doc_id, "title": d.title, "label": d.label,
             "content": d.content[:self.max_chars], "truncated": len(d.content) > self.max_chars}
            for d in selected]}


# -- grounding ----------------------------------------------------------------
CITE = re.compile(r"\[\[cite:([A-Za-z0-9._:/-]{1,128})\]\]")
_MAX_EXTRACTIVE_CITATIONS = 16
_MAX_EXTRACTIVE_TEXT_BYTES = 32_768
_MAX_EXTRACTIVE_CONTEXT_DOCUMENTS = 256
_MAX_EXTRACTIVE_SOURCE_CHARS = 1_048_576


def _utf8_size(value):
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def citations(value):
    """Collect (doc_id, quote) pairs from [[cite:ID]] markers and citation lists."""
    found = []

    def walk(item, depth=0):
        if depth > 40:
            raise ValueError("citation_depth_exceeded")
        if isinstance(item, str):
            found.extend((match, None) for match in CITE.findall(item))
        elif type(item) is dict:
            for key, child in item.items():
                if key == "citations" and type(child) is list:
                    for entry in child:
                        if isinstance(entry, str):
                            found.append((entry, None))
                        elif type(entry) is dict and isinstance(entry.get("doc_id"), str):
                            quote = entry.get("quote")
                            found.append((entry["doc_id"], quote if isinstance(quote, str) else None))
                        else:
                            found.append(("", None))
                else:
                    walk(child, depth + 1)
        elif type(item) is list:
            for child in item:
                walk(child, depth + 1)

    walk(value)
    return found


def _check_extractive_grounding(value, allowed):
    """Validate the one supported source-extractive response envelope."""
    if type(value) is not dict or len(value) != 2 or any(type(key) is not str for key in value) or set(value) != {
            "answer", "citations"}:
        return False, "extractive_schema_invalid"
    answer, cited = value["answer"], value["citations"]
    if type(answer) is not str or not answer or type(cited) is not list or not (
            1 <= len(cited) <= _MAX_EXTRACTIVE_CITATIONS):
        return False, "extractive_schema_invalid"
    if len(answer) > _MAX_EXTRACTIVE_TEXT_BYTES:
        return False, "extractive_output_too_large"
    answer_bytes = _utf8_size(answer)
    if answer_bytes is None:
        return False, "extractive_schema_invalid"
    if answer_bytes > _MAX_EXTRACTIVE_TEXT_BYTES:
        return False, "extractive_output_too_large"
    if type(allowed) is not dict or len(allowed) > _MAX_EXTRACTIVE_CONTEXT_DOCUMENTS or any(
            type(doc_id) is not str or not _ID.fullmatch(doc_id) or type(source) is not str
            or len(source) > _MAX_EXTRACTIVE_SOURCE_CHARS
            for doc_id, source in allowed.items()):
        return False, "extractive_context_invalid"

    quotes = []
    quoted_bytes = 0
    for entry in cited:
        if type(entry) is not dict or len(entry) != 2 or any(type(key) is not str for key in entry) or set(entry) != {
                "doc_id", "quote"}:
            return False, "extractive_schema_invalid"
        doc_id, quote = entry["doc_id"], entry["quote"]
        if type(doc_id) is not str or not _ID.fullmatch(doc_id) or type(quote) is not str or not quote:
            return False, "extractive_schema_invalid"
        if len(quote) > _MAX_EXTRACTIVE_TEXT_BYTES:
            return False, "extractive_output_too_large"
        quote_bytes = _utf8_size(quote)
        if quote_bytes is None:
            return False, "extractive_schema_invalid"
        quoted_bytes += quote_bytes
        if quoted_bytes > _MAX_EXTRACTIVE_TEXT_BYTES:
            return False, "extractive_output_too_large"
        if doc_id not in allowed:
            return False, "citation_not_in_retrieved_context"
        source = allowed[doc_id]
        if quote not in source:
            return False, "quote_not_found_in_cited_document"
        quotes.append(quote)

    if answer != "".join(quotes):
        return False, "answer_not_source_extractive"
    return True, "extractive_spans_verified"


def check_grounding(value, allowed, *, required=True, mode="citations"):
    """Return (grounded, reason). ``allowed`` maps retrieved doc IDs to content.

    ``citations`` preserves the historical citation-presence check. ``extractive``
    accepts only the strict envelope validated by :func:`_check_extractive_grounding`.
    """
    if type(mode) is not str:
        return False, "unsupported_grounding_mode"
    if mode == "extractive":
        # ``required=False`` never authorizes unquoted prose in extractive mode.
        try:
            return _check_extractive_grounding(value, allowed)
        except Exception:
            return False, "extractive_context_invalid"
    if mode != "citations":
        return False, "unsupported_grounding_mode"
    cited = citations(value)
    if not cited:
        return (not required), ("citations_missing" if required else "no_citations")
    for doc_id, quote in cited:
        if doc_id not in allowed:
            return False, "citation_not_in_retrieved_context"
        if quote is not None and normalize(quote) not in normalize(allowed[doc_id]):
            return False, "quote_not_found_in_cited_document"
    return True, "citations_verified"


def grounding_control(context_documents, *, required=True, mode="citations", name="grounding"):
    """PrivateAI output control. ``context_documents(operation)`` is a trusted
    host callable returning the {doc_id: content} supplied to this request."""
    if not callable(context_documents):
        raise ValueError("grounding_context_required")

    async def control(operation):
        context = operation.context
        try:
            ok, _ = check_grounding(operation.payload(), context_documents(operation), required=required, mode=mode)
        except Exception:
            ok = False
        return ControlResult(name, context.tenant_id, context.operation_id, Action.ALLOW if ok else Action.DENY)

    return control
