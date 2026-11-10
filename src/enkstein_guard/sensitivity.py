"""Explicit sensitivity levels, trusted classification and durable agent taint.

Labels come only from trusted sources: host configuration (route levels and
field rules), local detectors, operator-declared context and Guard-owned
document records. Caller-supplied labels are ignored. Vault references are
opaque and carry no level of their own.

Detection limits: declared-context matching finds verbatim or lightly
obfuscated reuse of text the operator declared. Heuristics flag common
confidentiality markers. Neither recognizes arbitrary confidential prose,
paraphrase or translation; see docs/data-protection.md and the evaluation.
"""
from __future__ import annotations

import base64
import binascii
from contextlib import closing
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from urllib.parse import unquote

from cryptography.fernet import Fernet

from .contracts import Action, ControlResult
from .vault import TOKEN, _check_private

LEVELS = ("public", "internal", "confidential", "restricted")
RANK = {name: index for index, name in enumerate(LEVELS)}


def rank(level: str) -> int:
    if level not in RANK:
        raise ValueError("invalid_sensitivity_level")
    return RANK[level]


def highest(*levels: str) -> str:
    return max(levels, key=rank, default="public")


def permits(clearance: str, level: str) -> bool:
    return rank(level) <= rank(clearance)


# -- normalization ----------------------------------------------------------
_ZERO_WIDTH = dict.fromkeys(map(ord, "­​‌‍‎‏⁠⁡⁢⁣﻿"))
# Common Cyrillic/Greek confusables mapped to Latin. Deliberately small and
# documented; it is not a complete Unicode confusable table.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ԁ": "d", "ӏ": "l", "ѕ": "s", "һ": "h", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "ε": "e", "υ": "u",
})
_WORD = re.compile(r"[a-z0-9]+")


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).casefold().translate(_CONFUSABLES)
    return " ".join(_WORD.findall(text))


def _variants(text: str):
    """Text plus decodings an attacker commonly uses to smuggle a phrase."""
    yield text
    if "%" in text:
        decoded = unquote(text)
        if decoded != text:
            yield decoded
    for count, match in enumerate(re.finditer(r"[A-Za-z0-9+/_-]{12,}={0,2}", text)):
        if count >= 64:
            break
        chunk = match[0]
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(chunk + "=" * (-len(chunk) % 4))
                decoded = raw.decode("utf-8")
            except (ValueError, binascii.Error, UnicodeDecodeError):
                continue
            if decoded.isprintable():
                yield decoded
                break
    for count, match in enumerate(re.finditer(r"\b(?:[0-9a-fA-F]{2}){8,}\b", text)):
        if count >= 64:
            break
        try:
            decoded = bytes.fromhex(match[0]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            yield decoded


# -- declared context -------------------------------------------------------
@dataclass(frozen=True)
class DeclaredEntry:
    name: str
    level: str
    text: str
    canary: bool = False


class DeclaredContext:
    """Keyed fingerprints of operator-declared confidential text.

    Short entries (or entries marked canary) match as whole phrases, also
    after removing spacing/punctuation. Longer entries match when at least
    ``min_shingles`` distinct word shingles of the declared text reappear.
    """

    def __init__(self, entries=(), *, shingle=4, min_shingles=2, key=None, max_entries=256):
        entries = tuple(entries)
        if len(entries) > max_entries:
            raise ValueError("too_many_declared_entries")
        if type(shingle) is not int or not 2 <= shingle <= 8 or type(min_shingles) is not int or min_shingles < 1:
            raise ValueError("invalid_declared_context_options")
        self._key = key or secrets.token_bytes(32)
        self._shingle, self._min = shingle, min_shingles
        self._phrases = []   # (hash, length, squashed hash, level, name)
        self._shingles = {}  # hash -> {(name, level)}
        self._names = {}
        self._phrase_lengths = set()
        for entry in entries:
            if type(entry) is not DeclaredEntry or not entry.name or len(entry.name) > 64:
                raise ValueError("invalid_declared_entry")
            rank(entry.level)
            words = normalize(entry.text).split()
            if not words:
                raise ValueError("empty_declared_entry")
            self._names[entry.name] = entry.level
            if entry.canary or len(words) < shingle:
                if len(words) > 16:
                    raise ValueError("declared_canary_too_long")
                squashed = "".join(words)
                if len(squashed) < 6:
                    raise ValueError("declared_canary_too_short")
                self._phrases.append((self._digest(" ".join(words)), len(words), squashed, entry.level, entry.name))
                self._phrase_lengths.add(len(words))
            else:
                for index in range(len(words) - shingle + 1):
                    digest = self._digest(" ".join(words[index:index + shingle]))
                    self._shingles.setdefault(digest, set()).add((entry.name, entry.level))

    def _digest(self, text):
        return hmac.new(self._key, text.encode(), hashlib.sha256).digest()

    def __bool__(self):
        return bool(self._phrases or self._shingles)

    def match(self, text: str):
        """Return (highest level or None, sorted entry names)."""
        if not self or not isinstance(text, str) or not text:
            return None, ()
        found = {}
        for variant in _variants(text):
            words = normalize(variant).split()
            if not words:
                continue
            grams = {}
            for length in self._phrase_lengths:
                for index in range(len(words) - length + 1):
                    grams.setdefault(length, set()).add(self._digest(" ".join(words[index:index + length])))
            squashed = "".join(words)
            for digest, length, squashed_phrase, level, name in self._phrases:
                if digest in grams.get(length, ()) or squashed_phrase in squashed:
                    found[name] = level
            if self._shingles:
                hits = {}
                for index in range(len(words) - self._shingle + 1):
                    for name, level in self._shingles.get(self._digest(" ".join(words[index:index + self._shingle])), ()):
                        hits.setdefault((name, level), set()).add(index)
                for (name, level), positions in hits.items():
                    if len(positions) >= self._min:
                        found[name] = level
        if not found:
            return None, ()
        return highest(*found.values()), tuple(sorted(found))


# -- heuristics for unlabelled data ----------------------------------------
HEURISTIC_RULES = (
    ("marker.confidential", "confidential",
     r"(?i)\b(?:confidential|internal[\s-]+only|do\s+not\s+(?:share|distribute|disclose|forward)|proprietary"
     r"|not\s+for\s+(?:external|public)\s+(?:use|release|distribution)|under\s+nda)\b"),
    ("marker.hidden_context", "confidential",
     r"(?i)\b(?:system\s+prompt|hidden\s+(?:instructions?|context|prompt|rules?)|developer\s+message"
     r"|internal\s+(?:routing|instructions?|notes?|codename|code\s+name|phrase|guidance))\b"),
    ("marker.codename", "confidential", r"(?i)\b(?:project\s+)?code\s?name\s*[:\-]\s*\w+"),
    ("marker.passphrase", "restricted",
     r"(?i)\b(?:pass\s?phrase|secret\s+(?:phrase|word|code)|access\s+code|pin\s+code)\s*(?:is|[:=])\s*\S+"),
    ("marker.internal_host", "internal", r"(?i)\b[a-z0-9][a-z0-9-]*\.(?:internal|corp|intranet|lan)\b"),
    ("marker.private_address", "internal",
     r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"),
)
_HEURISTICS = tuple((rule, level, re.compile(pattern)) for rule, level, pattern in HEURISTIC_RULES)
_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{32,}")


def _entropy(token):
    counts = {}
    for char in token:
        counts[char] = counts.get(char, 0) + 1
    return -sum(n / len(token) * math.log2(n / len(token)) for n in counts.values())


def heuristic_findings(text: str):
    """Return ((rule_id, level), ...) for confidentiality markers in text."""
    if not isinstance(text, str) or not text:
        return ()
    stripped = TOKEN.sub(" ", text)
    findings = [(rule, level) for rule, level, pattern in _HEURISTICS if pattern.search(stripped)]
    for match in _ENTROPY_TOKEN.finditer(stripped):
        token = match[0]
        if (_entropy(token) >= 4.2 and any(c.isdigit() for c in token) and any(c.isupper() for c in token)
                and any(c.islower() for c in token)):
            findings.append(("marker.high_entropy_secret", "restricted"))
            break
    return tuple(findings)


# -- classification ---------------------------------------------------------
@dataclass(frozen=True)
class FieldLevel:
    path: tuple[str, ...]
    level: str

    def __post_init__(self):
        if type(self.path) is not tuple or not self.path or any(
                type(part) is not str or not part or len(part) > 128 for part in self.path):
            raise ValueError("invalid_field_level_path")
        rank(self.level)


@dataclass(frozen=True)
class Classification:
    level: str
    sources: tuple[str, ...]
    heuristic: tuple[str, ...] = ()


class Classifier:
    """Trusted classification of JSON values; never reads caller labels."""

    def __init__(self, *, field_levels=(), detected_level="confidential", secret_level="restricted",
                 declared: DeclaredContext | None = None, heuristics="monitor", heuristic_floor=None):
        for level in (detected_level, secret_level):
            rank(level)
        if heuristics not in ("off", "monitor", "enforce"):
            raise ValueError("invalid_heuristic_mode")
        self.field_levels = tuple(field_levels)
        if any(type(rule) is not FieldLevel for rule in self.field_levels):
            raise ValueError("invalid_field_levels")
        self.detected_level, self.secret_level = detected_level, secret_level
        self.declared = declared or DeclaredContext()
        self.heuristics = heuristics
        self.heuristic_floor = heuristic_floor
        from .privacy import _PATTERNS, _CARD, numeric_card
        from .policy import SECRET_RULES, _luhn_valid
        self._numeric_card = numeric_card
        secret_count = len(SECRET_RULES)
        self._secret_patterns = _PATTERNS[:secret_count] + [_PATTERNS[secret_count]]  # plus private key blocks
        self._pii_patterns = _PATTERNS[secret_count + 1:]
        self._card, self._luhn = _CARD, _luhn_valid

    def _field_level(self, path):
        level = None
        for rule in self.field_levels:
            if len(rule.path) == len(path) and all(want in ("*", got) for want, got in zip(rule.path, path)):
                level = highest(level or "public", rule.level)
        return level

    def classify(self, value) -> Classification:
        level, sources, heuristic = "public", set(), set()

        def raise_to(new, source):
            nonlocal level
            if rank(new) > rank(level):
                level = new
            sources.add(source)

        def text(value, path):
            stripped = TOKEN.sub(" ", value)
            if not stripped.strip():
                return
            if any(pattern.search(stripped) for pattern in self._secret_patterns):
                raise_to(self.secret_level, "detector.secret")
            if any(pattern.search(stripped) for pattern in self._pii_patterns):
                raise_to(self.detected_level, "detector.pii")
            for match in self._card.finditer(stripped):
                digits = re.sub(r"\D", "", match[0])
                if 13 <= len(digits) <= 19 and self._luhn(digits):
                    raise_to(self.detected_level, "detector.payment_card")
                    break
            found, names = self.declared.match(stripped)
            if found is not None:
                raise_to(found, "declared:" + ",".join(names))
            if self.heuristics != "off":
                for rule, rule_level in heuristic_findings(stripped):
                    heuristic.add(rule)
                    if self.heuristics == "enforce":
                        raise_to(self.heuristic_floor or rule_level, "heuristic:" + rule)

        def walk(value, path, depth):
            if depth > 40:
                raise ValueError("classification_depth_exceeded")
            rule = self._field_level(path) if path else None
            if rule is not None:
                raise_to(rule, "field:" + ".".join(path))
            if isinstance(value, str):
                text(value, path)
            elif type(value) is dict:
                for key, child in value.items():
                    if isinstance(key, str):
                        text(key, path)
                        walk(child, (*path, key), depth + 1)
            elif type(value) is list:
                for child in value:
                    walk(child, (*path, "*"), depth + 1)
            elif type(value) in (int, float) and self._numeric_card(value):
                raise_to(self.detected_level, "detector.payment_card_number")

        walk(value, (), 0)
        return Classification(level, tuple(sorted(sources)), tuple(sorted(heuristic)))


# -- durable taint ------------------------------------------------------------
def agent_key(tenant: str, principal: str, agent: str) -> str:
    return hashlib.sha256(json.dumps([tenant, principal, agent]).encode()).hexdigest()


class TaintError(Exception):
    pass


class TaintStore:
    """Sticky per-agent level persisted before data is released to the agent."""

    @classmethod
    def initialize(cls, database, key_file):
        database, key_file = Path(database), Path(key_file)
        if database.exists() or key_file.exists() or database == key_file:
            raise TaintError("taint_store_exists")
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
            connection.execute("INSERT INTO identity VALUES (?)", (Fernet(key).encrypt(b"guard-taint-v1"),))
            connection.execute("CREATE TABLE taint (agent TEXT PRIMARY KEY, record BLOB NOT NULL)")
            connection.commit()
        return cls(database, key_file)

    def __init__(self, database, key_file):
        self.database, self.key_file = Path(database), Path(key_file)
        for path in (self.database, self.key_file):
            _check_private(path.parent, directory=True)
            _check_private(path)
        self._cipher = Fernet(self.key_file.read_bytes())
        self._lock = threading.RLock()
        self._cache = {}
        with closing(self._connect()) as connection:
            for agent, record in connection.execute("SELECT agent, record FROM taint").fetchall():
                self._cache[agent] = self._decode(agent, record)["level"]

    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=5)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            row = connection.execute("SELECT record FROM identity").fetchall()
            if len(row) != 1 or self._cipher.decrypt(row[0][0]) != b"guard-taint-v1":
                raise ValueError()
            return connection
        except Exception:
            connection.close()
            raise TaintError("taint_store_integrity_failed") from None

    def _decode(self, agent, encrypted):
        try:
            record = json.loads(self._cipher.decrypt(encrypted))
            if record["agent"] != agent:
                raise ValueError()
            rank(record["level"])
            return record
        except Exception:
            raise TaintError("taint_store_integrity_failed") from None

    def level(self, key: str) -> str:
        with self._lock:
            return self._cache.get(key, "public")

    def raise_to(self, key: str, level: str):
        """Persist max(current, level); returns (previous, current)."""
        rank(level)
        with self._lock:
            previous = self._cache.get(key, "public")
            if rank(level) <= rank(previous):
                return previous, previous
            try:
                with closing(self._connect()) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    record = {"agent": key, "level": level, "updated_at": int(time.time())}
                    connection.execute(
                        "INSERT INTO taint VALUES (?, ?) ON CONFLICT(agent) DO UPDATE SET record=excluded.record",
                        (key, self._cipher.encrypt(json.dumps(record).encode())))
                    connection.commit()
            except TaintError:
                raise
            except Exception:
                raise TaintError("taint_store_write_failed") from None
            self._cache[key] = level
            return previous, level

    def reset(self, key: str) -> str:
        """Operator action after the agent's state is discarded (audited by caller)."""
        with self._lock:
            previous = self._cache.get(key, "public")
            try:
                with closing(self._connect()) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute("DELETE FROM taint WHERE agent=?", (key,))
                    connection.commit()
            except TaintError:
                raise
            except Exception:
                raise TaintError("taint_store_write_failed") from None
            self._cache.pop(key, None)
            return previous

    def snapshot(self):
        with self._lock:
            return dict(self._cache)


def sensitivity_control(classifier: Classifier, clearances, taint: TaintStore | None = None, *, name="sensitivity"):
    """Deny when max(agent taint, payload level) exceeds the route clearance.

    ``clearances`` maps trusted route names to the highest level the route's
    destination may receive. Unknown routes are denied.
    """
    clearances = dict(clearances)
    for level in clearances.values():
        rank(level)

    async def control(operation):
        context = operation.context
        allowed = False
        try:
            clearance = clearances.get(operation.route)
            if clearance is not None:
                level = classifier.classify(operation.payload()).level
                if taint is not None:
                    level = highest(level, taint.level(agent_key(context.tenant_id, context.principal_id,
                                                                  context.agent_id)))
                allowed = permits(clearance, level)
        except Exception:
            allowed = False
        return ControlResult(name, context.tenant_id, context.operation_id,
                             Action.ALLOW if allowed else Action.DENY)

    return control


def declared_output_control(declared: DeclaredContext, clearance: str, *, name="declared_context"):
    """PrivateAI/SDK output control: withhold output that reproduces declared
    context above the caller's clearance."""
    rank(clearance)

    async def control(operation):
        context = operation.context
        try:
            level, _ = declared.match(operation.payload_json)
            allowed = level is None or permits(clearance, level)
        except Exception:
            allowed = False
        return ControlResult(name, context.tenant_id, context.operation_id,
                             Action.ALLOW if allowed else Action.DENY)

    return control
