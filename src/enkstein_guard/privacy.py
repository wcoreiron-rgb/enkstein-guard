"""Local text/JSON tokenization. Detection is heuristic, not all-data discovery."""

import json
import math
import re
import secrets

from .policy import SECRET_RULES, _luhn_valid
from .vault import LocalVault, Scope, TOKEN, VaultError

_PATTERNS = [re.compile(pattern, re.IGNORECASE) for _, _, pattern, _ in SECRET_RULES]
_PATTERNS.extend([
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"),
    re.compile(r"\b(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b"),
])
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
DEFAULT_FIELDS = frozenset({"password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
                            "authorization", "ssn", "credit_card", "email", "phone", "name", "full_name"})


def numeric_card(value):
    """True for a JSON number whose digits form a Luhn-valid 13-19 digit card number.

    Card numbers sent as numbers bypass text patterns; other sensitive numbers
    (SSNs, phone numbers without separators) are not recognized and need
    field rules.
    """
    if type(value) is float:
        if not math.isfinite(value) or not value.is_integer() or abs(value) >= 1e19:
            return False
        value = int(value)
    if type(value) is not int:
        return False
    digits = str(abs(value))
    return 13 <= len(digits) <= 19 and _luhn_valid(digits)


class Tokenizer:
    def __init__(self, vault: LocalVault, *, sensitive_fields=DEFAULT_FIELDS, ttl=300):
        self.vault = vault
        self.fields = frozenset(sensitive_fields)
        self.ttl = ttl

    def tokenize(self, payload, scope: Scope, destinations: tuple[str, ...], *, allow_references=False,
                 numeric_cards="reject"):
        """``numeric_cards``: "reject" (fail closed; for requests whose
        destination expects numbers) or "tokenize" (replace with a string
        reference; for outputs and inspection copies)."""
        if numeric_cards not in ("reject", "tokenize"):
            raise ValueError("invalid_numeric_card_mode")
        cache = {}
        def store(value):
            if value not in cache:
                if len(cache)>=128:
                    raise VaultError("private_value_count_exceeded")
                cache[value] = "__EG_STAGE_"+secrets.token_hex(32)+"__"
            return cache[value]

        def text(value, force=False):
            if "[[EGV:" in value:
                if not allow_references:
                    raise VaultError("reserved_vault_reference")
                # Validate every reference locally; originals never leave here.
                self.vault.restore(value, scope, destinations[0], consume=False)
            if force and value and not TOKEN.fullmatch(value):
                return store(value)
            references = [(m.start(), m.end()) for m in TOKEN.finditer(value)]
            spans = []
            for pattern in _PATTERNS:
                spans.extend((m.start(), m.end()) for m in pattern.finditer(value)
                             if not any(m.start() < b and m.end() > a for a, b in references))
            for match in _CARD.finditer(value):
                digits = re.sub(r"\D", "", match[0])
                if (13 <= len(digits) <= 19 and _luhn_valid(digits)
                        and not any(match.start() < b and match.end() > a for a, b in references)):
                    spans.append((match.start(), match.end()))
            merged = []
            for start, end in sorted(spans):
                if merged and start < merged[-1][1]:
                    merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
                else:
                    merged.append((start, end))
            for start, end in reversed(merged):
                value = value[:start] + store(value[start:end]) + value[end:]
            return value

        def walk(value, force=False, depth=0):
            if depth > 40:
                raise VaultError("unsupported_payload_depth")
            if isinstance(value, str):
                return text(value, force)
            if type(value) is dict:
                result = {}
                for key, child in value.items():
                    if not isinstance(key, str) or "[[EGV:" in key or any(p.search(key) for p in _PATTERNS):
                        raise VaultError("sensitive_or_invalid_json_key")
                    # Image/audio/file parts need a separate content adapter.
                    if key.lower() in {"image_url", "audio", "input_audio", "file_data", "file_id"}:
                        raise VaultError("unsupported_multimodal_payload")
                    if key == "type" and child in ("input_image", "input_audio", "input_file", "image", "audio", "file"):
                        raise VaultError("unsupported_multimodal_payload")
                    result[key] = walk(child, force or key.lower() in self.fields, depth+1)
                return result
            if type(value) is list:
                return [walk(child, force, depth+1) for child in value]
            if value is None or type(value) in (int, float, bool):
                if force and value is not None:
                    raise VaultError("unsupported_sensitive_scalar")
                if type(value) is not bool and numeric_card(value):
                    if numeric_cards == "reject":
                        raise VaultError("unsupported_sensitive_scalar")
                    return store(str(int(value)))
                return value
            raise VaultError("unsupported_payload_type")

        # Strict JSON validation rejects NaN/Infinity and custom Python objects.
        try:
            encoded = json.dumps(payload, allow_nan=False)
            if len(encoded.encode()) > 1_048_576:
                raise ValueError()
            result=walk(payload)
            if not cache:return result
            tokens=self.vault.put_many(tuple(cache),scope,destinations,ttl=self.ttl)
            encoded=json.dumps(result,allow_nan=False)
            for staged,token in zip(cache.values(),tokens):
                encoded=encoded.replace(staged,token)
            return json.loads(encoded)
        except VaultError:
            raise
        except Exception:
            raise VaultError("invalid_private_payload") from None
