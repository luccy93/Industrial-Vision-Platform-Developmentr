"""Central credential detection and redaction (V29).

This module is the single source of truth for detecting credential-bearing
names, assignments, URLs, HTTP headers, structured fields, and private-key
material. Backend logging and the release tooling both import it so a value is
treated consistently whether it is emitted in a log record or retained as
evidence.

The policy is deliberately conservative: a small set of well-understood secret
names and formats is redacted, while metadata such as ``key_id``,
``token_count``, ``password_policy``, ``api_key_required``, and
``public_key_fingerprint`` is preserved. Unknown proprietary formats are not
claimed to be detected; callers that retain evidence must still fail closed
when a structured document cannot be parsed or safely sanitized.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote

REDACTED = "[REDACTED]"

#: Metadata suffixes that describe a credential rather than contain one.
_METADATA_SUFFIXES = (
    "_ALGORITHM",
    "_ARN",
    "_COUNT",
    "_ENABLED",
    "_ENV",
    "_EXPIRES_AT",
    "_EXPIRY",
    "_FILE",
    "_FINGERPRINT",
    "_FORMAT",
    "_HEADER",
    "_HOST",
    "_ID",
    "_IDS",
    "_KIND",
    "_LENGTH",
    "_LIMIT",
    "_MIN_LENGTH",
    "_MODE",
    "_NAME",
    "_PATH",
    "_POLICY",
    "_PORT",
    "_PROVIDER",
    "_REGION",
    "_REQUIRED",
    "_SCHEME",
    "_SIZE",
    "_SOURCE",
    "_STATE",
    "_STATUS",
    "_TTL",
    "_TYPE",
    "_URI",
    "_URL",
    "_USER",
    "_USERNAME",
    "_VERSION",
)
_METADATA_EXACT = frozenset(
    {
        "api_key_required",
        "key_id",
        "password_policy",
        "public_key_fingerprint",
        "repository_id",
        "token_count",
    }
)
_HASH_SUFFIX = re.compile(r"_(?:DIGEST|HASH|SHA256)$", re.IGNORECASE)
_LOW_ENTROPY_NAME = re.compile(r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|CLIENT_SECRET)", re.IGNORECASE)
_SENSITIVE_NAME = re.compile(
    r"(?:^|_)(?:"
    r"PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|CREDENTIAL|CREDENTIALS|COOKIE|AUTHORIZATION|"
    r"API_?KEY|ACCESS_KEY|PRIVATE_KEY|SIGNING_KEY|ENCRYPTION_KEY|PAT"
    r")(?:_|$)|(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|CREDENTIAL|CREDENTIALS|"
    r"APIKEY|PRIVATEKEY|SIGNINGKEY|ENCRYPTIONKEY|CLIENTSECRET|WEBHOOKSECRET|"
    r"AWSSECRETACCESSKEY)$",
    re.IGNORECASE,
)
_SENSITIVE_HEADERS = frozenset(
    {
        "api-key",
        "apikey",
        "authorization",
        "cookie",
        "private-token",
        "proxy-authorization",
        "set-cookie",
        "x-api-key",
        "x-api-token",
        "x-apikey",
        "x-auth-token",
        "x-access-token",
        "x-gitlab-token",
        "x-secret",
        "x-token",
        "x-webhook-secret",
    }
)
_HEADER_SECRET_SUFFIXES = ("-api-key", "-apikey", "-auth", "-secret", "-token")
_AUTH_SCHEMES = frozenset({"basic", "bearer", "digest", "negotiate", "ntlm"})
_URL_SCHEMES = frozenset(
    {
        "amqp",
        "amqps",
        "ftp",
        "git",
        "http",
        "https",
        "mariadb",
        "mongodb",
        "mysql",
        "postgres",
        "postgresql",
        "redis",
        "rediss",
        "rtsp",
        "rtsps",
        "ssh",
        "ws",
        "wss",
    }
)
_SCHEME_STOPWORDS = frozenset(
    {
        "authentication",
        "authorization",
        "credential",
        "credentials",
        "header",
        "headers",
        "required",
        "scheme",
        "support",
        "supported",
        "token",
    }
)

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
    r".*?"
    r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
    re.DOTALL,
)
_PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
_URL_USERINFO = re.compile(r"(?i)\b(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<userinfo>[^/\s?#@]+)@")
_QUERY_CREDENTIAL = re.compile(
    r"(?i)(?P<prefix>[?&;](?:"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|api[_-]?key|apikey|"
    r"token|secret|password|passwd|client[_-]?secret|session(?:[_-]?id)?|jwt|ticket|"
    r"signature|sig|x-amz-signature|x-amz-credential|x-amz-security-token|"
    r"awsaccesskeyid|googleaccessid"
    r")=)(?P<value>[^&#\s\"']*)"
)
_HEADER_LINE = re.compile(
    r"(?im)(?P<name>(?<![\w-])(?:proxy-)?authorization|set-cookie|cookie|"
    r"x-[a-z0-9-]*(?:api-key|apikey|token|secret|auth)[a-z0-9-]*|"
    r"api-key|apikey|private-token|x-gitlab-token)"
    r"(?P<separator>\s*[:=]\s*)"
    r"(?P<value>[^\r\n]*)"
)
_ASSIGNMENT = re.compile(
    r"(?P<prefix>(?<![\w.-])(?:\\?[\"'])?)"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P<suffix>(?:\\?[\"'])?\s*[=:]\s*)"
    r"(?P<value>"
    r"(?i:\[redacted\])"
    r"|\\?\"(?:\\.|[^\"\\])*\\?\""
    r"|\\?'(?:\\.|[^'\\])*\\?'"
    r"|[^\s,;&}\]\)\"']+"
    r")"
)
_SCHEME_CREDENTIAL = re.compile(
    r"(?i)(?P<scheme>(?<![\w-])(?:basic|bearer|digest|negotiate|ntlm))"
    r"(?P<space>\s+)"
    r"(?P<credential>[A-Za-z0-9._~+/=-]{8,})"
)
_GITHUB_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b")
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_STRIPE_KEY = re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")
_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")


class RedactionError(ValueError):
    """Structured evidence cannot be parsed or safely sanitized."""


def _normalise_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")


def _header_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _is_marker(value: str) -> bool:
    stripped = value.strip().strip("\"'")
    if not stripped:
        return False
    lowered = stripped.lower()
    if lowered in {"[redacted]", "<redacted>", "redacted"}:
        return True
    return len(stripped) >= 3 and set(stripped) == {"*"}


def _is_metadata_suffix(normalised: str) -> bool:
    upper = normalised.upper()
    if not upper.endswith(_METADATA_SUFFIXES):
        return False
    # A low-entropy password or token hash is still credential material even
    # though hashes are normally metadata. Public key fingerprints and key IDs
    # are not affected because they do not carry a secret token.
    if _HASH_SUFFIX.search(normalised) and _LOW_ENTROPY_NAME.search(normalised):
        return False
    return True


def is_sensitive_name(name: str) -> bool:
    """Return whether *name* is a credential-bearing field or environment name."""
    if not isinstance(name, str) or not name.strip():
        return False
    normalised = _normalise_name(name)
    if not normalised or normalised in _METADATA_EXACT:
        return False
    if _SENSITIVE_NAME.search(normalised) is None:
        return False
    return not _is_metadata_suffix(normalised)


def is_sensitive_header(name: str) -> bool:
    """Return whether *name* is an HTTP header that carries credentials."""
    if not isinstance(name, str) or not name.strip():
        return False
    header = _header_name(name)
    if header in _SENSITIVE_HEADERS:
        return True
    return header.endswith(_HEADER_SECRET_SUFFIXES) and not header.endswith(("-count", "-policy"))


def _is_credential_text(value: str) -> bool:
    stripped = value.strip()
    if not stripped or _is_marker(stripped):
        return False
    lowered = stripped.lower()
    if lowered in _SCHEME_STOPWORDS:
        return False
    if any(character.isdigit() for character in stripped):
        return True
    if any(character in "._~+/=-" for character in stripped):
        return True
    return len(stripped) >= 16


def _split_quoted(value: str) -> tuple[str, str, str]:
    """Return (opening quote, inner value, closing quote) for a quoted value."""
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        return value[0], value[1:-1], value[-1]
    if (
        len(value) >= 4
        and value[0] == "\\"
        and value[1] in "\"'"
        and value[-2] == "\\"
        and value[-1] == value[1]
    ):
        return value[:2], value[2:-2], value[-2:]
    return "", value, ""


def _header_has_credential(name: str, value: str) -> bool:
    stripped = value.strip()
    if not stripped or _is_marker(stripped):
        return False
    if _header_name(name) in {"authorization", "proxy-authorization"}:
        parts = stripped.split(None, 1)
        if len(parts) == 1 and parts[0].lower() in _AUTH_SCHEMES:
            return False
        if len(parts) == 2 and parts[0].lower() in _AUTH_SCHEMES:
            return not _is_marker(parts[1].strip())
        return True
    return True


def _redact_header_value(name: str, value: str) -> str:
    stripped = value.strip()
    if not stripped or _is_marker(stripped):
        return value
    if _header_name(name) in {"authorization", "proxy-authorization"}:
        parts = stripped.split(None, 1)
        if len(parts) == 1 and parts[0].lower() in _AUTH_SCHEMES:
            return value
        if len(parts) == 2 and parts[0].lower() in _AUTH_SCHEMES:
            if _is_marker(parts[1].strip()):
                return value
            return f"{parts[0]} {REDACTED}"
        return REDACTED
    return REDACTED


def _url_userinfo_is_credential(userinfo: str) -> bool:
    decoded = unquote(userinfo)
    if ":" in decoded:
        return True
    return _is_credential_text(decoded)


def _url_userinfo_repl(match: re.Match[str]) -> str:
    if _url_userinfo_is_credential(match.group("userinfo")):
        return f"{match.group('scheme')}{REDACTED}@"
    return match.group(0)


def _query_repl(match: re.Match[str]) -> str:
    value = match.group("value")
    if not value or _is_marker(value):
        return match.group(0)
    return f"{match.group('prefix')}{REDACTED}"


def _header_repl(match: re.Match[str]) -> str:
    name = match.group("name")
    value = match.group("value")
    if not is_sensitive_header(name):
        return match.group(0)
    return f"{name}{match.group('separator')}{_redact_header_value(name, value)}"


def _assignment_repl(match: re.Match[str]) -> str:
    key = match.group("key")
    value = match.group("value")
    opening, inner, closing = _split_quoted(value)
    if key.lower() in _URL_SCHEMES and inner.startswith("//"):
        return match.group(0)
    sensitive_name = is_sensitive_name(key)
    sensitive_header = is_sensitive_header(key)
    if not sensitive_name and not sensitive_header:
        cleaned = redact_text(inner)
        if cleaned == inner:
            return match.group(0)
        return f"{match.group('prefix')}{key}{match.group('suffix')}{opening}{cleaned}{closing}"
    if _is_marker(inner):
        return match.group(0)
    if sensitive_header:
        cleaned = _redact_header_value(key, inner)
    else:
        cleaned = REDACTED
    return f"{match.group('prefix')}{key}{match.group('suffix')}{opening}{cleaned}{closing}"


def _scheme_repl(match: re.Match[str]) -> str:
    if not _is_credential_text(match.group("credential")):
        return match.group(0)
    return f"{match.group('scheme')}{match.group('space')}{REDACTED}"


def _strip_unterminated_private_key(text: str) -> str:
    match = _PRIVATE_KEY_BEGIN.search(text)
    if match is None:
        return text
    return f"{text[: match.start()]}{REDACTED}"


def redact_text(text: str) -> str:
    """Redact credential-bearing substrings while preserving safe context."""
    if not isinstance(text, str) or not text:
        return text
    redacted = _PRIVATE_KEY_BLOCK.sub(REDACTED, text)
    redacted = _strip_unterminated_private_key(redacted)
    redacted = _URL_USERINFO.sub(_url_userinfo_repl, redacted)
    redacted = _QUERY_CREDENTIAL.sub(_query_repl, redacted)
    redacted = _HEADER_LINE.sub(_header_repl, redacted)
    redacted = _ASSIGNMENT.sub(_assignment_repl, redacted)
    redacted = _SCHEME_CREDENTIAL.sub(_scheme_repl, redacted)
    redacted = _GITHUB_TOKEN.sub(REDACTED, redacted)
    redacted = _AWS_ACCESS_KEY.sub(REDACTED, redacted)
    redacted = _JWT.sub(REDACTED, redacted)
    redacted = _STRIPE_KEY.sub(REDACTED, redacted)
    redacted = _SLACK_TOKEN.sub(REDACTED, redacted)
    redacted = _GOOGLE_API_KEY.sub(REDACTED, redacted)
    return redacted


def redact_structure(value: Any) -> Any:
    """Recursively redact a JSON-like value without dropping non-secret fields."""
    if isinstance(value, Mapping):
        cleaned: dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if is_sensitive_header(key_text) or is_sensitive_name(key_text):
                cleaned[key] = REDACTED
            else:
                cleaned[key] = redact_structure(item)
        return cleaned
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_structure(item) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, bytes):
        return redact_text(value.decode("utf-8", errors="replace"))
    return value


def dump_sanitized_json(payload: Any) -> str:
    """Return canonical JSON for a sanitized copy of *payload*.

    The returned bytes are the bytes that must be persisted and hashed. The
    caller must never compute a digest over the unsanitized payload and attach
    it to the sanitized copy.
    """
    cleaned = redact_structure(payload)
    try:
        text = json.dumps(cleaned, indent=2, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise RedactionError("structured evidence cannot be serialized safely") from exc
    return text + "\n"


def sanitize_json_document(text: str) -> tuple[Any, str]:
    """Parse, sanitize, and re-serialize a JSON document.

    Invalid JSON raises :class:`RedactionError`; callers must fail closed rather
    than persist a raw document that could not be inspected.
    """
    try:
        payload = json.loads(text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RedactionError("structured evidence is not valid JSON") from exc
    return redact_structure(payload), dump_sanitized_json(payload)


def contains_url_credentials(text: str) -> bool:
    """Return whether *text* contains URL userinfo that carries a credential."""
    if not isinstance(text, str):
        return False
    return any(_url_userinfo_is_credential(match.group("userinfo")) for match in _URL_USERINFO.finditer(text))


def scan_text(text: str) -> list[str]:
    """Return sorted credential categories found in *text* without echoing values."""
    if not isinstance(text, str) or not text:
        return []
    found: set[str] = set()
    if _PRIVATE_KEY_BEGIN.search(text):
        found.add("private-key")
    if _GITHUB_TOKEN.search(text):
        found.add("github-token")
    if _AWS_ACCESS_KEY.search(text):
        found.add("aws-access-key")
    if _JWT.search(text):
        found.add("jwt")
    if _STRIPE_KEY.search(text):
        found.add("stripe-key")
    if _SLACK_TOKEN.search(text):
        found.add("slack-token")
    if _GOOGLE_API_KEY.search(text):
        found.add("google-api-key")
    for match in _HEADER_LINE.finditer(text):
        name = match.group("name")
        if not is_sensitive_header(name):
            continue
        if not _header_has_credential(name, match.group("value")):
            continue
        if _header_name(name) in {"authorization", "proxy-authorization"}:
            found.add("authorization-header")
        elif _header_name(name) in {"cookie", "set-cookie"}:
            found.add("cookie-header")
        else:
            found.add("api-key-header")
    for match in _URL_USERINFO.finditer(text):
        if _url_userinfo_is_credential(match.group("userinfo")):
            found.add("credential-url")
    for match in _QUERY_CREDENTIAL.finditer(text):
        if not _is_marker(match.group("value")):
            found.add("credential-url")
    for match in _ASSIGNMENT.finditer(text):
        key = match.group("key")
        _, inner, _ = _split_quoted(match.group("value"))
        if key.lower() in _URL_SCHEMES and inner.startswith("//"):
            continue
        if not (is_sensitive_name(key) or is_sensitive_header(key)):
            found.update(scan_text(inner))
            continue
        if _is_marker(inner):
            continue
        if is_sensitive_header(key):
            if not _header_has_credential(key, inner):
                continue
            if _header_name(key) in {"authorization", "proxy-authorization"}:
                found.add("authorization-header")
            elif _header_name(key) in {"cookie", "set-cookie"}:
                found.add("cookie-header")
            else:
                found.add("api-key-header")
            continue
        normalised = _normalise_name(key)
        if "csrf" in normalised or "ticket" in normalised or normalised.endswith("_session_token"):
            found.add("csrf-or-ticket")
        else:
            found.add("secret-assignment")
    for match in _SCHEME_CREDENTIAL.finditer(text):
        if _is_credential_text(match.group("credential")):
            found.add("authorization-header")
    return sorted(found)


def contains_sensitive_material(text: str) -> bool:
    """Return whether *text* contains any supported credential material."""
    return bool(scan_text(text))


def redact_url(url: str) -> str:
    """Redact credentials from a URL without changing its safe route metadata."""
    return redact_text(url)
