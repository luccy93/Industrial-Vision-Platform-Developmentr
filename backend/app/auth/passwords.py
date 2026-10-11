"""Password policy and Argon2id hashing (V16).

Locked V16 policy: 15–128 characters, Unicode and spaces supported, no
mandatory character-class rules, no routine rotation, salted Argon2id
hashes, and a shipped common/compromised-password blocklist (offline;
online breach-corpus checks are a documented limitation).

Passwords are never truncated: over-length values are rejected. Error
messages never echo the candidate value.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError

MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128

#: Curated offline blocklist of common/compromised passwords (compared
#: case-insensitively). Shannon-level coverage of online breach corpora
#: is intentionally out of scope for offline deployments.
COMMON_PASSWORD_BLOCKLIST = frozenset(
    {
        "password",
        "password1",
        "password123",
        "password123!",
        "passwordpassword",
        "changeme",
        "changeme123",
        "letmein",
        "letmein123",
        "welcome",
        "welcome123",
        "admin",
        "admin123",
        "administrator",
        "qwerty",
        "qwerty123",
        "qwertyuiop",
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "111111",
        "000000",
        "abc123",
        "abcd1234",
        "iloveyou",
        "monkey",
        "dragon",
        "master",
        "sunshine",
        "princess",
        "football",
        "superman",
        "michael",
        "jesus",
        "trustno1",
        "passw0rd",
        "p@ssw0rd",
        "p@ssword",
        "p@ssword123",
        "industrial",
        "vision",
        "safety",
        "operator",
        "viewer",
        "factory",
        "camera",
        "cameras",
        "secure123",
        "test123",
        "demo1234",
    }
)


class PasswordPolicyError(ValueError):
    """Raised when a candidate password violates policy (no value echoed)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_hasher = PasswordHasher()


def validate_password(candidate: object) -> None:
    """Enforce the V16 password policy; raises ``PasswordPolicyError``."""
    if not isinstance(candidate, str) or not candidate:
        raise PasswordPolicyError("password_required", "A password is required.")
    if len(candidate) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            "password_too_short",
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters.",
        )
    if len(candidate) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            "password_too_long",
            f"Password must be at most {MAX_PASSWORD_LENGTH} characters.",
        )
    if candidate.strip() != candidate and len(candidate.strip()) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            "password_too_short",
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters.",
        )
    if candidate.lower() in COMMON_PASSWORD_BLOCKLIST:
        raise PasswordPolicyError(
            "password_blocklisted",
            "Password is too common; choose a less predictable password.",
        )


def hash_password(candidate: str) -> str:
    """Validate policy, then return a salted Argon2id hash."""
    validate_password(candidate)
    return _hasher.hash(candidate)


def verify_password(stored_hash: str, candidate: str) -> bool:
    """Constant-shape verification; False on mismatch or malformed hash."""
    try:
        return bool(_hasher.verify(stored_hash, candidate))
    except (VerifyMismatchError, InvalidHash, AttributeError, TypeError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True when the stored hash no longer matches current parameters."""
    try:
        return bool(_hasher.check_needs_rehash(stored_hash))
    except (InvalidHash, AttributeError):
        return True
