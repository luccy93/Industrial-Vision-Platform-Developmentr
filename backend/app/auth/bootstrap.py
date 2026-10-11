"""One-time administrator bootstrap (V16).

No public registration and no shipped default credentials: the first
administrator is created explicitly against the real configured
database (which must already be migrated)::

    python -m backend.app.auth.bootstrap --email ops@example.com

The password is read securely via ``getpass`` (never from argv, never
printed, never logged). Refuses when an active administrator already
exists. Ordinary startup never seeds credentials.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from datetime import UTC, datetime

from backend.app.auth.passwords import PasswordPolicyError, hash_password, validate_password
from backend.app.auth.repository import AuthRepository, BootstrapExistsError, UserExistsError
from backend.app.auth.sessions import normalize_email, validate_email_shape
from backend.app.core.config import get_settings
from backend.app.infrastructure.db import get_session_factory


def bootstrap_admin(
    repository: AuthRepository,
    *,
    email: str,
    password: str,
    now: datetime | None = None,
):  # type: ignore[no-untyped-def]
    """Service-level bootstrap path (used by the CLI and automated tests)."""
    normalized = normalize_email(email)
    validate_email_shape(normalized)
    validate_password(password)
    moment = now or datetime.now(UTC)
    return repository.bootstrap_admin(
        email=normalized, password_hash=hash_password(password), now=moment
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create the first V16 administrator.")
    parser.add_argument("--email", required=True, help="Administrator login email.")
    args = parser.parse_args(argv)
    try:
        normalized = normalize_email(args.email)
        validate_email_shape(normalized)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        password = getpass.getpass("Administrator password: ")
        confirm = getpass.getpass("Confirm password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nerror: aborted.", file=sys.stderr)
        return 2
    if password != confirm:
        print("error: passwords do not match.", file=sys.stderr)
        return 2
    try:
        validate_password(password)
    except PasswordPolicyError as exc:
        print(f"error: {exc} (minimum 15 characters)", file=sys.stderr)
        return 2
    settings = get_settings()
    repository = AuthRepository(get_session_factory(str(settings.database_url)))
    try:
        created = bootstrap_admin(repository, email=normalized, password=password)
    except (BootstrapExistsError, UserExistsError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"administrator created: {created.email} (id {created.id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
