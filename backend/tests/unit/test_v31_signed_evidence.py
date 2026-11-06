"""V31 signed-checkpoint, trust-store, and key-lifecycle tests.

All keys, evidence, reports, manifests, audit chains, trust stores, and trust
states are synthetic and live under pytest's temporary directory. The tests
never contact a network service, cloud KMS, registry, release endpoint, or real
credential. Private keys are generated per test and never printed or committed.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from backend.app.core.redaction import REDACTED, dump_sanitized_json
from tools.release.cli import main
from tools.release.evidence_verification import (
    render_verification_json,
    seal_report_evidence,
    verify_audit_file,
    verify_report,
)
from tools.release.integrity import (
    canonical_json_bytes,
)
from tools.release.trust import (
    AUDIT_HASH_ROLLBACK,
    CHAIN_TRUNCATION,
    CHECKPOINT_ALGORITHM_UNKNOWN,
    CHECKPOINT_CONFLICT,
    CHECKPOINT_ID_MISMATCH,
    CHECKPOINT_ID_REUSED,
    CHECKPOINT_MANIFEST_MISMATCH,
    CHECKPOINT_PAYLOAD_DIGEST_MISMATCH,
    CHECKPOINT_REPLAY,
    CHECKPOINT_REPORT_MISMATCH,
    CHECKPOINT_SCHEMA_INVALID,
    CHECKPOINT_SEQUENCE_DECREASING,
    CHECKPOINT_SEQUENCE_DUPLICATE,
    CHECKPOINT_SEQUENCE_INVALID,
    CHECKPOINT_SIGNATURE_MALFORMED,
    CHECKPOINT_SIGNATURE_MISMATCH,
    CHECKPOINT_TIMESTAMP_INCONSISTENT,
    CHECKPOINT_TIMESTAMP_INVALID,
    CHECKPOINT_UNSIGNED,
    EXTERNAL_ANCHOR_MISMATCH,
    EXTERNAL_ANCHOR_REFERENCE_MISSING,
    EXTERNAL_ANCHOR_UNCONFIGURED,
    HISTORICAL_REVOCATION_ALLOW,
    HISTORICAL_REVOCATION_DENY,
    INDEPENDENT_FRESHNESS_UNAVAILABLE,
    MANIFEST_DIGEST_ROLLBACK,
    PRIVATE_KEY_INVALID,
    SIGNED_CHECKPOINT_DOMAIN,
    SIGNED_CHECKPOINT_REQUIRES_REPORT,
    TRUST_FINGERPRINT_MISMATCH,
    TRUST_KEY_ALGORITHM_DISALLOWED,
    TRUST_KEY_EXPIRED,
    TRUST_KEY_NOT_YET_VALID,
    TRUST_KEY_PURPOSE_INVALID,
    TRUST_KEY_REVOKED,
    TRUST_KEY_UNKNOWN,
    TRUST_KEY_UNTRUSTED,
    TRUST_STATE_MISSING,
    TRUST_STORE_INVALID,
    TRUST_STORE_MISSING,
    ExternalTrustAnchor,
    TrustConflict,
    TrustInvalid,
    TrustUnavailable,
    activate_key,
    advance_trust_state,
    build_signed_checkpoint_payload,
    checkpoint_payload,
    checkpoint_payload_digest,
    create_signed_checkpoint,
    decode_public_key,
    derive_checkpoint_id,
    evaluate_trust_state,
    expire_key,
    export_public_key,
    generate_key_files,
    load_private_key,
    load_public_key_descriptor,
    load_signed_checkpoint,
    load_trust_state,
    load_trust_store,
    new_trust_store,
    register_public_key,
    revoke_key,
    rotate_key,
    sign_checkpoint_payload,
    signed_payload_bytes,
    trust_state_entry,
    validate_signed_checkpoint,
    validate_trust_store,
    verify_signed_checkpoint,
    write_private_key,
    write_signed_checkpoint,
    write_trust_store,
)
from tools.release.verification import FAIL, NOT_RUN, PASS, UNAVAILABLE

REPO_ROOT = Path(__file__).resolve().parents[3]
SENTINEL = "v31_test_sentinel_do_not_disclose"
T0 = "2026-11-01T00:00:00Z"
T1 = "2026-11-04T00:00:00Z"
T2 = "2026-11-04T00:00:10Z"
T3 = "2026-11-05T00:00:00Z"
T4 = "2027-01-01T00:00:00Z"


def _sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8", newline="\n")
    else:
        path.write_bytes(data)
    return path


def _evidence_report(entries: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "profile": "test",
        "generated_at": T1,
        "evidence": entries,
    }
    payload.update(overrides)
    return payload


def _bound(path: str, data: bytes | str, **overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "kind": "evidence",
        "path": path,
        "sha256": _sha(data),
        "state": PASS,
    }
    entry.update(overrides)
    return entry


def _write_report(path: Path, payload: dict[str, Any]) -> Path:
    return _write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _sealed(
    tmp_path: Path,
    *,
    files: dict[str, bytes] | None = None,
) -> tuple[Path, Path, Path, Path]:
    files = files or {"target.json": b'{"safe": "value"}\n'}
    evidence_root = tmp_path / "evidence"
    entries = []
    for name, data in files.items():
        _write(evidence_root / name, data)
        entries.append(_bound(name, data, kind="evidence"))
    report_path = _write_report(tmp_path / "report.json", _evidence_report(entries))
    integrity_path = tmp_path / "report.integrity.json"
    audit_path = tmp_path / "report.audit.jsonl"
    seal_report_evidence(
        report_path,
        integrity_path=integrity_path,
        audit_path=audit_path,
        evidence_root=evidence_root,
        timestamp=T1,
    )
    return report_path, evidence_root, integrity_path, audit_path


def _key(
    tmp_path: Path,
    key_id: str = "key-one",
    *,
    generated_at: str = T1,
) -> tuple[Path, dict[str, Any]]:
    private_key = tmp_path / "keys" / f"{key_id}.pem"
    public_key = tmp_path / "keys" / f"{key_id}.pub.json"
    generate_key_files(
        key_id=key_id,
        private_key_path=private_key,
        public_key_path=public_key,
        generated_at=generated_at,
    )
    return private_key, load_public_key_descriptor(public_key)


def _store(
    tmp_path: Path,
    descriptor: dict[str, Any],
    *,
    activated_at: str = T0,
    expires_at: str | None = None,
    historical_policy: str = HISTORICAL_REVOCATION_ALLOW,
) -> tuple[Path, Any]:
    store = register_public_key(
        new_trust_store(historical_revocation_policy=historical_policy),
        descriptor,
        activated_at=activated_at,
        expires_at=expires_at,
    )
    path = tmp_path / "trust-store.json"
    write_trust_store(path, store)
    return path, store


def _checkpoint(
    report_path: Path,
    integrity_path: Path,
    audit_path: Path,
    private_key: Path,
    *,
    key_id: str = "key-one",
    sequence: int = 1,
    created_at: str = T2,
) -> dict[str, Any]:
    return create_signed_checkpoint(
        audit_path=audit_path,
        report_path=report_path,
        integrity_path=integrity_path,
        private_key_path=private_key,
        key_id=key_id,
        sequence=sequence,
        created_at=created_at,
    )


def _signed_setup(tmp_path: Path) -> dict[str, Any]:
    report_path, evidence_root, integrity_path, audit_path = _sealed(tmp_path)
    private_key, descriptor = _key(tmp_path)
    store_path, store = _store(tmp_path, descriptor)
    checkpoint = _checkpoint(report_path, integrity_path, audit_path, private_key)
    checkpoint_path = tmp_path / "report.signed-checkpoint.json"
    write_signed_checkpoint(checkpoint_path, checkpoint)
    return {
        "report_path": report_path,
        "evidence_root": evidence_root,
        "integrity_path": integrity_path,
        "audit_path": audit_path,
        "private_key": private_key,
        "descriptor": descriptor,
        "store_path": store_path,
        "store": store,
        "checkpoint": checkpoint,
        "checkpoint_path": checkpoint_path,
        "trust_state_path": tmp_path / "trust-state.json",
    }


def _verify(setup: dict[str, Any], **overrides: Any):
    kwargs: dict[str, Any] = {
        "report_path": setup["report_path"],
        "integrity_path": setup["integrity_path"],
        "audit_path": setup["audit_path"],
        "trust_store_path": setup["store_path"],
        "trust_state_path": setup["trust_state_path"],
    }
    kwargs.update(overrides)
    checkpoint = kwargs.pop("checkpoint", setup["checkpoint"])
    return verify_signed_checkpoint(checkpoint, **kwargs)


def _check(result: Any, name: str) -> Any:
    return next(check for check in result.checks if check.name == name)


def _rehash_payload(checkpoint: dict[str, Any]) -> dict[str, Any]:
    """Recompute ID, digest, and signature after a payload mutation."""
    payload = checkpoint_payload(checkpoint)
    payload["checkpoint_id"] = derive_checkpoint_id(payload)
    return sign_checkpoint_payload(payload, load_private_key(Path(checkpoint["_key_path"])))


# ---------------------------------------------------------------------------
# Signed checkpoint schema, canonicalization, and signatures
# ---------------------------------------------------------------------------


class TestSignedCheckpoint:
    def test_schema_accepts_generated_checkpoint(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        schema = json.loads(
            (REPO_ROOT / "release" / "signed-checkpoint.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(setup["checkpoint"])

    def test_checkpoint_is_bound_to_report_manifest_and_audit(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        checkpoint = setup["checkpoint"]
        assert checkpoint["evidence_report_id"] == f"report:{_sha(setup['report_path'].read_bytes())}"
        assert checkpoint["evidence_manifest_digest"] == _sha(setup["integrity_path"].read_bytes())
        audit_records = setup["audit_path"].read_text(encoding="utf-8").splitlines()
        assert checkpoint["audit_record_count"] == len(audit_records)
        assert checkpoint["audit_chain_terminal_hash"] == json.loads(audit_records[-1])["record_hash"]

    def test_canonical_payload_is_deterministic(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        checkpoint = setup["checkpoint"]
        payload = checkpoint_payload(checkpoint)
        assert signed_payload_bytes(payload) == SIGNED_CHECKPOINT_DOMAIN + canonical_json_bytes(payload)
        assert checkpoint_payload_digest(payload) == checkpoint["payload_digest"]

    def test_domain_prefix_is_required(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        checkpoint = setup["checkpoint"]
        payload = checkpoint_payload(checkpoint)
        private_key = load_private_key(setup["private_key"])
        checkpoint["signature"] = private_key.sign(canonical_json_bytes(payload)).hex()
        result = _verify(setup, checkpoint=checkpoint)
        assert result.outcome == FAIL
        assert CHECKPOINT_SIGNATURE_MISMATCH in result.reason_codes

    def test_unknown_algorithm_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        payload = checkpoint_payload(setup["checkpoint"])
        payload["signature_algorithm"] = "rsa-pss"
        with pytest.raises(TrustInvalid) as excinfo:
            build_signed_checkpoint_payload(
                evidence_report_id=payload["evidence_report_id"],
                audit_chain_terminal_hash=payload["audit_chain_terminal_hash"],
                audit_chain_terminal_event_id=payload["audit_chain_terminal_event_id"],
                audit_chain_terminal_timestamp=payload["audit_chain_terminal_timestamp"],
                audit_record_count=payload["audit_record_count"],
                evidence_manifest_digest=payload["evidence_manifest_digest"],
                checkpoint_sequence=payload["checkpoint_sequence"],
                created_at=payload["created_at"],
                key_id=payload["key_id"],
                public_key=payload["public_key"],
                public_key_fingerprint_value=payload["public_key_fingerprint"],
                signature_algorithm="rsa-pss",
            )
        assert excinfo.value.reason_code == CHECKPOINT_ALGORITHM_UNKNOWN

    @pytest.mark.parametrize("signature", ["", "zz", "0" * 127, "0" * 129])
    def test_malformed_signature_is_rejected(self, tmp_path: Path, signature: str) -> None:
        setup = _signed_setup(tmp_path)
        checkpoint = dict(setup["checkpoint"])
        checkpoint["signature"] = signature
        with pytest.raises(TrustInvalid) as excinfo:
            validate_signed_checkpoint(checkpoint)
        assert excinfo.value.reason_code == CHECKPOINT_SIGNATURE_MALFORMED

    def test_signature_mismatch_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        checkpoint = dict(setup["checkpoint"])
        checkpoint["signature"] = "0" * 128
        result = _verify(setup, checkpoint=checkpoint)
        assert result.outcome == FAIL
        assert CHECKPOINT_SIGNATURE_MISMATCH in result.reason_codes

    def test_payload_digest_mismatch_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        checkpoint = dict(setup["checkpoint"])
        checkpoint["payload_digest"] = "sha256:" + "0" * 64
        with pytest.raises(TrustInvalid) as excinfo:
            validate_signed_checkpoint(checkpoint)
        assert excinfo.value.reason_code == CHECKPOINT_PAYLOAD_DIGEST_MISMATCH

    def test_checkpoint_id_mismatch_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        checkpoint = dict(setup["checkpoint"])
        checkpoint["checkpoint_id"] = "chk-" + "0" * 32
        with pytest.raises(TrustInvalid) as excinfo:
            validate_signed_checkpoint(checkpoint)
        assert excinfo.value.reason_code == CHECKPOINT_ID_MISMATCH

    def test_extra_or_missing_fields_are_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        checkpoint = dict(setup["checkpoint"])
        checkpoint["extra"] = "value"
        with pytest.raises(TrustInvalid) as excinfo:
            validate_signed_checkpoint(checkpoint)
        assert excinfo.value.reason_code == CHECKPOINT_SCHEMA_INVALID
        missing = dict(setup["checkpoint"])
        del missing["key_id"]
        with pytest.raises(TrustInvalid):
            validate_signed_checkpoint(missing)

    def test_duplicate_json_fields_are_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        text = setup["checkpoint_path"].read_text(encoding="utf-8")
        duplicated = text.replace(
            '"key_id": "key-one"',
            '"key_id": "key-one", "key_id": "key-one"',
            1,
        )
        path = _write(tmp_path / "duplicate.json", duplicated)
        with pytest.raises(TrustInvalid) as excinfo:
            load_signed_checkpoint(path)
        assert excinfo.value.reason_code == CHECKPOINT_SCHEMA_INVALID

    @pytest.mark.parametrize("value", [0, -1, True, "1", 1.5, None])
    def test_invalid_sequence_values_are_rejected(self, tmp_path: Path, value: Any) -> None:
        setup = _signed_setup(tmp_path)
        payload = checkpoint_payload(setup["checkpoint"])
        payload["checkpoint_sequence"] = value
        payload["checkpoint_id"] = derive_checkpoint_id(payload)
        with pytest.raises(TrustInvalid) as excinfo:
            validate_signed_checkpoint(
                {
                    **payload,
                    "payload_digest": checkpoint_payload_digest(payload),
                    "signature_encoding": "hex",
                    "signature": "0" * 128,
                }
            )
        assert excinfo.value.reason_code == CHECKPOINT_SEQUENCE_INVALID

    @pytest.mark.parametrize(
        "field_name",
        ["created_at", "audit_chain_terminal_timestamp"],
    )
    def test_invalid_timestamps_are_rejected(self, tmp_path: Path, field_name: str) -> None:
        setup = _signed_setup(tmp_path)
        payload = checkpoint_payload(setup["checkpoint"])
        payload[field_name] = "2026-11-04 00:00:00"
        payload["checkpoint_id"] = derive_checkpoint_id(payload)
        with pytest.raises(TrustInvalid) as excinfo:
            validate_signed_checkpoint(
                {
                    **payload,
                    "payload_digest": checkpoint_payload_digest(payload),
                    "signature_encoding": "hex",
                    "signature": "0" * 128,
                }
            )
        assert excinfo.value.reason_code == CHECKPOINT_TIMESTAMP_INVALID

    def test_verification_does_not_regenerate_signature(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        checkpoint = dict(setup["checkpoint"])
        checkpoint["signature"] = "0" * 128
        before = checkpoint["signature"]
        _verify(setup, checkpoint=checkpoint)
        assert checkpoint["signature"] == before

    def test_report_binding_mismatch_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        other_report = _write(tmp_path / "other-report.json", b'{"different": true}\n')
        result = _verify(setup, report_path=other_report)
        assert result.outcome == FAIL
        assert CHECKPOINT_REPORT_MISMATCH in result.reason_codes

    def test_manifest_binding_mismatch_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        other_manifest = _write(tmp_path / "other-integrity.json", b"{}\n")
        result = _verify(setup, integrity_path=other_manifest)
        assert result.outcome == FAIL
        assert CHECKPOINT_MANIFEST_MISMATCH in result.reason_codes


# ---------------------------------------------------------------------------
# Trust store: explicit trust, lifecycle, and fail-safe behavior
# ---------------------------------------------------------------------------


class TestTrustStore:
    def test_schema_accepts_generated_store(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        schema = json.loads((REPO_ROOT / "release" / "trust-store.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(setup["store"].to_dict())

    def test_trusted_key_verifies(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        result = _verify(setup)
        assert result.outcome == PASS
        assert result.trust is not None
        assert result.trust["source"] == "trust_store"
        assert result.trust["trusted"] is True
        assert result.trust["fingerprint"] == setup["descriptor"]["fingerprint"]

    def test_missing_trust_store_is_unavailable(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        result = _verify(setup, trust_store_path=None)
        assert result.outcome == UNAVAILABLE
        assert TRUST_STORE_MISSING in result.reason_codes
        assert result.assurance == "reduced"

    def test_missing_trust_store_file_is_unavailable(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        result = _verify(setup, trust_store_path=tmp_path / "absent.json")
        assert result.outcome == UNAVAILABLE
        assert TRUST_STORE_MISSING in result.reason_codes

    def test_unknown_key_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        other_private, other_descriptor = _key(tmp_path, "other-key")
        other_store_path, _ = _store(tmp_path, other_descriptor)
        result = _verify(setup, trust_store_path=other_store_path)
        assert result.outcome == FAIL
        assert TRUST_KEY_UNKNOWN in result.reason_codes

    def test_checkpoint_key_is_not_trusted_by_self_assertion(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        # An attacker generates a key and signs a checkpoint with it. The
        # checkpoint carries the matching public key, but no trust store entry
        # exists for it.
        attacker_key, _ = _key(tmp_path, "attacker-key")
        attacker_checkpoint = _checkpoint(
            setup["report_path"],
            setup["integrity_path"],
            setup["audit_path"],
            attacker_key,
            key_id="attacker-key",
        )
        result = _verify(setup, checkpoint=attacker_checkpoint)
        assert result.outcome == FAIL
        assert TRUST_KEY_UNKNOWN in result.reason_codes
        assert result.trust is not None
        assert result.trust["trusted"] is False

    def test_fingerprint_pin_verifies_without_store(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        result = _verify(
            setup,
            trust_store_path=None,
            trusted_key_fingerprint=setup["descriptor"]["fingerprint"],
        )
        assert result.outcome == PASS
        assert result.trust is not None
        assert result.trust["source"] == "fingerprint_pin"
        assert result.assurance == "reduced"
        assert any("Fingerprint pinning" in item for item in result.limitations)

    def test_fingerprint_pin_mismatch_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        result = _verify(
            setup,
            trust_store_path=None,
            trusted_key_fingerprint="sha256:" + "0" * 64,
        )
        assert result.outcome == FAIL
        assert TRUST_KEY_UNTRUSTED in result.reason_codes

    def test_invalid_fingerprint_pin_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        result = _verify(
            setup,
            trust_store_path=None,
            trusted_key_fingerprint="not-a-fingerprint",
        )
        assert result.outcome == FAIL
        assert TRUST_FINGERPRINT_MISMATCH in result.reason_codes

    def test_store_and_pin_must_agree(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        _, other_descriptor = _key(tmp_path, "other-key")
        result = _verify(
            setup,
            trusted_key_fingerprint=other_descriptor["fingerprint"],
        )
        assert result.outcome == FAIL
        assert TRUST_KEY_UNTRUSTED in result.reason_codes

    def test_malformed_store_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        payload = setup["store"].to_dict()
        payload["unexpected"] = True
        path = _write(tmp_path / "bad-store.json", json.dumps(payload))
        result = _verify(setup, trust_store_path=path)
        assert result.outcome == FAIL
        assert TRUST_STORE_INVALID in result.reason_codes

    def test_duplicate_key_ids_are_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        payload = setup["store"].to_dict()
        payload["keys"].append(dict(payload["keys"][0]))
        with pytest.raises(TrustInvalid) as excinfo:
            validate_trust_store(payload)
        assert excinfo.value.reason_code == TRUST_STORE_INVALID

    def test_duplicate_fingerprints_are_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        payload = setup["store"].to_dict()
        duplicate = dict(payload["keys"][0])
        duplicate["key_id"] = "another-key"
        payload["keys"].append(duplicate)
        with pytest.raises(TrustInvalid) as excinfo:
            validate_trust_store(payload)
        assert excinfo.value.reason_code == TRUST_STORE_INVALID

    def test_wrong_fingerprint_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        payload = setup["store"].to_dict()
        payload["keys"][0]["fingerprint"] = "sha256:" + "0" * 64
        with pytest.raises(TrustInvalid) as excinfo:
            validate_trust_store(payload)
        assert excinfo.value.reason_code == TRUST_FINGERPRINT_MISMATCH

    def test_unsupported_algorithm_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        payload = setup["store"].to_dict()
        payload["keys"][0]["allowed_algorithms"] = ["rsa-pss"]
        with pytest.raises(TrustInvalid) as excinfo:
            validate_trust_store(payload)
        assert excinfo.value.reason_code == TRUST_KEY_ALGORITHM_DISALLOWED

    def test_wrong_purpose_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        payload = setup["store"].to_dict()
        payload["keys"][0]["purpose"] = "tls_server"
        with pytest.raises(TrustInvalid) as excinfo:
            validate_trust_store(payload)
        assert excinfo.value.reason_code == TRUST_KEY_PURPOSE_INVALID

    def test_invalid_lifecycle_timestamps_are_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        payload = setup["store"].to_dict()
        payload["keys"][0]["expires_at"] = T0
        with pytest.raises(TrustInvalid) as excinfo:
            validate_trust_store(payload)
        assert excinfo.value.reason_code == TRUST_STORE_INVALID

    def test_revocation_reason_requires_revoked_at(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        payload = setup["store"].to_dict()
        payload["keys"][0]["revocation_reason"] = "compromised"
        with pytest.raises(TrustInvalid) as excinfo:
            validate_trust_store(payload)
        assert excinfo.value.reason_code == TRUST_STORE_INVALID

    def test_sensitive_revocation_reason_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        store = revoke_key(
            setup["store"],
            "key-one",
            revoked_at=T3,
            reason="compromised",
        )
        payload = store.to_dict()
        payload["keys"][0]["revocation_reason"] = f"password={SENTINEL}"
        with pytest.raises(TrustInvalid) as excinfo:
            validate_trust_store(payload)
        assert excinfo.value.reason_code == TRUST_STORE_INVALID

    def test_historical_revocation_allow_verifies_old_checkpoint(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        store = revoke_key(setup["store"], "key-one", revoked_at=T3, reason="rotation")
        write_trust_store(setup["store_path"], store)
        result = _verify(setup)
        assert result.outcome == PASS
        assert result.trust is not None
        assert result.trust["status"] == "revoked_historical"
        assert result.trust["historical"] is True

    def test_historical_revocation_deny_blocks_old_checkpoint(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        store = revoke_key(setup["store"], "key-one", revoked_at=T3, reason="rotation")
        payload = store.to_dict()
        payload["historical_revocation_policy"] = HISTORICAL_REVOCATION_DENY
        write_trust_store(setup["store_path"], validate_trust_store(payload))
        result = _verify(setup)
        assert result.outcome == FAIL
        assert TRUST_KEY_REVOKED in result.reason_codes

    def test_revocation_before_checkpoint_blocks_new_trust(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        store = revoke_key(setup["store"], "key-one", revoked_at=T0, reason="compromised")
        write_trust_store(setup["store_path"], store)
        result = _verify(setup)
        assert result.outcome == FAIL
        assert TRUST_KEY_REVOKED in result.reason_codes

    def test_expired_key_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        store = expire_key(setup["store"], "key-one", expires_at=T1)
        write_trust_store(setup["store_path"], store)
        result = _verify(setup)
        assert result.outcome == FAIL
        assert TRUST_KEY_EXPIRED in result.reason_codes

    def test_not_yet_valid_key_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        store = activate_key(setup["store"], "key-one", activated_at=T3)
        write_trust_store(setup["store_path"], store)
        result = _verify(setup)
        assert result.outcome == FAIL
        assert TRUST_KEY_NOT_YET_VALID in result.reason_codes


# ---------------------------------------------------------------------------
# Key lifecycle
# ---------------------------------------------------------------------------


class TestKeyLifecycle:
    def test_generate_export_and_fingerprint_are_consistent(self, tmp_path: Path) -> None:
        private_key, descriptor = _key(tmp_path, "lifecycle-key")
        exported = export_public_key(
            private_key_path=private_key,
            key_id="lifecycle-key",
            generated_at=T1,
        )
        assert exported == descriptor
        assert (
            descriptor["fingerprint"]
            == "sha256:" + hashlib.sha256(decode_public_key(descriptor["public_key"])).hexdigest()
        )

    def test_generate_refuses_to_overwrite(self, tmp_path: Path) -> None:
        private_key, _ = _key(tmp_path, "no-overwrite")
        with pytest.raises(TrustConflict):
            generate_key_files(
                key_id="no-overwrite",
                private_key_path=private_key,
                generated_at=T1,
            )

    def test_register_is_explicit_and_replacement_is_not_automatic(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        # Merely generating a replacement key does not alter the trust store.
        _key(tmp_path, "replacement-key")
        store = load_trust_store(setup["store_path"])
        assert [key.key_id for key in store.keys] == ["key-one"]
        with pytest.raises(TrustConflict):
            register_public_key(store, setup["descriptor"])

    def test_activation_can_move_forward(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        updated = activate_key(setup["store"], "key-one", activated_at=T3)
        assert updated.key_by_id("key-one").activated_at == T3

    def test_activation_after_expiration_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        store = expire_key(setup["store"], "key-one", expires_at=T3)
        with pytest.raises(TrustConflict):
            activate_key(store, "key-one", activated_at=T4)

    def test_expire_then_rotate_preserves_historical_verification(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        replacement_private, replacement_descriptor = _key(tmp_path, "replacement-key")
        store = rotate_key(
            setup["store"],
            replacement_descriptor,
            activated_at=T3,
            revoke_old_key_id="key-one",
            revoke_at=T3,
            reason="scheduled rotation",
        )
        write_trust_store(setup["store_path"], store)
        historical = _verify(setup)
        assert historical.outcome == PASS
        assert historical.trust is not None
        assert historical.trust["status"] == "revoked_historical"
        new_checkpoint = _checkpoint(
            setup["report_path"],
            setup["integrity_path"],
            setup["audit_path"],
            replacement_private,
            key_id="replacement-key",
            sequence=2,
            created_at=T3,
        )
        fresh = _verify(setup, checkpoint=new_checkpoint)
        assert fresh.outcome == PASS
        assert fresh.trust is not None
        assert fresh.trust["key_id"] == "replacement-key"

    def test_rotation_with_deny_policy_blocks_historical(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        replacement_private, replacement_descriptor = _key(tmp_path, "replacement-key")
        store = rotate_key(
            setup["store"],
            replacement_descriptor,
            activated_at=T3,
            revoke_old_key_id="key-one",
            revoke_at=T3,
            reason="scheduled rotation",
        )
        payload = store.to_dict()
        payload["historical_revocation_policy"] = HISTORICAL_REVOCATION_DENY
        write_trust_store(setup["store_path"], validate_trust_store(payload))
        historical = _verify(setup)
        assert historical.outcome == FAIL
        assert TRUST_KEY_REVOKED in historical.reason_codes

    def test_rotate_requires_new_key_id(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        with pytest.raises(TrustConflict):
            rotate_key(
                setup["store"],
                setup["descriptor"],
                revoke_old_key_id="key-one",
                revoke_at=T3,
            )

    def test_private_key_is_not_in_public_descriptor(self, tmp_path: Path) -> None:
        private_key, descriptor = _key(tmp_path, "public-only")
        serialized = json.dumps(descriptor, sort_keys=True)
        assert "PRIVATE KEY" not in serialized
        assert private_key.read_text(encoding="utf-8") not in serialized

    def test_private_key_must_be_ed25519(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "not-a-key.pem", "not a private key")
        with pytest.raises(TrustInvalid) as excinfo:
            load_private_key(path)
        assert excinfo.value.reason_code == PRIVATE_KEY_INVALID

    def test_missing_private_key_is_unavailable(self, tmp_path: Path) -> None:
        with pytest.raises(TrustUnavailable) as excinfo:
            load_private_key(tmp_path / "absent.pem")
        assert excinfo.value.reason_code == PRIVATE_KEY_INVALID

    @pytest.mark.skipif(os.name != "posix", reason="POSIX file-mode semantics are required")
    def test_private_key_permissions_are_restricted(self, tmp_path: Path) -> None:
        private_key, _ = _key(tmp_path, "permissions")
        mode = stat.S_IMODE(private_key.stat().st_mode)
        assert mode & 0o077 == 0
        assert mode & 0o400

    @pytest.mark.skipif(os.name == "posix", reason="Windows best-effort permissions differ")
    def test_private_key_permissions_are_platform_best_effort(self, tmp_path: Path) -> None:
        private_key, _ = _key(tmp_path, "permissions")
        # Windows does not expose POSIX mode bits; the writer still uses an
        # exclusive create and never widens access explicitly.
        assert private_key.is_file()

    def test_private_key_write_never_overwrites(self, tmp_path: Path) -> None:
        private_key, _ = _key(tmp_path, "exclusive")
        before = private_key.read_bytes()
        with pytest.raises(TrustConflict):
            write_private_key(private_key, load_private_key(private_key))
        assert private_key.read_bytes() == before


# ---------------------------------------------------------------------------
# Rollback, replay, and freshness
# ---------------------------------------------------------------------------


def _state_with(tmp_path: Path, checkpoints: list[dict[str, Any]]) -> Path:
    path = tmp_path / "trust-state.json"
    for checkpoint in checkpoints:
        advance_trust_state(
            path,
            trust_state_entry(checkpoint),
            updated_at=checkpoint["created_at"],
        )
    return path


class TestRollbackAndReplay:
    def test_missing_trust_state_reports_reduced_assurance(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        result = _verify(setup, trust_state_path=None)
        assert result.outcome == PASS
        assert result.assurance == "reduced"
        assert TRUST_STATE_MISSING in result.reason_codes
        assert result.freshness["independent_monotonic"] is False
        assert result.freshness["status"] == "NOT_CONFIGURED"

    def test_local_state_is_not_claimed_as_independent(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        state_path = _state_with(tmp_path, [setup["checkpoint"]])
        result = _verify(setup, trust_state_path=state_path)
        # The same checkpoint is now a replay.
        assert result.outcome == FAIL
        assert CHECKPOINT_REPLAY in result.reason_codes
        assert result.freshness["status"] == "ROLLBACK_DETECTED"

    def test_advancing_state_accepts_new_sequence(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        state_path = _state_with(tmp_path, [setup["checkpoint"]])
        second = _checkpoint(
            setup["report_path"],
            setup["integrity_path"],
            setup["audit_path"],
            setup["private_key"],
            sequence=2,
            created_at=T3,
        )
        result = _verify(setup, checkpoint=second, trust_state_path=state_path)
        assert result.outcome == PASS
        updated = advance_trust_state(
            state_path,
            result.state_entry,
            updated_at=second["created_at"],
        )
        assert [entry["checkpoint_sequence"] for entry in updated["checkpoints"]] == [1, 2]
        assert result.freshness["status"] == "LOCAL_STATE_ONLY"
        assert result.freshness["assurance"] == "reduced"
        assert result.freshness["independent_monotonic"] is False

    def test_replay_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        state_path = _state_with(tmp_path, [setup["checkpoint"]])
        result = _verify(setup, trust_state_path=state_path)
        assert result.outcome == FAIL
        assert CHECKPOINT_REPLAY in result.reason_codes

    def test_older_checkpoint_replay_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        first = setup["checkpoint"]
        second = _checkpoint(
            setup["report_path"],
            setup["integrity_path"],
            setup["audit_path"],
            setup["private_key"],
            sequence=2,
            created_at=T3,
        )
        state_path = _state_with(tmp_path, [first, second])
        result = _verify(setup, checkpoint=first, trust_state_path=state_path)
        assert result.outcome == FAIL
        assert CHECKPOINT_REPLAY in result.reason_codes

    def test_sequence_decreasing_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        second = _checkpoint(
            setup["report_path"],
            setup["integrity_path"],
            setup["audit_path"],
            setup["private_key"],
            sequence=2,
            created_at=T3,
        )
        third = _checkpoint(
            setup["report_path"],
            setup["integrity_path"],
            setup["audit_path"],
            setup["private_key"],
            sequence=3,
            created_at=T4,
        )
        state_path = _state_with(tmp_path, [third])
        result = _verify(setup, checkpoint=second, trust_state_path=state_path)
        assert result.outcome == FAIL
        assert CHECKPOINT_SEQUENCE_DECREASING in result.reason_codes

    def test_duplicate_sequence_with_different_checkpoint_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        second_a = _checkpoint(
            setup["report_path"],
            setup["integrity_path"],
            setup["audit_path"],
            setup["private_key"],
            sequence=2,
            created_at=T2,
        )
        second_b = _checkpoint(
            setup["report_path"],
            setup["integrity_path"],
            setup["audit_path"],
            setup["private_key"],
            sequence=2,
            created_at=T3,
        )
        assert second_a["checkpoint_id"] != second_b["checkpoint_id"]
        state_path = _state_with(tmp_path, [second_a])
        result = _verify(setup, checkpoint=second_b, trust_state_path=state_path)
        assert result.outcome == FAIL
        assert CHECKPOINT_SEQUENCE_DUPLICATE in result.reason_codes

    def test_reused_checkpoint_id_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        state_path = _state_with(tmp_path, [setup["checkpoint"]])
        mutated = dict(setup["checkpoint"])
        mutated["checkpoint_sequence"] = 2
        mutated["created_at"] = T3
        check = evaluate_trust_state(mutated, load_trust_state(state_path))
        assert check.outcome == FAIL
        assert check.reason_code == CHECKPOINT_ID_REUSED

    def test_terminal_hash_rollback_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        state_path = _state_with(tmp_path, [setup["checkpoint"]])
        mutated = dict(setup["checkpoint"])
        mutated["checkpoint_id"] = "chk-" + "1" * 32
        mutated["checkpoint_sequence"] = 2
        mutated["created_at"] = T3
        mutated["audit_chain_terminal_hash"] = "sha256:" + "0" * 64
        check = evaluate_trust_state(mutated, load_trust_state(state_path))
        assert check.outcome == FAIL
        assert check.reason_code == AUDIT_HASH_ROLLBACK

    def test_manifest_digest_rollback_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        base = trust_state_entry(setup["checkpoint"])
        first = {
            **base,
            "checkpoint_id": "chk-" + "a" * 32,
            "checkpoint_sequence": 1,
            "audit_record_count": 1,
            "audit_chain_terminal_hash": "sha256:" + "1" * 64,
            "evidence_manifest_digest": "sha256:" + "a" * 64,
            "created_at": T1,
        }
        second = {
            **base,
            "checkpoint_id": "chk-" + "b" * 32,
            "checkpoint_sequence": 2,
            "audit_record_count": 2,
            "audit_chain_terminal_hash": "sha256:" + "2" * 64,
            "evidence_manifest_digest": "sha256:" + "b" * 64,
            "created_at": T2,
        }
        state_path = tmp_path / "trust-state.json"
        advance_trust_state(state_path, first, updated_at=T1)
        advance_trust_state(state_path, second, updated_at=T2)
        mutated = {
            **second,
            "checkpoint_id": "chk-" + "c" * 32,
            "checkpoint_sequence": 3,
            "audit_record_count": 3,
            "audit_chain_terminal_hash": "sha256:" + "3" * 64,
            "evidence_manifest_digest": first["evidence_manifest_digest"],
            "created_at": T3,
        }
        check = evaluate_trust_state(mutated, load_trust_state(state_path))
        assert check.outcome == FAIL
        assert check.reason_code == MANIFEST_DIGEST_ROLLBACK

    def test_conflicting_checkpoints_are_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        state_path = _state_with(tmp_path, [setup["checkpoint"]])
        mutated = dict(setup["checkpoint"])
        mutated["checkpoint_id"] = "chk-" + "3" * 32
        mutated["checkpoint_sequence"] = 2
        mutated["created_at"] = T3
        mutated["evidence_manifest_digest"] = "sha256:" + "0" * 64
        check = evaluate_trust_state(mutated, load_trust_state(state_path))
        assert check.outcome == FAIL
        assert check.reason_code == CHECKPOINT_CONFLICT

    def test_timestamp_regression_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        second = _checkpoint(
            setup["report_path"],
            setup["integrity_path"],
            setup["audit_path"],
            setup["private_key"],
            sequence=2,
            created_at=T3,
        )
        state_path = _state_with(tmp_path, [second])
        mutated = dict(second)
        mutated["checkpoint_id"] = "chk-" + "4" * 32
        mutated["checkpoint_sequence"] = 3
        mutated["created_at"] = T2
        check = evaluate_trust_state(mutated, load_trust_state(state_path))
        assert check.outcome == FAIL
        assert check.reason_code == CHECKPOINT_TIMESTAMP_INCONSISTENT

    def test_tampered_state_digest_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        state_path = _state_with(tmp_path, [setup["checkpoint"]])
        payload = json.loads(state_path.read_text(encoding="utf-8"))
        payload["updated_at"] = T4
        state_path.write_text(json.dumps(payload), encoding="utf-8")
        result = _verify(setup, trust_state_path=state_path)
        assert result.outcome == FAIL
        assert result.freshness["status"] == "INVALID"

    def test_chain_truncation_is_detected(self, tmp_path: Path) -> None:
        report_path, _evidence_root, integrity_path, audit_path = _sealed(
            tmp_path / "two",
            files={"a.bin": b"a", "b.bin": b"b"},
        )
        private_key, descriptor = _key(tmp_path, "truncation-key")
        store_path, _ = _store(tmp_path, descriptor)
        checkpoint = _checkpoint(
            report_path,
            integrity_path,
            audit_path,
            private_key,
            key_id="truncation-key",
        )
        lines = audit_path.read_text(encoding="utf-8").splitlines(keepends=True)
        audit_path.write_text("".join(lines[:1]), encoding="utf-8")
        result = verify_signed_checkpoint(
            checkpoint,
            report_path=report_path,
            integrity_path=integrity_path,
            audit_path=audit_path,
            trust_store_path=store_path,
        )
        assert result.outcome == FAIL
        assert CHAIN_TRUNCATION in result.reason_codes

    def test_checkpoint_timestamp_before_terminal_audit_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        payload = checkpoint_payload(setup["checkpoint"])
        payload["created_at"] = T0
        payload["checkpoint_id"] = derive_checkpoint_id(payload)
        checkpoint = sign_checkpoint_payload(payload, load_private_key(setup["private_key"]))
        result = _verify(setup, checkpoint=checkpoint)
        assert result.outcome == FAIL
        assert CHECKPOINT_TIMESTAMP_INCONSISTENT in result.reason_codes

    def test_create_rejects_timestamp_before_terminal_audit(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        with pytest.raises(TrustConflict) as excinfo:
            _checkpoint(
                setup["report_path"],
                setup["integrity_path"],
                setup["audit_path"],
                setup["private_key"],
                created_at=T0,
            )
        assert excinfo.value.reason_code == CHECKPOINT_TIMESTAMP_INCONSISTENT

    def test_require_independent_freshness_is_not_run(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        result = _verify(setup, require_independent_freshness=True)
        assert result.outcome == NOT_RUN
        assert INDEPENDENT_FRESHNESS_UNAVAILABLE in result.reason_codes


# ---------------------------------------------------------------------------
# External trust-anchor interface (local test doubles only)
# ---------------------------------------------------------------------------


class _LocalAnchor(ExternalTrustAnchor):
    def __init__(self, reference: dict[str, Any] | None, *, fail: bool = False) -> None:
        self.reference = reference
        self.fail = fail

    def describe(self) -> dict[str, Any]:
        return {"provider": "local-test-double", "network": False}

    def fetch_reference(self, evidence_report_id: str) -> dict[str, Any] | None:
        if self.fail:
            raise RuntimeError("synthetic anchor failure")
        if self.reference is not None and self.reference["evidence_report_id"] != evidence_report_id:
            return None
        return self.reference


def _reference(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_report_id": checkpoint["evidence_report_id"],
        "checkpoint_id": checkpoint["checkpoint_id"],
        "checkpoint_sequence": checkpoint["checkpoint_sequence"],
        "audit_record_count": checkpoint["audit_record_count"],
        "audit_chain_terminal_hash": checkpoint["audit_chain_terminal_hash"],
        "evidence_manifest_digest": checkpoint["evidence_manifest_digest"],
        "created_at": checkpoint["created_at"],
    }


class TestExternalAnchor:
    def test_unconfigured_anchor_is_not_run(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        result = _verify(setup)
        assert result.external_anchor["configured"] is False
        assert result.external_anchor["used"] is False
        assert result.external_anchor["status"] == "UNCONFIGURED"
        assert EXTERNAL_ANCHOR_UNCONFIGURED in result.reason_codes
        assert result.assurance == "reduced"

    def test_matching_local_reference_is_independent(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        anchor = _LocalAnchor(_reference(setup["checkpoint"]))
        result = _verify(setup, external_anchor=anchor)
        assert result.outcome == PASS
        assert result.assurance == "independent"
        assert result.external_anchor["used"] is True
        assert result.external_anchor["status"] == "REFERENCE_VERIFIED"
        assert result.freshness["independent_monotonic"] is True
        assert result.freshness["status"] == "EXTERNAL_REFERENCE"

    def test_missing_local_reference_is_not_run(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        anchor = _LocalAnchor(None)
        result = _verify(setup, external_anchor=anchor)
        assert result.outcome == PASS
        assert result.assurance == "reduced"
        assert EXTERNAL_ANCHOR_REFERENCE_MISSING in result.reason_codes

    def test_mismatched_local_reference_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        reference = _reference(setup["checkpoint"])
        reference["audit_chain_terminal_hash"] = "sha256:" + "0" * 64
        anchor = _LocalAnchor(reference)
        result = _verify(setup, external_anchor=anchor)
        assert result.outcome == FAIL
        assert EXTERNAL_ANCHOR_MISMATCH in result.reason_codes

    def test_anchor_failure_is_rejected(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        anchor = _LocalAnchor(_reference(setup["checkpoint"]), fail=True)
        result = _verify(setup, external_anchor=anchor)
        assert result.outcome == FAIL
        assert EXTERNAL_ANCHOR_MISMATCH in result.reason_codes

    def test_required_independent_freshness_passes_with_local_double(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        anchor = _LocalAnchor(_reference(setup["checkpoint"]))
        result = _verify(
            setup,
            external_anchor=anchor,
            require_independent_freshness=True,
        )
        assert result.outcome == PASS
        assert result.assurance == "independent"


# ---------------------------------------------------------------------------
# Private-key handling and redaction
# ---------------------------------------------------------------------------


class TestPrivateKeyAndRedaction:
    def test_checkpoint_contains_no_private_material(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        private_bytes = setup["private_key"].read_bytes()
        serialized = json.dumps(setup["checkpoint"], sort_keys=True)
        assert "PRIVATE KEY" not in serialized
        assert private_bytes.decode("utf-8") not in serialized

    def test_trust_store_contains_no_private_material(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        serialized = setup["store_path"].read_text(encoding="utf-8")
        assert "PRIVATE KEY" not in serialized
        assert setup["private_key"].read_text(encoding="utf-8") not in serialized

    def test_verification_json_contains_no_private_material(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        serialized = render_verification_json(
            verify_report(
                setup["report_path"],
                integrity_path=setup["integrity_path"],
                audit_path=setup["audit_path"],
                checkpoint_path=setup["checkpoint_path"],
                trust_store_path=setup["store_path"],
            )
        )
        assert "PRIVATE KEY" not in serialized
        assert setup["private_key"].read_text(encoding="utf-8") not in serialized

    def test_sanitized_output_redacts_sentinel(self) -> None:
        output = dump_sanitized_json({"detail": f"token={SENTINEL}"})
        assert SENTINEL not in output
        assert REDACTED in output

    def test_generated_key_result_omits_private_bytes(self, tmp_path: Path) -> None:
        result = generate_key_files(
            key_id="sanitized",
            private_key_path=tmp_path / "keys" / "sanitized.pem",
            generated_at=T1,
        )
        serialized = json.dumps(result, sort_keys=True)
        assert "PRIVATE KEY" not in serialized
        assert (tmp_path / "keys" / "sanitized.pem").read_text(encoding="utf-8") not in serialized

    def test_no_private_key_is_written_under_evidence(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        evidence_files = list(setup["evidence_root"].rglob("*"))
        assert all(path.suffix != ".pem" for path in evidence_files)


# ---------------------------------------------------------------------------
# V30 compatibility and CLI behavior
# ---------------------------------------------------------------------------


class TestV30Compatibility:
    def test_unsigned_checkpoint_still_verifies(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        from tools.release.integrity import create_checkpoint, write_checkpoint

        unsigned = create_checkpoint(setup["audit_path"], source_label="v30-test")
        unsigned_path = tmp_path / "unsigned-checkpoint.json"
        write_checkpoint(unsigned_path, unsigned)
        result = verify_report(
            setup["report_path"],
            integrity_path=setup["integrity_path"],
            audit_path=setup["audit_path"],
            checkpoint_path=unsigned_path,
        )
        assert result.outcome == PASS
        assert result.signed_checkpoint is None
        assert result.assurance == "none"
        assert not any(check.name == "signed-checkpoint-signature" for check in result.checks)

    def test_audit_only_rejects_signed_checkpoint(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        result = verify_audit_file(
            setup["audit_path"],
            checkpoint_path=setup["checkpoint_path"],
        )
        assert result.outcome == FAIL
        assert SIGNED_CHECKPOINT_REQUIRES_REPORT in result.reason_codes

    def test_signed_checkpoint_requires_trust_store(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        result = verify_report(
            setup["report_path"],
            integrity_path=setup["integrity_path"],
            audit_path=setup["audit_path"],
            checkpoint_path=setup["checkpoint_path"],
        )
        assert result.outcome == UNAVAILABLE
        assert TRUST_STORE_MISSING in result.reason_codes
        assert result.assurance == "reduced"

    def test_require_signed_checkpoint_rejects_unsigned(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        from tools.release.integrity import create_checkpoint, write_checkpoint

        unsigned = create_checkpoint(setup["audit_path"], source_label="v30-test")
        unsigned_path = tmp_path / "unsigned-checkpoint.json"
        write_checkpoint(unsigned_path, unsigned)
        result = verify_report(
            setup["report_path"],
            integrity_path=setup["integrity_path"],
            audit_path=setup["audit_path"],
            checkpoint_path=unsigned_path,
            require_signed_checkpoint=True,
        )
        assert result.outcome == FAIL
        assert CHECKPOINT_UNSIGNED in result.reason_codes

    def test_require_signed_checkpoint_rejects_absent_checkpoint(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        result = verify_report(
            setup["report_path"],
            integrity_path=setup["integrity_path"],
            audit_path=setup["audit_path"],
            require_signed_checkpoint=True,
        )
        assert result.outcome == FAIL
        assert CHECKPOINT_UNSIGNED in result.reason_codes

    def test_unsigned_checkpoint_does_not_satisfy_require_signed(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        from tools.release.integrity import create_checkpoint, write_checkpoint

        unsigned = create_checkpoint(setup["audit_path"], source_label="v30-test")
        unsigned_path = tmp_path / "unsigned-checkpoint.json"
        write_checkpoint(unsigned_path, unsigned)
        result = verify_report(
            setup["report_path"],
            integrity_path=setup["integrity_path"],
            audit_path=setup["audit_path"],
            checkpoint_path=unsigned_path,
            trust_store_path=setup["store_path"],
            require_signed_checkpoint=True,
        )
        assert result.outcome == FAIL
        assert CHECKPOINT_UNSIGNED in result.reason_codes


class TestCli:
    def _verify_args(self, setup: dict[str, Any], *extra: str) -> list[str]:
        return [
            "verify-evidence",
            "--report",
            str(setup["report_path"]),
            "--integrity",
            str(setup["integrity_path"]),
            "--audit",
            str(setup["audit_path"]),
            "--checkpoint",
            str(setup["checkpoint_path"]),
            *extra,
        ]

    def test_cli_passes_with_trust_store(self, tmp_path: Path, capsys: Any) -> None:
        setup = _signed_setup(tmp_path)
        code = main(self._verify_args(setup, "--trust-store", str(setup["store_path"])))
        captured = capsys.readouterr()
        assert code == 0
        assert "Signed checkpoint:" in captured.out
        assert "Assurance: reduced" in captured.out

    def test_cli_missing_trust_store_is_exit_2(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        assert main(self._verify_args(setup)) == 2

    def test_cli_required_independent_freshness_is_exit_3(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        assert (
            main(
                self._verify_args(
                    setup,
                    "--trust-store",
                    str(setup["store_path"]),
                    "--require-independent-freshness",
                )
            )
            == 3
        )

    def test_cli_unsigned_checkpoint_with_require_signed_is_exit_1(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        from tools.release.integrity import create_checkpoint, write_checkpoint

        unsigned = create_checkpoint(setup["audit_path"], source_label="v30-test")
        unsigned_path = tmp_path / "unsigned-checkpoint.json"
        write_checkpoint(unsigned_path, unsigned)
        args = [
            "verify-evidence",
            "--report",
            str(setup["report_path"]),
            "--integrity",
            str(setup["integrity_path"]),
            "--audit",
            str(setup["audit_path"]),
            "--checkpoint",
            str(unsigned_path),
            "--require-signed-checkpoint",
        ]
        assert main(args) == 1

    def test_cli_update_trust_state_requires_state_path(self, tmp_path: Path) -> None:
        setup = _signed_setup(tmp_path)
        assert (
            main(
                self._verify_args(
                    setup,
                    "--trust-store",
                    str(setup["store_path"]),
                    "--update-trust-state",
                )
            )
            == 4
        )

    def test_cli_update_trust_state_writes_only_after_pass(self, tmp_path: Path, capsys: Any) -> None:
        setup = _signed_setup(tmp_path)
        state_path = setup["trust_state_path"]
        args = self._verify_args(
            setup,
            "--trust-store",
            str(setup["store_path"]),
            "--trust-state",
            str(state_path),
            "--update-trust-state",
        )
        assert main(args) == 0
        assert state_path.is_file()
        state = load_trust_state(state_path)
        assert state is not None
        assert len(state.entries) == 1
        # A replay is rejected and does not append a second entry.
        assert main(args) == 1
        state = load_trust_state(state_path)
        assert state is not None
        assert len(state.entries) == 1
        capsys.readouterr()

    def test_cli_sign_checkpoint_round_trip(self, tmp_path: Path, capsys: Any) -> None:
        setup = _signed_setup(tmp_path)
        output = tmp_path / "cli-checkpoint.json"
        code = main(
            [
                "sign-checkpoint",
                "--audit",
                str(setup["audit_path"]),
                "--report",
                str(setup["report_path"]),
                "--integrity",
                str(setup["integrity_path"]),
                "--private-key",
                str(setup["private_key"]),
                "--key-id",
                "key-one",
                "--sequence",
                "2",
                "--created-at",
                T3,
                "--output",
                str(output),
            ]
        )
        captured = capsys.readouterr()
        assert code == 0
        assert "signed checkpoint written" in captured.out
        checkpoint = load_signed_checkpoint(output)
        assert checkpoint["checkpoint_sequence"] == 2

    def test_cli_json_output_is_sanitized(self, tmp_path: Path, capsys: Any) -> None:
        setup = _signed_setup(tmp_path)
        code = main(
            self._verify_args(
                setup,
                "--trust-store",
                str(setup["store_path"]),
                "--json",
            )
        )
        captured = capsys.readouterr()
        assert code == 0
        payload = json.loads(captured.out)
        assert payload["outcome"] == PASS
        assert payload["assurance"] == "reduced"
        assert "PRIVATE KEY" not in captured.out
        assert setup["private_key"].read_text(encoding="utf-8") not in captured.out


# __V31_TESTS_CONTINUE__
