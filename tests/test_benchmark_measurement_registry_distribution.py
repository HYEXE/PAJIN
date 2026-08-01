from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pajin.benchmark import (
    BenchmarkMeasurementKeyState,
    BenchmarkMeasurementRegistryActivationStore,
    BenchmarkMeasurementRegistryDistributionBundle,
    BenchmarkMeasurementRegistryDistributionError,
    BenchmarkMeasurementRegistryDistributionKey,
    BenchmarkMeasurementRegistryDistributionSigner,
    BenchmarkMeasurementRegistryDistributionTrustAnchor,
    BenchmarkMeasurementRegistryKey,
    BenchmarkMeasurementTrustAnchor,
    BenchmarkMeasurementTrustRegistry,
    benchmark_measurement_public_key_base64url,
    benchmark_measurement_registry_distribution_public_key_base64url,
    verify_benchmark_measurement_registry_distribution_bundle,
)

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
MEASUREMENT_A = bytes(range(32))
MEASUREMENT_B = bytes(range(32, 64))
MEASUREMENT_C = bytes(range(64, 96))
DISTRIBUTION_A = bytes(range(96, 128))
DISTRIBUTION_B = bytes(range(128, 160))


def _measurement_anchor(key_id: str, private_key: bytes) -> BenchmarkMeasurementTrustAnchor:
    return BenchmarkMeasurementTrustAnchor(
        authorityId="measurement-authority:distribution-test",
        authorityVersion="1.0.0",
        keyId=key_id,
        publicKeyBase64url=benchmark_measurement_public_key_base64url(private_key),
    )


def _registry_one() -> BenchmarkMeasurementTrustRegistry:
    return BenchmarkMeasurementTrustRegistry(
        registryId="measurement-registry:distribution-test",
        registryRevision=1,
        measurementAuthorityId="measurement-authority:distribution-test",
        measurementAuthorityVersion="1.0.0",
        issuedAt=NOW - timedelta(hours=2),
        keys=[
            BenchmarkMeasurementRegistryKey(
                trustAnchor=_measurement_anchor("measurement-key:a", MEASUREMENT_A),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=NOW - timedelta(days=1),
            )
        ],
    )


def _registry_two(
    previous: BenchmarkMeasurementTrustRegistry,
    *,
    revoke_old: bool = False,
) -> BenchmarkMeasurementTrustRegistry:
    issued_at = NOW + timedelta(minutes=10)
    return BenchmarkMeasurementTrustRegistry(
        registryId=previous.registry_id,
        registryRevision=2,
        previousRegistryDigest=previous.registry_digest,
        measurementAuthorityId=previous.measurement_authority_id,
        measurementAuthorityVersion=previous.measurement_authority_version,
        issuedAt=issued_at,
        keys=[
            BenchmarkMeasurementRegistryKey(
                trustAnchor=previous.keys[0].trust_anchor,
                state=(
                    BenchmarkMeasurementKeyState.REVOKED
                    if revoke_old
                    else BenchmarkMeasurementKeyState.RETIRED
                ),
                notBefore=previous.keys[0].not_before,
                notAfter=issued_at,
                revokedAt=issued_at if revoke_old else None,
            ),
            BenchmarkMeasurementRegistryKey(
                trustAnchor=_measurement_anchor("measurement-key:b", MEASUREMENT_B),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=issued_at,
            ),
        ],
    )


def _registry_three(
    previous: BenchmarkMeasurementTrustRegistry,
) -> BenchmarkMeasurementTrustRegistry:
    issued_at = NOW + timedelta(minutes=20)
    return BenchmarkMeasurementTrustRegistry(
        registryId=previous.registry_id,
        registryRevision=3,
        previousRegistryDigest=previous.registry_digest,
        measurementAuthorityId=previous.measurement_authority_id,
        measurementAuthorityVersion=previous.measurement_authority_version,
        issuedAt=issued_at,
        keys=[
            previous.keys[0],
            BenchmarkMeasurementRegistryKey(
                trustAnchor=previous.keys[1].trust_anchor,
                state=BenchmarkMeasurementKeyState.RETIRED,
                notBefore=previous.keys[1].not_before,
                notAfter=issued_at,
            ),
            BenchmarkMeasurementRegistryKey(
                trustAnchor=_measurement_anchor("measurement-key:c", MEASUREMENT_C),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=issued_at,
            ),
        ],
    )


def _distribution_anchor(
    *,
    first_state: BenchmarkMeasurementKeyState = BenchmarkMeasurementKeyState.ACTIVE,
) -> BenchmarkMeasurementRegistryDistributionTrustAnchor:
    keys = [
        BenchmarkMeasurementRegistryDistributionKey(
            keyId="distribution-key:a",
            publicKeyBase64url=(
                benchmark_measurement_registry_distribution_public_key_base64url(
                    DISTRIBUTION_A
                )
            ),
            state=first_state,
            notBefore=NOW - timedelta(days=1),
            notAfter=(
                NOW + timedelta(hours=1)
                if first_state is not BenchmarkMeasurementKeyState.ACTIVE
                else None
            ),
        )
    ]
    if first_state is not BenchmarkMeasurementKeyState.ACTIVE:
        keys.append(
            BenchmarkMeasurementRegistryDistributionKey(
                keyId="distribution-key:b",
                publicKeyBase64url=(
                    benchmark_measurement_registry_distribution_public_key_base64url(
                        DISTRIBUTION_B
                    )
                ),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=NOW - timedelta(days=1),
            )
        )
    return BenchmarkMeasurementRegistryDistributionTrustAnchor(
        trustDomain="benchmark-registry:distribution-test",
        issuer="benchmark-registry-issuer:test",
        keys=keys,
    )


def _signer() -> BenchmarkMeasurementRegistryDistributionSigner:
    anchor = _distribution_anchor()
    return BenchmarkMeasurementRegistryDistributionSigner.from_private_key_bytes(
        active_key_id=anchor.active_key.key_id,
        private_key=DISTRIBUTION_A,
        trust_anchor=anchor,
    )


def _bundle_one() -> tuple[
    BenchmarkMeasurementRegistryDistributionTrustAnchor,
    BenchmarkMeasurementRegistryDistributionBundle,
]:
    signer = _signer()
    bundle = signer.sign(
        registry=_registry_one(),
        issued_at=NOW - timedelta(hours=1),
        not_before=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(days=1),
    )
    return signer.trust_anchor, bundle


def _bundle_two(
    first: BenchmarkMeasurementRegistryDistributionBundle,
    *,
    revoke_old: bool = False,
) -> BenchmarkMeasurementRegistryDistributionBundle:
    return _signer().sign(
        registry=_registry_two(first.statement.registry, revoke_old=revoke_old),
        predecessor_registry=first.statement.registry,
        previous_bundle_digest=first.bundle_digest,
        issued_at=NOW + timedelta(minutes=11),
        not_before=NOW + timedelta(minutes=11),
        expires_at=NOW + timedelta(days=1),
    )


def test_signed_bundle_verifies_and_activation_survives_restart(tmp_path: Path) -> None:
    anchor, first = _bundle_one()
    key = verify_benchmark_measurement_registry_distribution_bundle(
        first,
        trust_anchor=anchor,
        now=NOW,
    )
    assert key.key_id == "distribution-key:a"

    path = tmp_path / "registry-activation.sqlite3"
    store = BenchmarkMeasurementRegistryActivationStore(path)
    activation = store.activate(first, trust_anchor=anchor, now=NOW)
    repeated = store.activate(first, trust_anchor=anchor, now=NOW + timedelta(minutes=1))
    reopened = BenchmarkMeasurementRegistryActivationStore(path).latest(
        trust_domain=anchor.trust_domain,
        issuer=anchor.issuer,
        registry_id=first.statement.registry.registry_id,
    )
    assert repeated == activation
    assert reopened == activation
    assert reopened is not None and reopened.bundle == first
    assert DISTRIBUTION_A.hex() not in path.read_bytes().hex()


def test_distribution_rejects_signature_expiry_unknown_and_revoked_key() -> None:
    anchor, first = _bundle_one()
    replacement = "A" if first.signature_base64url[-1] != "A" else "B"
    forged = first.model_copy(
        update={"signature_base64url": first.signature_base64url[:-1] + replacement}
    )
    with pytest.raises(BenchmarkMeasurementRegistryDistributionError, match="signature"):
        verify_benchmark_measurement_registry_distribution_bundle(
            forged,
            trust_anchor=anchor,
            now=NOW,
        )
    with pytest.raises(BenchmarkMeasurementRegistryDistributionError, match="currently valid"):
        verify_benchmark_measurement_registry_distribution_bundle(
            first,
            trust_anchor=anchor,
            now=NOW + timedelta(days=2),
        )

    unknown = first.model_copy(update={"key_id": "distribution-key:unknown"})
    with pytest.raises(BenchmarkMeasurementRegistryDistributionError, match="unknown"):
        verify_benchmark_measurement_registry_distribution_bundle(
            unknown,
            trust_anchor=anchor,
            now=NOW,
        )

    invalid_anchor = anchor.model_copy(update={"keys": ()})
    with pytest.raises(BenchmarkMeasurementRegistryDistributionError, match="structurally invalid"):
        verify_benchmark_measurement_registry_distribution_bundle(
            first,
            trust_anchor=invalid_anchor,
            now=NOW,
        )

    revoked_anchor = _distribution_anchor(first_state=BenchmarkMeasurementKeyState.REVOKED)
    with pytest.raises(BenchmarkMeasurementRegistryDistributionError, match="revoked"):
        verify_benchmark_measurement_registry_distribution_bundle(
            first,
            trust_anchor=revoked_anchor,
            now=NOW,
        )


def test_activation_rejects_rollback_gap_equivocation_and_wrong_predecessor(
    tmp_path: Path,
) -> None:
    anchor, first = _bundle_one()
    second = _bundle_two(first)
    store = BenchmarkMeasurementRegistryActivationStore(tmp_path / "activation.sqlite3")
    store.activate(first, trust_anchor=anchor, now=NOW)

    substituted_anchor = BenchmarkMeasurementRegistryDistributionTrustAnchor(
        trustDomain=anchor.trust_domain,
        issuer=anchor.issuer,
        keys=[
            anchor.active_key,
            BenchmarkMeasurementRegistryDistributionKey(
                keyId="distribution-key:b",
                publicKeyBase64url=(
                    benchmark_measurement_registry_distribution_public_key_base64url(
                        DISTRIBUTION_B
                    )
                ),
                state=BenchmarkMeasurementKeyState.RETIRED,
                notBefore=NOW - timedelta(days=1),
                notAfter=NOW + timedelta(hours=1),
            ),
        ],
    )
    with pytest.raises(BenchmarkMeasurementRegistryDistributionError, match="Trust Anchor"):
        store.activate(
            second,
            trust_anchor=substituted_anchor,
            now=NOW + timedelta(minutes=12),
        )

    store.activate(second, trust_anchor=anchor, now=NOW + timedelta(minutes=12))

    with pytest.raises(BenchmarkMeasurementRegistryDistributionError, match="rollback"):
        store.activate(first, trust_anchor=anchor, now=NOW + timedelta(minutes=13))

    equivocated = _bundle_two(first, revoke_old=True)
    with pytest.raises(BenchmarkMeasurementRegistryDistributionError, match="equivocated"):
        store.activate(equivocated, trust_anchor=anchor, now=NOW + timedelta(minutes=13))

    third_registry = _registry_three(second.statement.registry)
    third = _signer().sign(
        registry=third_registry,
        predecessor_registry=second.statement.registry,
        previous_bundle_digest=second.bundle_digest,
        issued_at=NOW + timedelta(minutes=21),
        not_before=NOW + timedelta(minutes=21),
        expires_at=NOW + timedelta(days=1),
    )
    gap_store = BenchmarkMeasurementRegistryActivationStore(tmp_path / "gap.sqlite3")
    gap_store.activate(first, trust_anchor=anchor, now=NOW)
    with pytest.raises(BenchmarkMeasurementRegistryDistributionError, match="gap"):
        gap_store.activate(third, trust_anchor=anchor, now=NOW + timedelta(minutes=22))

    wrong = _signer().sign(
        registry=third_registry,
        predecessor_registry=second.statement.registry,
        previous_bundle_digest="f" * 64,
        issued_at=NOW + timedelta(minutes=21),
        not_before=NOW + timedelta(minutes=21),
        expires_at=NOW + timedelta(days=1),
    )
    with pytest.raises(BenchmarkMeasurementRegistryDistributionError, match="predecessor"):
        store.activate(wrong, trust_anchor=anchor, now=NOW + timedelta(minutes=22))


def test_activation_store_is_append_only_and_rejects_hardlinks(tmp_path: Path) -> None:
    anchor, first = _bundle_one()
    path = tmp_path / "activation.sqlite3"
    store = BenchmarkMeasurementRegistryActivationStore(path)
    store.activate(first, trust_anchor=anchor, now=NOW)

    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE activations SET registry_digest = ?", ("f" * 64,))
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM activations")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT OR REPLACE INTO activations
                SELECT trust_domain, issuer, registry_id, revision, bundle_digest,
                       registry_digest, trust_anchor_digest, activation_json
                FROM activations
                """
            )
    finally:
        connection.close()

    alias = tmp_path / "activation-hardlink.sqlite3"
    os.link(path, alias)
    with pytest.raises(
        BenchmarkMeasurementRegistryDistributionError,
        match="single-link",
    ):
        BenchmarkMeasurementRegistryActivationStore(alias)


def test_activation_reader_rejects_row_content_mismatch(tmp_path: Path) -> None:
    anchor, first = _bundle_one()
    path = tmp_path / "activation-corrupt.sqlite3"
    store = BenchmarkMeasurementRegistryActivationStore(path)
    store.activate(first, trust_anchor=anchor, now=NOW)

    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TRIGGER activations_no_update")
        connection.execute("UPDATE activations SET registry_digest = ?", ("f" * 64,))
        connection.commit()
    finally:
        connection.close()

    reopened = BenchmarkMeasurementRegistryActivationStore(path)
    with pytest.raises(BenchmarkMeasurementRegistryDistributionError, match="differs"):
        reopened.latest(
            trust_domain=anchor.trust_domain,
            issuer=anchor.issuer,
            registry_id=first.statement.registry.registry_id,
        )
