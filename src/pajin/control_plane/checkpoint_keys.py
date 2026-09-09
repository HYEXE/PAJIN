"""Host-local checkpoint key continuity at startup and before signing."""

from __future__ import annotations

import hmac
from hashlib import sha256

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from pajin.control_plane.database import (
    CheckpointKeyIdentityRecord,
    CheckpointRecord,
    ControlPlaneRepository,
    utc_now,
)
from pajin.control_plane.security import CheckpointIntegrityError, CheckpointSigner

_KEYRING_LOCK = int.from_bytes(
    sha256(b"pajin.control-plane.checkpoint-keyring.v1").digest()[:8], "big", signed=True
)


class CheckpointKeyringGuard:
    """Pin key IDs only after every existing checkpoint verifies under the keyring.

    The database and deployment remain trusted host state. A copied or rolled-back
    whole database cannot be distinguished without an independently retained head.
    """

    def __init__(self, repository: ControlPlaneRepository, signer: CheckpointSigner) -> None:
        self._repository = repository
        self._signer = signer
        self._activated = False

    def activate(self) -> None:
        self._activated = False
        with self._repository.transaction() as session:
            self._lock(session)
            self._verify_and_bind(session)
        self._activated = True

    def require_signing_key(self, session: Session) -> None:
        """Also fence embedded services that do not use the HTTP startup hook."""

        self._lock(session)
        missing = self._verify_identities(session)
        if missing or not self._activated:
            self._verify_and_bind(session)

    def _lock(self, session: Session) -> None:
        # SQLite's repository transaction already holds BEGIN IMMEDIATE. PostgreSQL
        # needs a common lock even before the first key-identity row exists.
        if self._repository.dialect_name == "postgresql":
            session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _KEYRING_LOCK})

    def _verify_identities(self, session: Session) -> dict[str, str]:
        missing: dict[str, str] = {}
        for key_id, commitment in sorted(self._signer.key_commitments().items()):
            stored = session.get(CheckpointKeyIdentityRecord, key_id)
            if stored is None:
                missing[key_id] = commitment
            elif not hmac.compare_digest(stored.key_commitment, commitment):
                raise CheckpointIntegrityError("checkpoint key identity has changed")
        return missing

    def _verify_and_bind(self, session: Session) -> None:
        missing = self._verify_identities(session)
        checkpoints = session.scalars(
            select(CheckpointRecord)
            .order_by(CheckpointRecord.checkpoint_id)
            .execution_options(yield_per=8)
        )
        for checkpoint in checkpoints:
            self._signer.verify(
                checkpoint_id=checkpoint.checkpoint_id,
                run_id=checkpoint.run_id,
                sequence=checkpoint.sequence,
                schema_version=checkpoint.schema_version,
                payload=checkpoint.payload,
                payload_sha256=checkpoint.payload_sha256,
                signature=checkpoint.signature,
                key_id=checkpoint.key_id,
            )
        now = utc_now()
        for key_id, commitment in missing.items():
            session.add(
                CheckpointKeyIdentityRecord(
                    key_id=key_id, key_commitment=commitment, first_seen_at=now
                )
            )
