"""Offline-only provisioning and issuance for one-call Web analysis grants.

This module deliberately owns private-key handling. Its public-wire contracts
are implemented inside this standalone distribution; it has no dependency on
the PAJIN execution package or any runtime, Provider, target, journal,
materialization, receipt, or dispatch code.
"""

from __future__ import annotations

import base64
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .contracts import (
    MAX_BUNDLE_BYTES,
    MAX_REQUEST_BYTES,
    MAX_TRUST_ANCHOR_BYTES,
    SignedWebAnalysisOneCallAuthorizationV2,
    WebAnalysisOneCallAuthorizationKeyState,
    WebAnalysisOneCallAuthorizationRequestV2,
    WebAnalysisOneCallAuthorizationTrustAnchor,
    WebAnalysisOneCallAuthorizationVerificationKey,
    authorization_statement_signing_bytes_v2,
    build_web_analysis_one_call_authorization_statement_v2,
    canonical_json_bytes,
    parse_strict_json_bytes,
    parse_web_analysis_one_call_authorization_request_v2,
    parse_web_analysis_one_call_authorization_trust_anchor,
)

_OWNER_FILE_MODE: Final = 0o600
_OWNER_DIRECTORY_MODE: Final = 0o700
_PRIVATE_KEY_BYTES: Final = 32
_MAX_DIGEST_BYTES: Final = 65
_MAX_AUTHORIZATION_LIFETIME_SECONDS: Final = 180
_SHA256_LENGTH: Final = 64


class OfflineAuthorizationError(ValueError):
    """Raised when offline authority material cannot be handled safely."""


@dataclass(frozen=True, slots=True)
class ProvisionedAuthorizationAuthority:
    """Non-secret summary of a newly provisioned offline authority."""

    key_id: str
    trust_anchor_digest: str
    private_key_file: Path
    trust_anchor_file: Path
    trust_anchor_digest_file: Path


@dataclass(frozen=True, slots=True)
class IssuedAuthorizationBundle:
    """Non-secret summary of one newly issued authorization bundle."""

    key_id: str
    nonce: str
    expires_at: datetime
    bundle_digest: str
    signed_bundle_file: Path


def provision_authorization_authority(
    *,
    private_key_file: Path,
    trust_anchor_file: Path,
    trust_anchor_digest_file: Path,
    trust_domain: str,
    issuer: str,
    key_id: str,
    not_before: datetime,
    not_after: datetime,
) -> ProvisionedAuthorizationAuthority:
    """Create one random private seed and its independently retainable public anchor."""

    not_before_utc = _aware_utc(not_before, label="key not-before time")
    not_after_utc = _aware_utc(not_after, label="key not-after time")
    if not_after_utc <= not_before_utc:
        raise OfflineAuthorizationError("offline signing-key validity window is empty")
    destinations = _distinct_paths(
        private_key_file,
        trust_anchor_file,
        trust_anchor_digest_file,
    )
    for path, label in zip(
        destinations,
        ("private key", "trust anchor", "trust-anchor digest"),
        strict=True,
    ):
        _require_absent_owner_file(path, label=label)

    private_key = Ed25519PrivateKey.generate()
    private_seed = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    if len(private_seed) != _PRIVATE_KEY_BYTES:
        raise OfflineAuthorizationError("generated Ed25519 private seed has an invalid length")
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_key_base64url = _base64url(public_key)
    try:
        trust_anchor = WebAnalysisOneCallAuthorizationTrustAnchor(
            trustDomain=trust_domain,
            issuer=issuer,
            keys=(
                WebAnalysisOneCallAuthorizationVerificationKey(
                    keyId=key_id,
                    publicKeyBase64url=public_key_base64url,
                    state=WebAnalysisOneCallAuthorizationKeyState.ACTIVE,
                    notBefore=not_before_utc,
                    notAfter=not_after_utc,
                ),
            ),
        )
    except Exception as exc:
        raise OfflineAuthorizationError("offline trust-anchor parameters are invalid") from exc

    anchor_bytes = _canonical_model_bytes(
        trust_anchor,
        label="Web analysis authorization trust anchor",
        max_bytes=MAX_TRUST_ANCHOR_BYTES,
    )
    digest_bytes = (trust_anchor.digest + "\n").encode("ascii")
    _exclusive_owner_write(destinations[0], private_seed, label="private key")
    _exclusive_owner_write(destinations[1], anchor_bytes, label="trust anchor")
    _exclusive_owner_write(
        destinations[2],
        digest_bytes,
        label="trust-anchor digest",
    )
    return ProvisionedAuthorizationAuthority(
        key_id=key_id,
        trust_anchor_digest=trust_anchor.digest,
        private_key_file=destinations[0],
        trust_anchor_file=destinations[1],
        trust_anchor_digest_file=destinations[2],
    )


def issue_authorization_bundle(
    *,
    private_key_file: Path,
    trust_anchor_file: Path,
    trust_anchor_digest_file: Path,
    authorization_request_file: Path,
    signed_bundle_file: Path,
    lifetime_seconds: int,
) -> IssuedAuthorizationBundle:
    """Issue one fresh signed bundle from exact canonical, owner-only inputs."""

    if type(lifetime_seconds) is not int or not (
        1 <= lifetime_seconds <= _MAX_AUTHORIZATION_LIFETIME_SECONDS
    ):
        raise OfflineAuthorizationError("authorization lifetime must be 1..180 seconds")
    source_paths = _distinct_paths(
        private_key_file,
        trust_anchor_file,
        trust_anchor_digest_file,
        authorization_request_file,
        signed_bundle_file,
    )
    _require_absent_owner_file(source_paths[4], label="signed authorization bundle")
    private_seed = _read_owner_file(
        source_paths[0],
        max_bytes=_PRIVATE_KEY_BYTES,
        label="private key",
    )
    if len(private_seed) != _PRIVATE_KEY_BYTES:
        raise OfflineAuthorizationError("Ed25519 private seed must contain exactly 32 bytes")
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(private_seed)
    except ValueError as exc:
        raise OfflineAuthorizationError("Ed25519 private seed is invalid") from exc

    anchor_content = _read_owner_file(
        source_paths[1],
        max_bytes=MAX_TRUST_ANCHOR_BYTES,
        label="trust anchor",
    )
    trust_anchor = _parse_canonical_trust_anchor(anchor_content)
    retained_digest = _parse_digest_file(
        _read_owner_file(
            source_paths[2],
            max_bytes=_MAX_DIGEST_BYTES,
            label="trust-anchor digest",
        )
    )
    if not compare_digest(trust_anchor.digest, retained_digest):
        raise OfflineAuthorizationError("retained trust-anchor digest differs from the anchor")

    active_keys = tuple(
        key
        for key in trust_anchor.keys
        if key.state is WebAnalysisOneCallAuthorizationKeyState.ACTIVE
    )
    if len(active_keys) != 1:
        raise OfflineAuthorizationError("trust anchor must contain exactly one active key")
    active_key = active_keys[0]
    actual_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if not compare_digest(active_key.public_key_base64url, _base64url(actual_public_key)):
        raise OfflineAuthorizationError("private seed does not match the active trust-anchor key")

    request_content = _read_owner_file(
        source_paths[3],
        max_bytes=MAX_REQUEST_BYTES,
        label="authorization request",
    )
    request = _parse_canonical_request(request_content)
    issued_at = datetime.now(UTC).replace(microsecond=0)
    not_before = issued_at
    expires_at = issued_at + timedelta(seconds=lifetime_seconds)
    key_not_before = _aware_utc(active_key.not_before, label="active key not-before time")
    if issued_at < key_not_before:
        raise OfflineAuthorizationError("active signing key is not valid yet")
    if active_key.not_after is not None:
        key_not_after = _aware_utc(active_key.not_after, label="active key not-after time")
        if expires_at > key_not_after:
            raise OfflineAuthorizationError("authorization would outlive the active signing key")

    nonce = "offline-" + secrets.token_urlsafe(24)
    try:
        statement = build_web_analysis_one_call_authorization_statement_v2(
            request,
            trust_domain=trust_anchor.trust_domain,
            issuer=trust_anchor.issuer,
            signing_key_id=active_key.key_id,
            nonce=nonce,
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
        )
        canonical_statement = canonical_json_bytes(
            statement.model_dump(mode="json", by_alias=True),
            label="Web analysis one-call authorization v2 statement",
            max_bytes=MAX_BUNDLE_BYTES,
        )
        signature = private_key.sign(authorization_statement_signing_bytes_v2(statement))
        bundle = SignedWebAnalysisOneCallAuthorizationV2(
            keyId=active_key.key_id,
            statement=statement,
            statementSha256=sha256(canonical_statement).hexdigest(),
            signatureBase64url=_base64url(signature),
        )
    except Exception as exc:
        raise OfflineAuthorizationError("authorization request cannot be issued") from exc

    bundle_bytes = _canonical_model_bytes(
        bundle,
        label="signed Web analysis one-call authorization v2 bundle",
        max_bytes=MAX_BUNDLE_BYTES,
    )
    _exclusive_owner_write(
        source_paths[4],
        bundle_bytes,
        label="signed authorization bundle",
    )
    return IssuedAuthorizationBundle(
        key_id=active_key.key_id,
        nonce=nonce,
        expires_at=expires_at,
        bundle_digest=bundle.digest,
        signed_bundle_file=source_paths[4],
    )


def _parse_canonical_trust_anchor(content: bytes) -> WebAnalysisOneCallAuthorizationTrustAnchor:
    decoded = _parse_exact_canonical_json(
        content,
        label="Web analysis authorization trust anchor",
        max_bytes=MAX_TRUST_ANCHOR_BYTES,
    )
    canonical = canonical_json_bytes(
        decoded,
        label="Web analysis authorization trust anchor",
        max_bytes=MAX_TRUST_ANCHOR_BYTES,
    )
    try:
        anchor = parse_web_analysis_one_call_authorization_trust_anchor(canonical)
    except Exception as exc:
        raise OfflineAuthorizationError(
            "Web analysis authorization trust anchor is invalid"
        ) from exc
    if content != _canonical_model_bytes(
        anchor,
        label="Web analysis authorization trust anchor",
        max_bytes=MAX_TRUST_ANCHOR_BYTES,
    ):
        raise OfflineAuthorizationError(
            "Web analysis authorization trust anchor omits or changes canonical fields"
        )
    return anchor


def _parse_canonical_request(content: bytes) -> WebAnalysisOneCallAuthorizationRequestV2:
    _parse_exact_canonical_json(
        content,
        label="Web analysis one-call authorization v2 request",
        max_bytes=MAX_REQUEST_BYTES,
    )
    try:
        request = parse_web_analysis_one_call_authorization_request_v2(content)
    except Exception as exc:
        raise OfflineAuthorizationError("Web analysis authorization request is invalid") from exc
    if content != _canonical_model_bytes(
        request,
        label="Web analysis one-call authorization v2 request",
        max_bytes=MAX_REQUEST_BYTES,
    ):
        raise OfflineAuthorizationError(
            "Web analysis authorization request omits or changes canonical fields"
        )
    return request


def _parse_exact_canonical_json(content: bytes, *, label: str, max_bytes: int) -> object:
    try:
        decoded = parse_strict_json_bytes(
            content,
            label=label,
            max_bytes=max_bytes,
            max_depth=24,
            max_nodes=30_000,
        )
        canonical = canonical_json_bytes(decoded, label=label, max_bytes=max_bytes)
    except Exception as exc:
        raise OfflineAuthorizationError(f"{label} is not strict JSON") from exc
    if content != canonical + b"\n":
        raise OfflineAuthorizationError(f"{label} must be exact canonical JSON plus one line feed")
    return decoded


def _parse_digest_file(content: bytes) -> str:
    if len(content) != _MAX_DIGEST_BYTES or not content.endswith(b"\n"):
        raise OfflineAuthorizationError("trust-anchor digest file has an invalid encoding")
    try:
        digest = content[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise OfflineAuthorizationError("trust-anchor digest file must be ASCII") from exc
    if len(digest) != _SHA256_LENGTH or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise OfflineAuthorizationError("trust-anchor digest file must contain lowercase SHA-256")
    return digest


def _canonical_model_bytes(
    value: WebAnalysisOneCallAuthorizationTrustAnchor
    | WebAnalysisOneCallAuthorizationRequestV2
    | SignedWebAnalysisOneCallAuthorizationV2,
    *,
    label: str,
    max_bytes: int,
) -> bytes:
    canonical = canonical_json_bytes(
        value.model_dump(mode="json", by_alias=True),
        label=label,
        max_bytes=max_bytes - 1,
    )
    return canonical + b"\n"


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise OfflineAuthorizationError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _absolute_path(path: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("offline authorization file paths must be pathlib.Path values")
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.name or absolute.name in {".", ".."}:
        raise OfflineAuthorizationError("offline authorization path requires a filename")
    return absolute


def _distinct_paths(*paths: Path) -> tuple[Path, ...]:
    absolute = tuple(_absolute_path(path) for path in paths)
    if len(set(absolute)) != len(absolute):
        raise OfflineAuthorizationError("offline authorization input and output paths must differ")
    return absolute


def _require_posix_nofollow() -> None:
    if os.name != "posix" or not all(
        hasattr(os, name) for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    ):
        raise OfflineAuthorizationError("offline authorization requires POSIX no-follow file I/O")


@contextmanager
def _open_owner_parent(path: Path, *, label: str) -> Iterator[int]:
    _require_posix_nofollow()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parent.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise OfflineAuthorizationError(f"{label} parent path is not safe") from exc
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OfflineAuthorizationError(f"{label} parent must be a directory")
        if metadata.st_uid != os.geteuid():
            raise OfflineAuthorizationError(f"{label} parent must be owned by the current user")
        if stat.S_IMODE(metadata.st_mode) != _OWNER_DIRECTORY_MODE:
            raise OfflineAuthorizationError(f"{label} parent mode must be exactly 0700")
        yield descriptor
    finally:
        os.close(descriptor)


def _require_absent_owner_file(path: Path, *, label: str) -> None:
    destination = _absolute_path(path)
    with _open_owner_parent(destination, label=label) as parent_descriptor:
        try:
            os.stat(destination.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise OfflineAuthorizationError(
                f"{label} output path cannot be inspected safely"
            ) from exc
        raise OfflineAuthorizationError(f"{label} output already exists")


def _exclusive_owner_write(path: Path, content: bytes, *, label: str) -> None:
    destination = _absolute_path(path)
    with _open_owner_parent(destination, label=label) as parent_descriptor:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(
                destination.name,
                flags,
                _OWNER_FILE_MODE,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise OfflineAuthorizationError(
                f"{label} output cannot be created exclusively"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            _require_owner_file_metadata(opened, label=label, exact_size=0)
            view = memoryview(content)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count < 1:
                    raise OfflineAuthorizationError(f"{label} output write made no progress")
                written += count
            os.fsync(descriptor)
            final_descriptor = os.fstat(descriptor)
            _require_owner_file_metadata(
                final_descriptor,
                label=label,
                exact_size=len(content),
            )
            final_path = os.stat(
                destination.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if _file_revision(final_descriptor) != _file_revision(final_path):
                raise OfflineAuthorizationError(f"{label} output changed while being written")
            os.fsync(parent_descriptor)
        finally:
            os.close(descriptor)


def _read_owner_file(path: Path, *, max_bytes: int, label: str) -> bytes:
    source = _absolute_path(path)
    with _open_owner_parent(source, label=label) as parent_descriptor:
        try:
            observed = os.stat(source.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError as exc:
            raise OfflineAuthorizationError(f"{label} input cannot be inspected safely") from exc
        _require_owner_file_metadata(observed, label=label, max_bytes=max_bytes)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(source.name, flags, dir_fd=parent_descriptor)
        except OSError as exc:
            raise OfflineAuthorizationError(f"{label} input cannot be opened safely") from exc
        try:
            opened = os.fstat(descriptor)
            _require_owner_file_metadata(opened, label=label, max_bytes=max_bytes)
            if _file_identity(observed) != _file_identity(opened):
                raise OfflineAuthorizationError(f"{label} input changed while being opened")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise OfflineAuthorizationError(f"{label} input exceeds its byte limit")
            final_descriptor = os.fstat(descriptor)
            _require_owner_file_metadata(final_descriptor, label=label, max_bytes=max_bytes)
            final_path = os.stat(source.name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                _file_revision(opened) != _file_revision(final_descriptor)
                or _file_revision(opened) != _file_revision(final_path)
                or total != opened.st_size
            ):
                raise OfflineAuthorizationError(f"{label} input changed while being read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)


def _require_owner_file_metadata(
    metadata: os.stat_result,
    *,
    label: str,
    max_bytes: int | None = None,
    exact_size: int | None = None,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise OfflineAuthorizationError(f"{label} must be a regular file")
    if metadata.st_uid != os.geteuid():
        raise OfflineAuthorizationError(f"{label} must be owned by the current user")
    if metadata.st_nlink != 1:
        raise OfflineAuthorizationError(f"{label} must have exactly one hard link")
    if stat.S_IMODE(metadata.st_mode) != _OWNER_FILE_MODE:
        raise OfflineAuthorizationError(f"{label} mode must be exactly 0600")
    if max_bytes is not None and metadata.st_size > max_bytes:
        raise OfflineAuthorizationError(f"{label} exceeds its byte limit")
    if exact_size is not None and metadata.st_size != exact_size:
        raise OfflineAuthorizationError(f"{label} has an unexpected size")


def _file_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _file_revision(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
