"""Loopback-only request mediation shared by browser traffic and HTTP diagnostics."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import time
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast, overload
from urllib.parse import unquote, urlsplit

import httpx

from pajin.policy.scope import normalize_scope_pattern, normalize_target_url, scope_matches
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment.discovery import browser_discovery_request_path_rejection
from pajin.web_assessment.models import (
    PassiveDiscoveryBoundaryReceipt,
    RequestEvidence,
    WebAssessmentPlan,
    passive_media_type_essence,
    request_evidence_digest,
)


class AssessmentBoundaryError(ValueError):
    """The current request is outside the approved assessment or resource budget."""


HTTPMethod = Literal["GET", "HEAD", "POST"]
_GZIP_METADATA_BUDGET_BYTES = 64 * 1024


def _declared_content_length(response: httpx.Response) -> int | None:
    value = response.headers.get("content-length")
    if value is None:
        return None
    normalized = value.strip()
    if not normalized or not normalized.isascii() or not normalized.isdecimal():
        raise AssessmentBoundaryError("invalid-content-length")
    return int(normalized)


def _gzip_wire_byte_limit(decoded_limit: int) -> int:
    # zlib's conservative DEFLATE bound plus a fixed budget for the gzip wrapper
    # and optional metadata. Larger metadata is not useful to this bounded assessor.
    deflate_bound = (
        decoded_limit + (decoded_limit >> 12) + (decoded_limit >> 14) + (decoded_limit >> 25) + 13
    )
    return deflate_bound + _GZIP_METADATA_BUDGET_BYTES


async def _read_bounded_response_body(
    response: httpx.Response,
    *,
    method: HTTPMethod,
    response_encoding: Literal["", "identity", "gzip"],
    limit: int,
) -> bytes:
    declared_length = None if method == "HEAD" else _declared_content_length(response)
    wire_limit = _gzip_wire_byte_limit(limit) if response_encoding == "gzip" else limit
    if declared_length is not None and declared_length > wire_limit:
        raise AssessmentBoundaryError("response-byte-limit")

    # Mock/custom transports can return an already-consumed response. HTTPX stores that
    # representation decoded, so it can only be checked after the transport materialized it.
    # Production HTTP responses take the raw streaming path below.
    if response.is_stream_consumed:
        if response_encoding == "gzip":
            raise AssessmentBoundaryError("encoded-response-already-consumed")
        try:
            preloaded = response.content
        except httpx.ResponseNotRead as exc:  # pragma: no cover - defensive transport boundary
            raise AssessmentBoundaryError("response-stream-already-consumed") from exc
        if len(preloaded) > limit:
            raise AssessmentBoundaryError("response-byte-limit")
        return bytes(preloaded)

    wire_body = bytearray()
    async for raw_chunk in response.aiter_raw():
        if len(raw_chunk) > wire_limit - len(wire_body):
            raise AssessmentBoundaryError("response-byte-limit")
        wire_body.extend(raw_chunk)

    if response_encoding != "gzip" or method == "HEAD":
        return bytes(wire_body)

    decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
    try:
        decoded = decoder.decompress(bytes(wire_body), limit)
    except zlib.error as exc:
        raise AssessmentBoundaryError("invalid-gzip-response") from exc
    if decoder.unconsumed_tail or (len(decoded) == limit and not decoder.eof):
        raise AssessmentBoundaryError("response-byte-limit")
    if not decoder.eof:
        raise AssessmentBoundaryError("invalid-gzip-response")
    if decoder.unused_data:
        raise AssessmentBoundaryError("invalid-gzip-response")
    return bytes(decoded)


@dataclass(frozen=True)
class Exchange:
    status: int
    headers: dict[str, str]
    body: bytes
    evidence_id: str

    def json(self) -> object:
        if "json" not in self.headers.get("content-type", "").lower():
            return None
        try:
            return parse_strict_json_bytes(
                self.body,
                label="web response",
                max_bytes=10_000_000,
                max_depth=32,
                max_nodes=100_000,
            )
        except ValueError:
            return None


@dataclass(frozen=True)
class RequestReservation:
    sequence: int
    evidence_id: str
    phase: str
    method: HTTPMethod
    url: str
    request_sha256: str
    canonical_origin: str
    path: str
    query_present: bool
    request_bytes: int
    redirect_hops: int


@dataclass(frozen=True)
class PassiveMetadataCompletion:
    """Generic evidence plus its non-authoritative passive-boundary receipt."""

    evidence: RequestEvidence
    boundary_receipt: PassiveDiscoveryBoundaryReceipt


class AssessmentNetwork:
    """No ambient proxies, redirects, DNS targets, or shared authentication jar."""

    def __init__(
        self,
        plan: WebAssessmentPlan,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        total_request_ceiling: int = 100,
    ) -> None:
        if type(total_request_ceiling) is not int or not 1 <= total_request_ceiling <= 500:
            raise ValueError("assessment total request ceiling must be between 1 and 500")
        self.plan = plan
        self.client = httpx.AsyncClient(
            trust_env=False,
            follow_redirects=False,
            transport=transport,
        )
        self.deadline = time.monotonic() + plan.duration_seconds
        self.phase = "uninitialized"
        self.policy: EgressPolicy | None = None
        self.phase_requests = 0
        self.total_request_ceiling = total_request_ceiling
        self.total_requests = 0
        self.total_bytes = 0
        self.evidence: list[RequestEvidence] = []
        self.blocked: dict[str, int] = {}
        self.failures: dict[str, int] = {}
        self._fingerprint_key = secrets.token_bytes(32)
        self._lock = asyncio.Lock()
        self._sequence = 0
        self._open_reservations: dict[str, RequestReservation] = {}
        self._authorization_expires_at: datetime | None = None

    def bind_authorization_deadline(self, expires_at: datetime) -> None:
        """Prevent a Run started near expiry from issuing requests after authorization ends."""

        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ValueError("assessment authorization expiry requires an explicit UTC offset")
        normalized = expires_at.astimezone(UTC)
        if (
            self._authorization_expires_at is not None
            and self._authorization_expires_at != normalized
        ):
            raise AssessmentBoundaryError("authorization-already-bound")
        self._authorization_expires_at = normalized
        remaining = max(0.0, (normalized - datetime.now(UTC)).total_seconds())
        self.deadline = min(self.deadline, time.monotonic() + remaining)

    def _require_live_authorization(self) -> None:
        expires_at = self._authorization_expires_at
        if expires_at is not None and datetime.now(UTC) >= expires_at:
            raise AssessmentBoundaryError("authorization-expired")
        if time.monotonic() >= self.deadline:
            raise AssessmentBoundaryError("assessment-deadline")

    def begin_phase(self, phase: str, policy: EgressPolicy) -> None:
        self._require_live_authorization()
        if self._open_reservations:
            raise AssessmentBoundaryError("phase-has-open-requests")
        self.phase = phase
        self.policy = EgressPolicy.model_validate(policy.model_dump())
        self.phase_requests = 0

    def require_url(self, url: str, method: str) -> None:
        parsed = urlsplit(url)
        origin = urlsplit(self.plan.origin)
        if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc):
            raise AssessmentBoundaryError("outside-approved-origin")
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or any(ord(char) < 32 or char == "\\" for char in url)
        ):
            raise AssessmentBoundaryError("invalid-url")
        decoded_path = unquote(parsed.path)
        if any(decoded_path.startswith(path) for path in self.plan.deny_paths):
            raise AssessmentBoundaryError("denied-path")
        if method not in {"GET", "HEAD", "POST"}:
            raise AssessmentBoundaryError("unapproved-method")
        if method == "POST" and parsed.path not in self.plan.allowed_post_paths:
            raise AssessmentBoundaryError("unapproved-post-path")
        if self.policy is None or not self.policy.allow_private_networks:
            raise AssessmentBoundaryError("missing-egress-grant")
        if method not in self.policy.allowed_methods:
            raise AssessmentBoundaryError("outside-campaign-scope")
        if not any(scope_matches(rule, url) for rule in self.policy.allow):
            raise AssessmentBoundaryError("outside-campaign-scope")
        normalized_target = normalize_target_url(url)
        if any(
            scope_matches(rule, url)
            or scope_matches(
                normalize_scope_pattern(rule).casefold(),
                normalized_target.casefold(),
            )
            for rule in self.policy.deny
        ):
            raise AssessmentBoundaryError("outside-campaign-scope")

    async def reserve(
        self,
        method: str,
        url: str,
        *,
        content: bytes | None = None,
        redirect_hops: int = 0,
    ) -> RequestReservation:
        normalized_method = method.upper()
        method = cast(HTTPMethod, normalized_method)
        request_bytes = len(content or b"")
        if request_bytes > 64_000:
            raise AssessmentBoundaryError("request-byte-limit")
        if type(redirect_hops) is not int or not 0 <= redirect_hops <= 20:
            raise AssessmentBoundaryError("invalid-redirect-hops")
        parsed = urlsplit(url)
        query_present = "?" in url.partition("#")[0]
        async with self._lock:
            self._require_live_authorization()
            self.require_url(url, normalized_method)
            policy = self.policy
            assert policy is not None
            phase = self.phase
            if phase == "browser-passive-discovery":
                if method != "GET":
                    raise AssessmentBoundaryError("unapproved-method")
                if query_present:
                    raise AssessmentBoundaryError("query-values")
                if request_bytes != 0:
                    raise AssessmentBoundaryError("request-body-disabled")
                if redirect_hops != 0:
                    raise AssessmentBoundaryError("redirect-disabled")
                path_rejection = browser_discovery_request_path_rejection(
                    origin=self.plan.origin,
                    url=url,
                )
                if path_rejection is not None:
                    raise AssessmentBoundaryError(path_rejection)
            if self.phase_requests >= policy.max_requests:
                raise AssessmentBoundaryError("phase-request-budget")
            if self.total_requests >= self.total_request_ceiling:
                raise AssessmentBoundaryError("total-request-budget")
            if self.total_bytes >= 128_000_000:
                raise AssessmentBoundaryError("total-response-budget")
            self.phase_requests += 1
            self.total_requests += 1
            self._sequence += 1
            evidence_id = f"http-{self._sequence}-{secrets.token_hex(4)}"
            reservation = RequestReservation(
                sequence=self._sequence,
                evidence_id=evidence_id,
                phase=phase,
                method=method,
                url=url,
                request_sha256=hmac.new(
                    self._fingerprint_key,
                    method.encode() + url.encode() + (content or b""),
                    hashlib.sha256,
                ).hexdigest(),
                canonical_origin=self.plan.origin,
                path=parsed.path or "/",
                query_present=query_present,
                request_bytes=request_bytes,
                redirect_hops=redirect_hops,
            )
            self._open_reservations[evidence_id] = reservation
            return reservation

    async def complete(
        self,
        reservation: RequestReservation,
        *,
        status: int,
        headers: dict[str, str],
        body: bytes,
    ) -> RequestEvidence:
        if type(status) is not int or not 100 <= status <= 599:
            await self.fail(reservation, reason="invalid-response-status")
            raise AssessmentBoundaryError("invalid-response-status")
        policy = self.policy
        if policy is None:
            await self.fail(reservation, reason="missing-egress-grant")
            raise AssessmentBoundaryError("missing-egress-grant")
        limit = min(self.plan.max_response_bytes, policy.max_response_bytes)
        if len(body) > limit:
            await self.fail(reservation, reason="response-byte-limit")
            raise AssessmentBoundaryError("response-byte-limit")
        async with self._lock:
            if self._open_reservations.get(reservation.evidence_id) is not reservation:
                raise AssessmentBoundaryError("unknown-request-reservation")
            if self.total_bytes + len(body) > 128_000_000:
                self._open_reservations.pop(reservation.evidence_id)
                self.failures["total-response-budget"] = (
                    self.failures.get("total-response-budget", 0) + 1
                )
                raise AssessmentBoundaryError("total-response-budget")
            self.total_bytes += len(body)
            evidence = RequestEvidence(
                evidence_id=reservation.evidence_id,
                phase=reservation.phase,
                method=reservation.method,
                path=reservation.path,
                request_sha256=reservation.request_sha256,
                status=status,
                response_sha256=hashlib.sha256(body).hexdigest(),
                response_bytes=len(body),
                media_type=headers.get("content-type", "")[:100],
            )
            self.evidence.append(evidence)
            self._open_reservations.pop(reservation.evidence_id)
            return evidence

    @overload
    async def complete_passive_metadata(
        self,
        reservation: RequestReservation,
        *,
        status: int,
        headers: dict[str, str],
        observed_response_bytes: int,
        return_boundary_receipt: Literal[False] = False,
    ) -> RequestEvidence: ...

    @overload
    async def complete_passive_metadata(
        self,
        reservation: RequestReservation,
        *,
        status: int,
        headers: dict[str, str],
        observed_response_bytes: int,
        return_boundary_receipt: Literal[True],
    ) -> PassiveMetadataCompletion: ...

    async def complete_passive_metadata(
        self,
        reservation: RequestReservation,
        *,
        status: int,
        headers: dict[str, str],
        observed_response_bytes: int,
        return_boundary_receipt: bool = False,
    ) -> RequestEvidence | PassiveMetadataCompletion:
        """Complete one discovery GET without retaining its response body.

        Observed encoded response-body bytes still consume the monotonic response
        budget.  The sealed RequestEvidence truthfully describes the retained
        payload as empty and is accepted only for the dedicated passive-discovery
        phase.
        """

        if reservation.phase != "browser-passive-discovery" or reservation.method != "GET":
            await self.fail(reservation, reason="passive-metadata-outside-discovery")
            raise AssessmentBoundaryError("passive-metadata-outside-discovery")
        if reservation.canonical_origin != self.plan.origin or reservation.path != (
            urlsplit(reservation.url).path or "/"
        ):
            await self.fail(reservation, reason="passive-metadata-reservation-mismatch")
            raise AssessmentBoundaryError("passive-metadata-reservation-mismatch")
        if reservation.query_present or "?" in reservation.url.partition("#")[0]:
            await self.fail(reservation, reason="passive-metadata-query-present")
            raise AssessmentBoundaryError("passive-metadata-query-present")
        if reservation.request_bytes != 0:
            await self.fail(reservation, reason="passive-metadata-request-body")
            raise AssessmentBoundaryError("passive-metadata-request-body")
        if reservation.redirect_hops != 0:
            await self.fail(reservation, reason="passive-metadata-redirect")
            raise AssessmentBoundaryError("passive-metadata-redirect")
        if type(return_boundary_receipt) is not bool:
            await self.fail(reservation, reason="invalid-passive-metadata-return-mode")
            raise AssessmentBoundaryError("invalid-passive-metadata-return-mode")
        if type(status) is not int or not 100 <= status <= 599:
            await self.fail(reservation, reason="invalid-response-status")
            raise AssessmentBoundaryError("invalid-response-status")
        if type(observed_response_bytes) is not int or observed_response_bytes < 0:
            await self.fail(reservation, reason="invalid-response-size")
            raise AssessmentBoundaryError("invalid-response-size")
        policy = self.policy
        if policy is None:
            await self.fail(reservation, reason="missing-egress-grant")
            raise AssessmentBoundaryError("missing-egress-grant")
        limit = min(self.plan.max_response_bytes, policy.max_response_bytes)
        if observed_response_bytes > limit:
            await self.fail(reservation, reason="response-byte-limit")
            raise AssessmentBoundaryError("response-byte-limit")
        media_type = passive_media_type_essence(headers.get("content-type", ""))
        evidence = RequestEvidence(
            evidence_id=reservation.evidence_id,
            phase=reservation.phase,
            method=reservation.method,
            path=reservation.path,
            request_sha256=reservation.request_sha256,
            status=status,
            response_sha256=hashlib.sha256(b"").hexdigest(),
            response_bytes=0,
            media_type=media_type,
        )
        boundary_receipt = PassiveDiscoveryBoundaryReceipt(
            evidenceId=evidence.evidence_id,
            requestEvidenceDigest=request_evidence_digest(evidence),
            reservationSequence=reservation.sequence,
            evidenceSequence=reservation.sequence,
            canonicalOrigin=reservation.canonical_origin,
            method=reservation.method,
            queryPresent=reservation.query_present,
            requestBytes=reservation.request_bytes,
            redirectHops=reservation.redirect_hops,
            path=reservation.path,
            status=status,
            observedResponseBodyBytes=observed_response_bytes,
            retainedResponseBytes=evidence.response_bytes,
            retainedResponseSha256=evidence.response_sha256,
            mediaType=media_type,
        )
        async with self._lock:
            if self._open_reservations.get(reservation.evidence_id) is not reservation:
                raise AssessmentBoundaryError("unknown-request-reservation")
            if self.total_bytes + observed_response_bytes > 128_000_000:
                self._open_reservations.pop(reservation.evidence_id)
                self.failures["total-response-budget"] = (
                    self.failures.get("total-response-budget", 0) + 1
                )
                raise AssessmentBoundaryError("total-response-budget")
            self.total_bytes += observed_response_bytes
            self.evidence.append(evidence)
            self._open_reservations.pop(reservation.evidence_id)
            if return_boundary_receipt:
                return PassiveMetadataCompletion(evidence, boundary_receipt)
            return evidence

    async def fail(self, reservation: RequestReservation, *, reason: str) -> None:
        async with self._lock:
            if self._open_reservations.get(reservation.evidence_id) is reservation:
                self._open_reservations.pop(reservation.evidence_id)
                self.failures[reason] = self.failures.get(reason, 0) + 1

    async def exchange(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        accept_encoding: Literal["identity", "gzip"] = "identity",
    ) -> Exchange:
        if accept_encoding not in {"identity", "gzip"}:
            raise AssessmentBoundaryError("unapproved-response-encoding")
        reservation = await self.reserve(method, url, content=content)
        # An explicit Request bypasses the client's response-cookie jar. Browser cookies
        # come from that exact fresh context; probes provide only their selected token.
        selected_headers = {
            key: value
            for key, value in (headers or {}).items()
            if key.lower() not in {"host", "content-length", "connection", "proxy-authorization"}
        }
        selected_headers["accept-encoding"] = accept_encoding
        request = httpx.Request(method, url, headers=selected_headers, content=content)
        try:
            timeout = min(
                self.plan.request_timeout_seconds,
                self.deadline - time.monotonic(),
            )
            async with asyncio.timeout(max(0.001, timeout)):
                response = await self.client.send(request, stream=True, follow_redirects=False)
                try:
                    response_encoding = response.headers.get("content-encoding", "").strip().lower()
                    if response_encoding not in {"", accept_encoding}:
                        raise AssessmentBoundaryError("unapproved-response-encoding")
                    assert self.policy is not None
                    limit = min(
                        self.plan.max_response_bytes,
                        self.policy.max_response_bytes,
                    )
                    data = await _read_bounded_response_body(
                        response,
                        method=reservation.method,
                        response_encoding=cast(Literal["", "identity", "gzip"], response_encoding),
                        limit=limit,
                    )
                    response_headers = {
                        key: value
                        for key, value in response.headers.items()
                        if key.lower()
                        not in {
                            "content-encoding",
                            "content-length",
                            "transfer-encoding",
                            "connection",
                        }
                    }
                    status = response.status_code
                finally:
                    await response.aclose()
        except AssessmentBoundaryError as exc:
            await self.fail(reservation, reason=str(exc))
            raise
        except (Exception, asyncio.CancelledError):
            await self.fail(reservation, reason="transport-or-response-failure")
            raise
        finally:
            self.client.cookies.clear()
        evidence = await self.complete(
            reservation,
            status=status,
            headers=response_headers,
            body=data,
        )
        return Exchange(status, response_headers, data, evidence.evidence_id)

    async def json_request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        token: str | None = None,
    ) -> Exchange:
        headers = {"accept": "application/json"}
        content = None
        if payload is not None:
            headers["content-type"] = "application/json"
            content = json.dumps(payload, allow_nan=False).encode()
        if token is not None:
            headers["authorization"] = f"Bearer {token}"
        return await self.exchange(
            method,
            self.plan.origin + path,
            headers=headers,
            content=content,
        )

    def record_block(self, reason: str) -> None:
        self.blocked[reason] = self.blocked.get(reason, 0) + 1

    async def close(self) -> None:
        await self.client.aclose()
