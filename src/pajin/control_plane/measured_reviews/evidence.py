"""Server-selected, verified public evidence for the human review workflow."""

from __future__ import annotations

from datetime import UTC, datetime
from threading import Lock

from pajin.control_plane.errors import StateConflict
from pajin.control_plane.measured_reviews.models import ReviewDomain, ReviewEvidence
from pajin.workflow.ai_measured_product_reader import (
    AIMeasuredProductReader,
    AIMeasuredProductReaderError,
)
from pajin.workflow.network_measured_product_reader import (
    NetworkMeasuredProductReader,
    NetworkMeasuredProductReaderError,
)
from pajin.workflow.web_measured_product_reader import (
    WebMeasuredProductReader,
    WebMeasuredProductReaderError,
)


class ReviewEvidenceUnavailable(RuntimeError):
    """No deployment-selected reader exists for the requested domain."""


class MeasuredReviewEvidenceReader:
    """Adapt exact product readers without accepting any caller-supplied source."""

    def __init__(
        self,
        *,
        web: WebMeasuredProductReader | None = None,
        network: NetworkMeasuredProductReader | None = None,
        ai: AIMeasuredProductReader | None = None,
    ) -> None:
        for reader, expected in (
            (web, WebMeasuredProductReader),
            (network, NetworkMeasuredProductReader),
            (ai, AIMeasuredProductReader),
        ):
            if reader is not None and type(reader) is not expected:
                raise TypeError("Review evidence requires exact deployment-selected readers")
        self._readers = {"web": web, "network": network, "ai": ai}
        self._lock = Lock()

    def read(self, domain: ReviewDomain) -> ReviewEvidence:
        reader = self._readers.get(domain)
        if reader is None:
            raise ReviewEvidenceUnavailable("Review evidence for this domain is not configured")
        try:
            with self._lock:
                projection = reader.read()
                return ReviewEvidence.model_validate(
                    {"domain": domain, "projection": projection, "verifiedAt": datetime.now(UTC)}
                )
        except (
            WebMeasuredProductReaderError,
            NetworkMeasuredProductReaderError,
            AIMeasuredProductReaderError,
            ValueError,
        ) as exc:
            raise StateConflict("Measured review source is not integrity-valid") from exc

    def read_exact(self, domain: ReviewDomain, digest: str) -> ReviewEvidence:
        evidence = self.read(domain)
        if evidence.evidence_digest != digest:
            raise StateConflict("Evidence changed; reload it before submitting a review")
        return evidence
