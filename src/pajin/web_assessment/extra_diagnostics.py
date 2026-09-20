"""Versioned, passive diagnostics kept separate from the WEB-003 result contract."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Final, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import StrictModel
from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment.network import AssessmentNetwork, Exchange

EXTRA_DIAGNOSTIC_RECIPE_API_VERSION: Final[
    Literal["pajin.dev/local-web-extra-diagnostic-recipe/v1alpha1"]
] = "pajin.dev/local-web-extra-diagnostic-recipe/v1alpha1"
EXTRA_DIAGNOSTIC_RESULT_API_VERSION: Final[
    Literal["pajin.dev/local-web-extra-diagnostic-result/v1alpha1"]
] = "pajin.dev/local-web-extra-diagnostic-result/v1alpha1"

ExtraDiagnosticStatus = Literal["locally-observed", "not-observed", "inconclusive"]
TrialRepetition = Literal["source", "replay"]

_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_HTTP_EVIDENCE_PATTERN = r"^http-[1-9][0-9]*-[a-f0-9]{8}$"
_MAX_PASSIVE_RESPONSE_BYTES: Final[Literal[262_144]] = 262_144
_DIRECTORY_ANCHOR_LIMIT = 10_000


class _ExtraDiagnosticContract(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class SecurityHeaderPostureRecipe(_ExtraDiagnosticContract):
    """One exact root-page read per source or replay trial."""

    api_version: Literal["pajin.dev/local-web-extra-diagnostic-recipe/v1alpha1"] = (
        EXTRA_DIAGNOSTIC_RECIPE_API_VERSION
    )
    check: Literal["security-header-posture"] = "security-header-posture"
    method: Literal["GET"] = "GET"
    path: Literal["/"] = "/"
    required_protections: tuple[
        Literal["content-security-policy"],
        Literal["no-sniff"],
        Literal["frame-protection"],
    ] = ("content-security-policy", "no-sniff", "frame-protection")
    requests_per_trial: Literal[1] = 1
    total_request_budget: Literal[2] = 2
    max_response_bytes: Literal[262_144] = _MAX_PASSIVE_RESPONSE_BYTES

    @property
    def recipe_digest(self) -> str:
        return discovery_digest(
            "pajin.web-assessment.extra-diagnostic-recipe/v1",
            self.model_dump(mode="json"),
        )


class FTPDirectoryListingRecipe(_ExtraDiagnosticContract):
    """Read only the FTP directory index and one fixed missing-path control."""

    api_version: Literal["pajin.dev/local-web-extra-diagnostic-recipe/v1alpha1"] = (
        EXTRA_DIAGNOSTIC_RECIPE_API_VERSION
    )
    check: Literal["ftp-directory-listing"] = "ftp-directory-listing"
    method: Literal["GET"] = "GET"
    path: Literal["/ftp/"] = "/ftp/"
    missing_path: Literal["/ftp/pajin-web004-control-missing-v1.md"] = (
        "/ftp/pajin-web004-control-missing-v1.md"
    )
    requests_per_trial: Literal[2] = 2
    total_request_budget: Literal[4] = 4
    max_response_bytes: Literal[262_144] = _MAX_PASSIVE_RESPONSE_BYTES

    @property
    def recipe_digest(self) -> str:
        return discovery_digest(
            "pajin.web-assessment.extra-diagnostic-recipe/v1",
            self.model_dump(mode="json"),
        )


class SecurityHeaderPostureFacts(_ExtraDiagnosticContract):
    response_status: int = Field(strict=True, ge=100, le=599)
    html_response: bool = Field(strict=True)
    content_security_policy_present: bool = Field(strict=True)
    no_sniff_present: bool = Field(strict=True)
    frame_protection_present: bool = Field(strict=True)
    missing_protection_count: int = Field(strict=True, ge=0, le=3)

    @model_validator(mode="after")
    def bind_missing_count(self) -> Self:
        expected = sum(
            protection is False
            for protection in (
                self.content_security_policy_present,
                self.no_sniff_present,
                self.frame_protection_present,
            )
        )
        if self.missing_protection_count != expected:
            raise ValueError("security-header missing count differs from the observed posture")
        return self


class FTPDirectoryListingFacts(_ExtraDiagnosticContract):
    listing_status: int = Field(strict=True, ge=100, le=599)
    listing_html_response: bool = Field(strict=True)
    directory_listing_shape: bool = Field(strict=True)
    listing_anchor_count: int = Field(strict=True, ge=0, le=_DIRECTORY_ANCHOR_LIMIT)
    missing_control_status: int = Field(strict=True, ge=100, le=599)
    missing_control_html_response: bool = Field(strict=True)
    missing_control_listing_shape: bool = Field(strict=True)
    missing_control_anchor_count: int = Field(
        strict=True,
        ge=0,
        le=_DIRECTORY_ANCHOR_LIMIT,
    )

    @model_validator(mode="after")
    def bind_listing_shapes(self) -> Self:
        if self.directory_listing_shape and (
            not self.listing_html_response or self.listing_anchor_count == 0
        ):
            raise ValueError("FTP listing shape lacks its bounded HTML evidence")
        if self.missing_control_listing_shape and (
            not self.missing_control_html_response or self.missing_control_anchor_count == 0
        ):
            raise ValueError("FTP missing-control shape lacks its bounded HTML evidence")
        return self


class SecurityHeaderPostureTrial(_ExtraDiagnosticContract):
    check: Literal["security-header-posture"] = "security-header-posture"
    repetition: TrialRepetition
    reproduced: bool = Field(strict=True)
    controls_passed: bool = Field(strict=True)
    evidence_ids: tuple[str] = Field(min_length=1, max_length=1)
    facts: SecurityHeaderPostureFacts

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence_ids(cls, value: tuple[str]) -> tuple[str]:
        if any(not _matches_http_evidence_id(item) for item in value):
            raise ValueError("security-header trial references invalid HTTP Evidence")
        return value

    @model_validator(mode="after")
    def bind_outcome(self) -> Self:
        expected_controls = self.facts.html_response and self.facts.response_status == 200
        expected_reproduced = expected_controls and self.facts.missing_protection_count > 0
        if self.controls_passed != expected_controls or self.reproduced != expected_reproduced:
            raise ValueError("security-header trial outcome differs from its bounded facts")
        return self


class FTPDirectoryListingTrial(_ExtraDiagnosticContract):
    check: Literal["ftp-directory-listing"] = "ftp-directory-listing"
    repetition: TrialRepetition
    reproduced: bool = Field(strict=True)
    controls_passed: bool = Field(strict=True)
    evidence_ids: tuple[str, str] = Field(min_length=2, max_length=2)
    facts: FTPDirectoryListingFacts

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence_ids(cls, value: tuple[str, str]) -> tuple[str, str]:
        if len(set(value)) != len(value) or any(
            not _matches_http_evidence_id(item) for item in value
        ):
            raise ValueError("FTP listing trial references invalid HTTP Evidence")
        return value

    @model_validator(mode="after")
    def bind_outcome(self) -> Self:
        probe_interpretable = self.facts.listing_status in {403, 404} or (
            self.facts.listing_status == 200 and self.facts.listing_html_response
        )
        expected_controls = (
            probe_interpretable
            and self.facts.missing_control_status in {404, 410}
            and not self.facts.missing_control_listing_shape
        )
        expected_reproduced = (
            self.facts.listing_status == 200 and self.facts.directory_listing_shape
        )
        if self.controls_passed != expected_controls or self.reproduced != expected_reproduced:
            raise ValueError("FTP listing trial outcome differs from its bounded facts")
        return self


class SecurityHeaderPostureResult(_ExtraDiagnosticContract):
    api_version: Literal["pajin.dev/local-web-extra-diagnostic-result/v1alpha1"] = (
        EXTRA_DIAGNOSTIC_RESULT_API_VERSION
    )
    result_id: str = Field(default="", max_length=120)
    recipe_digest: str = Field(pattern=_SHA256_PATTERN)
    check: Literal["security-header-posture"] = "security-header-posture"
    cwe: Literal["CWE-693"] = "CWE-693"
    severity: Literal["low"] = "low"
    status: ExtraDiagnosticStatus
    title: str = Field(min_length=1, max_length=300)
    observed_impact: str = Field(min_length=1, max_length=1_000)
    trials: tuple[SecurityHeaderPostureTrial, SecurityHeaderPostureTrial]
    finding_authority: Literal[False] = False
    target_write_performed: Literal[False] = False
    external_callback_performed: Literal[False] = False
    raw_body_persisted: Literal[False] = False
    file_names_persisted: Literal[False] = False
    query_values_persisted: Literal[False] = False
    secrets_persisted: Literal[False] = False

    @field_validator(
        "finding_authority",
        "target_write_performed",
        "external_callback_performed",
        "raw_body_persisted",
        "file_names_persisted",
        "query_values_persisted",
        "secrets_persisted",
        mode="before",
    )
    @classmethod
    def require_false_safety_markers(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("passive diagnostic safety and authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_result(self) -> Self:
        _bind_repetitions(self.trials)
        _bind_unique_evidence(self.trials)
        expected_status = _status_from_trials(self.trials)
        expected_title, expected_impact = _result_narrative(self.check, expected_status)
        if self.status != expected_status:
            raise ValueError("security-header result status differs from its trials")
        if self.title != expected_title or self.observed_impact != expected_impact:
            raise ValueError("security-header result narrative differs from its trials")
        if self.recipe_digest != SecurityHeaderPostureRecipe().recipe_digest:
            raise ValueError("security-header result references an unknown recipe")
        _bind_result_id(self, "security-header-posture")
        return self


class FTPDirectoryListingResult(_ExtraDiagnosticContract):
    api_version: Literal["pajin.dev/local-web-extra-diagnostic-result/v1alpha1"] = (
        EXTRA_DIAGNOSTIC_RESULT_API_VERSION
    )
    result_id: str = Field(default="", max_length=120)
    recipe_digest: str = Field(pattern=_SHA256_PATTERN)
    check: Literal["ftp-directory-listing"] = "ftp-directory-listing"
    cwe: Literal["CWE-548"] = "CWE-548"
    severity: Literal["low"] = "low"
    status: ExtraDiagnosticStatus
    title: str = Field(min_length=1, max_length=300)
    observed_impact: str = Field(min_length=1, max_length=1_000)
    trials: tuple[FTPDirectoryListingTrial, FTPDirectoryListingTrial]
    finding_authority: Literal[False] = False
    target_write_performed: Literal[False] = False
    external_callback_performed: Literal[False] = False
    raw_body_persisted: Literal[False] = False
    file_names_persisted: Literal[False] = False
    query_values_persisted: Literal[False] = False
    secrets_persisted: Literal[False] = False

    @field_validator(
        "finding_authority",
        "target_write_performed",
        "external_callback_performed",
        "raw_body_persisted",
        "file_names_persisted",
        "query_values_persisted",
        "secrets_persisted",
        mode="before",
    )
    @classmethod
    def require_false_safety_markers(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("passive diagnostic safety and authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_result(self) -> Self:
        _bind_repetitions(self.trials)
        _bind_unique_evidence(self.trials)
        expected_status = _status_from_trials(self.trials)
        expected_title, expected_impact = _result_narrative(self.check, expected_status)
        if self.status != expected_status:
            raise ValueError("FTP listing result status differs from its trials")
        if self.title != expected_title or self.observed_impact != expected_impact:
            raise ValueError("FTP listing result narrative differs from its trials")
        if self.recipe_digest != FTPDirectoryListingRecipe().recipe_digest:
            raise ValueError("FTP listing result references an unknown recipe")
        _bind_result_id(self, "ftp-directory-listing")
        return self


def _matches_http_evidence_id(value: str) -> bool:
    return re.fullmatch(_HTTP_EVIDENCE_PATTERN, value) is not None


def _bind_repetitions(trials: tuple[object, object]) -> None:
    repetitions = tuple(getattr(trial, "repetition", None) for trial in trials)
    if repetitions != ("source", "replay"):
        raise ValueError("extra diagnostics require ordered source and replay trials")


def _bind_unique_evidence(
    trials: tuple[SecurityHeaderPostureTrial, SecurityHeaderPostureTrial]
    | tuple[FTPDirectoryListingTrial, FTPDirectoryListingTrial],
) -> None:
    evidence_ids = [evidence_id for trial in trials for evidence_id in trial.evidence_ids]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("extra diagnostic source and replay require distinct Evidence")


def _status_from_trials(
    trials: tuple[SecurityHeaderPostureTrial, SecurityHeaderPostureTrial]
    | tuple[FTPDirectoryListingTrial, FTPDirectoryListingTrial],
) -> ExtraDiagnosticStatus:
    if all(trial.reproduced and trial.controls_passed for trial in trials):
        return "locally-observed"
    if all(not trial.reproduced and trial.controls_passed for trial in trials):
        return "not-observed"
    return "inconclusive"


def _result_narrative(
    check: Literal["security-header-posture", "ftp-directory-listing"],
    status: ExtraDiagnosticStatus,
) -> tuple[str, str]:
    narratives: dict[
        tuple[str, ExtraDiagnosticStatus],
        tuple[str, str],
    ] = {
        ("security-header-posture", "locally-observed"): (
            "Incomplete browser security headers were locally observed",
            "Both controlled root-page reads showed that one or more code-owned browser "
            "response protections were absent or invalid.",
        ),
        ("security-header-posture", "not-observed"): (
            "Required browser security-header posture was observed",
            "Both controlled root-page reads contained the code-owned content-policy, "
            "MIME-sniffing, and framing protections.",
        ),
        ("security-header-posture", "inconclusive"): (
            "Browser security-header posture diagnostic was inconclusive",
            "The source and replay responses or their root-HTML controls did not support a "
            "stable browser security-header conclusion.",
        ),
        ("ftp-directory-listing", "locally-observed"): (
            "FTP directory listing was locally observed",
            "Both controlled reads returned an HTML directory-listing shape while the fixed "
            "missing-path controls did not.",
        ),
        ("ftp-directory-listing", "not-observed"): (
            "FTP directory listing was not observed",
            "Both controlled reads found no FTP directory-listing shape and the fixed "
            "missing-path controls behaved as missing resources.",
        ),
        ("ftp-directory-listing", "inconclusive"): (
            "FTP directory-listing diagnostic was inconclusive",
            "The source and replay responses or their fixed missing-path controls did not "
            "support a stable directory-listing conclusion.",
        ),
    }
    return narratives[(check, status)]


def _bind_result_id(
    result: SecurityHeaderPostureResult | FTPDirectoryListingResult,
    check: Literal["security-header-posture", "ftp-directory-listing"],
) -> None:
    material = result.model_dump(mode="json", exclude={"result_id"})
    digest = discovery_digest("pajin.web-assessment.extra-diagnostic-result/v1", material)
    expected = f"web-extra:{check}:{digest}"
    if result.result_id and result.result_id != expected:
        raise ValueError("extra diagnostic result ID differs from its trials")
    object.__setattr__(result, "result_id", expected)


def _exact_get_policy(
    network: AssessmentNetwork,
    *,
    paths: tuple[str, ...],
    max_requests: int,
    max_response_bytes: int,
) -> EgressPolicy:
    if not paths or any(
        not path.startswith("/") or "?" in path or "#" in path or "\\" in path for path in paths
    ):
        raise ValueError("passive diagnostic paths must be exact origin-relative paths")
    return EgressPolicy(
        allow=[network.plan.origin + path for path in paths],
        allowed_methods={"GET"},
        allow_private_networks=True,
        max_response_bytes=max_response_bytes,
        max_requests=max_requests,
        max_request_bytes=1,
    )


def _normalized_headers(exchange: Exchange) -> dict[str, str]:
    return {key.lower(): value.strip() for key, value in exchange.headers.items()}


def _looks_like_html(exchange: Exchange) -> bool:
    media_type = _normalized_headers(exchange).get("content-type", "").lower()
    prefix = exchange.body[:8_192].lstrip().lower()
    return "text/html" in media_type and (
        prefix.startswith(b"<!doctype html") or b"<html" in prefix
    )


def _has_frame_ancestors(content_security_policy: str) -> bool:
    for directive in content_security_policy.split(";"):
        tokens = directive.strip().lower().split()
        if len(tokens) >= 2 and tokens[0] == "frame-ancestors":
            return "*" not in tokens[1:]
    return False


def _security_header_facts(exchange: Exchange) -> SecurityHeaderPostureFacts:
    headers = _normalized_headers(exchange)
    content_security_policy = headers.get("content-security-policy", "")
    content_security_policy_present = bool(content_security_policy)
    no_sniff_present = headers.get("x-content-type-options", "").lower() == "nosniff"
    frame_options = headers.get("x-frame-options", "").lower()
    frame_protection_present = frame_options in {"deny", "sameorigin"} or (
        _has_frame_ancestors(content_security_policy)
    )
    missing_count = sum(
        protection is False
        for protection in (
            content_security_policy_present,
            no_sniff_present,
            frame_protection_present,
        )
    )
    return SecurityHeaderPostureFacts(
        response_status=exchange.status,
        html_response=_looks_like_html(exchange),
        content_security_policy_present=content_security_policy_present,
        no_sniff_present=no_sniff_present,
        frame_protection_present=frame_protection_present,
        missing_protection_count=missing_count,
    )


class _DirectoryListingParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchor_count = 0
        self.directory_marker = False
        self.marker_context_depth = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        normalized_tag = tag.lower()
        if normalized_tag in {"h1", "title"}:
            self.marker_context_depth += 1
        if normalized_tag != "a" or self.anchor_count >= _DIRECTORY_ANCHOR_LIMIT:
            return
        if any(name.lower() == "href" and value is not None for name, value in attrs):
            self.anchor_count += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"h1", "title"} and self.marker_context_depth > 0:
            self.marker_context_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.marker_context_depth == 0:
            return
        normalized = " ".join(data.lower().split())
        if any(
            marker in normalized
            for marker in (
                "index of /ftp",
                "listing directory /ftp",
                "directory listing for /ftp",
            )
        ):
            self.directory_marker = True


def _directory_listing_shape(exchange: Exchange) -> tuple[bool, bool, int]:
    html_response = _looks_like_html(exchange)
    if not html_response:
        return False, False, 0
    parser = _DirectoryListingParser()
    try:
        parser.feed(exchange.body.decode("utf-8", errors="replace"))
        parser.close()
    except (ValueError, AssertionError):
        return True, False, 0
    return (
        True,
        parser.directory_marker and parser.anchor_count > 0,
        parser.anchor_count,
    )


async def diagnose_security_header_posture(
    *,
    network: AssessmentNetwork,
    recipe: SecurityHeaderPostureRecipe | None = None,
) -> SecurityHeaderPostureResult:
    selected = recipe or SecurityHeaderPostureRecipe()
    policy = _exact_get_policy(
        network,
        paths=(selected.path,),
        max_requests=selected.requests_per_trial,
        max_response_bytes=selected.max_response_bytes,
    )
    trials: list[SecurityHeaderPostureTrial] = []
    for repetition in ("source", "replay"):
        network.begin_phase(f"extra-security-headers-{repetition}", policy)
        response = await network.exchange(
            selected.method,
            network.plan.origin + selected.path,
            headers={"accept": "text/html"},
        )
        facts = _security_header_facts(response)
        controls_passed = facts.html_response and facts.response_status == 200
        trials.append(
            SecurityHeaderPostureTrial(
                repetition=repetition,
                reproduced=controls_passed and facts.missing_protection_count > 0,
                controls_passed=controls_passed,
                evidence_ids=(response.evidence_id,),
                facts=facts,
            )
        )
    typed_trials = (trials[0], trials[1])
    status = _status_from_trials(typed_trials)
    title, observed_impact = _result_narrative(selected.check, status)
    return SecurityHeaderPostureResult(
        recipe_digest=selected.recipe_digest,
        status=status,
        title=title,
        observed_impact=observed_impact,
        trials=typed_trials,
    )


async def diagnose_ftp_directory_listing(
    *,
    network: AssessmentNetwork,
    recipe: FTPDirectoryListingRecipe | None = None,
) -> FTPDirectoryListingResult:
    selected = recipe or FTPDirectoryListingRecipe()
    policy = _exact_get_policy(
        network,
        paths=(selected.path, selected.missing_path),
        max_requests=selected.requests_per_trial,
        max_response_bytes=selected.max_response_bytes,
    )
    trials: list[FTPDirectoryListingTrial] = []
    for repetition in ("source", "replay"):
        network.begin_phase(f"extra-ftp-listing-{repetition}", policy)
        listing = await network.exchange(
            selected.method,
            network.plan.origin + selected.path,
            headers={"accept": "text/html"},
            accept_encoding="gzip",
        )
        missing = await network.exchange(
            selected.method,
            network.plan.origin + selected.missing_path,
            headers={"accept": "text/html"},
        )
        listing_html, listing_shape, anchor_count = _directory_listing_shape(listing)
        missing_html, missing_shape, missing_anchor_count = _directory_listing_shape(missing)
        facts = FTPDirectoryListingFacts(
            listing_status=listing.status,
            listing_html_response=listing_html,
            directory_listing_shape=listing_shape,
            listing_anchor_count=anchor_count,
            missing_control_status=missing.status,
            missing_control_html_response=missing_html,
            missing_control_listing_shape=missing_shape,
            missing_control_anchor_count=missing_anchor_count,
        )
        probe_interpretable = listing.status in {403, 404} or (
            listing.status == 200 and listing_html
        )
        controls_passed = probe_interpretable and missing.status in {404, 410} and not missing_shape
        trials.append(
            FTPDirectoryListingTrial(
                repetition=repetition,
                reproduced=listing.status == 200 and listing_shape,
                controls_passed=controls_passed,
                evidence_ids=(listing.evidence_id, missing.evidence_id),
                facts=facts,
            )
        )
    typed_trials = (trials[0], trials[1])
    status = _status_from_trials(typed_trials)
    title, observed_impact = _result_narrative(selected.check, status)
    return FTPDirectoryListingResult(
        recipe_digest=selected.recipe_digest,
        status=status,
        title=title,
        observed_impact=observed_impact,
        trials=typed_trials,
    )
