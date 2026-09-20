"""Code-owned semantic checks for persisted WEB-003 diagnostic facts.

The WEB-003 wire contract intentionally keeps ``ProbeTrial.facts`` generic.  This
module is the stricter boundary used by later orchestration: every supported check
must match an exact fact schema and its asserted outcome must be derivable from
those facts.  Passing this boundary proves only that a sealed WEB-003 result is
internally consistent with the code-owned oracle.  It is not executor or target
attestation and it never grants Finding authority.
"""

from __future__ import annotations

from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import StrictModel
from pajin.web_assessment.models import (
    AssessmentIssue,
    IssueCheck,
    IssueStatus,
    LocalWebAssessmentResult,
    ProbeTrial,
)

SEMANTIC_CLAIMS_API_VERSION: Literal["pajin.dev/local-web-semantic-claims/v1alpha1"] = (
    "pajin.dev/local-web-semantic-claims/v1alpha1"
)

_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_ISSUE_POLICY: dict[IssueCheck, tuple[str, Literal["high", "medium"]]] = {
    "sql-login": ("CWE-89", "high"),
    "object-access": ("CWE-639", "high"),
    "dom-xss": ("CWE-79", "medium"),
}


class WebSemanticError(ValueError):
    """Raised when a WEB-003 result cannot pass the code-owned semantic oracle."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class SQLLoginFacts(_FrozenStrictModel):
    true_status: int = Field(alias="trueStatus", strict=True, ge=100, le=599)
    false_status: int = Field(alias="falseStatus", strict=True, ge=100, le=599)
    session_minted: bool = Field(alias="sessionMinted", strict=True)
    object_identity_present: bool = Field(alias="objectIdentityPresent", strict=True)
    authorized_directory_status: int | None = Field(
        alias="authorizedDirectoryStatus",
        default=None,
        strict=True,
        ge=100,
        le=599,
    )
    authorized_directory_record_count: int = Field(
        alias="authorizedDirectoryRecordCount",
        strict=True,
        ge=0,
        le=100_000,
    )
    credential_guess_used: Literal[False] = Field(
        default=False,
        alias="credentialGuessUsed",
    )

    @field_validator("credential_guess_used", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("SQL login facts cannot claim credential guessing")
        return value

    @model_validator(mode="after")
    def bind_session_and_directory(self) -> Self:
        if self.authorized_directory_status is None:
            if self.authorized_directory_record_count != 0:
                raise ValueError("SQL login facts count records without a directory response")
        elif not self.session_minted or not self.object_identity_present:
            raise ValueError("SQL login facts read a directory without a usable session identity")
        return self


class ObjectAccessUnavailableFacts(_FrozenStrictModel):
    chainable_session_available: Literal[False] = Field(
        default=False,
        alias="chainableSessionAvailable",
    )
    target_was_disposable_assessment_account: Literal[True] = Field(
        default=True,
        alias="targetWasDisposableAssessmentAccount",
    )


class ObjectAccessFacts(_FrozenStrictModel):
    attack_and_target_objects_differ: Literal[True] = Field(
        default=True,
        alias="attackAndTargetObjectsDiffer",
    )
    own_object_returned: bool = Field(alias="ownObjectReturned", strict=True)
    target_object_returned: bool = Field(alias="targetObjectReturned", strict=True)
    missing_object_returned: bool = Field(alias="missingObjectReturned", strict=True)
    target_status: int = Field(alias="targetStatus", strict=True, ge=100, le=599)
    target_product_count: int | None = Field(
        alias="targetProductCount",
        default=None,
        strict=True,
        ge=0,
        le=100_000,
    )
    target_was_disposable_assessment_account: Literal[True] = Field(
        default=True,
        alias="targetWasDisposableAssessmentAccount",
    )


class DOMXSSFacts(_FrozenStrictModel):
    control_marker_executed: bool = Field(alias="controlMarkerExecuted", strict=True)
    probe_marker_executed: bool = Field(alias="probeMarkerExecuted", strict=True)
    external_transmission: Literal[False] = Field(
        default=False,
        alias="externalTransmission",
    )

    @field_validator("external_transmission", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("DOM XSS facts cannot claim an external transmission")
        return value


class ValidatedWebTrial(_FrozenStrictModel):
    check: IssueCheck
    repetition: Literal["source", "replay"]
    evidence_ids: tuple[str, ...] = Field(alias="evidenceIds", max_length=20)
    facts_digest: str = Field(alias="factsDigest", pattern=_SHA256_PATTERN)
    reproduced: bool = Field(strict=True)
    controls_passed: bool = Field(alias="controlsPassed", strict=True)
    code_owned_oracle_passed: Literal[True] = Field(
        default=True,
        alias="codeOwnedOraclePassed",
    )


class ValidatedWebIssueClaim(_FrozenStrictModel):
    claim_digest: str = Field(default="", alias="claimDigest", max_length=64)
    source_issue_id: str = Field(
        alias="sourceIssueId",
        pattern=r"^web-issue:[a-f0-9]{64}$",
    )
    check: IssueCheck
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]{0,4}$")
    severity: Literal["high", "medium"]
    status: IssueStatus
    trials: tuple[ValidatedWebTrial, ValidatedWebTrial]
    executor_attested: Literal[False] = Field(default=False, alias="executorAttested")
    target_attested: Literal[False] = Field(default=False, alias="targetAttested")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")

    @field_validator(
        "executor_attested",
        "target_attested",
        "finding_authority",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("local semantic claims cannot assert attestation or Finding authority")
        return value

    @model_validator(mode="after")
    def bind_claim(self) -> Self:
        if _ISSUE_POLICY[self.check] != (self.cwe, self.severity):
            raise ValueError("local semantic claim differs from the code-owned issue policy")
        if tuple(trial.repetition for trial in self.trials) != ("source", "replay"):
            raise ValueError("local semantic claim requires ordered source and replay trials")
        if any(trial.check != self.check for trial in self.trials):
            raise ValueError("local semantic claim and trial checks differ")
        expected_status: IssueStatus
        if all(trial.reproduced and trial.controls_passed for trial in self.trials):
            expected_status = "locally-reproduced"
        elif all(not trial.reproduced and trial.controls_passed for trial in self.trials):
            expected_status = "not-reproduced"
        else:
            expected_status = "inconclusive"
        if self.status != expected_status:
            raise ValueError("local semantic claim status differs from validated facts")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"claim_digest"},
        )
        expected = discovery_digest("pajin.web-assessment.semantic-issue/v1", material)
        if self.claim_digest and self.claim_digest != expected:
            raise ValueError("local semantic claim digest differs")
        object.__setattr__(self, "claim_digest", expected)
        return self


class ValidatedLocalWebSemanticClaims(_FrozenStrictModel):
    api_version: Literal["pajin.dev/local-web-semantic-claims/v1alpha1"] = Field(
        default=SEMANTIC_CLAIMS_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ValidatedLocalWebSemanticClaims"] = "ValidatedLocalWebSemanticClaims"
    claims_digest: str = Field(default="", alias="claimsDigest", max_length=64)
    run_id: str = Field(
        alias="runId",
        pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$",
    )
    result_digest: str = Field(alias="resultDigest", pattern=_SHA256_PATTERN)
    claims: tuple[ValidatedWebIssueClaim, ...] = Field(min_length=3, max_length=3)
    source_integrity_only: Literal[True] = Field(
        default=True,
        alias="sourceIntegrityOnly",
    )
    independent_execution_attested: Literal[False] = Field(
        default=False,
        alias="independentExecutionAttested",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")

    @field_validator(
        "independent_execution_attested",
        "finding_authority",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("semantic validation cannot create execution or Finding authority")
        return value

    @field_validator("source_integrity_only", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("semantic validation must disclose its source-integrity-only scope")
        return value

    @model_validator(mode="after")
    def bind_claims(self) -> Self:
        if tuple(claim.check for claim in self.claims) != (
            "sql-login",
            "object-access",
            "dom-xss",
        ):
            raise ValueError("semantic validation requires the three ordered WEB-003 checks")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"claims_digest"},
        )
        expected = discovery_digest("pajin.web-assessment.semantic-claims/v1", material)
        if self.claims_digest and self.claims_digest != expected:
            raise ValueError("semantic claims digest differs")
        object.__setattr__(self, "claims_digest", expected)
        return self


def validate_local_web_assessment_semantics(
    result: LocalWebAssessmentResult,
) -> ValidatedLocalWebSemanticClaims:
    """Recompute every WEB-003 trial outcome from its exact typed fact schema."""

    canonical = LocalWebAssessmentResult.model_validate(
        result.model_dump(mode="json", by_alias=True)
    )
    claims = tuple(_validate_issue(issue) for issue in canonical.issues)
    return ValidatedLocalWebSemanticClaims(
        runId=canonical.run_id,
        resultDigest=canonical.result_digest,
        claims=claims,
    )


def validate_web_assessment_issue_semantics(
    issue: AssessmentIssue,
) -> ValidatedWebIssueClaim:
    """Validate one detached issue without granting authority to its parent Run."""

    canonical = AssessmentIssue.model_validate(issue.model_dump(mode="json", by_alias=True))
    return _validate_issue(canonical)


def _validate_issue(issue: AssessmentIssue) -> ValidatedWebIssueClaim:
    try:
        trials = tuple(_validate_trial(issue.check, trial) for trial in issue.trials)
    except WebSemanticError:
        raise
    except (TypeError, ValidationError, ValueError) as exc:
        raise WebSemanticError(
            f"{issue.check} facts differ from the code-owned semantic schema"
        ) from exc
    typed_trials = (trials[0], trials[1])
    if any(
        observed.reproduced != asserted.reproduced
        or observed.controls_passed != asserted.controls_passed
        for observed, asserted in zip(typed_trials, issue.trials, strict=True)
    ):
        raise WebSemanticError(
            f"{issue.check} asserted outcome differs from the code-owned fact oracle"
        )
    return ValidatedWebIssueClaim(
        sourceIssueId=issue.issue_id,
        check=issue.check,
        cwe=issue.cwe,
        severity=issue.severity,
        status=issue.status,
        trials=typed_trials,
    )


def _validate_trial(check: IssueCheck, trial: ProbeTrial) -> ValidatedWebTrial:
    if trial.check != check:
        raise WebSemanticError("WEB-003 issue and semantic trial checks differ")
    facts_model: _FrozenStrictModel
    if check == "sql-login":
        sql_facts = SQLLoginFacts.model_validate(trial.facts)
        facts_model = sql_facts
        controls_passed = sql_facts.false_status in {400, 401, 403}
        reproduced = (
            sql_facts.true_status == 200
            and sql_facts.session_minted
            and sql_facts.object_identity_present
            and sql_facts.authorized_directory_status == 200
            and sql_facts.authorized_directory_record_count > 1
        )
        expected_evidence_count = 3 if sql_facts.authorized_directory_status is not None else 2
    elif check == "object-access":
        if "chainableSessionAvailable" in trial.facts:
            object_unavailable_facts = ObjectAccessUnavailableFacts.model_validate(trial.facts)
            facts_model = object_unavailable_facts
            controls_passed = False
            reproduced = False
            expected_evidence_count = 0
        else:
            object_facts = ObjectAccessFacts.model_validate(trial.facts)
            facts_model = object_facts
            controls_passed = (
                object_facts.own_object_returned and not object_facts.missing_object_returned
            )
            reproduced = object_facts.target_status == 200 and object_facts.target_object_returned
            expected_evidence_count = 3
    else:
        dom_xss_facts = DOMXSSFacts.model_validate(trial.facts)
        facts_model = dom_xss_facts
        controls_passed = not dom_xss_facts.control_marker_executed
        reproduced = dom_xss_facts.probe_marker_executed
        expected_evidence_count = 2
    if len(trial.evidence_ids) != expected_evidence_count:
        raise WebSemanticError(
            f"{check} Evidence cardinality differs from its typed semantic facts"
        )
    facts_material = facts_model.model_dump(mode="json", by_alias=True)
    facts_digest = discovery_digest(
        f"pajin.web-assessment.{check}-facts/v1",
        facts_material,
    )
    return ValidatedWebTrial(
        check=check,
        repetition=trial.repetition,
        evidenceIds=trial.evidence_ids,
        factsDigest=facts_digest,
        reproduced=reproduced,
        controlsPassed=controls_passed,
    )


__all__ = [
    "SEMANTIC_CLAIMS_API_VERSION",
    "DOMXSSFacts",
    "ObjectAccessFacts",
    "ObjectAccessUnavailableFacts",
    "SQLLoginFacts",
    "ValidatedLocalWebSemanticClaims",
    "ValidatedWebIssueClaim",
    "ValidatedWebTrial",
    "WebSemanticError",
    "validate_local_web_assessment_semantics",
    "validate_web_assessment_issue_semantics",
]
