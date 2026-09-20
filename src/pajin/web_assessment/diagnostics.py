"""Deterministic, control-backed diagnostics for the local Web assessment flow."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from pajin.discovery.canonicalization import discovery_digest
from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment.models import (
    AssessmentIssue,
    AttackPath,
    AttackPathStage,
    IssueStatus,
    ProbeTrial,
    WebAssessmentPlan,
    issue_observation,
    json_at,
)
from pajin.web_assessment.network import AssessmentNetwork, Exchange


class WebDiagnosticError(RuntimeError):
    """Raised when a diagnostic cannot produce a bounded, interpretable trial."""


@dataclass(frozen=True, repr=False)
class SQLLoginDiagnostic:
    token: str | None
    object_id: int | None
    issue: AssessmentIssue


def _positive_object_id(value: object) -> int | None:
    if type(value) is int and 0 < value <= 2_147_483_647:
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit():
        parsed = int(value)
        if 0 < parsed <= 2_147_483_647:
            return parsed
    return None


def _issue_status(
    trials: tuple[ProbeTrial, ProbeTrial],
) -> IssueStatus:
    if all(trial.reproduced and trial.controls_passed for trial in trials):
        return "locally-reproduced"
    if all(not trial.reproduced and trial.controls_passed for trial in trials):
        return "not-reproduced"
    return "inconclusive"


def _issue_id(
    *,
    check: str,
    cwe: str,
    trials: tuple[ProbeTrial, ProbeTrial],
) -> str:
    digest = discovery_digest(
        "pajin.web-assessment.issue/v1",
        {
            "check": check,
            "cwe": cwe,
            "trials": [trial.model_dump(mode="json") for trial in trials],
        },
    )
    return f"web-issue:{digest}"


def _records(exchange: Exchange, path: str) -> list[object]:
    value = json_at(exchange.json(), path)
    return value if isinstance(value, list) else []


async def diagnose_sql_login(
    *,
    network: AssessmentNetwork,
    plan: WebAssessmentPlan,
    policy: EgressPolicy,
) -> SQLLoginDiagnostic:
    recipe = plan.sql_login
    if recipe is None:
        raise WebDiagnosticError("SQL login recipe is unavailable")
    trials: list[ProbeTrial] = []
    selected_token: str | None = None
    selected_object_id: int | None = None
    for repetition in ("source", "replay"):
        network.begin_phase(f"sql-login-{repetition}", policy)
        password = f"pajin-control-{secrets.token_hex(8)}"
        true_response = await network.json_request(
            "POST",
            plan.login.endpoint,
            payload={
                plan.login.username_field: recipe.true_expression,
                plan.login.password_field: password,
            },
        )
        false_response = await network.json_request(
            "POST",
            plan.login.endpoint,
            payload={
                plan.login.username_field: recipe.false_expression,
                plan.login.password_field: password,
            },
        )
        decoded = true_response.json()
        token = json_at(decoded, plan.login.token_path)
        object_id = _positive_object_id(json_at(decoded, plan.login.object_id_path))
        impact_response: Exchange | None = None
        if isinstance(token, str) and token and object_id is not None:
            impact_response = await network.json_request(
                "GET",
                recipe.impact_endpoint,
                token=token,
            )
            selected_token = token
            selected_object_id = object_id
        impact_records = _records(impact_response, recipe.records_path) if impact_response else []
        false_token = json_at(false_response.json(), plan.login.token_path)
        controls_passed = false_response.status in {400, 401, 403} and not isinstance(
            false_token, str
        )
        reproduced = (
            true_response.status == 200
            and isinstance(token, str)
            and bool(token)
            and object_id is not None
            and impact_response is not None
            and impact_response.status == 200
            and len(impact_records) > 1
        )
        evidence_ids = [true_response.evidence_id, false_response.evidence_id]
        if impact_response is not None:
            evidence_ids.append(impact_response.evidence_id)
        trials.append(
            ProbeTrial(
                check="sql-login",
                repetition=repetition,
                reproduced=reproduced,
                controls_passed=controls_passed,
                evidence_ids=tuple(evidence_ids),
                facts={
                    "trueStatus": true_response.status,
                    "falseStatus": false_response.status,
                    "sessionMinted": isinstance(token, str) and bool(token),
                    "objectIdentityPresent": object_id is not None,
                    "authorizedDirectoryStatus": (
                        impact_response.status if impact_response is not None else None
                    ),
                    "authorizedDirectoryRecordCount": len(impact_records),
                    "credentialGuessUsed": False,
                },
            )
        )
    typed_trials = (trials[0], trials[1])
    status = _issue_status(typed_trials)
    title, observed_impact = issue_observation("sql-login", status)
    issue = AssessmentIssue(
        issue_id=_issue_id(check="sql-login", cwe="CWE-89", trials=typed_trials),
        check="sql-login",
        cwe="CWE-89",
        status=status,
        severity="high",
        title=title,
        observed_impact=observed_impact,
        potential_impact=(
            "An unauthenticated attacker could impersonate a privileged account and reach data "
            "or actions exposed to that account."
        ),
        remediation=(
            "Use parameterized queries for credential lookup, reject authentication input that "
            "changes query structure, and add true/false-condition regression tests."
        ),
        trials=typed_trials,
    )
    return SQLLoginDiagnostic(
        token=selected_token,
        object_id=selected_object_id,
        issue=issue,
    )


def _object_record(exchange: Exchange, *, path: str) -> dict[str, object] | None:
    value = json_at(exchange.json(), path)
    return value if isinstance(value, dict) else None


def _record_id(record: dict[str, object] | None, field: str) -> int | None:
    return _positive_object_id(record.get(field)) if record is not None else None


async def diagnose_object_access(
    *,
    network: AssessmentNetwork,
    plan: WebAssessmentPlan,
    policy: EgressPolicy,
    attack_token: str | None,
    attack_object_id: int | None,
    target_object_id: int,
) -> AssessmentIssue:
    recipe = plan.object_access
    if recipe is None:
        raise WebDiagnosticError("object access recipe is unavailable")
    if attack_token is None or attack_object_id is None:
        source_trial = ProbeTrial(
            check="object-access",
            repetition="source",
            reproduced=False,
            controls_passed=False,
            evidence_ids=(),
            facts={
                "chainableSessionAvailable": False,
                "targetWasDisposableAssessmentAccount": True,
            },
        )
        replay_trial = ProbeTrial(
            check="object-access",
            repetition="replay",
            reproduced=False,
            controls_passed=False,
            evidence_ids=(),
            facts={
                "chainableSessionAvailable": False,
                "targetWasDisposableAssessmentAccount": True,
            },
        )
        unavailable_trials = (
            source_trial,
            replay_trial,
        )
        title, observed_impact = issue_observation("object-access", "inconclusive")
        return AssessmentIssue(
            issue_id=_issue_id(
                check="object-access",
                cwe="CWE-639",
                trials=unavailable_trials,
            ),
            check="object-access",
            cwe="CWE-639",
            status="inconclusive",
            severity="high",
            title=title,
            observed_impact=observed_impact,
            potential_impact=(
                "Caller-controlled basket identifiers require a separate authorized session "
                "test before an access-control conclusion can be made."
            ),
            remediation=(
                "Resolve basket ownership from the authenticated principal and add explicit "
                "cross-owner denial tests."
            ),
            trials=unavailable_trials,
        )
    if attack_object_id == target_object_id:
        raise WebDiagnosticError("object access diagnostic requires two distinct account objects")
    trials: list[ProbeTrial] = []
    missing_object_id = 2_147_483_647
    for repetition in ("source", "replay"):
        network.begin_phase(f"object-access-{repetition}", policy)
        own = await network.json_request(
            "GET",
            recipe.endpoint_template.format(id=attack_object_id),
            token=attack_token,
        )
        target = await network.json_request(
            "GET",
            recipe.endpoint_template.format(id=target_object_id),
            token=attack_token,
        )
        missing = await network.json_request(
            "GET",
            recipe.endpoint_template.format(id=missing_object_id),
            token=attack_token,
        )
        own_record = _object_record(own, path=recipe.object_path)
        target_record = _object_record(target, path=recipe.object_path)
        missing_record = _object_record(missing, path=recipe.object_path)
        own_id = _record_id(own_record, recipe.id_field)
        returned_target_id = _record_id(target_record, recipe.id_field)
        returned_missing_id = _record_id(missing_record, recipe.id_field)
        products = target_record.get("Products") if target_record is not None else None
        controls_passed = (
            own.status == 200
            and own_id == attack_object_id
            and (missing.status in {200, 404} and returned_missing_id != missing_object_id)
        )
        reproduced = target.status == 200 and returned_target_id == target_object_id
        trials.append(
            ProbeTrial(
                check="object-access",
                repetition=repetition,
                reproduced=reproduced,
                controls_passed=controls_passed,
                evidence_ids=(own.evidence_id, target.evidence_id, missing.evidence_id),
                facts={
                    "attackAndTargetObjectsDiffer": True,
                    "ownObjectReturned": own_id == attack_object_id,
                    "targetObjectReturned": returned_target_id == target_object_id,
                    "missingObjectReturned": returned_missing_id == missing_object_id,
                    "targetStatus": target.status,
                    "targetProductCount": len(products) if isinstance(products, list) else None,
                    "targetWasDisposableAssessmentAccount": True,
                },
            )
        )
    typed_trials = (trials[0], trials[1])
    status = _issue_status(typed_trials)
    title, observed_impact = issue_observation("object-access", status)
    return AssessmentIssue(
        issue_id=_issue_id(check="object-access", cwe="CWE-639", trials=typed_trials),
        check="object-access",
        cwe="CWE-639",
        status=status,
        severity="high",
        title=title,
        observed_impact=observed_impact,
        potential_impact=(
            "An attacker with any accepted session could enumerate basket identifiers and disclose "
            "other customers' cart contents."
        ),
        remediation=(
            "Resolve basket ownership from the authenticated principal instead of a "
            "caller-supplied "
            "identifier, and deny every cross-owner object lookup."
        ),
        trials=typed_trials,
    )


def dom_xss_issue(trials: tuple[ProbeTrial, ProbeTrial]) -> AssessmentIssue:
    status = _issue_status(trials)
    title, observed_impact = issue_observation("dom-xss", status)
    return AssessmentIssue(
        issue_id=_issue_id(check="dom-xss", cwe="CWE-79", trials=trials),
        check="dom-xss",
        cwe="CWE-79",
        status=status,
        severity="medium",
        title=title,
        observed_impact=observed_impact,
        potential_impact=(
            "A victim following a crafted URL could run attacker-controlled script with the "
            "application origin's browser privileges."
        ),
        remediation=(
            "Render search terms as text, remove unsafe HTML sinks, and enforce a restrictive "
            "Content Security Policy without unsafe inline execution."
        ),
        trials=trials,
    )


def build_attack_paths(issues: tuple[AssessmentIssue, ...]) -> tuple[AttackPath, ...]:
    by_check = {issue.check: issue for issue in issues}
    sql = by_check["sql-login"]
    object_access = by_check["object-access"]
    dom_xss = by_check["dom-xss"]
    chained = sql.status == "locally-reproduced" and object_access.status == "locally-reproduced"
    sql_evidence = tuple(evidence for trial in sql.trials for evidence in trial.evidence_ids)
    object_evidence = tuple(
        evidence for trial in object_access.trials for evidence in trial.evidence_ids
    )
    xss_evidence = tuple(evidence for trial in dom_xss.trials for evidence in trial.evidence_ids)
    return (
        AttackPath(
            title=(
                "Unauthenticated login injection to cross-account basket access"
                if chained
                else "Login-injection to cross-account basket chain was incomplete"
            ),
            status="locally-validated" if chained else "incomplete",
            stages=(
                AttackPathStage(
                    ordinal=1,
                    stage_id="unauthenticated-login-input",
                    state="observed",
                    summary=(
                        "The public login endpoint was exercised with controlled identity input."
                    ),
                    evidence_ids=sql_evidence[:2],
                ),
                AttackPathStage(
                    ordinal=2,
                    stage_id="sql-authentication-bypass",
                    state=(
                        "locally-reproduced" if sql.status == "locally-reproduced" else "potential"
                    ),
                    summary=(
                        "A true SQL condition minted a session while the false control failed."
                        if sql.status == "locally-reproduced"
                        else "The controlled trials did not reproduce a stable session-minting "
                        "bypass."
                    ),
                    issue_id=sql.issue_id,
                    evidence_ids=sql_evidence,
                ),
                AttackPathStage(
                    ordinal=3,
                    stage_id="cross-account-basket-read",
                    state=(
                        "locally-reproduced"
                        if object_access.status == "locally-reproduced"
                        else "potential"
                    ),
                    summary=(
                        "That injected session read the distinct basket created for the normal "
                        "browser-login account."
                        if object_access.status == "locally-reproduced"
                        else "The controlled trials did not reproduce stable access to the "
                        "browser-login account's basket."
                    ),
                    issue_id=object_access.issue_id,
                    evidence_ids=object_evidence,
                ),
            ),
            observed_impact=(
                "The full chain reached another account's basket container in the approved "
                "local lab."
                if chained
                else "The full chain was not reproduced in both controlled trials."
            ),
            potential_impact=(
                "The combined weaknesses can turn unauthenticated input into privileged session "
                "access and cross-customer cart disclosure."
            ),
        ),
        AttackPath(
            title=(
                "Crafted search URL to same-origin script execution"
                if dom_xss.status == "locally-reproduced"
                else "Crafted search-route script-execution chain was incomplete"
            ),
            status=(
                "locally-validated" if dom_xss.status == "locally-reproduced" else "incomplete"
            ),
            stages=(
                AttackPathStage(
                    ordinal=1,
                    stage_id="crafted-search-route",
                    state="observed",
                    summary="The SPA search route was exercised with controlled input.",
                    evidence_ids=xss_evidence[::2],
                ),
                AttackPathStage(
                    ordinal=2,
                    stage_id="same-origin-script-execution",
                    state=(
                        "locally-reproduced"
                        if dom_xss.status == "locally-reproduced"
                        else "potential"
                    ),
                    summary=(
                        "The probe changed only its dedicated DOM marker without transmission."
                        if dom_xss.status == "locally-reproduced"
                        else "The controlled trials did not reproduce stable DOM-marker execution."
                    ),
                    issue_id=dom_xss.issue_id,
                    evidence_ids=xss_evidence,
                ),
            ),
            observed_impact=(
                "Same-origin JavaScript execution was observed in the disposable browser context."
                if dom_xss.status == "locally-reproduced"
                else "Same-origin execution was not reproduced twice with passing controls."
            ),
            potential_impact=(
                "A weaponized payload could read browser-accessible data or act as the victim, "
                "subject to the application's browser security boundaries."
            ),
        ),
    )
