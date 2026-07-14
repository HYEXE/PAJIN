"""Persist canonical finding-validation ledgers and lightweight status views."""

from pajin.domain.validation import FindingDisposition, FindingValidationSet
from pajin.runtime.store import RunStore


def write_validation_artifacts(
    store: RunStore,
    validation: FindingValidationSet,
) -> None:
    """Write one immutable-at-seal snapshot without duplicating Candidate bodies."""

    store.write_json(
        "candidate-findings.json",
        [candidate.model_dump(mode="json") for candidate in validation.candidates],
    )
    store.write_json(
        "validation-decisions.json",
        [decision.model_dump(mode="json") for decision in validation.decisions],
    )
    candidates_by_disposition = {
        disposition.value: [
            decision.candidate_id
            for decision in validation.decisions
            if decision.disposition is disposition
        ]
        for disposition in FindingDisposition
    }
    store.write_json(
        "validation-index.json",
        {
            "candidatesByDisposition": candidates_by_disposition,
            "confirmedFindingIds": [
                finding.finding_id for finding in validation.confirmed_findings
            ],
        },
    )
