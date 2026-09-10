"""Private, disjoint corpus and immutable comparison settings; no public prompt export."""

from __future__ import annotations

import hashlib
import inspect
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from pajin.benchmark.effectiveness.suite import (
    Case,
    Coordinate,
    Digest,
    FrozenModel,
    ModelPin,
    RuntimePin,
    SourcePin,
    digest,
    implementation_pins,
    matrix,
    model_pins,
    new_suite,
    normalized_prompt,
    oracle_verdict,
)
from pajin.tools.disclosure import detect_disclosure_suspicion


class ComparisonSuite(FrozenModel):
    version: Literal["effect-002-corpus-v1"] = "effect-002-corpus-v1"
    cases: tuple[Case, ...] = Field(min_length=18, max_length=18)

    @model_validator(mode="after")
    def require_disjoint_private_corpus(self) -> Self:
        coordinates = [
            *(("development", f"dev-{i:02d}") for i in range(2)),
            *(("held-out", f"holdout-{i:02d}") for i in range(16)),
        ]
        if [(case.split, case.case_id) for case in self.cases] != coordinates:
            raise ValueError(
                "comparison requires two development and sixteen ordered holdout cases"
            )
        prompts = {normalized_prompt(case.prompt) for case in self.cases}
        if len(prompts) != len(self.cases):
            raise ValueError("development and holdout prompts overlap")
        legacy = {normalized_prompt(case.prompt) for case in new_suite().cases}
        heldout = self.cases[2:]
        if any(normalized_prompt(case.prompt) in legacy for case in heldout):
            raise ValueError("new holdout overlaps the previous development/evaluation corpus")
        if sum(case.category == "benign" for case in heldout) != 8:
            raise ValueError("comparison requires eight extraction and eight benign holdout cases")
        if len({case.private_canary for case in self.cases}) != len(self.cases):
            raise ValueError("canaries must be distinct")
        for case in self.cases:
            if any(case.private_canary.casefold() in prompt for prompt in prompts):
                raise ValueError("private canary must not be included in user text")
            if any(oracle_verdict(other.prompt, case.private_canary) for other in self.cases):
                raise ValueError("private canary must not be included in user text")
        return self


def comparison_pins() -> tuple[SourcePin, ...]:
    detector = inspect.getsourcefile(detect_disclosure_suspicion)
    if detector is None:
        raise ValueError("detector source unavailable")
    sources = [("pajin.tools.disclosure", Path(detector))]
    sources.extend(("comparison/" + p.name, p) for p in sorted(Path(__file__).parent.glob("*.py")))
    return (
        *implementation_pins(),
        *(
            SourcePin(name=name, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            for name, path in sources
        ),
    )


class ComparisonPlan(FrozenModel):
    version: Literal["effect-002-v1"] = "effect-002-v1"
    suite: ComparisonSuite
    runtime: RuntimePin
    models: tuple[ModelPin, ...]
    coordinates: tuple[Coordinate, ...]
    implementation: tuple[SourcePin, ...]
    development_report_root: Digest
    oracle: Literal["complete-private-nonce-v1"] = "complete-private-nonce-v1"
    baseline: Literal["m03-public-marker-v1"] = "m03-public-marker-v1"
    candidate: Literal["novel-opaque-output-v1"] = "novel-opaque-output-v1"
    improvement_rule: Literal["higher-pooled-f1-without-precision-or-recall-loss"] = (
        "higher-pooled-f1-without-precision-or-recall-loss"
    )

    @model_validator(mode="after")
    def require_complete_comparison(self) -> Self:
        if self.models != model_pins() or self.coordinates != matrix():
            raise ValueError("comparison requires both models and all 24 frozen coordinates")
        if not self.implementation or len({p.name for p in self.implementation}) != len(
            self.implementation
        ):
            raise ValueError("comparison requires unique source identities")
        return self

    @property
    def commitment(self) -> str:
        return digest(self.model_dump(mode="json"))

    def public_manifest(self) -> dict[str, object]:
        public = self.model_dump(mode="json", exclude={"suite"})
        public["plan_commitment"] = self.commitment
        public["suite_commitment"] = digest(self.suite.model_dump(mode="json"))
        public["cases"] = [
            {
                "id": case.case_id,
                "split": case.split,
                "category": case.category,
                "commitment": digest(case.model_dump(mode="json")),
            }
            for case in self.suite.cases
        ]
        public["model_training_decontamination"] = "unknown"
        return public
