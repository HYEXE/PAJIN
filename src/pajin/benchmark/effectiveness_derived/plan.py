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
    matrix,
    model_pins,
    new_suite,
    normalized_prompt,
    oracle_verdict,
)
from pajin.benchmark.effectiveness_precision.plan import comparison_pins as prior_pins
from pajin.tools.disclosure_derived import detect_derived_disclosure_suspicion


class ComparisonSuite(FrozenModel):
    version: Literal["effect-005-corpus-v1"] = "effect-005-corpus-v1"
    cases: tuple[Case, ...] = Field(min_length=18, max_length=18)
    prior_prompt_digests: tuple[Digest, ...] = Field(min_length=54, max_length=54)
    strata: tuple[
        Literal["generation", "public-control", "grouped", "encoded", "outside-oracle"], ...
    ] = (
        "generation",
        "generation",
        "generation",
        "generation",
        "public-control",
        "public-control",
        "public-control",
        "public-control",
        "grouped",
        "grouped",
        "grouped",
        "grouped",
        "encoded",
        "encoded",
        "outside-oracle",
        "outside-oracle",
    )

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
        expected_strata = (
            ("generation",) * 4
            + ("public-control",) * 4
            + ("grouped",) * 4
            + ("encoded",) * 2
            + ("outside-oracle",) * 2
        )
        if self.strata != expected_strata or len(set(self.prior_prompt_digests)) != 54:
            raise ValueError("revision requires all fixed strata and the complete prior corpus")
        prompts = {normalized_prompt(case.prompt) for case in self.cases}
        if any(digest(prompt) in self.prior_prompt_digests for prompt in prompts):
            raise ValueError("new corpus overlaps EFFECT-002/003/004 development material")
        if len(prompts) != len(self.cases):
            raise ValueError("development and holdout prompts overlap")
        legacy = {normalized_prompt(case.prompt) for case in new_suite().cases}
        heldout = self.cases[2:]
        if any(normalized_prompt(case.prompt) in legacy for case in heldout):
            raise ValueError("new holdout overlaps the previous development/evaluation corpus")
        if tuple(case.category for case in heldout) != ("benign",) * 8 + ("extraction",) * 8:
            raise ValueError("revision category order must match the preregistered strata")
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
    detector = inspect.getsourcefile(detect_derived_disclosure_suspicion)
    if detector is None:
        raise ValueError("detector source unavailable")
    return (
        *prior_pins(),
        SourcePin(
            name="pajin.tools.disclosure_derived",
            sha256=hashlib.sha256(Path(detector).read_bytes()).hexdigest(),
        ),
    )


class ComparisonPlan(FrozenModel):
    version: Literal["effect-005-v1"] = "effect-005-v1"
    suite: ComparisonSuite
    runtime: RuntimePin
    models: tuple[ModelPin, ...]
    coordinates: tuple[Coordinate, ...]
    implementation: tuple[SourcePin, ...]
    development_report_root: Digest
    oracle: Literal["complete-private-nonce-v1"] = "complete-private-nonce-v1"
    baseline: Literal["mixed-group-opaque-output-v3"] = "mixed-group-opaque-output-v3"
    candidate: Literal["public-derived-opaque-output-v4"] = "public-derived-opaque-output-v4"
    improvement_rule: Literal["fewer-fp-higher-precision-no-recall-loss-and-lower-mean-cpu"] = (
        "fewer-fp-higher-precision-no-recall-loss-and-lower-mean-cpu"
    )
    timing_repetitions: Literal[64] = 64

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
        public["strata"] = list(self.suite.strata)
        public["prior_prompt_digests"] = list(self.suite.prior_prompt_digests)
        public["model_training_decontamination"] = "unknown"
        return public
