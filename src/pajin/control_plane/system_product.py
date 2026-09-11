"""Subject- and Campaign-bound reads of independently pinned SYS-002 evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from pajin.control_plane.measured_product_sources import _RecipeModel
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunIntegrityError
from pajin.system_read.models import SystemRunReference
from pajin.system_read.report import SystemReportTrust, compare_system_runs, read_system_run

CampaignId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")]
Subject = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")]


class SystemProductRecipe(_RecipeModel):
    """Private deployment input; never selected or supplied by an HTTP request."""

    campaign_id: CampaignId = Field(alias="campaignId")
    operator_subjects: tuple[Subject, ...] = Field(
        alias="operatorSubjects", min_length=1, max_length=100
    )
    root: Path
    trust: SystemReportTrust
    source: SystemRunReference | None = None
    replay: SystemRunReference | None = None

    @model_validator(mode="after")
    def require_source(self) -> Self:
        if self.replay is not None and self.source is None:
            raise ValueError("System replay requires a separately pinned source")
        if (
            self.source is not None
            and self.replay is not None
            and (
                self.source.run_id == self.replay.run_id
                or self.source.root_digest == self.replay.root_digest
            )
        ):
            raise ValueError("System source and replay require distinct sealed Runs")
        if len(set(self.operator_subjects)) != len(self.operator_subjects):
            raise ValueError("System Operator subjects must be unique")
        return self


class SystemDistributionMetadata(StrictModel):
    distribution_id: str = Field(alias="ID", min_length=1, max_length=1024)
    version_id: str = Field(alias="VERSION_ID", min_length=1, max_length=1024)
    pretty_name: str = Field(alias="PRETTY_NAME", min_length=1, max_length=1024)


class SystemDistributionView(StrictModel):
    metadata: SystemDistributionMetadata
    file_sha256: str = Field(alias="fileSha256", pattern=r"^[a-f0-9]{64}$")
    file_bytes: int = Field(alias="fileBytes", strict=True, ge=1, le=8192)


class SystemRunView(StrictModel):
    run: SystemRunReference
    worker_executed: bool = Field(alias="workerExecuted", strict=True)
    distribution: SystemDistributionView | None
    cleanup: Literal["absent", "present", "unknown", "not-created"]
    complete: bool = Field(strict=True)


class SystemOperatorView(StrictModel):
    version: Literal["pajin.sys-003.operator-read/v1"] = "pajin.sys-003.operator-read/v1"
    campaign_id: CampaignId = Field(alias="campaignId")
    state: Literal["empty", "verified", "incomplete"]
    source: SystemRunView | None
    replay: SystemRunView | None
    distribution_match: bool | None = Field(alias="distributionMatch")
    evidence_verified: bool = Field(alias="evidenceVerified", strict=True)
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    general_system_support: Literal[False] = Field(default=False, alias="generalSystemSupport")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    read_only: Literal[True] = Field(default=True, alias="readOnly")


class SystemProductNotFound(RuntimeError):
    """No result is visible to this subject and Campaign pair."""


class SystemProductIntegrityError(RuntimeError):
    """Retained evidence or its independent pins no longer agree."""


class SystemProductUnavailable(RuntimeError):
    """Configured evidence could not be read; no private details are exposed."""


class SystemProductReader:
    def __init__(self, recipe: SystemProductRecipe) -> None:
        # Keep deployment authority separate from a caller's mutable model objects.
        self._recipe = SystemProductRecipe.model_validate_json(recipe.model_dump_json())

    def authorize(self, campaign: str, subject: str) -> None:
        if campaign != self._recipe.campaign_id or subject not in self._recipe.operator_subjects:
            raise SystemProductNotFound("No System result is visible for this Campaign")

    def read(self, *, campaign: str, subject: str) -> SystemOperatorView:
        self.authorize(campaign, subject)
        return self.preflight()

    def preflight(self) -> SystemOperatorView:
        """Startup verification and per-request verification use the same fixed reader."""
        try:
            return self._read()
        except (ValueError, RunIntegrityError):
            raise SystemProductIntegrityError("System evidence is not integrity-valid") from None
        except Exception:
            raise SystemProductUnavailable("System evidence could not be read") from None

    def _read(self) -> SystemOperatorView:
        recipe = self._recipe

        def read(reference: SystemRunReference | None) -> SystemRunView | None:
            if reference is None:
                return None
            raw = read_system_run(
                recipe.root, reference, recipe.trust, expected_campaign=recipe.campaign_id
            )
            # An explicit allowlist excludes raw output, credentials and deployment inventory.
            return SystemRunView.model_validate(
                {
                    key: raw[key]
                    for key in ("run", "workerExecuted", "distribution", "cleanup", "complete")
                }
            )

        source, replay = read(recipe.source), read(recipe.replay)
        match = None
        complete = source is not None and source.complete
        if replay is not None:
            complete = bool(complete and replay.complete)
            if (
                source is not None
                and source.distribution is not None
                and replay.distribution is not None
            ):
                assert recipe.source is not None and recipe.replay is not None
                comparison = compare_system_runs(
                    recipe.root,
                    recipe.source,
                    recipe.replay,
                    recipe.trust,
                    expected_campaign=recipe.campaign_id,
                )
                match = comparison["distributionMatch"] is True
                complete = complete and comparison["complete"] is True
        return SystemOperatorView(
            campaignId=recipe.campaign_id,
            state="empty" if source is None else "verified" if complete else "incomplete",
            source=source,
            replay=replay,
            distributionMatch=match,
            evidenceVerified=source is not None,
        )
