"""Campaign manifest loading and validation."""

from pathlib import Path
from typing import Any

import yaml

from pajin.domain.models import CampaignManifest


def load_manifest(path: Path) -> CampaignManifest:
    """Load a YAML campaign manifest and validate the complete contract."""

    raw: Any
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError("campaign manifest must contain a YAML mapping")
    return CampaignManifest.model_validate(raw)
