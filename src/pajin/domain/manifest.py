"""Campaign manifest loading and validation."""

from pathlib import Path

from pajin.domain.models import CampaignManifest
from pajin.domain.yaml_loader import load_yaml_mapping


def load_manifest(path: Path) -> CampaignManifest:
    """Load a YAML campaign manifest and validate the complete contract."""

    raw = load_yaml_mapping(path, label="campaign manifest")
    return CampaignManifest.model_validate(raw)
