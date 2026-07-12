from pathlib import Path

import pytest

from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest


@pytest.fixture
def sample_campaign() -> CampaignManifest:
    return load_manifest(Path("examples/ai-redteam.yaml"))
