"""Lightweight environment contract for optional measurement deployment loading."""

from __future__ import annotations

import re
from pathlib import Path

MEASURED_PRODUCT_DEPLOYMENT_PATH_ENV = "PAJIN_CP_MEASURED_PRODUCT_DEPLOYMENT_PATH"
MEASURED_PRODUCT_DEPLOYMENT_SHA256_ENV = "PAJIN_CP_MEASURED_PRODUCT_DEPLOYMENT_SHA256"


def validate_measured_product_deployment_settings(path: Path | None, digest: str | None) -> None:
    if (path is None) != (digest is None):
        raise ValueError(
            f"{MEASURED_PRODUCT_DEPLOYMENT_PATH_ENV} and "
            f"{MEASURED_PRODUCT_DEPLOYMENT_SHA256_ENV} must be configured together"
        )
    if path is not None and (not isinstance(path, Path) or not path.is_absolute()):
        raise ValueError("measured product deployment path must be absolute")
    if digest is not None and re.fullmatch(r"[a-f0-9]{64}", digest) is None:
        raise ValueError("measured product deployment SHA256 must contain 64 lowercase hex digits")
