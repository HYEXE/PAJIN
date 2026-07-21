"""Fail-closed ownership initialization for Control Plane artifact volumes."""

from __future__ import annotations

import os
import stat
from pathlib import Path

_OWNER_UID = 10001
_OWNER_GID = 10001
_ROOT_ENVIRONMENTS = (
    "PAJIN_CP_ARTIFACT_STAGING_ROOT",
    "PAJIN_CP_ARTIFACT_REPOSITORY_ROOT",
)


def _initialize_private_root(path: Path) -> None:
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise SystemExit("artifact root must be a bounded absolute path")
    try:
        if path.resolve(strict=True) != path:
            raise SystemExit("artifact root must not contain symlinks")
        before = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise SystemExit("artifact root is not a real directory")
        # A prior successful run leaves the mount root owner-only under UID
        # 10001. CAP_CHOWN does not bypass those read permissions, so restore
        # root ownership by pathname before opening it. The mount parent is
        # image-owned and not writable by PAJIN services; the inode check below
        # additionally fails closed if the target changes before open().
        os.chown(path, 0, 0, follow_symlinks=False)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise SystemExit("cannot initialize private artifact root") from None
    try:
        observed = os.fstat(descriptor)
        if (observed.st_dev, observed.st_ino) != (before.st_dev, before.st_ino):
            raise SystemExit("artifact root changed during ownership initialization")
        # Complete all remaining changes through the open descriptor.
        os.fchmod(descriptor, 0o700)
        os.fchown(descriptor, _OWNER_UID, _OWNER_GID)
        os.fsync(descriptor)
        verified = os.fstat(descriptor)
        if (
            verified.st_uid != _OWNER_UID
            or verified.st_gid != _OWNER_GID
            or stat.S_IMODE(verified.st_mode) != 0o700
        ):
            raise SystemExit("artifact root ownership initialization failed")
    except OSError:
        raise SystemExit("cannot make artifact root private") from None
    finally:
        os.close(descriptor)


def main() -> None:
    if os.geteuid() != 0 or os.getegid() != 0:
        raise SystemExit("artifact volume initializer must run as root")
    roots: list[Path] = []
    for name in _ROOT_ENVIRONMENTS:
        raw = os.environ.get(name)
        if raw is None or not raw.startswith("/"):
            raise SystemExit(f"{name} must be an absolute path")
        roots.append(Path(raw))
    if roots[0] == roots[1] or roots[0] in roots[1].parents or roots[1] in roots[0].parents:
        raise SystemExit("artifact staging and repository roots must be disjoint")
    for root in roots:
        _initialize_private_root(root)


if __name__ == "__main__":
    main()
