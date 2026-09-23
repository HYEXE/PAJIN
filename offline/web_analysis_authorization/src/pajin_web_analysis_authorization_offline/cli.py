"""Command-line interface for the physically separated offline authority."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from .authority import (
    OfflineAuthorizationError,
    issue_authorization_bundle,
    provision_authorization_authority,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pajin-web-analysis-authorization-offline",
        description="Provision and use a physically separated one-call authorization key.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    provision = commands.add_parser(
        "provision",
        help="create a new random offline authority",
        allow_abbrev=False,
    )
    provision.add_argument("--private-key-file", type=Path, required=True)
    provision.add_argument("--trust-anchor-file", type=Path, required=True)
    provision.add_argument("--trust-anchor-digest-file", type=Path, required=True)
    provision.add_argument("--trust-domain", required=True)
    provision.add_argument("--issuer", required=True)
    provision.add_argument("--key-id", required=True)
    provision.add_argument("--not-before", type=_parse_utc_timestamp, required=True)
    provision.add_argument("--not-after", type=_parse_utc_timestamp, required=True)

    issue = commands.add_parser(
        "issue",
        help="sign exactly one canonical authorization request",
        allow_abbrev=False,
    )
    issue.add_argument("--private-key-file", type=Path, required=True)
    issue.add_argument("--trust-anchor-file", type=Path, required=True)
    issue.add_argument("--trust-anchor-digest-file", type=Path, required=True)
    issue.add_argument("--authorization-request-file", type=Path, required=True)
    issue.add_argument("--signed-bundle-file", type=Path, required=True)
    issue.add_argument("--lifetime-seconds", type=int, choices=range(1, 181), required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "provision":
            provisioned = provision_authorization_authority(
                private_key_file=arguments.private_key_file,
                trust_anchor_file=arguments.trust_anchor_file,
                trust_anchor_digest_file=arguments.trust_anchor_digest_file,
                trust_domain=arguments.trust_domain,
                issuer=arguments.issuer,
                key_id=arguments.key_id,
                not_before=arguments.not_before,
                not_after=arguments.not_after,
            )
            payload = {
                "keyId": provisioned.key_id,
                "privateKeyFile": str(provisioned.private_key_file),
                "trustAnchorDigest": provisioned.trust_anchor_digest,
                "trustAnchorDigestFile": str(provisioned.trust_anchor_digest_file),
                "trustAnchorFile": str(provisioned.trust_anchor_file),
            }
        elif arguments.command == "issue":
            issued = issue_authorization_bundle(
                private_key_file=arguments.private_key_file,
                trust_anchor_file=arguments.trust_anchor_file,
                trust_anchor_digest_file=arguments.trust_anchor_digest_file,
                authorization_request_file=arguments.authorization_request_file,
                signed_bundle_file=arguments.signed_bundle_file,
                lifetime_seconds=arguments.lifetime_seconds,
            )
            payload = {
                "bundleDigest": issued.bundle_digest,
                "expiresAt": issued.expires_at.isoformat().replace("+00:00", "Z"),
                "keyId": issued.key_id,
                "nonce": issued.nonce,
                "signedBundleFile": str(issued.signed_bundle_file),
            }
        else:  # pragma: no cover - argparse owns the command set
            parser.error("unknown command")
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except (OfflineAuthorizationError, OSError, ValueError) as exc:
        sys.stderr.write(f"offline authorization failed: {exc}\n")
        return 2


def _parse_utc_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timestamp must use YYYY-MM-DDTHH:MM:SSZ") from exc
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise argparse.ArgumentTypeError("timestamp must be canonical UTC")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
