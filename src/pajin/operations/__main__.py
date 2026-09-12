"""Bounded OPS-003 commands for an explicitly pinned managed Linux hybrid deployment."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pajin.control_plane.security import CheckpointSigner
from pajin.operations.checkpoint_anchor import CheckpointAnchor
from pajin.operations.hybrid import (
    create_checkpoint,
    implementation_digest,
    load_deployment,
    operator_lock,
    preflight,
    restore_checkpoint,
    verify_restored,
    write_report,
)
from pajin.operations.hybrid_docker import WriterFence
from pajin.operations.hybrid_files import authenticate, read
from pajin.operations.hybrid_models import MAX_BYTES, ResumeAuthorization
from pajin.operations.hybrid_resume import resume
from pajin.runtime.safe_files import parse_strict_json_bytes


def keyring(path: Path) -> CheckpointSigner:
    value = parse_strict_json_bytes(
        read(path, limit=65536), label="recovery keyring", max_bytes=65536
    )
    if not isinstance(value, dict) or set(value) != {"active_key_id", "keys"}:
        raise ValueError("original CP keyring has an invalid shape")
    if not isinstance(value["keys"], dict) or not isinstance(value["active_key_id"], str):
        raise ValueError("original CP keyring has invalid types")
    values = value["keys"]
    if any(not isinstance(k, str) or not isinstance(v, str) for k, v in values.items()):
        raise ValueError("original CP keyring requires hexadecimal key values")
    return CheckpointSigner(
        active_key_id=value["active_key_id"],
        keys={k: bytes.fromhex(v) for k, v in values.items()},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation",
        choices=("code-digest", "preflight", "stop", "checkpoint", "restore", "verify", "resume"),
    )
    parser.add_argument("--deployment", type=Path)
    parser.add_argument("--deployment-pin")
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--checkpoint-pin")
    parser.add_argument("--encryption-key", type=Path)
    parser.add_argument("--cp-keyring", type=Path)
    parser.add_argument("--verification", type=Path)
    parser.add_argument("--resume-authorization", type=Path)
    parser.add_argument("--operator-ca", type=Path)
    parser.add_argument("--attempt", type=Path)
    parser.add_argument("--anchor-directory", type=Path)
    parser.add_argument("--anchor-key", type=Path)
    parser.add_argument("--witness-directory", type=Path)
    parser.add_argument("--witness-key", type=Path)
    parser.add_argument("--expected-anchor-sequence", type=int)
    args = parser.parse_args()
    if args.operation == "code-digest":
        print(implementation_digest())
        return
    if not all((args.deployment, args.deployment_pin, args.state_root, args.output)):
        parser.error(
            "operation requires deployment, independent pin, absolute state root and new output"
        )
    if args.output.exists() or args.output.is_relative_to(args.state_root):
        parser.error("output must be create-only and outside application state")
    try:
        plan = load_deployment(args.deployment, pin=args.deployment_pin, state=args.state_root)
        with operator_lock(args.state_root):
            if args.operation == "preflight":
                result = preflight(plan, args.state_root)
            elif args.operation == "stop":
                WriterFence(plan).stop()
                result = {"writers_stopped": True, "execution_authorized": False}
            else:
                result = _state_operation(args, plan)
            report_pin = write_report(args.output, result)
        print(json.dumps({"report_sha256": report_pin, "operation": args.operation}))
    except Exception as exc:
        # Validation/SQL/TLS errors may embed raw configuration. Never print those values.
        reason = str(exc) if type(exc) is ValueError else type(exc).__name__
        print("Recovery incomplete: " + reason, file=sys.stderr)
        raise SystemExit(2) from None


def _state_operation(args: argparse.Namespace, plan: object) -> dict[str, object]:
    from pajin.operations.hybrid_models import Deployment

    assert isinstance(plan, Deployment)
    anchor = None
    if args.anchor_directory is not None:
        if plan.recovery_anchor is None:
            raise ValueError("anchor directory requires independent deployment enrollment")
        witness = None
        if args.witness_directory is not None:
            from pajin.operations.checkpoint_witness import CheckpointWitness

            if plan.recovery_anchor.witness is None:
                raise ValueError("witness directory requires independent deployment enrollment")
            witness = CheckpointWitness(args.witness_directory, plan.recovery_anchor.witness)
        anchor = CheckpointAnchor(args.anchor_directory, plan.recovery_anchor, witness=witness)
    elif args.witness_directory is not None or args.witness_key is not None:
        raise ValueError("witness options require an enrolled anchor")
    if not all((args.cp_keyring, args.encryption_key, args.checkpoint)):
        raise ValueError(
            "state operations require external CP keyring, encryption key and checkpoint"
        )
    signer = keyring(args.cp_keyring)
    encryption_key = read(args.encryption_key, limit=32)
    database_url = os.environ.get("PAJIN_RECOVERY_DATABASE_URL", "")
    if args.operation == "checkpoint":
        pin = create_checkpoint(
            plan,
            args.state_root,
            database_url=database_url,
            signer=signer,
            encryption_key=encryption_key,
            destination=args.checkpoint,
            anchor=anchor,
            anchor_key=(
                Ed25519PrivateKey.from_private_bytes(read(args.anchor_key, limit=32))
                if args.anchor_key is not None
                else None
            ),
            expected_anchor_sequence=args.expected_anchor_sequence,
            witness_key=(
                Ed25519PrivateKey.from_private_bytes(read(args.witness_key, limit=32))
                if args.witness_key is not None
                else None
            ),
        )
        return {"checkpoint_sha256": pin, "source_stopped": True, "execution_authorized": False}
    if not args.checkpoint_pin:
        raise ValueError("restoration requires the independently retained checkpoint pin")
    checkpoint = authenticate(
        read(args.checkpoint, limit=MAX_BYTES * 3 + 28),
        pin=args.checkpoint_pin,
        key=encryption_key,
    )
    if args.operation in ("restore", "verify"):
        operation = restore_checkpoint if args.operation == "restore" else verify_restored
        return operation(
            checkpoint,
            plan,
            args.state_root,
            database_url=database_url,
            signer=signer,
            checkpoint_pin=args.checkpoint_pin,
            anchor=anchor,
        )
    if not all((args.verification, args.resume_authorization, args.operator_ca, args.attempt)):
        raise ValueError(
            "resume requires verified receipt, separate signed approval, CA and new attempt"
        )
    if args.attempt.is_relative_to(args.state_root):
        raise ValueError("resume attempt evidence must remain outside restored application state")
    report = parse_strict_json_bytes(
        read(args.verification), label="verification receipt", max_bytes=MAX_BYTES
    )
    if not isinstance(report, dict):
        raise ValueError("verification receipt must be an object")
    return resume(
        checkpoint,
        plan,
        args.state_root,
        database_url=database_url,
        signer=signer,
        report=cast(dict[str, object], report),
        checkpoint_pin=args.checkpoint_pin,
        grant=ResumeAuthorization.model_validate_json(read(args.resume_authorization, limit=65536)),
        ca_path=args.operator_ca,
        token=os.environ.get("PAJIN_RECOVERY_OPERATOR_TOKEN", ""),
        attempt_path=args.attempt,
        anchor=anchor,
    )


if __name__ == "__main__":
    main()
