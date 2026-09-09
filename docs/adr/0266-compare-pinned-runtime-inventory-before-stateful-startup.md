# ADR-0266: Compare Pinned Runtime Inventory Before Stateful Startup

- Status: Accepted
- Scope: OPS-001 startup configuration drift detection

## Context

The existing deployment files bind Campaigns, policies, public keys and configured stores.
Checkpoint-key and budget ledgers preserve their own durable identities. Reopening them does not
establish that the next process uses the same verifier implementation or complete configuration.
Code-owned default entry points need a comparison before constructing stateful deployment readers
or accepting work. An injected object's public ID is insufficient evidence of its implementation.

## Decision

Add an optional, independently digest-pinned `pajin.dev/runtime-inventory/v1` to the default
Control Plane, Worker and Replay Worker entry points. The trusted process owner supplies its
absolute path, SHA-256 and optional component ID. The inventory contains only named component
roles and package/configuration digests. It neither selects executable code nor grants permission.

Compute package fingerprints from current PAJIN source and packaged assets, Python runtime identity,
and installed distribution metadata. Compute private configuration fingerprints from effective CP
settings, inherited environment, process location/default identity, and directly configured
deployment/TLS file contents. Use bounded no-follow reads and strict JSON; never export raw
configuration or credentials. Do not cache the package hash across comparisons.

Compare before loading measured readers, constructing CP stores, loading the Capability Graph
deployment, or creating the Worker backend/client. The existing CP `--check-config` path performs
the comparison too. Inventory mode refuses arbitrary injected CP runtimes/readers; their public
identifiers cannot establish the code and configuration being compared. Existing embedded callers
without inventory configuration retain their existing behavior.

Provide CLI commands to print a component fingerprint, compose fingerprints into an inventory,
and verify the current component. They do not write stores, overwrite approved inventories, or
automatically bless configuration changes. A fingerprint command is not a successful full runtime
preflight or a recovery checkpoint.

## Consequences and limits

This is a deployment-drift gate under a trusted, unchanged host process environment, not remote
attestation or an independent anti-rollback authority. The comparison must be repeated at restart;
the host must keep code/configuration stable while processes run. Distribution metadata does not
authenticate arbitrary modifications to third-party file bytes, dynamic code, OS trust stores,
external services, Docker executables, mutable image tags, or the host administrator.

The initial inventory is location-specific and has no automatic migration/relocation. An approved
configuration/key rotation needs a newly reviewed inventory; CP key history must still verify.
Keeping the expected digest beside a copied inventory is not independent rollback protection.
Both inventory variables absent preserve legacy startup, which is not enrolled recovery. A
partial/blank pair or an orphan component selector is rejected.

Complete OPS-001 still requires first-work budget/urgent-producer composition, explicit participant
stores, enforced quiescence, complete backup contents/heads and a separately retained expected
checkpoint. This gate supplies a real default-startup connection without treating that connection
as completion of the full recovery boundary.
