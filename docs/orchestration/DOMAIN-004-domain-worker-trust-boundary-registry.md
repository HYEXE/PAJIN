# DOMAIN-004: Domain Worker Trust-boundary Registry

- Status: Implemented, registry and deployment-binding contract only
- Contract versions:
  - `pajin.dev/domain-worker-boundary-profile/v1alpha1`
  - `pajin.dev/domain-worker-boundary-profile-registry/v1alpha1`
  - `pajin.dev/domain-worker-deployment-binding/v1alpha1`
  - `pajin.dev/domain-worker-deployment-registry/v1alpha1`
- Decision: [ADR-0206](../adr/0206-bind-domain-workers-to-existing-authority-path.md)

## Scope

DOMAIN-004 registers code-owned minimum Worker trust-boundary profiles for all nine DOMAIN-001
classifications. It can bind one exact, lifecycle-verified signed Capability release to one exact
DOMAIN-003 classification, one exact profile, and one deployment-owned Worker mTLS subject and
certificate SPKI.

The catalog and deployment registry are non-executable contracts. They do not activate a release,
select a Campaign Profile, expand Scope, admit a Graph Decision, satisfy approval, issue or consume
an ActionPermit, authorize Gateway dispatch, prove runtime conformance, or confirm a Finding.
Existing PENTEST and REDTEAM deployments are unchanged and do not implicitly acquire DOMAIN-004
bindings.

## Code-owned minimum profiles

The exact registry contains one content-addressed profile per DOMAIN-001 value in canonical order:

| Domain | Network | Filesystem | Credentials | Runtime | Exact identity requirements |
| --- | --- | --- | --- | --- | --- |
| Web | bounded egress | no host access | none | isolated non-root | HTTP method and target |
| Network | exact host/protocol/port | no host access | none | isolated non-root | address family, host, port, protocol |
| System | deployment-scoped | bounded host read | deployment authentication | authenticated non-root agent | authorized host and host agent |
| Application | disabled by default | read-only artifact | none | offline sandbox | analyzer and artifact digest |
| Mobile | disabled by default | read-only artifact | none | device-bound | app, artifact, and emulator or device identity |
| Cloud | bounded egress | no host access | ephemeral lease | isolated non-root | account/project, lease, and resource |
| AI | bounded egress | no host access | ephemeral lease | isolated non-root | AI surface, provider, model, and Tool |
| Cryptography | disabled by default | read-only artifact | none | offline sandbox | analyzer and artifact digest |
| Forensics | disabled by default | immutable evidence | none | provenance-preserving parser | evidence source and parser |

These are minimum requirements, not Worker implementations or access grants. Every profile fixes
Domain-only and Tool-metadata selection, network, filesystem, credential, device, evidence
mutation, Worker selection, runtime-support assertion, and execution authorization to false.
Dynamic execution and mutation require separate exact Capabilities. Network protocol privileges
require explicit review. The Forensics profile additionally requires provenance preservation and
cannot authorize evidence mutation.

## Exact deployment binding

`register_domain_worker_deployment_binding` performs all of the following before producing a
binding:

1. resolves the exact DOMAIN-003 classification against the current CAP-001/CAP-002 source
   registries;
2. resolves the exact code-owned profile reference;
3. resolves the exact signed release from an already verified CAP-004 lifecycle registry;
4. requires the release's complete `CodeBackedCapabilityRef` to equal the DOMAIN-003 record;
5. requires the profile's DOMAIN-001 reference to equal that record's classification;
6. requires the exact Worker subject to exist in the supplied deployment mTLS policy; and
7. binds the signed release-bundle digest, complete Capability authority identity, profile digest,
   mTLS policy digest, subject, and certificate SPKI into one content digest.

The resulting record explicitly keeps current activation, Campaign authority, Graph Decision,
approval, Permit, Gateway dispatch, profile conformance, Worker selection, runtime support, and
execution authority absent. A lifecycle-verified historical release can therefore be inventoried,
but it cannot run unless the separate existing activation and execution path admits it at dispatch
time.

`DomainWorkerDeploymentRegistry` accepts only canonical bindings owned by one exact deployment,
sorts them by content identity, rejects duplicates and cross-deployment membership, and binds the
exact nine-profile catalog digest. Resolution accepts only a complete binding ID, digest, and
deployment ID. There is no lookup API by Domain label, legacy Capability namespace, Surface, Tool
category, MCP metadata, or discovered Worker.

## Existing authority path

DOMAIN-004 does not add a parallel executor. A future vertical slice that adopts one of these
bindings must still use the existing path:

```text
exact current Capability release + Campaign authority + Graph Decision
-> Proposal + Policy / Approval
-> single-use ActionPermit
-> Tool Gateway policy re-entry
-> exact deployment-bound Worker identity
-> trusted receipt + Observation / Evidence
```

The deployment registry is not accepted in place of any predecessor above. Exact retry, cleanup,
Evidence lineage, Replay, validation floor, and Finding rules remain unchanged.

## Fail-closed cases

Registration or exact resolution rejects:

- an unregistered, substituted, or digest-drifted signed release;
- a release whose complete CAP-002 authority identity differs from the DOMAIN-003 record;
- a missing, relabeled, or substituted DOMAIN-003 record;
- a profile from another Domain or a changed profile/catalog digest;
- an absent Worker subject or substituted certificate SPKI;
- changed mTLS policy content, cross-deployment membership, duplicates, or reordered membership;
- aliases, `latest`, partial references, extra Domain/Tool/Scope/Permit fields; and
- boolean coercion or any attempt to turn a fixed non-authority marker on.

## Implemented versus not implemented

Implemented:

- exact nine-profile code-owned registry;
- exact signed release-bundle, CAP-002, DOMAIN-003, profile, deployment, mTLS policy, Worker subject,
  and SPKI binding;
- exact binding registry and reference resolution; and
- positive and adversarial contract tests.

Contract or scaffold only:

- the nine minimum profiles describe requirements; they do not prove that a concrete Worker meets
  them;
- the deployment registry is content-addressed but is not yet a separately signed deployment
  authority; and
- no existing Gateway or Worker runtime consumes the registry as execution authority.

Planned:

- profile conformance evidence and deployment signing authority;
- adoption by each domain vertical slice through its existing Permit/Gateway/Worker path;
- cross-host fencing and production provider isolation; and
- general Network, System, Application, Mobile, Cloud, Cryptography, or Forensics Workers.

## Compatibility, migration, and rollback

DOMAIN-004 is additive. It changes no DOMAIN-001/002/003, CAP-001 through CAP-005, Graph, Permit,
Gateway, Worker Job, receipt, REDTEAM, PENTEST, Profile, Finding, Evidence, or wire identity. Existing
deployments remain valid without a DOMAIN-004 record and cannot be widened by one.

Rollback removes the new registry module, tests, and contract or stops publishing the optional
bindings. Existing releases, activations, deployments, Permits, receipts, Graph records, Evidence,
and Findings require no rewrite.

## Follow-up boundary

- DOMAIN-005 may admit a cross-domain Surface or Hypothesis to the existing Canonical Graph. That
  knowledge remains registered-not-authorized and cannot select a DOMAIN-004 Worker binding.
- DOMAIN-006 may register common and domain-specific validation and benchmark metrics without
  turning registry presence into detection quality or Finding authority.
- Each domain vertical slice must add concrete conformance and negative tests before it can claim
  runtime support for one profile.
