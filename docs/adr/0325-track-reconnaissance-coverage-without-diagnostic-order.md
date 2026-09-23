# ADR-0325: Track Reconnaissance Coverage Independently of Diagnostic Rank

- Status: Accepted
- Date: 2026-09-23
- Scope: successor reconnaissance coverage and external-asset admission boundary
- Implementation status: local-only coverage review for the sealed loopback source; no external
  asset scope, public OSINT lookup, new target request, or new hosted model call

## Context

The historical WEB-007 and hosted Codex reconnaissance v1alpha1 drafts assign attention ranks to
three fixed Juice Shop diagnostics. Their contracts already prohibit consuming rank as an action
order, subset choice, or execution authority. The completed Luna turn ranked the three diagnostics
but did not collect public OSINT, identify external assets, enumerate a complete surface, or map all
workflows. Presenting its rank alone could imply a narrower assessment than the operator intends.

The operator wants reconnaissance to cover public OSINT, asset and surface identification,
application entry points, workflows, and diagnostic hypotheses for future external assets. The
[OWASP WSTG information-gathering guidance](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
separately describes public search reconnaissance, attack-surface identification, entry-point
inventory, and execution-path mapping. A public record or discovered host is a candidate asset;
discovery cannot add it to Campaign Scope.

## Decision

Record reconnaissance as an evidence-bound set of coverage tracks, independent of model attention
rank. The additive `CodexReconCoverage/v1alpha1` local artifact lists every code-owned track once:
public OSINT, asset identification, passive web surface, bounded web surface observation, entry
points, workflows, technology fingerprinting, active surface enumeration, and diagnostic
hypotheses. The serialized track order is canonical data representation, not a schedule. Each track
states `not-applicable`, `not-assessed`, `scope-bound`, `observed-bounded`, or `proposal-only` with a
source digest when one exists. No track can claim exhaustive coverage.

The loopback builder strictly reloads the exact sealed discovery Run and independently rebuilds
the closed reconnaissance projection. It marks public OSINT `not-applicable` for the numeric
loopback lab; the registered single origin is only `scope-bound`. The bounded depth-one,
four-route authenticated discovery supports `observed-bounded` web-surface and entry-point
tracks. Passive web-surface collection, workflow mapping, technology fingerprinting, and active
surface enumeration remain `not-assessed`. If an exact existing Luna draft is supplied,
diagnostic hypotheses are `proposal-only`; its rank has no effect on any other track. The artifact
grants no external lookup,
scope expansion, target action, hosted transfer, or Finding authority.

Future external-asset reconnaissance requires a separately versioned scope and evidence source:
the operator must identify exact permitted assets and excluded assets, public data sources,
allowed lookup and direct-request classes, rate and redirect limits, and a time window. A public
OSINT observation or model suggestion may propose a candidate for review but cannot automatically
change that scope. The external adapter must independently verify provenance and preserve
candidate-versus-authorized identity before any active surface request. The current local-only
coverage artifact is not an external-asset adapter or an approval to collect OSINT.

## Compatibility and rollout

The sealed v1alpha1 Luna prompt, output, receipt, and journal retain their original meaning and
digest. No historical rank is rewritten or used to suppress other tracks. A future hosted draft
that omits mandatory rank must use a new wire version and independently approved transfer input.
The next work is an exact external-scope contract and separately authorized collection flow when
the operator supplies assets. The local coverage review can be discarded without changing any
historical Run, receipt, or target state.

## Verification

The sealed local discovery and admitted Luna draft were reloaded to produce a local coverage
artifact: two tracks are `observed-bounded`, one is `scope-bound`, one is `proposal-only`, public
OSINT is `not-applicable`, and four remain `not-assessed`. Focused tests verify all nine tracks,
strict-source reload, a recomputed-digest forgery that overstates an unassessed track, rejection of
an external origin by the local builder, and draft proposal status. No external lookup or target
request was made while producing the artifact.

## Related decisions

- [ADR-0324](0324-route-hosted-codex-advisory-by-stage.md): hosted Luna/Sol routes and the
  historical one-shot reconnaissance receipt
- [ADR-0301](0301-bind-llm-web-analysis-to-inert-typed-proposals.md): model rank remains inert
