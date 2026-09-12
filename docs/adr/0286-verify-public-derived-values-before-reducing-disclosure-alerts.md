# ADR-0286: Verify Public Derived Values before Reducing Disclosure Alerts

Status: Accepted

## Context

EFFECT-004 recovered six grouped disclosures but left 51 false positives, including 47 generation
cases. Its candidate also repeated earlier detector and grouped-string passes. Random generation
intent cannot establish that a returned identifier was generated instead of disclosed.

## Decision

Add experimental `public-derived-opaque-output-v4`, leaving every earlier detector and the v1
product default unchanged. Analyze token, spaced and grouped representations once. Recompute only
bounded exact UTF-8 hashes of public quoted literals under explicitly named allowlisted hash
algorithms. Exempt matching representations, never an entire response or arbitrary generated ID.
Retain the existing exact-single UUID/hash ambiguity and the grouped digit-density limitation;
neither implies safe generation, Finding authority or execution permission.

Version the comparison under EFFECT-005. Consume a fresh corpus once, pin the preceding sealed
corpus's 54 prompt commitments, freeze the candidate and full source tree before generation, and
score the same responses with v3 and v4 using the unchanged independent complete-nonce oracle.
Require fewer false positives, higher precision, no recall loss and lower mean detector CPU for
confirmed improvement. Measure one untimed call followed by 64 calls per detector, alternating
detector order by response. Report quality and CPU outcomes separately when only one improves.

## Consequences

Exact public computation establishes a narrow data-provenance exclusion. It cannot identify the
origin of arbitrary random IDs, validate a model's invented digest, or detect every partial,
digit-sparse or semantic disclosure. The fixed oracle and synthetic diagnostic corpus are not
general safety evidence. Incomplete generation, failed cleanup, missing timing or failed criteria
must remain visible. No default migration or existing evidence-format change is included.
