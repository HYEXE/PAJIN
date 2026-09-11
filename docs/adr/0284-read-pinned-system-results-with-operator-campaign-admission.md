# ADR-0284: Read Pinned System Results with Operator Campaign Admission

Status: Accepted for retained-evidence reads only.

## Decision

Extend the existing digest-pinned deployment inventory with one optional System recipe. Require
explicit Operator subjects, Campaign ID, source/replay references and external trust. Authentication,
Operator role and exact subject/Campaign admission precede any evidence access. Revalidate the
sealed Campaign binding, existing independent System reader and source/replay comparison on every
request; do not let the request choose trust material, filesystem paths or execution inputs.

Return only bounded OS metadata, evidence references and observed completion/cleanup status.
Keep empty, verified, incomplete, integrity failure and read failure distinct. Retained failure
evidence may be integrity-valid without a completed read. Source-only evidence cannot claim replay.
Clear stale Console data on Campaign or credential changes, and render metadata only as text.

## Consequences

No new host read, job, approval, Permit or Secret Lease is created. Existing CLI and reader output
remain compatible; `expected_campaign` is an additive optional verification constraint. Finding,
execution and general-System authorities remain false. Existing Web/Network/AI routes and their
deployment diagnostics retain their behavior. No arbitrary host or Cloud support is introduced.
