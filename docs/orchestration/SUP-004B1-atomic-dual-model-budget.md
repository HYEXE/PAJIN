# SUP-004B1: Atomic Dual Model Budget Reservation

- Status: Implemented
- Runtime boundary: `DualModelUsageBudget`
- Decision: [ADR-0121](../adr/0121-atomically-charge-campaign-and-dedicated-model-budgets.md)

## Scope

SUP-004B1 adds the first actual-call prerequisite after the non-invocable SUP-004A plan. One
`DualModelUsageBudget` charges the same conservative model-call, Tool-call, prompt-token,
completion-token, and cost bound to both the Campaign `BudgetController` and a distinct dedicated
`BudgetController`. It also enforces both duration ceilings and uses their minimum remaining time.
`PolicyBoundProviderPort` accepts this boundary additively while its
existing Campaign-only constructor and `chat()`/`complete()` behavior remain unchanged.

This slice does not invoke the Shadow Supervisor by itself. It does not define a stable Provider
request ID, a bound Provider outcome, a durable invocation claim, a Supervisor receipt, a draft
admission, Task or Plan mutation, Scope expansion, Stop application, Capability, Permit,
execution, or activation authority. Those remain SUP-004B2/B3 work.

## Atomicity and lifecycle

Each `BudgetController` revalidates and detaches its supplied `Budgets` authority, then owns an
internal reentrant usage lock. All usage checks, mutations, reservation settlement, restoration,
duration reads, and snapshots use that lock. A dual boundary
orders the two controller locks by object identity before it checks or changes either ledger. A
direct Campaign reservation therefore competes on the same Campaign lock as a dual reservation.

Reservation semantics are conservative:

- Campaign denial leaves the dedicated ledger unchanged;
- dedicated denial rolls the Campaign reservation back before either lock is released;
- successful dispatch commits the same upper bound to both ledgers;
- only a Gateway outcome that proves non-execution releases both reservations; and
- timeout, cancellation, transport uncertainty, executed failure, or invalid Provider output
  keeps both upper bounds consumed through the existing Provider lifecycle.

The returned `DualModelUsageReservation` exposes only the composite identity and common charged
bound. It does not expose either controller's internal reservation handle. Commit and release first
require the exact active composite object and both exact internal active reservations.

## Negative boundaries

The boundary fails closed for:

- using the same controller as both Campaign and dedicated budget;
- attaching a dual boundary to a Provider port whose Campaign controller it does not charge;
- Campaign or dedicated call, Tool-call, token, cost, or duration exhaustion;
- boolean-as-number Campaign ceilings, runtime usage, or restored checkpoint usage and non-finite
  costs or elapsed duration;
- failure while publishing the composite reservation after both internal reservations succeed;
- forged, copied, already committed, or already released composite reservations; and
- a Campaign-only reservation appearing while a Provider port is configured for dual charging.

Thread competition tests require one winner when a direct Campaign reservation and a dual
reservation race for one remaining call. Rollback tests require both ledgers to remain unchanged
when the dedicated capacity rejects after Campaign preflight or composite identity publication
fails after both internal reservations succeed.

## Compatibility and limits

The dual controller and Provider constructor parameter are additive. Existing runtime callers use
the original single Campaign controller. Budget accounting remains process-local; two processes
with independent `BudgetController` objects are not one global budget authority. SUP-004B3 must
use a durable invocation journal for at-most-once dispatch, while any future distributed budget
authority requires a separate persistent ledger and contract.
