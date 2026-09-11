# EFFECT-004: Bounded Worker Diagnostics and Paired Precision Evaluation

Status: Local bounded Worker diagnostics verified. The separate experimental comparison is added in the next change; product default remains v1.

## Diagnostic contract

The Worker preserves supported CLI actions, secret envelope versions, success JSON and exit codes
64/65/70. A handled failure keeps the legacy first stderr line and adds exactly one bounded
`pajin-worker-failure-v1 stage=<enum> category=<enum>` line. Unknown actions retain exit 64. Stages
are worker input/action, Provider request preparation/open/read/normalization. Streaming read and
normalization share the read phase. Categories describe observable exception classes: timeout,
subprocess timeout, TLS verification/TLS, HTTP response/protocol, connection, I/O, runtime, invalid
data or unknown transport. They never establish a deeper root cause. In particular an I/O error is
not proof of resource exhaustion, and a timeout is not proof that a remote call never executed.

No exception message, prompt, response, URL, local path, credential, canary, status body or traceback
is included in this diagnostic. The host accepts only the complete allowlisted two-line record
with a compatible exit code. Truncated, legacy, appended, unrecognized or malformed records become
`unknown`. Even recognized records are Worker reports, not independently attested explanations.

The Provider records the safe classification with the existing failure and evidence references.
Execution/policy/result bindings still precede diagnostics. A dispatched failure keeps the full
reserved token/cost charge; an uncertain call is neither retried nor refunded. A confirmed
non-executed outcome follows the existing release rule. Diagnostics cannot change any of those
choices. Existing sealed artifacts are unchanged; legacy readers retain their existing formats.
The two EFFECT-003 exit-70 failures remain unknown because their retained records are insufficient.
