# ADR 0009: Approval-Gated Workflow Execution

## Status

Accepted.

## Context

Workflow drafts can convert verified evidence bundles into command requests, but a draft is still
an operational recommendation. The system needs a review trail before any automation writes to the
mission ledger.

## Decision

Add `astragrid-approvals`, an append-only JSON Lines approval log with its own BLAKE3 hash chain.
The log records draft submission, approval, rejection, and execution as separate records. A draft
can be submitted only when it is ready and contains a command request. `approval append-approved`
loads the approved draft, signs the exact request with a local operator identity, optionally checks
the operator registry, appends to the mission ledger, and records the resulting ledger event hash.

## Consequences

- Operators get a replayable review history separate from the mission ledger.
- Blocked workflow drafts cannot enter the approval queue.
- Approved drafts cannot be executed without local signing authority.
- Ledger append failures leave the approval item approved, so operators can retry or manually mark
  an already completed external append with its ledger event hash.
