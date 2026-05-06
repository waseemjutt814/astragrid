# ADR 0012: Durable Peer Sync Queue

## Status

Accepted.

## Context

One-shot peer snapshots are useful for controlled sync, but a mission system must survive peer
offline periods, transient network failures, and repeated attempts without losing operator intent.

## Decision

Add `astragrid-sync-queue`, a SQLite-backed peer sync queue. Jobs are created from peer manifests
and record peer name, address, status, attempts, retry timing, last error, and the last sync/apply
report. `peer-queue process` fetches due peer snapshots through the authenticated peer transport,
compares them against the local ledger, applies only append-only suffixes, and updates the durable
job state.

## Consequences

- Peer sync intent survives process exits.
- Offline peers become retry or failed jobs instead of disappearing from a one-shot report.
- Successful jobs preserve the last sync plan and append result for audit.
- A daemon can be added later on top of the same queue without changing the ledger semantics.
