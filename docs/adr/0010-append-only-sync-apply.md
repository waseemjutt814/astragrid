# ADR 0010: Append-Only Sync Apply

## Status

Accepted.

## Context

Sync planning can identify when a peer ledger is an append-only extension of the local ledger. A
manual copy step is error-prone, but automatically merging conflicting histories would weaken the
audit model.

## Decision

Add `sync apply --target --source`, backed by `astragrid-sync::apply_append_only`. The command
verifies both ledgers, compares their common prefix, and appends only the missing source suffix
when the source is ahead of the target. Imported events are written exactly as received after
sequence, previous-hash, event-hash, signature, and admission-policy validation.

## Consequences

- Identical ledgers and target-ahead ledgers are safe no-op applies.
- Source-ahead ledgers can be reconciled without rehashing or rewriting events.
- Diverged ledgers fail closed and require an explicit operator decision.
