# ADR 0007: Ledger State Projection

## Status

Accepted.

## Context

The ledger is the source of truth, but operators need the current mission view without manually
reading every event.

## Decision

Add `astragrid-state`, a deterministic state projection over verified ledger events. The
projection tracks mission metadata, incidents, observations, dispatches, annotations, and last
hash.

## Consequences

- Operators can query current state without weakening the ledger model.
- Invalid transitions fail closed.
- Future UI and reports can consume a typed state model instead of re-parsing ledger events.
