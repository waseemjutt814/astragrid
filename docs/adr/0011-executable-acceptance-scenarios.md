# ADR 0011: Executable Acceptance Scenarios

## Status

Accepted.

## Context

Unit tests verify crate behavior, but operators also need a repeatable way to prove end-to-end
mission workflows. Shell snippets are useful for humans but are hard to assert in CI.

## Decision

Add `astragrid-scenario`, a JSON scenario runner that executes typed mission steps in a work
directory. The first supported steps initialize a ledger, append mission events, verify the
ledger, ingest the SQLite store, and assert materialized state or store counts.

## Consequences

- Acceptance workflows can be stored as data and run by the CLI.
- Scenario assertions fail the command instead of producing a soft warning.
- The runner uses the same Rust crates as production flows, so scenario behavior exercises real
  ledger, state, and store logic.
