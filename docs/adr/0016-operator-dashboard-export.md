# ADR 0016: Operator Dashboard Export

## Status

Accepted.

## Context

The project has separate ledger, state, store, approval, peer queue, map, and evidence artifacts.
Operators need a single offline view without requiring a web service or frontend build pipeline.

## Decision

Add `astragrid-dashboard` and `dashboard export`. The CLI reads verified local artifacts and the
crate renders a self-contained HTML dashboard with mission metrics, recent events, approvals, peer
queue state, evidence bundle summaries, and an optional map link.

## Consequences

- Operators can attach a dashboard artifact to reports or handoffs.
- Dashboard export stays offline and deterministic.
- Rich interactive consoles can later reuse the same data contracts.
