# ADR 0008: Evidence To Command Workflow Drafts

## Status

Accepted.

## Context

Evidence bundles can describe recommendations, but mission software should not silently mutate the
ledger from an automated recommendation.

## Decision

Add `astragrid-workflow`, which turns verified evidence bundles into command drafts. Drafting checks
confidence thresholds, current state, action parsing, and admission policy. It never appends.

## Consequences

- Operators get structured command proposals instead of free text.
- Unsafe or duplicate transitions are blocked before signing.
- Human approval remains required for ledger mutation.
