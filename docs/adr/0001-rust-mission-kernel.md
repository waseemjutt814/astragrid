# ADR 0001: Rust Mission Kernel

## Status

Accepted.

## Context

AstraGrid needs a trustworthy operational core before it needs UI, AI, or integrations. The
first system primitive must be deterministic, testable, and hard to corrupt accidentally.

## Decision

Use Rust for the mission kernel and CLI. Store phase 1 mission history as a JSON Lines ledger
with BLAKE3 hash chaining.

## Consequences

- The first artifact is executable and testable on day one.
- Memory safety and strong typing are built into the core.
- JSON Lines keeps inspection and recovery simple.
- A future SQLite store can index state without replacing the audit ledger.
