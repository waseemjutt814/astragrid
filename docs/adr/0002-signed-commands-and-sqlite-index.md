# ADR 0002: Signed Commands and SQLite Index

## Status

Accepted.

## Context

The mission ledger proves event order and tamper detection, but operators also need attribution.
Operators will also need fast local queries without weakening the ledger as the source of truth.

## Decision

Add Ed25519 local operator identities and signed command append. Store the signature attestation
inside each signed ledger event. Add a SQLite index crate that ingests only verified ledgers and
stores query columns plus full event JSON.

## Consequences

- Operator-facing commands can be cryptographically attributed.
- Ledger tampering remains detectable through both signature and hash-chain checks.
- SQLite improves query speed without becoming the authoritative event store.
- Encrypted private key storage is covered by ADR 0004; operator-facing workflows should use
  encrypted keys rather than plain bootstrap keys.
