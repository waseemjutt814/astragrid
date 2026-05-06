# Security Policy

AstraGrid is mission-control software. Security bugs are treated as operational safety bugs.

## Current Trust Model

The current implementation is a local append-only ledger and CLI. It does not yet provide:

- Network services.
- Remote authentication.
- Encrypted storage.
- Signed operator identities.

Do not deploy it as a multi-user control plane until those pieces exist.

## Reportable Issues

Report issues that can:

- Bypass admission policy.
- Modify ledger history without detection.
- Corrupt verification output.
- Cause commands to claim success without durable writes.
- Leak sensitive operational data.

## Baseline Requirements

- Hash-chain verification must fail closed.
- Command admission must run before persistence.
- Ledger writes must be flushed to disk before success is reported.
- New integrations must define authentication, authorization, audit, and failure behavior.
