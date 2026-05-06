# ADR 0017: Workspace Doctor

## Status

Accepted.

## Context

As the local mission workspace gains more artifacts, operators need a single read-only command that
reports whether the workspace is safe to continue using.

## Decision

Add `astragrid-doctor` and `doctor workspace`. The doctor verifies the ledger, materializes state,
checks optional SQLite store, key files, approval logs, and peer queue DBs, and returns structured
healthy, warning, or failed output.

## Consequences

- Health checks are repeatable and scriptable.
- Missing optional artifacts are warnings rather than hidden assumptions.
- The command remains read-only, so it can be used before risky operations.
