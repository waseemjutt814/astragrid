# ADR 0018: Peer Queue Worker

## Status

Accepted.

## Context

Durable peer queue processing works as a one-shot command, but operators also need a process that
can run repeatedly under a supervisor.

## Decision

Add `peer-queue worker`. The worker uses the existing queue processor, shared-key authenticated
peer fetch, append-only apply logic, and retry accounting. It can run for a fixed number of cycles
for validation or indefinitely when `--cycles` is omitted.

## Consequences

- No separate sync semantics are introduced for daemon-style processing.
- Local smoke tests can run finite cycles.
- Service wrappers can supervise the same CLI command later.
