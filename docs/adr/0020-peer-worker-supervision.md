# ADR 0020: Peer Worker Supervision Artifacts

## Status

Accepted.

## Context

The peer sync queue worker is designed for long-running operation, but operators need repeatable
service manager artifacts instead of handwritten commands.

## Decision

Add a supervisor artifact generator that renders systemd units and Windows Scheduled Task
registration scripts for `astragrid peer-queue worker`. The generator validates paths and numeric
settings, references a shared-key file path instead of embedding secret material, and uses the same
worker arguments as the CLI.

## Consequences

- Local and server deployments can run the peer queue worker under native process supervision.
- Generated artifacts stay reviewable before installation.
- Future health telemetry can build on the same worker configuration model.
