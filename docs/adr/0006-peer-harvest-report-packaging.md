# ADR 0006: Peer Snapshots, Harvesting, Reports, and Packaging

## Status

Accepted.

## Context

After the local mission kernel, operators need practical movement of mission data: peer transfer,
remote geospatial harvest, sealed artifacts, readable reports, and a packageable binary.

## Decision

Add:

- `astragrid-net` for authenticated one-shot TCP ledger snapshots.
- `astragrid-net` peer manifests for multi-peer sync planning.
- `astragrid-harvest` for remote GeoJSON/OGC Features fetching and profile cache metadata.
- `astragrid-crypto` for encrypted artifact sealing.
- `astragrid-report` for Markdown and JSON incident report bundle export.
- Local install and release packaging scripts.

## Consequences

- Peer transport is real and intentionally simple. Durable queueing, worker loops, health
  telemetry, and supervisor artifacts are now handled by later ADRs.
- Harvesting validates GeoJSON through the same ingestion path and can avoid unnecessary network
  calls when a profile cache is present.
- Reports, report bundles, and sealed artifacts are generated from verified local data.
- Release packaging is automated locally and smoke-tested in Windows CI.
