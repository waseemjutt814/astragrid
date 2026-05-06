# ADR 0005: GeoJSON, Evidence Bundles, and Offline Sync Plans

## Status

Accepted.

## Context

AstraGrid needs mission data that can be inspected without a live service: geospatial features,
recommendation evidence, and peer ledger state.

## Decision

Add three executable crates:

- `astragrid-geo` for GeoJSON validation, bounding boxes, and feature digests.
- `astragrid-evidence` for hash-bound evidence bundles and recommendation citations.
- `astragrid-sync` for offline ledger comparison, append-only delta apply, and divergence
  detection.

## Consequences

- Geo features and evidence can be generated and verified locally.
- AI recommendations must use evidence ids rather than unsupported prose.
- Sync planning detects divergence.
- Sync apply imports only verified suffix events and does not auto-merge conflicts.
