# ADR 0014: Offline Feature Map Export

## Status

Accepted.

## Context

GeoJSON ingestion creates validated feature records, but operators need a visual artifact they can
open without a server, browser bundle, or network dependency.

## Decision

Add `astragrid-map` and `geo map`. The command reads feature JSON Lines, computes a union bounding
box, projects features into a self-contained HTML/SVG map, and includes a feature table with ids,
geometry types, and digests.

## Consequences

- Map artifacts can be attached to offline reports.
- The first map layer is static and deterministic.
- A richer browser console can build on the same feature records later.
