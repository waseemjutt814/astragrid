# ADR 0015: Evidence-Bound Recommendation Rules

## Status

Accepted.

## Context

The system needs automation that can recommend actions, but emitting free-text advice would weaken
auditability. A model-backed adapter may be added later, but the output contract must be proven
first.

## Decision

Add `astragrid-recommend`, a deterministic rule engine that evaluates threshold rules over sensor
readings and emits verified `EvidenceBundle` values. Each matching reading becomes a hashed
evidence item, and each recommendation cites the evidence ids it used.

## Consequences

- Automation can feed the existing workflow draft path without bypassing evidence checks.
- Non-matching or low-confidence readings produce no recommendation bundle.
- Future model adapters must emit the same evidence-bound structure rather than raw prose.
