# AstraGrid Roadmap TODO

This is the completed build checklist for the current high-value phases.

## Current Quality Gate

- [x] Dashboard renders peer health, due work, stale retrying jobs, and recent peer errors.
- [x] Dashboard export reports peer health fields in machine-readable CLI output.
- [x] CLI parser coverage includes OS key, model adapter, map console, peer health, dashboard, and quorum commands.
- [x] Release doctor verifies package provenance, optional signatures, and optional quorum custody.
- [x] Run full format, lint, test, build, docs, package, and provenance verification gate.

## Phase 1: OS-Backed Operator Key Protection

- [x] Add an OS-sealed passphrase envelope for supported platforms.
- [x] Wire OS-sealed passphrases into signing commands.
- [x] Add operator docs for provider expansion beyond Windows DPAPI.

## Phase 2: Evidence-Constrained Model Adapter

- [x] Accept model recommendation candidates only as structured JSON.
- [x] Reject candidates that cite unknown evidence ids.
- [x] Emit verified `EvidenceBundle` output for accepted candidates.

## Phase 3: Browser Map Console With State Overlays

- [x] Export an operator console that combines feature maps and mission state.
- [x] Show open/closed incidents, observations, dispatches, and annotations.
- [x] Keep the console self-contained and safe for offline use.

## Phase 4: Multi-Signature Release Provenance Quorum

- [x] Bundle multiple provenance signatures into one quorum file.
- [x] Verify minimum signature threshold and distinct signer ids.
- [x] Add CLI gates for release promotion.

## Phase 5: Peer Worker Health Telemetry

- [x] Snapshot peer queue health from durable queue state.
- [x] Include due, stale, failed, and last-error telemetry.
- [x] Export health JSON for supervisor and dashboard consumption.

## Next Wave: Operator Productization

- [x] Add an operator handoff bundle that exports dashboard, state, workspace doctor, optional map console, optional release doctor, and manifest files.
- [x] Add release custody policy files for required signer ids and promotion thresholds.
- [x] Add live-refresh local dashboard serving without weakening offline export behavior.
- [x] Add peer worker install/uninstall wrappers around generated supervisor artifacts.
- [x] Add a full mission acceptance pack that exercises identity, registry, evidence, approval, dashboard, ops bundle, package, and doctor gates together.
