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

## Next Wave: Production Hardening

- [x] Add a release custody pack command that signs provenance, creates quorum and policy files, writes a manifest, and requires a healthy release doctor gate.
- [x] Wire signed package builds through the custody pack so signed releases produce complete promotion evidence instead of a loose signature only.
- [x] Add live-refresh local map console serving without weakening offline HTML export behavior.
- [x] Add public trusted-registry bundle export and verification for multi-host operator handoff.
- [x] Add parser and executable tests for custody packs, live map serving, and registry trust bundles.

## Next Wave: Field Readiness

- [x] Add verified registry trust bundle import with identity-conflict checks and revocation-dominant merge behavior.
- [x] Add a release evidence pack that writes checksums, doctor output, and a handoff manifest from signed custody artifacts.
- [x] Add a finite readiness gate for repeated workspace and release doctor cycles.
- [x] Add parser and executable tests for registry import, release evidence packs, and readiness gates.

## Next Wave: Windows Distribution Runtime

- [x] Make `astragrid.exe` useful when launched without arguments instead of exiting as a failed command.
- [x] Add a double-click friendly `START-ASTRAGRID.cmd` launcher to the Windows package.
- [x] Add a packaged `VERIFY-ASTRAGRID.ps1` executable smoke helper.
- [x] Include launcher and smoke helper files in package provenance metadata.
- [x] Add parser/runtime tests for no-argument launcher behavior.
