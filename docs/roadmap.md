# AstraGrid Roadmap TODO

This is the completed build checklist for the current high-value phases.

## Current Quality Gate

- [x] Dashboard renders peer health, due work, stale retrying jobs, and recent peer errors.
- [x] Dashboard export reports peer health fields in machine-readable CLI output.
- [x] CLI parser coverage includes OS key, model adapter, map console, peer health, dashboard, UI, and quorum commands.
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

## Next Wave: Installer, Smoke, and Artifact Retention

- [x] Add a no-fake A-to-Z master implementation plan with explicit external-infrastructure gates.
- [x] Add a packaged Windows installer script that installs the extracted release, runs a version smoke, and writes an install manifest.
- [x] Upgrade the local source installer to install the same runtime helper set and write a manifest.
- [x] Add package smoke automation that extracts the zip, verifies required files, runs no-arg/version smoke, runs the verifier, and checks installer output.
- [x] Add an `ops artifact-retention` CLI gate with dry-run-by-default reporting, explicit deletion, dist retention, cache retention, and optional target-cache cleanup.

## Next Wave: Ready-To-Use Operator Core

- [x] Add `setup first-run` to create workspace folders, an encrypted operator key, passphrase file, registry enrollment, genesis ledger, store DB, and secure profile.
- [x] Add `doctor profile` to validate a local profile and its configured workspace artifacts.
- [x] Add sealed workspace `ops backup` and `ops restore` commands with manifest hashes and fail-closed restore validation.
- [x] Add `identity rotate` to revoke an old operator id, create a new encrypted key, enroll it, and write rotation proof.
- [x] Add encrypted-at-rest `vault` ledger runtime commands for init, append, verify, and tail without storing a plaintext ledger as the primary artifact.
- [x] Extend the acceptance pack so fresh-machine style runs cover first-run setup, profile doctor, backup/restore, key rotation, and encrypted vault operations.

## Next Wave: Local Team Security Core

- [x] Add signed local team sessions with registry fingerprint binding, active-identity checks, expiry, and detached signature verification.
- [x] Add `team authorize` for policy checks through a verified session.
- [x] Add `team append` so mission mutation can require a valid team session plus the matching operator signing key.
- [x] Add signed device pairing grants with device id/name, operator identity, registry digest, expiry, and verification.
- [x] Extend the acceptance pack and unit tests to cover session issue/verify, authorization, authenticated append, and pairing verify.

## Next Wave: Signed Policy Rule Packs

- [x] Add `astragrid-policy-pack` with schema validation, compatibility metadata, rule matching, payload-field requirements, and deterministic SHA-256 digests.
- [x] Add detached policy-pack signatures and fail-closed verification against the signed pack digest.
- [x] Add registry-aware signer checks so policy packs can require an active enrolled operator signer.
- [x] Add `policy-pack template`, `sign`, `verify`, and `evaluate` CLI commands.
- [x] Wire verified policy pack enforcement into `append-signed` and `team append`.
- [x] Extend acceptance coverage and docs for signed policy pack verification and enforcement.

## Next Wave: Quorum Registry Changes

- [x] Add registry-change proposals for operator enroll/revoke actions with authority, current registry digest, nonce, and required approval count.
- [x] Add detached proposal signatures through active local operator keys.
- [x] Add quorum verification that rejects stale registries, duplicate signers, revoked signers, wrong-role signers, and invalid signatures.
- [x] Add fail-closed apply so registry mutation happens only after verified distinct incident-commander approvals.
- [x] Extend acceptance coverage and docs for quorum-governed operator enrollment.

## Next Wave: Worker Watchdog Recovery

- [x] Add `supervisor watchdog-run` for real local child-process supervision without shell interpolation.
- [x] Add JSONL audit events for watchdog start, attempt start/exit, restart scheduling, recovery, and final failure.
- [x] Add capped restart enforcement with nonzero exit recovery and fail-closed exhausted-budget reporting.
- [x] Add parser and executable tests for watchdog recovery and failure paths.
- [x] Extend acceptance coverage and docs for live worker recovery.

## Next Wave: Replication Worker Service Hardening

- [x] Add optional `peer-queue worker --health-file` JSON output with lifecycle status and queue health.
- [x] Add optional `peer-queue worker --audit-log` JSONL records for start, cycles, failures, and stop.
- [x] Add stale retry threshold handling to worker health output.
- [x] Wire peer worker supervisor artifacts to render health, audit, and stale-threshold arguments.
- [x] Add parser, executable worker, supervisor, and acceptance coverage.

## Next Wave: Federation Daemon Service Hardening

- [x] Add `net serve-daemon` for authenticated ledger snapshot service runs.
- [x] Verify local ledger integrity before binding the listener.
- [x] Add finite `--max-requests` smoke mode and optional idle-timeout shutdown.
- [x] Add health JSON and JSONL audit output for daemon lifecycle and peer requests.
- [x] Add parser and executable tests for daemon serving, health output, audit output, and invalid config.
- [x] Extend acceptance coverage and docs for hardened federation serving.

## Next Wave: Federation Daemon Service Artifacts

- [x] Add typed supervisor specs for the federation daemon command contract.
- [x] Add systemd unit rendering with restart policy, working directory, health path, and audit path.
- [x] Add Windows Scheduled Task rendering for the same real daemon command.
- [x] Add install/uninstall kits for systemd and Windows federation daemon services.
- [x] Add renderer and CLI parser tests for the daemon service artifacts.
- [x] Extend acceptance coverage and docs for generated federation service kits.

## Next Wave: Peer Registry Authorization

- [x] Add signed peer challenge response on top of the shared-key peer protocol.
- [x] Add daemon `--peer-registry` enforcement for active enrolled operator identities.
- [x] Add signed client options to `net fetch`, `net plan-peers`, `peer-queue process`, and `peer-queue worker`.
- [x] Add supervisor rendering for peer worker identities and federation daemon registries.
- [x] Add protocol, parser, daemon, and acceptance coverage for registry-authorized peers.

## Next Wave: Operator Audit Timeline

- [x] Build dashboard timeline items from real mission events, approvals, peer jobs, and evidence bundles.
- [x] Render timeline severity, source, actor, subject, detail, and references in exported/served dashboard HTML.
- [x] Include timeline counts in dashboard export JSON output.
- [x] Add focused dashboard coverage for ordering, severity, and HTML escaping.

## Next Wave: Divergent Ledger Merge Proof

- [x] Add `sync merge` for verified output ledgers built from two local input ledgers.
- [x] Preserve identical and append-only events without rehashing.
- [x] Deterministically replay divergent branch suffixes into a new hash chain.
- [x] Emit merge proof mapping source hashes to merged hashes with preserved/replayed markers.
- [x] Add sync library, CLI parser, acceptance, and docs coverage.

## Next Wave: Evidence-Bound AI Runner

- [x] Add `astragrid-ai` crate for bounded local runner execution.
- [x] Add `recommend ai-run` with no-shell process launch, stdin evidence request, timeout, and output caps.
- [x] Reuse structured recommendation validation so unknown evidence citations fail closed.
- [x] Add runner unit tests for candidate output, envelope output, unknown citations, output caps, and timeout.
- [x] Extend acceptance coverage and docs for the local runner boundary.

## Next Wave: API-Backed Operator Console

- [x] Add `astragrid-ui` as a Rust route/render crate instead of a placeholder app shell.
- [x] Add `ui serve` for a loopback visual console that rebuilds verified mission data per request.
- [x] Expose read-only JSON endpoints for summary, events, approvals, audit, peer health, full dashboard data, and health.
- [x] Add token-gated access by default with explicit `--no-auth` for isolated smoke runs.
- [x] Add `ui serve --profile` so first-run workspaces can open the console without manually wiring ledger and store paths.
- [x] Make console refresh manual by default, with operator-controlled live polling instead of page reloads.
- [x] Replace raw event-code and hash-first tables with a mission brief, latest activity, attention rows, human-readable action labels, and short integrity proofs.
- [x] Add parser, route, token, escaping, refresh, and unknown-route tests.
- [x] Extend the acceptance pack to smoke token-authenticated `/api/summary` and `/console.html` against profile-backed and artifact-backed mission data.
