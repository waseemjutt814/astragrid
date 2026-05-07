# AstraGrid

AstraGrid is an offline-first mission control kernel for evidence-led crisis operations.

The current foundation is executable: an append-only mission ledger, hash-chain verification,
encrypted local signing identities, trusted operator registry, SQLite indexing, GeoJSON feature
ingestion, evidence bundles, authenticated peer snapshots, offline sync planning and deterministic
divergent-ledger merge proofing, encrypted
artifact sealing, materialized mission state, report export, packaging scripts, approval-gated
workflow execution, executable acceptance scenarios, operator dashboard export, API-backed
loopback operator console, workspace doctor, admission policy checks, signed local team sessions,
secure device pairing grants,
quorum-governed registry changes, signed policy rule packs, evidence-to-command workflow drafting,
and a CLI.

## What Exists Now

- Rust workspace with `astragrid-core` and `astragrid` CLI.
- JSON Lines mission ledger with BLAKE3 hash chaining.
- Policy gate for mission actions and roles.
- Local Ed25519 operator identities and signed command append.
- Argon2id + XChaCha20-Poly1305 encrypted operator key files.
- OS-sealed passphrase envelopes for supported local providers.
- Operator key audit for encryption state and local permission signals.
- Trusted operator registry with enrollment and revocation checks.
- Public registry trust bundle export and verification for multi-host handoff.
- Verified registry trust bundle import with conflict checks and revocation-dominant merge behavior.
- Quorum-governed registry proposals with registry fingerprint binding, distinct commander approvals, and fail-closed apply.
- Signed local team sessions that verify registry fingerprint, active identity, signature, and expiry.
- Team-authorized signed append path that requires both a valid session and the matching operator key.
- Signed device pairing grants with expiry, registry binding, and fail-closed verification.
- Signed policy rule packs with compatibility checks, registry-verified signers, and command evaluation.
- Team and signed append paths can enforce a verified policy rule pack before mutating the ledger.
- First-run setup that creates a local workspace profile, encrypted operator key, registry, genesis ledger, store DB, and required folders.
- Workspace profile doctor validation for configured local paths and artifacts.
- Operator key rotation that revokes the old id, enrolls the new encrypted key, and writes rotation proof.
- SQLite mission index with idempotent verified-ledger ingest, query, import, and export.
- Materialized mission state summaries derived from verified ledger events.
- GeoJSON feature ingestion with bounding boxes and content digests.
- Self-contained HTML/SVG map export from feature records.
- Self-contained browser map console with mission state overlays.
- Loopback map console serving that regenerates verified overlays for each request.
- Evidence bundles with cited evidence ids, confidence checks, and bundle hashes.
- Deterministic recommendation rules that emit verified evidence bundles.
- Structured model recommendation adapter that only emits verified evidence bundles.
- Bounded local AI runner that sends evidence JSON over stdin and accepts only citation-valid recommendation bundles.
- Authenticated one-shot TCP peer ledger snapshots.
- Hardened authenticated federation daemon with optional signed peer registry authorization, health JSON, and JSONL audit.
- Multi-peer sync planning from a peer manifest.
- Durable SQLite peer sync queue with retries and append-only apply.
- Finite-cycle or daemon-mode peer queue worker with optional health JSON and JSONL audit output.
- Offline ledger comparison, append-only delta apply, and divergent-ledger merge into a new verified ledger with replay proof.
- Encrypted artifact sealing for ledgers, exports, and reports.
- Sealed workspace backup and restore with per-file SHA-256 validation.
- Encrypted-at-rest ledger vault commands for init, append, verify, and tail.
- Source profiles with cache and retry metadata for remote harvesting.
- Markdown and JSON incident report bundle export.
- Evidence-to-command workflow drafts gated by state and policy.
- Hash-chained approval queue for ready workflow drafts.
- Approved draft execution through signed, registry-checked ledger append.
- JSON scenario runner for mission acceptance tests with ledger, state, and store assertions.
- Self-contained operator dashboard export with peer health status, recent errors, and map links.
- Operator audit timeline in dashboard exports, grouped from mission events, approvals, peer sync jobs, and evidence bundles.
- Loopback dashboard serving that regenerates verified dashboard HTML for each request.
- Token-gated API-backed loopback operator console with summary, events, approvals, audit, peer-health, and full dashboard JSON endpoints.
- Profile-aware operator console startup from first-run workspace profiles, with explicit CLI overrides for custom artifacts.
- Workspace doctor for ledger, state, store, key, approval, and peer queue checks.
- Release doctor for package provenance, detached signature, and quorum readiness checks.
- Release custody policy verification for required signer ids, allowed signer sets, clean Git state, and promotion thresholds.
- Operator handoff bundle export with dashboard, state, doctor reports, optional map console, and manifest.
- Release evidence pack export with checksums, healthy doctor output, and handoff manifest.
- Finite readiness gate for repeated workspace and release doctor cycles.
- Double-click friendly Windows launcher guidance and packaged executable smoke helper.
- Packaged Windows installer script with version smoke and install manifest output.
- Package smoke automation that extracts, verifies, launches, and installer-checks the release zip.
- Live worker watchdog that restarts failed local workers within a capped budget and writes JSONL recovery audit.
- Dry-run-first artifact retention command for cache, old dist releases, and optional target build cache cleanup.
- No-fake A-to-Z master implementation plan with external trust and hardware gates called out.
- Payload size limit and deterministic payload hashing.
- Release provenance verification with fail-closed SHA-256 checks for packaged artifacts.
- Optional operator-signed provenance envelopes for release custody.
- Multi-signature provenance quorum verification with distinct signer thresholds.
- One-shot release custody pack generation for signatures, quorum, policy, manifest, and healthy doctor gate.
- Deterministic supervisor artifact generation for peer queue workers.
- Watchdog recovery runner for local long-running workers.
- Peer worker service kits with generated install and uninstall wrappers plus health/audit paths.
- Federation daemon service kits with generated install and uninstall wrappers.
- Runnable mission acceptance pack generation.
- Peer queue health telemetry snapshots.
- `setup`, `init`, `append`, `append-signed`, `verify`, `tail`, `policy-check`, `policy-pack`, `identity`, `team`, `store`, `state`, `geo`, `evidence`, `sync`, `seal`, `vault`, `net`, `peer-queue`, `harvest`, `recommend`, `report`, `dashboard`, `ui`, `ops`, `doctor`, `provenance`, `approval`, `scenario`, `workflow`, and `supervisor` CLI commands.
- GitHub Actions CI for formatting, linting, tests, build, and docs.
- Release packaging emits SHA-256 provenance JSON and includes Windows launch/smoke helpers.

## Quick Start

```powershell
cargo build
cargo test
cargo run -p astragrid -- init --mission flood-watch --ledger data/mission.agl
'strong local passphrase' | Set-Content -Encoding UTF8 data/operators/lead.pass
cargo run -p astragrid -- identity create --path data/operators/lead.agkey --name lead --role incident_commander --passphrase-file data/operators/lead.pass
cargo run -p astragrid -- identity registry-init --registry data/operators/operators.agregistry --authority local-command
cargo run -p astragrid -- identity enroll --registry data/operators/operators.agregistry --identity data/operators/lead.agkey --passphrase-file data/operators/lead.pass --issued-by local-command
New-Item -ItemType Directory -Force data/sessions | Out-Null
cargo run -p astragrid -- team session-issue --identity data/operators/lead.agkey --passphrase-file data/operators/lead.pass --registry data/operators/operators.agregistry --output data/sessions/lead.session.json --ttl-minutes 480
cargo run -p astragrid -- policy-pack template --output data/field-safety.policy.json
cargo run -p astragrid -- policy-pack sign --pack data/field-safety.policy.json --output data/field-safety.policy.sig.json --identity data/operators/lead.agkey --passphrase-file data/operators/lead.pass
cargo run -p astragrid -- policy-pack verify --pack data/field-safety.policy.json --signature data/field-safety.policy.sig.json --registry data/operators/operators.agregistry
'{ "water_level_m": 5.2 }' | Set-Content -Encoding UTF8 data/river-east.json
cargo run -p astragrid -- team append --ledger data/mission.agl --identity data/operators/lead.agkey --passphrase-file data/operators/lead.pass --registry data/operators/operators.agregistry --session data/sessions/lead.session.json --policy-pack data/field-safety.policy.json --policy-signature data/field-safety.policy.sig.json --action declare_incident --subject river-east --priority critical --payload '@data/river-east.json'
cargo run -p astragrid -- verify --ledger data/mission.agl
cargo run -p astragrid -- store ingest --ledger data/mission.agl --db data/mission.db
cargo run -p astragrid -- store summary --db data/mission.db
```

## Design Standard

AstraGrid is built around four non-negotiables:

1. Every operational decision must be replayable.
2. Every AI or automation layer must cite evidence and uncertainty.
3. Every command path must have policy, audit, and failure behavior.
4. Offline mode is a first-class runtime mode, not a demo fallback.

## Repository Map

- `crates/astragrid-core`: mission event types, policy, and ledger implementation.
- `crates/astragrid-ai`: bounded local evidence-bound runner for structured recommendations.
- `crates/astragrid-approvals`: hash-chained workflow approval queue.
- `crates/astragrid-cli`: operator-facing CLI for local mission ledgers.
- `crates/astragrid-dashboard`: self-contained operator dashboard export.
- `crates/astragrid-doctor`: local workspace health checks.
- `crates/astragrid-evidence`: evidence bundle validation and hashing.
- `crates/astragrid-geo`: GeoJSON feature parsing and digesting.
- `crates/astragrid-harvest`: remote GeoJSON/OGC feature harvesting.
- `crates/astragrid-map`: self-contained HTML/SVG feature map export.
- `crates/astragrid-net`: authenticated peer ledger snapshots.
- `crates/astragrid-oskey`: OS-sealed local secret envelopes.
- `crates/astragrid-policy-pack`: signed mission policy rule packs.
- `crates/astragrid-provenance`: release provenance verification.
- `crates/astragrid-recommend`: deterministic evidence-bound recommendation rules.
- `crates/astragrid-report`: Markdown incident reports.
- `crates/astragrid-scenario`: executable mission acceptance scenarios.
- `crates/astragrid-state`: current mission state projection from ledger events.
- `crates/astragrid-store`: SQLite mission index for verified ledgers.
- `crates/astragrid-supervisor`: service manager artifacts for peer workers and federation daemons.
- `crates/astragrid-sync`: offline ledger comparison, append-only apply, and divergent-ledger merge proofing.
- `crates/astragrid-sync-queue`: durable peer sync queue and retry worker.
- `crates/astragrid-ui`: API-backed loopback operator console renderer and route layer.
- `crates/astragrid-workflow`: evidence-to-command workflow drafting.
- `docs/`: architecture, operations, security, and ADRs.
- `tools/local/`: local workstation helper scripts.

## Roadmap

See `docs/roadmap.md` for the completed phase checklist and `docs/a-to-z-master-plan.md` for
the no-fake capability gates. See `docs/operations/ready-to-use-runbook.md` for the operator
first-run, backup, restore, rotation, vault, merge, operator console, AI runner, and failure workflows.
