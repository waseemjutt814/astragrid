# AstraGrid

AstraGrid is an offline-first mission control kernel for evidence-led crisis
operations. It is built as a local command center and black-box record: every
mission action is written to a verifiable ledger, every operator path is
auditable, and every automation layer must stay bound to evidence.

The project is not a live emergency service, weather service, government data
feed, or hosted SaaS. It is a local Rust workspace for building trustworthy
mission records, offline peer handoff, signed operator workflows, evidence
bundles, release provenance, and read-only operator consoles.

Start here if you want the plain-language explanation:

- `docs/what-is-astragrid.md`

Use these for operator and engineering workflows:

- `docs/operations/ready-to-use-runbook.md`
- `docs/devops-blackbox.md`
- `docs/architecture.md`
- `docs/security/threat-model.md`
- `docs/a-to-z-master-plan.md`

## Executive Summary

AstraGrid answers the questions that matter after a field operation, incident
response drill, inspection, or crisis workflow:

- What happened?
- Who recorded or approved it?
- Which evidence supported the decision?
- Did the ledger change later?
- Can another machine verify the same mission record?
- Can the workspace be backed up, restored, merged, and handed off?

It does this with an append-only JSON Lines mission ledger, BLAKE3 hash-chain
verification, Ed25519 operator signatures, encrypted local keys, trusted
operator registries, SQLite indexing, evidence bundles, approval queues,
offline sync planning, sealed backups, release provenance, and a local
token-gated operator console.

## Current Status

The foundation is executable. The repo contains a Rust workspace, CLI, tests,
docs, Windows packaging helpers, release evidence, and CI workflows.

Validated locally before public upload:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
cargo doc --workspace --no-deps --locked
```

The public repo also includes a Windows package evidence set under `dist/`.
Treat that as local release evidence for this repository, not as a general
auto-update channel.

## Core Capabilities

| Area | What AstraGrid provides |
| --- | --- |
| Mission ledger | JSON Lines event log with monotonic sequence, UUIDv7 ids, UTC timestamps, actor, role, action, subject, priority, payload, previous hash, and current BLAKE3 hash |
| Admission policy | Deterministic policy checks before persistence, including role and priority gates |
| Operator identity | Local Ed25519 identities, signed command append, encrypted key files, key audit, and rotation proof |
| Registry trust | Trusted operator registry, enrollment, revocation, public trust bundle export/import, and quorum-governed registry changes |
| Team sessions | Signed local sessions, registry fingerprint binding, expiry checks, and team-authenticated append |
| Device pairing | Signed pairing grants with expiry and registry binding |
| Policy packs | Signed mission-specific rule packs that can deny commands, raise role requirements, require payload fields, and enforce priority rules |
| Store and state | SQLite ingest from verified ledgers and materialized mission state summaries |
| Geo and map | GeoJSON feature ingestion, digesting, bounding boxes, offline HTML/SVG map export, and loopback map serving |
| Evidence | Hash-bound evidence bundles with citation validation and confidence checks |
| Recommendations | Deterministic rules and bounded local AI runner boundary that reject uncited or invalid recommendations |
| Offline sync | Append-only comparison, deterministic divergent-ledger merge, proof files, and authenticated one-shot peer snapshots |
| Peer queue | Durable SQLite peer sync queue with retries, worker mode, health snapshots, and audit output |
| Approvals | Hash-chained approval queue and approved workflow execution through signed ledger append |
| Scenarios | Executable mission acceptance scenarios with ledger, state, and store assertions |
| Dashboard and UI | Self-contained dashboard export plus token-gated loopback operator console with read-only API endpoints |
| Operations | Workspace doctor, release doctor, backup/restore, vault commands, sealed artifacts, artifact retention, and handoff bundles |
| Release custody | SHA-256 provenance, optional operator signatures, quorum verification, custody policy, checksums, and release evidence packs |
| Supervision | Service-kit generation, peer worker artifacts, federation daemon artifacts, watchdog runner, and worker recovery audit |

## Design Standard

AstraGrid is built around four non-negotiables:

1. Every operational decision must be replayable.
2. Every AI or automation layer must cite evidence and uncertainty.
3. Every command path must have policy, audit, and failure behavior.
4. Offline mode is a first-class runtime mode, not a demo fallback.

## Quick Start From Source

Build and test:

```powershell
cargo build --workspace
cargo test --workspace
```

Create a first local workspace:

```powershell
cargo run -p astragrid -- setup first-run --root ops\field --mission flood-watch --operator-name lead --role incident_commander
cargo run -p astragrid -- doctor profile --profile ops\field\astragrid.profile.json
```

Open the read-only operator console:

```powershell
cargo run -p astragrid -- ui serve --profile ops\field\astragrid.profile.json --auth-token-file ops\field\data\operator-console.token --bind 127.0.0.1:17882
```

Run a minimal signed workflow manually:

```powershell
cargo run -p astragrid -- verify --ledger ops\field\data\mission.agl
cargo run -p astragrid -- store ingest --ledger ops\field\data\mission.agl --db ops\field\data\mission.db
cargo run -p astragrid -- state summary --ledger ops\field\data\mission.agl
```

For the full operator path, use:

- `docs/operations/ready-to-use-runbook.md`

## Windows Package Smoke

From source:

```powershell
cargo build --workspace --release
.\tools\local\package-release.ps1
.\tools\local\package-smoke.ps1 -Artifact dist\astragrid-windows-x64-0.1.0.zip
```

From an extracted package:

```powershell
.\VERIFY-ASTRAGRID.ps1
.\INSTALL-ASTRAGRID.ps1 -InstallDir "$env:LOCALAPPDATA\AstraGrid\bin" -SkipStartMenuShortcut
```

## CLI Surface

The main binary is `astragrid`. Current command families include:

```text
setup, init, append, append-signed, verify, tail, policy-check,
policy-pack, identity, team, store, state, geo, evidence, sync, seal,
vault, net, peer-queue, harvest, recommend, report, dashboard, ui, ops,
doctor, provenance, approval, scenario, workflow, supervisor, dev
```

The CLI keeps mutation paths explicit. The browser console is read-only by
design; operational changes go through signed CLI commands, approvals, policy
packs, registries, and verified ledgers.

## Workspace Layout

```text
astragrid/
|- crates/                    Rust workspace crates
|- docs/                      architecture, operations, security, ADRs, roadmap
|- tools/local/               local development and packaging helpers
|- tools/package/             Windows package helper scripts
|- dist/                      current local release evidence and package archive
|- Cargo.toml                 workspace manifest
|- Cargo.lock                 locked dependency graph
`- README.md                  public landing page
```

## Crate Map

| Crate | Responsibility |
| --- | --- |
| `astragrid-core` | mission events, identity primitives, admission policy, and ledger implementation |
| `astragrid-cli` | operator-facing command line |
| `astragrid-ai` | bounded local evidence-bound runner for model-like tools |
| `astragrid-approvals` | hash-chained workflow approval queue |
| `astragrid-crypto` | sealing helpers and cryptographic utilities |
| `astragrid-dashboard` | self-contained operator dashboard export |
| `astragrid-doctor` | workspace and release health checks |
| `astragrid-evidence` | evidence bundle validation and hashing |
| `astragrid-geo` | GeoJSON feature parsing and digesting |
| `astragrid-harvest` | remote GeoJSON/OGC feature harvesting with cache/retry metadata |
| `astragrid-map` | offline HTML/SVG map export |
| `astragrid-net` | authenticated peer ledger snapshots and federation daemon boundary |
| `astragrid-oskey` | OS-sealed local secret envelopes |
| `astragrid-policy-pack` | signed mission policy rule packs |
| `astragrid-provenance` | release provenance verification |
| `astragrid-recommend` | deterministic evidence-bound recommendation rules |
| `astragrid-report` | Markdown and JSON incident report bundle export |
| `astragrid-scenario` | executable mission acceptance scenarios |
| `astragrid-state` | current mission state projection from ledger events |
| `astragrid-store` | SQLite mission index for verified ledgers |
| `astragrid-supervisor` | service manager artifacts and watchdog helpers |
| `astragrid-sync` | ledger comparison, append-only apply, and divergent merge proof |
| `astragrid-sync-queue` | durable peer sync queue and retry worker |
| `astragrid-ui` | token-gated loopback operator console renderer and route layer |
| `astragrid-workflow` | evidence-to-command workflow drafting |

## Security Boundaries

AstraGrid is local-first operational software. It is designed to fail closed
when ledger verification, signatures, policy packs, registry checks, or
provenance checks fail.

Important boundaries:

- Do not use sample missions as real emergency data.
- Do not expose the loopback operator console to an untrusted network.
- Keep generated operator passphrase files, key files, registry files, local
  tokens, peer secrets, backups, and mission ledgers private.
- Treat local AI runners as untrusted subprocesses. AstraGrid validates their
  structured output, but it is not an OS sandbox.
- Treat release provenance as integrity evidence, not as third-party audit or
  notarization.

See `SECURITY.md` and `docs/security/threat-model.md`.

## What AstraGrid Is Not Yet

AstraGrid does not yet include:

- hosted multi-tenant SaaS
- remote certificate authority
- signed MSI or winget distribution
- hardware-backed operator custody with TPM/YubiKey flows
- mobile field app
- remote update channel
- real multi-site field deployment drill evidence

The local kernel, CLI, ledger, evidence, approval, backup, restore, sync queue,
release evidence, and read-only browser console exist and are tested.

## Verification Commands

Run these before release or public handoff:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
cargo doc --workspace --no-deps --locked
```

Windows package verification:

```powershell
.\tools\local\package-release.ps1
.\tools\local\package-smoke.ps1 -Artifact dist\astragrid-windows-x64-0.1.0.zip
cargo run -q -p astragrid -- doctor release --provenance dist\astragrid-windows-x64-0.1.0.provenance.json --signature dist\astragrid-windows-x64-0.1.0.provenance.sig.json --quorum dist\astragrid-windows-x64-0.1.0.provenance.quorum.json --policy dist\astragrid-windows-x64-0.1.0.provenance.release-policy.json
```

## License

Apache-2.0. See `LICENSE`.
