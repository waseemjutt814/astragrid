# Architecture

AstraGrid starts with a mission kernel, not a user interface. The kernel records what happened,
who requested it, what policy allowed it, and how the next state can be verified.

## Phase 1 Runtime

```text
operator CLI -> encrypted identity key -> signature -> trusted registry -> admission policy -> mission ledger -> SQLite index
mission ledger -> state projection
GeoJSON -> feature digest records
feature digest records -> HTML/SVG map artifact
evidence files -> evidence bundle hash
rules + sensor readings -> verified evidence bundle
peer ledger -> authenticated snapshot -> sync comparison plan
peer manifest -> durable sync queue -> authenticated snapshot -> append-only apply
mission artifacts -> sealed encrypted envelope
state + evidence bundle -> workflow command draft
workflow command draft -> approval log -> signed ledger append
scenario file -> ledger/state/store assertions
mission artifacts -> dashboard export
workspace artifacts -> doctor report
verified artifacts -> ops handoff bundle
```

## Mission Ledger

The ledger is JSON Lines on disk. Each event contains:

- A monotonic sequence number.
- A UUIDv7 event identifier.
- A UTC timestamp.
- Actor name and role.
- Action, subject, priority, and JSON payload.
- Previous event hash.
- Current event BLAKE3 hash.
- Optional signed command attestation.

The hash is computed over canonical event content, excluding the stored hash field. Object keys
inside JSON payloads are sorted before hashing so equivalent payloads hash consistently.

## Admission Policy

The policy layer currently enforces:

- Required actor name and subject.
- Role requirements per action.
- Incident commander or system authority for critical priority commands.
- Elevated or critical priority for field dispatch.

This is intentionally simple and testable. Unsigned commands trust CLI role flags and are meant
for bootstrap or migration flows. Registry-checked signed workflows bind the command request to a
local Ed25519 key and require that the operator is enrolled and active.

## Operator Identity

Operator identities use Ed25519. A local key file contains:

- Public identity metadata: operator id, name, role, public key.
- Plain or encrypted private signing key material.

Encrypted key files use Argon2id for key derivation and XChaCha20-Poly1305 for authenticated
encryption. `append-signed` loads the key file, signs the command request, verifies that signature
locally, then writes the attestation into the ledger event. Tampering with a signed request breaks
signature verification before append. Tampering with a written event breaks ledger hash-chain
verification.

For local operator workstations, passphrase files can be sealed into an OS-backed envelope and
opened by signing commands with `--passphrase-os-key`. The current Windows provider uses DPAPI for
the current user and fails closed on unsupported platforms instead of silently downgrading to a
portable secret. Provider behavior and expansion requirements are documented in
`docs/security/operator-key-providers.md`.

`identity audit` reports whether a key file is encrypted, whether plaintext private key material
is present, and whether local file permissions can be verified as private. Unix key files are
created with owner-only mode. Windows ACL privacy is reported as not inspected rather than guessed.

Unsigned `append` still exists for bootstrap, import, and system migration work. Operator-facing
workflows should prefer `append-signed`.

## Trusted Operator Registry

The operator registry is a local JSON trust document. It records:

- Authority name.
- Operator identity id, name, role, and public key.
- Active or revoked status.
- Issuer and revocation metadata.

When `append-signed --registry` is used, AstraGrid verifies the command signature and rejects the
append if the operator is not enrolled, has been revoked, or the signed identity no longer matches
the registry entry. The registry is still local trust; remote certificate authorities and hardware
keys are future work.

## Mission Store

`astragrid-store` indexes verified ledgers into SQLite. Ingest is idempotent and refuses corrupt
ledgers. The store keeps query-friendly columns for actor, action, subject, priority, hashes, and
attestation presence, while preserving the full event JSON for exact replay.

The store can export indexed events as a JSON array and import that array back into a new index,
but import still verifies event sequence, previous hashes, and event hashes first. The ledger is
the source of truth; SQLite is a query accelerator.

## Mission State

`astragrid-state` materializes current mission state from verified ledger events. It tracks
mission name, open and closed incidents, observations, dispatches, annotations, and the last
ledger hash. Invalid transitions, such as closing an incident that was never declared, fail
instead of producing a misleading state view.

## GeoJSON Features

`astragrid-geo` parses GeoJSON `Feature`, `FeatureCollection`, and raw `Geometry` documents. Each
feature record includes a geometry type, computed bounding box, properties, and a BLAKE3 digest
over id, geometry, and properties. Invalid or geometry-less features fail ingestion.

## Feature Maps

`astragrid-map` renders feature JSON Lines into a self-contained HTML/SVG map artifact. The map
uses verified feature bounding boxes, preserves feature ids and digests in the table, and escapes
operator-provided text before writing HTML. It is an offline report artifact, not a live tracking
surface.

## Evidence Bundles

`astragrid-evidence` creates a hash-bound recommendation object. A bundle must include at least
one evidence item, each recommendation must cite known evidence ids, and confidence values must be
finite values from `0.0` through `1.0`. Tampering with the recommendation or evidence breaks
bundle verification.

## Recommendation Rules

`astragrid-recommend` evaluates deterministic threshold rules over sensor readings and emits only
verified evidence bundles. It is intentionally not branded as model reasoning: every emitted
recommendation has cited evidence ids, reading digests, confidence, and a bundle hash. Future model
adapters must satisfy the same evidence-bundle output contract.

The structured model adapter accepts candidate recommendations only as JSON objects that cite
existing evidence ids. Unknown citations, invalid confidence values, or empty rationales are
rejected before an `EvidenceBundle` is written.

## Offline Sync

`astragrid-sync` compares two verified ledgers. It reports whether ledgers are identical,
append-only ahead on either side, or diverged at the first conflicting sequence. `sync apply`
imports only the missing suffix when the source ledger is an append-only extension of the target.
Diverged ledgers fail closed and require operator resolution.

## Peer Transport

`astragrid-net` provides an authenticated one-shot TCP snapshot protocol. A client and server
share a local secret, exchange challenge MACs, and then transfer a verified ledger snapshot as
JSON. This gives sync a real transport without pretending to solve full multi-peer replication.
The CLI can also read a peer manifest and produce one sync plan per peer.

## Durable Peer Queue

`astragrid-sync-queue` stores peer sync work in SQLite. Each job records peer identity, address,
status, attempts, retry timing, last error, and the last sync/apply result. `peer-queue process`
fetches due peer snapshots, compares them against the local ledger, applies only append-only
suffixes, and records success or retry/failure state. This keeps network sync recoverable without
requiring a separate scheduler. `peer-queue worker` runs the same processor for finite cycles or
as a long-lived daemon loop. `peer-queue health` returns a snapshot of due jobs, stale retrying
jobs, failed counts, and recent errors for dashboards and supervisor probes.

## Harvesting

`astragrid-harvest` fetches remote GeoJSON or OGC API Features URLs, applies optional `limit` and
`bbox` query parameters, and then passes the response through the same GeoJSON feature validator.
Source profiles add cache paths, retry counts, and retry delay metadata without hardcoding vendor
URLs. Operators can create NASA, Copernicus, or local OGC profiles with their real service URLs.

## Sealed Artifacts And Reports

`astragrid-crypto` seals arbitrary mission artifacts using Argon2id and XChaCha20-Poly1305.
`astragrid-report` renders Markdown reports and JSON report bundles from the SQLite mission index
and verified evidence bundles.

## Workflow Drafts

`astragrid-workflow` turns verified evidence bundles into command drafts. It checks the current
materialized state, confidence threshold, action parser, and admission policy. It does not append
commands; operators can inspect a draft before deciding whether to sign and append.

## Approval Queue

`astragrid-approvals` records workflow draft submit, approve, reject, and execution events in a
separate hash-chained JSON Lines log. Only ready drafts with command requests can be submitted.
Approved drafts can be appended through `approval append-approved`, which signs the exact drafted
request with a local operator identity, optionally checks the trusted registry, writes the mission
ledger event, and marks the approval item executed with the resulting ledger event hash.

## Scenario Runner

`astragrid-scenario` executes JSON acceptance scenarios against a local work directory. Scenarios
can initialize a ledger, append mission events, verify the ledger, ingest SQLite state, and assert
materialized state or store counts. It is meant for repeatable operator workflows and CI smoke
checks, not for replacing unit tests.

## Operator Dashboard

`astragrid-dashboard` renders a self-contained HTML mission dashboard from verified local
artifacts. The CLI assembles ledger state, recent events, optional store summary, approvals, peer
queue state, peer health telemetry, evidence bundles, and a map link. The renderer escapes text,
surfaces queue health as a status banner, and does not require a web server.

## Operator Handoff Bundle

`ops bundle` creates a handoff directory from verified local artifacts. It writes the dashboard,
state summary, workspace doctor report, manifest, and optional map console or release doctor
report. The manifest records only generated bundle-relative files so it can be copied to another
operator without embedding local workstation paths.

## Workspace Doctor

`astragrid-doctor` checks local artifact health without mutating them. It verifies the ledger,
materializes state, checks optional store, key, approval, and peer queue inputs, and returns an
overall healthy/warning/failed report. `doctor release` verifies package provenance and optional
signature, quorum, or release custody policy before an artifact is shared. Custody policies bind a
package to required signer ids, allowed signer ids, signer thresholds, target metadata, and clean
Git provenance.

## Future System Shape

Future crates should be added only when they have executable behavior:

- `astragrid-ui`: mission map and operator console.
- `astragrid-ai`: evidence-bound recommendation runner.
