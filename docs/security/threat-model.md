# Threat Model

## Assets

- Mission ledger integrity.
- Operator attribution.
- Policy decision correctness.
- Operational payload confidentiality.
- Build and release provenance.

## In Scope Now

- Local ledger tampering detection.
- Policy enforcement before append.
- Payload size limits to prevent accidental large writes.
- CI checks for formatting, linting, tests, build, and docs.
- Ed25519 signed command append.
- Argon2id + XChaCha20-Poly1305 encrypted key files.
- OS-sealed passphrase envelopes on supported local platforms.
- Operator key-file audit for encryption and file-permission signals.
- Trusted local operator enrollment and revocation.
- SQLite ingest that refuses corrupt ledgers.
- Evidence bundle hash verification.
- Deterministic recommendation rules that emit evidence bundles.
- Structured model recommendation candidates constrained to known evidence ids.
- Bounded local AI runner with stdin evidence input, timeout, output caps, and citation validation.
- HTML map export from verified feature records.
- Browser map console export with mission state overlays.
- Offline sync divergence detection.
- Append-only sync apply that refuses divergent histories.
- Authenticated one-shot peer ledger snapshots.
- Peer manifest sync planning.
- Durable peer sync queue with bounded retry attempts.
- Peer queue worker using the same bounded retry and append-only apply path.
- Generated service manager artifacts for peer queue worker supervision.
- Encrypted sealed artifact envelopes.
- Cached source profile harvests.
- Workflow command drafts from verified evidence bundles.
- Hash-chained approval records for workflow draft review and execution.
- Scenario runner assertions over local ledger, state, and store behavior.
- Self-contained dashboard export from verified local artifacts.
- Workspace doctor checks for local artifact health.
- Release provenance JSON with artifact and binary SHA-256 hashes.
- Optional operator-signed release provenance envelopes.
- Multi-signature release provenance quorum verification.
- Peer queue health telemetry derived from durable queue state.

## Out of Scope Until Implemented

- Remote service multi-user authentication.
- OS-level AI runner sandbox profiles.
- Hardware-backed keys.
- Remote update channels.
- Remote certificate authority.
- Signed release notarization.

## Design Commitments

- A corrupt ledger must not accept new events.
- Verification must report concrete failure line and code.
- Write success means the event was serialized and flushed to disk.
- Signed operator commands must verify before policy admission and append.
- Registry-checked signed commands must reject missing, mismatched, or revoked identities.
- Encrypted key files must fail closed when no passphrase or the wrong passphrase is supplied.
- OS-sealed passphrase envelopes must use local OS protection and must fail closed on unsupported
  platforms or tampered envelopes.
- Operator key audit must report plaintext key material and must not claim Windows ACL privacy
  checks that it does not perform.
- Map export must escape feature text before writing HTML.
- Peer snapshots must authenticate before sending mission events.
- Peer manifests must reference shared-key files instead of embedding raw secrets.
- Peer queue jobs must persist attempts, last error, and terminal failure state.
- Peer queue worker must use the same authenticated snapshot and append-only apply logic as
  one-shot queue processing.
- Supervisor artifact generation must validate command inputs and must not embed raw peer secrets.
- Sealed artifacts must fail closed on wrong passphrase or tampered ciphertext.
- Workflow drafts must not mutate the ledger automatically.
- Ready workflow drafts must pass through the approval log before automated signed append.
- Approval execution must sign the exact approved draft request and record the ledger event hash.
- Sync apply must append only verified suffix events and must not rewrite existing ledger history.
- Scenario runs must fail on assertion mismatch and must keep their writes inside the selected
  work directory unless an absolute path is explicitly provided.
- Dashboard export must escape operator-provided text before writing HTML.
- Doctor checks must be read-only.
- Release provenance must include toolchain and checksum data for packaged artifacts.
- Provenance verification must fail closed when any recorded artifact hash is missing or
  mismatched.
- Signed provenance verification must fail closed when the provenance file hash or Ed25519
  signature does not match.
- SQLite indexes must be derived from a verified ledger, never treated as the source of truth.
- Local registry enrollment and trust-bundle import prove role trust only for participating local
  authorities; remote certificate authorities and hardware-backed trust are separate trust roots.
- AI outputs must attach evidence and confidence through evidence bundles; free-text
  recommendations are not enough.
- Recommendation rule outputs must verify as evidence bundles before downstream workflow drafting.
- Model recommendation adapters must reject unknown evidence references before bundle creation.
- AI runner execution must avoid shell interpolation, enforce timeout/output limits, and reject
  unknown evidence citations before bundle creation.
