# Security Policy

AstraGrid is mission-control software. Security bugs are treated as operational
safety bugs because they can affect ledger integrity, operator trust, evidence
binding, release custody, or local mission handoff.

## Current Trust Model

AstraGrid is local-first and offline-first. The trusted base is the operator's
machine, local files, local operator identities, and explicitly configured peer
connections.

Current implemented trust surfaces include:

- append-only mission ledgers with BLAKE3 hash-chain verification
- Ed25519 operator identities and signed command append
- Argon2id + XChaCha20-Poly1305 encrypted local key files
- OS-sealed passphrase envelope support where a provider is implemented
- trusted operator registries with enrollment, revocation, public bundle
  export/import, and quorum-governed changes
- signed local team sessions and signed device pairing grants
- signed mission policy rule packs
- SQLite indexes derived from verified ledgers
- evidence bundles with citation and confidence validation
- bounded local AI runner subprocess boundary with strict structured-output
  validation
- authenticated peer ledger snapshots and durable peer sync queues
- token-gated loopback operator console
- sealed backups, vault commands, release provenance, signatures, quorum checks,
  and release evidence packs

AstraGrid does not yet provide a hosted multi-tenant control plane, remote
certificate authority, hardware-backed key ceremony, signed MSI/winget channel,
mobile field app, or public remote update service.

## Reportable Issues

Please report issues that can:

- bypass admission policy, policy packs, registry checks, or team-session checks
- append a mission event without the required signature or approval path
- modify ledger history without detection
- make corrupt ledger data look verified
- corrupt state/store/dashboard/report output from a verified ledger
- cause commands to claim success without durable writes
- leak operator key material, passphrases, peer shared secrets, local console
  tokens, mission ledgers, sealed backups, or private operational data
- accept uncited or invalid AI/recommendation output as verified evidence
- bypass token gating on the loopback operator console
- accept invalid release provenance, signatures, quorum, custody policy, or
  checksum evidence

## Reporting

Email: `waseemjutt814@gmail.com`

Include:

- affected command, crate, or file
- reproduction steps
- expected and actual behavior
- whether local secrets or mission data are exposed
- whether the issue requires local filesystem access, loopback access, or peer
  network access

## Baseline Requirements

- Hash-chain verification must fail closed.
- Command admission must run before persistence.
- Signed command paths must bind identity, payload, and registry expectations.
- Ledger writes must be flushed to disk before success is reported.
- Token-gated console routes must reject missing or wrong tokens before
  returning mission data.
- Peer sync must verify ledger integrity before compare, apply, or merge.
- AI runner output must cite known evidence and pass bundle validation before it
  can influence recommendations.
- New integrations must define authentication, authorization, audit, and failure
  behavior before they are treated as production paths.

## Public Repository Hygiene

Do not commit:

- `.env` files
- generated `data/`, `ops/`, or `secrets/` workspaces
- operator passphrase files
- operator `.agkey` files
- local console tokens
- peer shared keys
- sealed backups containing private mission data
- real mission ledgers, incident data, phone numbers, or personal information

Use obviously fake sample values in docs and tests.
