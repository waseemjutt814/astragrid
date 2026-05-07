# AstraGrid A-to-Z Master Implementation Plan

This plan is intentionally no-fake: an item is marked complete only when the repository contains
working code, tests or smoke automation, and operator documentation. Items that require external
trust roots, hardware, notarization accounts, hosted infrastructure, or multiple real machines stay
gated until those inputs exist.

## Execution Policy

- No placeholder services, demo-only integrations, or simulated security claims.
- Every destructive workflow starts as a dry run and requires an explicit delete/install/publish flag.
- Every release artifact must be reproducible from source and backed by checksums, doctor output, and
  package smoke evidence.
- Hardware, certificate authority, signing, and remote update claims require real keys or real
  infrastructure before completion.

## Current Completed Wave

- **Installer smoke automation:** `tools/local/package-release.ps1` now includes installer assets in
  the zip and runs `tools/local/package-smoke.ps1` unless explicitly skipped.
- **Package installer:** `tools/package/INSTALL-ASTRAGRID.ps1` installs an extracted package, runs a
  version smoke, can add the install directory to the user PATH, can create a Start Menu shortcut,
  and writes `astragrid-install.json`.
- **Local source installer:** `tools/local/install.ps1` builds the release binary, installs the same
  runtime helper set, runs a version smoke, and writes an install manifest.
- **Artifact retention gate:** `astragrid ops artifact-retention` reports safe cleanup candidates
  under one workspace root, keeps recent dist releases by policy, and deletes only when `--delete`
  is supplied.
- **Ready-to-use operator core:** `setup first-run`, `doctor profile`, sealed workspace
  backup/restore, operator key rotation proof, and encrypted ledger vault commands now have parser
  and executable tests.
- **Local team security core:** `team session-issue`, `team session-verify`, `team authorize`,
  `team append`, `team pair-create`, and `team pair-verify` add signed local sessions,
  registry-bound permission checks, and signed device pairing grants with executable tests.
- **Signed policy rule packs:** `policy-pack template`, `policy-pack sign`, `policy-pack verify`,
  and `policy-pack evaluate` add compatibility-checked rule bundles, detached signatures,
  registry-verified signers, and enforcement hooks on signed append paths.
- **Quorum registry changes:** `identity quorum-propose`, `identity quorum-sign`, `identity
  quorum-verify`, and `identity quorum-apply` bind operator enroll/revoke changes to the current
  registry digest and require distinct active incident-commander approvals before mutation.
- **Worker watchdog recovery:** `supervisor watchdog-run` starts a real child process, writes JSONL
  audit records, restarts failed workers within a capped budget, reports recovery, and fails closed
  when the worker never reaches the expected exit code.

## A-to-Z Delivery Gates

| ID | Capability | Honest completion gate |
| --- | --- | --- |
| A | Multi-user authentication | Complete for local CLI operation: signed sessions bind an enrolled active operator to a registry digest, expiry, and detached signature; remote service sessions remain gated on the service boundary. |
| B | Encrypted backups and restore | Complete for local workspaces: `ops backup` seals profile, ledger, store, registry, key/passphrase files, approvals when present, peer queue when present, and reports; `ops restore` validates hashes and refuses overwrite unless requested. |
| C | Remote certificate authority | Not started until a real CA root, enrollment policy, and rotation procedure exist. |
| D | Encrypted ledgers at rest | Complete for the vault runtime path: `vault init`, `vault append`, `vault verify`, and `vault tail` operate on a sealed ledger file as the primary at-rest artifact. Signed vault append remains a future hardening item. |
| E | Automatic conflict merge for divergent ledgers | Divergence is detected; automatic merge needs deterministic conflict policy and replay proofs. |
| F | Long-running secure network service | One-shot authenticated networking and supervised workers exist; daemon service needs hardened listener lifecycle and service tests. |
| G | `astragrid-ui` operator console | HTML exports and loopback serving exist; full app waits for a real UI runtime without heavy placeholder dependencies. |
| H | Hardware-backed keys | OS key sealing exists; TPM/YubiKey completion needs real hardware provider implementations and operator tests. |
| I | Windows installer and package smoke | Current wave adds script installer, packaged installer, manifest, and smoke automation; MSI/winget/Scoop require release-channel decisions. |
| J | Signed release notarization | Release custody signatures exist; notarization needs real code-signing/notary credentials. |
| K | Key rotation and recovery workflows | Complete for local registry authority: `identity rotate` revokes the old operator id, creates a new encrypted key, enrolls it, saves the registry, and writes rotation proof. Quorum recovery remains gated. |
| L | Remote update channel | Not started until signed update metadata and hosting are available. |
| M | Multi-host federation beyond bundle import | Trust bundles and peer sync exist; federation daemon needs multi-node integration tests. |
| N | Offline map tile packs | Map export exists; tile packs need a licensed tile source and pack manifest validation. |
| O | Operator audit timeline UI | Dashboard has recent events; timeline UI needs grouped audit interactions and export tests. |
| P | Policy rule pack system | Complete for local operation: policy packs validate schema/compatibility/rules, detached signatures bind the pack digest, registry checks verify active signer authority, and append paths can enforce a verified pack. |
| Q | Quorum enrollment for operators | Complete for local registry changes: proposals bind authority, current registry digest, nonce, change body, and required approval count; verification requires distinct active commander signatures, rejects duplicates/revoked signers/stale registries, and apply mutates only after verification. Remote CA-backed enrollment remains gated. |
| R | Replication daemon with service hardening | Peer queue worker and supervisor kits exist; replication daemon needs lifecycle hardening. |
| S | Secure device pairing | Complete for local signed pairing grants: pairing bundles bind device id/name, operator identity, registry digest, expiry, and signature. Network UX and revocation distribution remain future service work. |
| T | Team roles and permissions | Complete for the team-authenticated signed append path: sessions verify registry status and policy before mutation. Broader service/API command enforcement remains gated on the long-running service boundary. |
| U | `astragrid-ai` evidence-bound runner crate | Deterministic and structured recommendation paths exist; runner crate needs sandboxed execution and citation enforcement. |
| V | Visual dashboard app | Dashboard HTML exists; native/web app waits for storage budget and real runtime choice. |
| W | Worker watchdog with live service recovery | Complete for local process recovery: `supervisor watchdog-run` spawns the configured worker without shell interpolation, audits each attempt, restarts within a capped budget, reports recovered/failed state, and has executable restart/failure tests. OS service manager health integration remains deployment work. |
| X | Cross-platform release matrix | CI covers Windows/Linux/macOS; release packages need platform-specific artifact creation. |
| Y | Field deployment runbooks | Local ready-to-use runbook exists for install, first-run setup, backup, restore, rotation, vault use, update checks, and failure handling. Real site-specific drills remain gated. |
| Z | Disk cleanup and artifact retention | Current wave adds CLI retention reporting/deletion and package smoke cleanup behavior. |

## Next No-Fake Order

1. Add federation daemon service hardening.
2. Add service-bound team sessions once the long-running API boundary exists.
3. Add platform package expansion only when signing/notary/release-channel credentials exist.
4. Add hardware keys, remote CA, notarization, and update channels only when real credentials or real
   hardware are available.
