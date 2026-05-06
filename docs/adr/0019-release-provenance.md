# ADR 0019: Release Provenance

## Status

Accepted.

## Context

Release artifacts need machine-readable checksums and build context so operators can verify what
was packaged.

## Decision

Extend the local package script and release workflow to emit provenance JSON. Local Windows
packages record the zip hash, binary hash, included files, toolchain versions, and git state.
Tagged release builds upload a binary-level provenance document for every platform artifact.
The CLI verifies those documents by recomputing recorded SHA-256 hashes and returning a non-zero
exit code on missing or mismatched artifacts.
Operators can also create detached signature envelopes for provenance files with local Ed25519
operator identities. The signature signs the exact provenance file SHA-256 digest under the
`astragrid-release-provenance-v1` purpose.

## Consequences

- Operators can verify SHA-256 checksums without unpacking ad-hoc logs.
- Automation can gate package promotion on `astragrid provenance verify`.
- Release custody can be tied to the same local operator identity system used for mission command
  signatures.
- Dirty local package state is visible in local provenance.
- Future multi-party release approval can extend the signature envelope instead of inventing a new
  manifest format.
