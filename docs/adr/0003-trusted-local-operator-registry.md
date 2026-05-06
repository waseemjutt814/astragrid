# ADR 0003: Trusted Local Operator Registry

## Status

Accepted.

## Context

Signed commands prove that a request was made by a key, but a key can still self-claim a role.
Mission software needs an authority-controlled trust document that says which public keys are
allowed to operate and what role each key is allowed to use.

## Decision

Add a local operator registry. The registry records active and revoked operator identities and is
checked by `append-signed --registry` before policy admission and ledger append.

## Consequences

- Signed command workflows can reject unenrolled or revoked operators.
- Role trust is no longer taken only from the key file.
- The registry remains local trust. Remote certificate authorities, quorum enrollment, and
  hardware-backed identity are future work.
