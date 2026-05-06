# ADR 0013: Operator Key Audit

## Status

Accepted.

## Context

Operator signing keys are powerful. Encrypted key files already protect private key material, but
operators need a fast way to inspect whether a key file is encrypted and whether obvious local
permission risks are present.

## Decision

Add `identity audit`, backed by `OperatorKeypair::inspect_key_file`. The audit reports public
identity metadata, encrypted/plaintext key-material state, file size, warnings, and private
permission status when the operating system exposes a reliable mode check. Unix key files are
created with owner-only permissions. On Windows, ACL privacy is reported as not inspected rather
than inferred.

## Consequences

- Plaintext key files are visible in CLI audit output.
- Encrypted key files can be checked without decrypting the secret.
- The audit improves key custody without pretending to replace OS keychain or hardware-backed
  signing.
