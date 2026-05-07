# ADR 0004: Encrypted Operator Keys

## Status

Accepted.

## Context

Plain local key files are useful for early bootstrapping, but operator-facing workflows need a
file format that does not store the Ed25519 private key in clear text.

## Decision

Support encrypted operator key files using Argon2id for key derivation and XChaCha20-Poly1305 for
authenticated encryption. Public identity metadata stays visible so registries can enroll keys
without decrypting the private key. The private key can only be loaded with a passphrase file.

## Consequences

- Wrong or missing passphrases fail closed.
- CI and automation can use passphrase files without interactive prompts.
- Windows DPAPI passphrase envelopes are supported through the OS-key provider layer.
- macOS Keychain, Linux Secret Service, and hardware-backed providers must follow
  `docs/security/operator-key-providers.md` before being added.
