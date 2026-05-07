# Operator Key Providers

AstraGrid operator keys have two layers:

- The key file format, which supports plain or Argon2id plus XChaCha20-Poly1305 encrypted private
  key material.
- The passphrase source, which can be a local passphrase file or an OS-sealed passphrase envelope.

## Current Provider

Windows supports `identity os-seal-passphrase` through the current-user DPAPI provider. The sealed
envelope stores provider metadata and ciphertext only; signing commands open it with
`--passphrase-os-key` and never require the raw passphrase file at runtime.

Unsupported platforms fail closed for OS-sealed passphrase operations. They can still use encrypted
key files with `--passphrase-file`.

## Provider Contract

Every new provider must satisfy the same behavior:

- Seal bytes for the current operator account or an explicitly named local protection scope.
- Store provider name, purpose, creation time, and ciphertext in a JSON envelope.
- Open only on the intended local account or hardware context.
- Return a clear error when the provider is unavailable.
- Never fall back to plaintext storage, environment variables, or silent re-encryption.
- Keep signing command behavior identical: `--passphrase-file` and `--passphrase-os-key` remain
  mutually exclusive.

## Target Providers

- macOS Keychain: seal passphrases as application-password items scoped to the current login
  keychain.
- Linux Secret Service: seal passphrases through the user session collection when a desktop secret
  service is available.
- Hardware-backed keys: add a provider only when signing or secret unseal can be verified by a real
  hardware interface in tests or operator validation.

## Operator Guidance

Use encrypted key files for all operator-facing workflows. On Windows workstations, seal the
passphrase once:

```powershell
cargo run -q -p astragrid -- identity os-seal-passphrase --input data\operators\lead.pass --output data\operators\lead.pass.oskey
```

Then sign without passing the raw passphrase file:

```powershell
cargo run -q -p astragrid -- append-signed --ledger data\mission.agl --identity data\operators\lead.agkey --passphrase-os-key data\operators\lead.pass.oskey --action annotate_situation --subject sector-7 --payload "{}"
```

Keep raw passphrase files outside shared folders and remove them after the sealed envelope has been
validated for the workstation.
