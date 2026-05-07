# Ready-To-Use Operator Runbook

This runbook covers the local, no-fake ready-to-use path. It uses only shipped AstraGrid commands
and local files.

## Install And Smoke

From an extracted Windows package:

```powershell
.\VERIFY-ASTRAGRID.ps1
.\INSTALL-ASTRAGRID.ps1 -InstallDir "$env:LOCALAPPDATA\AstraGrid\bin" -SkipStartMenuShortcut
```

From source:

```powershell
cargo build --workspace --release
.\tools\local\package-smoke.ps1 -Artifact dist\astragrid-windows-x64-0.1.0.zip
```

## First Workspace

```powershell
.\target\release\astragrid.exe setup first-run --root ops\field --mission flood-watch --operator-name lead --role incident_commander
.\target\release\astragrid.exe doctor profile --profile ops\field\astragrid.profile.json
```

The setup command creates:

- `astragrid.profile.json`
- `data\mission.agl`
- `data\mission.db`
- `data\operators\lead.agkey`
- `data\operators\lead.pass`
- `data\operators\operators.agregistry`
- `data\reports`
- `data\backups`

The generated operator key is encrypted with the passphrase file. Keep the passphrase file private
or seal it with `identity os-seal-passphrase` on supported local platforms.

## Team Session And Pairing

Issue a local signed session for the enrolled operator:

```powershell
.\target\release\astragrid.exe team session-issue --identity ops\field\data\operators\lead.agkey --passphrase-file ops\field\data\operators\lead.pass --registry ops\field\data\operators\operators.agregistry --output ops\field\data\operators\lead.session.json --ttl-minutes 480
.\target\release\astragrid.exe team session-verify --session ops\field\data\operators\lead.session.json --registry ops\field\data\operators\operators.agregistry
```

Use the session-gated append path when a local team login should be required in addition to the
operator signing key:

```powershell
.\target\release\astragrid.exe team authorize --session ops\field\data\operators\lead.session.json --registry ops\field\data\operators\operators.agregistry --action declare_incident --subject river-east --priority critical --payload '{"water_level_m":5.2}'
.\target\release\astragrid.exe team append --ledger ops\field\data\mission.agl --identity ops\field\data\operators\lead.agkey --passphrase-file ops\field\data\operators\lead.pass --registry ops\field\data\operators\operators.agregistry --session ops\field\data\operators\lead.session.json --action declare_incident --subject river-east --priority critical --payload '{"water_level_m":5.2}'
```

Create and verify a signed device pairing grant:

```powershell
.\target\release\astragrid.exe team pair-create --identity ops\field\data\operators\lead.agkey --passphrase-file ops\field\data\operators\lead.pass --registry ops\field\data\operators\operators.agregistry --device-id field-tablet-01 --device-name "Field Tablet 01" --output ops\field\data\operators\field-tablet-01.pairing.json --ttl-minutes 1440
.\target\release\astragrid.exe team pair-verify --input ops\field\data\operators\field-tablet-01.pairing.json --registry ops\field\data\operators\operators.agregistry
```

Sessions and pairing grants fail closed when the signature, registry fingerprint, active identity,
or expiry check fails.

## Backup

```powershell
.\target\release\astragrid.exe ops backup --profile ops\field\astragrid.profile.json --output ops\field\data\backups\workspace.sealed.json --passphrase-file ops\field\data\operators\lead.pass
```

The backup is a sealed artifact. It includes profile, ledger, store, registry, encrypted key,
passphrase file, approvals when present, peer queue when present, and reports.

## Restore

```powershell
.\target\release\astragrid.exe ops restore --input ops\field\data\backups\workspace.sealed.json --output-dir ops\restore --passphrase-file ops\field\data\operators\lead.pass
.\target\release\astragrid.exe doctor profile --profile ops\restore\astragrid.profile.json
```

Restore validates each file hash and refuses to overwrite existing files unless `--overwrite` is
supplied.

## Key Rotation

```powershell
$old = .\target\release\astragrid.exe identity inspect --path ops\field\data\operators\lead.agkey --passphrase-file ops\field\data\operators\lead.pass | ConvertFrom-Json
.\target\release\astragrid.exe identity rotate --registry ops\field\data\operators\operators.agregistry --old-operator-id $old.id --new-identity ops\field\data\operators\lead-rotated.agkey --new-name lead-rotated --new-role incident_commander --new-passphrase-file ops\field\data\operators\lead-rotated.pass --issued-by local-command --revoked-by local-command --reason "planned rotation" --proof-output ops\field\data\operators\lead-rotation-proof.json
```

The proof file records the old id, new id, revocation entry, enrollment entry, and registry digest.

## Encrypted Ledger Vault

Use the vault path when the primary at-rest ledger artifact must stay encrypted:

```powershell
.\target\release\astragrid.exe vault init --ledger ops\field\data\mission.vault.json --passphrase-file ops\field\data\operators\lead.pass --mission flood-watch
.\target\release\astragrid.exe vault append --ledger ops\field\data\mission.vault.json --passphrase-file ops\field\data\operators\lead.pass --actor lead --role incident_commander --action annotate_situation --subject river-east --payload '{"note":"field update"}'
.\target\release\astragrid.exe vault verify --ledger ops\field\data\mission.vault.json --passphrase-file ops\field\data\operators\lead.pass
```

## Update And Release Evidence

```powershell
.\tools\local\package-release.ps1
.\target\release\astragrid.exe provenance verify --input dist\astragrid-windows-x64-0.1.0.provenance.json
.\target\release\astragrid.exe doctor release --provenance dist\astragrid-windows-x64-0.1.0.provenance.json
```

Signed release promotion still requires real local signing identities.

## Cleanup

Always dry-run first:

```powershell
.\target\release\astragrid.exe ops artifact-retention --root . --max-cache-age-days 14 --keep-dist-releases 2
```

Delete only after reviewing the report:

```powershell
.\target\release\astragrid.exe ops artifact-retention --root . --max-cache-age-days 14 --keep-dist-releases 2 --include-target-cache --delete
```

## Failure Handling

- Wrong backup or vault passphrase: command fails closed during sealed artifact open.
- Corrupt ledger: `verify`, `doctor workspace`, and `doctor profile` report failure.
- Missing key: profile doctor reports the identity path failure.
- Expired or revoked team session: `team session-verify`, `team authorize`, and `team append` fail.
- Broken pairing grant: `team pair-verify` fails before a device is trusted.
- Broken provenance: `provenance verify` and `doctor release` fail before handoff.
- Existing restore files: restore stops unless `--overwrite` is supplied.
