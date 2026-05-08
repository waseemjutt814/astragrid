# AstraGrid DevOps Blackbox

DevOps Blackbox is the practical product layer for AstraGrid.

Instead of asking operators to think in ledger terms, it lets a developer record project work as a
signed, verified timeline.

## What It Is For

Use this when you want a trustworthy record of project work:

- A bug was found.
- A fix started.
- A fix completed.
- Tests passed or failed.
- A build completed.
- A release package was created.
- A decision was made.
- A command was run and its result should be remembered.

It does not scan your whole PC. It only records what you explicitly ask it to record.

## First Run

Create a project blackbox:

```powershell
.\target\release\astragrid.exe dev init --project waseembot --root ops\waseembot-devops --operator-name waseem
```

This creates:

- `ops\waseembot-devops\astragrid.profile.json`
- a mission ledger
- a SQLite index
- an encrypted operator key
- an operator registry
- a local console token

## Record A Project Event

```powershell
.\target\release\astragrid.exe dev record --profile ops\waseembot-devops\astragrid.profile.json --kind bug-found --summary "Gateway test failed" --detail "Vitest reported a timeout"
```

Useful kinds:

- `note`
- `bug-found`
- `fix-started`
- `fix-completed`
- `tests-passed`
- `tests-failed`
- `build-completed`
- `release-built`
- `decision`

## Run A Command And Record The Result

```powershell
.\target\release\astragrid.exe dev run --profile ops\waseembot-devops\astragrid.profile.json --name "cargo tests" -- cargo test --workspace --offline
```

The record includes:

- command arguments
- exit code
- success or failure
- duration
- stdout and stderr hashes
- stdout and stderr tails
- current Git branch, commit, and dirty status when Git is available

The command is launched directly, not through a shell.

For CI-style local gates, add `--require-pass`. AstraGrid still writes the signed failure record,
then exits failed so the calling script can stop:

```powershell
.\target\release\astragrid.exe dev run --require-pass --profile ops\waseembot-devops\astragrid.profile.json --name "workspace gate" -- cargo test --workspace --offline
```

## Track A Project Task

```powershell
.\target\release\astragrid.exe dev task-open --profile ops\waseembot-devops\astragrid.profile.json --title "Fix gateway timeout" --detail "Vitest gate is hanging"
.\target\release\astragrid.exe dev task-complete --profile ops\waseembot-devops\astragrid.profile.json --title "Fix gateway timeout" --detail "Gate is green"
```

Both commands write signed append-only records. They do not edit or delete old task records.

## Open The Console In One Command

```powershell
.\target\release\astragrid.exe dev console --profile ops\waseembot-devops\astragrid.profile.json
```

For scripts, print the local URL without serving:

```powershell
.\target\release\astragrid.exe dev console --profile ops\waseembot-devops\astragrid.profile.json --print-only
```

## Validate The Blackbox

```powershell
.\target\release\astragrid.exe dev doctor --profile ops\waseembot-devops\astragrid.profile.json
```

This checks the profile paths and verifies the ledger.

## Export A Human Report

```powershell
.\target\release\astragrid.exe dev report --profile ops\waseembot-devops\astragrid.profile.json
```

By default, this writes:

```text
ops\waseembot-devops\data\reports\devops-blackbox.md
```

The report includes record counts, current Git snapshot, recent records, and latest failure detail.
It also lists attached artifact hashes, including files passed with `--artifact`.

## Backup And Restore Check

Create a sealed backup and record it:

```powershell
.\target\release\astragrid.exe dev backup --profile ops\waseembot-devops\astragrid.profile.json
```

Restore that backup into a check directory and run profile doctor on the restored copy:

```powershell
.\target\release\astragrid.exe dev restore-check --profile ops\waseembot-devops\astragrid.profile.json --input ops\waseembot-devops\data\backups\devops-backup-<timestamp>.agbackup
```

## Check Status

```powershell
.\target\release\astragrid.exe dev status --profile ops\waseembot-devops\astragrid.profile.json
```

This shows:

- whether the ledger verifies
- total records
- latest DevOps entries
- current Git status

## Open The Browser Console

`dev init` prints the token file path. Use it with the existing console:

```powershell
.\target\release\astragrid.exe ui serve --profile ops\waseembot-devops\astragrid.profile.json --auth-token-file ops\waseembot-devops\data\operator-console.token
```

Open:

```text
http://127.0.0.1:17882/console.html?token=<token-from-file>
```

## Why This Is Useful

Chat history is useful for conversation, but it is not a verified project record.

DevOps Blackbox gives you a local proof trail:

- what was done
- when it was done
- which command proved it
- which Git commit it happened on
- whether the record still verifies

For WaseemBot work, this can become the trusted memory of builds, tests, fixes, releases, and major
AI-assisted decisions.

## What Still Needs External Resources

These items cannot be honestly completed without real infrastructure or credentials:

- signed public binaries
- MSI, winget, and Scoop publication
- remote update channel
- hardware TPM or YubiKey provider tests
- hosted remote certificate authority
- real multi-site deployment drills

The local DevOps Blackbox flow is real and usable now.
