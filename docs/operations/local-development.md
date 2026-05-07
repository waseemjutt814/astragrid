# Local Development

The project is designed to run from a D drive workspace on Windows while staying portable to
Linux and macOS CI.

## Required Tools

- Rust stable with `cargo`, `rustfmt`, and `clippy`.
- Git.

Python, pip, Node, pnpm, and Docker are not required by phase 1. Do not install them into the
project until a real component needs them.

## D Drive Tooling Convention

Use `tools/local/bootstrap.ps1` to create local tool directories under the project. The script
does not install global software; it prepares environment variables and verifies Rust.

```powershell
.\tools\local\bootstrap.ps1
```

## Verification

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
cargo doc --workspace --no-deps
```

## Signed Command Smoke Test

```powershell
$id = [guid]::NewGuid().ToString('N')
$ledger = ".cache\mission-$id.agl"
$db = ".cache\mission-$id.db"
$key = ".cache\lead-$id.agkey"
$passphrase = ".cache\lead-$id.pass"
$deputyKey = ".cache\deputy-$id.agkey"
$deputyPassphrase = ".cache\deputy-$id.pass"
$medicKey = ".cache\medic-$id.agkey"
$medicPassphrase = ".cache\medic-$id.pass"
$registry = ".cache\operators-$id.agregistry"
$quorumProposal = ".cache\medic-enroll-$id.proposal.json"
$leadQuorumSignature = ".cache\lead-quorum-$id.sig.json"
$deputyQuorumSignature = ".cache\deputy-quorum-$id.sig.json"
$payload = ".cache\payload-$id.json"

'strong local passphrase' | Set-Content -Encoding UTF8 $passphrase
'deputy local passphrase' | Set-Content -Encoding UTF8 $deputyPassphrase
'medic local passphrase' | Set-Content -Encoding UTF8 $medicPassphrase
cargo run -q -p astragrid -- init --mission flood-watch --ledger $ledger
cargo run -q -p astragrid -- identity create --path $key --name lead --role incident_commander --passphrase-file $passphrase
cargo run -q -p astragrid -- identity create --path $deputyKey --name deputy --role incident_commander --passphrase-file $deputyPassphrase
cargo run -q -p astragrid -- identity create --path $medicKey --name medic --role operator --passphrase-file $medicPassphrase
cargo run -q -p astragrid -- identity os-seal-passphrase --input $passphrase --output "$passphrase.oskey"
cargo run -q -p astragrid -- identity inspect --path $key --passphrase-os-key "$passphrase.oskey"
cargo run -q -p astragrid -- identity audit --path $key
cargo run -q -p astragrid -- identity registry-init --registry $registry --authority local-command
cargo run -q -p astragrid -- identity enroll --registry $registry --identity $key --passphrase-file $passphrase --issued-by local-command
cargo run -q -p astragrid -- identity enroll --registry $registry --identity $deputyKey --passphrase-file $deputyPassphrase --issued-by bootstrap
cargo run -q -p astragrid -- identity quorum-propose --registry $registry --output $quorumProposal --change enroll --identity $medicKey --issued-by quorum --required-approvals 2
cargo run -q -p astragrid -- identity quorum-sign --proposal $quorumProposal --identity $key --passphrase-file $passphrase --output $leadQuorumSignature
cargo run -q -p astragrid -- identity quorum-sign --proposal $quorumProposal --identity $deputyKey --passphrase-file $deputyPassphrase --output $deputyQuorumSignature
cargo run -q -p astragrid -- identity quorum-verify --registry $registry --proposal $quorumProposal --signature $leadQuorumSignature --signature $deputyQuorumSignature
cargo run -q -p astragrid -- identity quorum-apply --registry $registry --proposal $quorumProposal --signature $leadQuorumSignature --signature $deputyQuorumSignature
cargo run -q -p astragrid -- identity registry-bundle --registry $registry --output ".cache\trust-bundle-$id.json"
cargo run -q -p astragrid -- identity registry-verify-bundle --input ".cache\trust-bundle-$id.json" --registry $registry
cargo run -q -p astragrid -- identity registry-import-bundle --registry $registry --input ".cache\trust-bundle-$id.json" --dry-run
'{ "water_level_m": 5.2 }' | Set-Content -Encoding UTF8 $payload
cargo run -q -p astragrid -- append-signed --ledger $ledger --identity $key --passphrase-file $passphrase --registry $registry --action declare_incident --subject river-east --priority critical --payload "@$payload"
cargo run -q -p astragrid -- verify --ledger $ledger
cargo run -q -p astragrid -- state summary --ledger $ledger
cargo run -q -p astragrid -- store ingest --ledger $ledger --db $db
cargo run -q -p astragrid -- store summary --db $db
```

## GeoJSON Smoke Test

```powershell
$geo = ".cache\features-$id.geojson"
$geoOut = ".cache\features-$id.jsonl"
$geoMap = ".cache\features-$id.html"
'{"type":"Feature","id":"river-east","properties":{"risk":"flood"},"geometry":{"type":"Point","coordinates":[72.2,31.2]}}' | Set-Content -Encoding UTF8 $geo
cargo run -q -p astragrid -- geo ingest --input $geo --output $geoOut
cargo run -q -p astragrid -- geo map --input $geoOut --output $geoMap --title "Flood Watch Map"
cargo run -q -p astragrid -- geo console --input $geoOut --ledger $ledger --output ".cache\console-$id.html" --title "Flood Watch Console"
$mapServer = Start-Job -ScriptBlock { param($geoOut, $ledger) cargo run -q -p astragrid -- geo serve --input $geoOut --ledger $ledger --bind 127.0.0.1:17881 --max-requests 1 } -ArgumentList $geoOut, $ledger
Start-Sleep -Seconds 2
Invoke-WebRequest http://127.0.0.1:17881/map-console.html | Select-Object -ExpandProperty StatusCode
Receive-Job $mapServer -Wait
```

## Evidence And Sync Smoke Test

```powershell
$evidence = ".cache\evidence-$id.json"
$bundle = ".cache\bundle-$id.json"
$workflowBundle = ".cache\workflow-bundle-$id.json"
$peerLedger = ".cache\peer-$id.agl"
'[{"id":"sensor-1","source":"river-gauge","kind":"sensor","confidence":0.92,"digest":"abc123","excerpt":"water=5.2"}]' | Set-Content -Encoding UTF8 $evidence
cargo run -q -p astragrid -- evidence build --mission flood-watch --evidence $evidence --action declare_incident --subject river-east --rationale "Gauge exceeded threshold." --confidence 0.88 --evidence-id sensor-1 --output $bundle
cargo run -q -p astragrid -- evidence build --mission flood-watch --evidence $evidence --action declare_incident --subject river-west --rationale "Second gauge exceeded threshold." --confidence 0.91 --evidence-id sensor-1 --output $workflowBundle
cargo run -q -p astragrid -- evidence verify --input $bundle
cargo run -q -p astragrid -- sync compare --left $ledger --right $ledger
Copy-Item $ledger $peerLedger
cargo run -q -p astragrid -- append --ledger $peerLedger --actor operator --role operator --action annotate_situation --subject sector-7 --priority elevated --payload '{ "note": "peer field check" }'
cargo run -q -p astragrid -- sync apply --target $ledger --source $peerLedger
```

## Recommendation Rule Smoke Test

```powershell
$rules = ".cache\recommend-rules-$id.json"
$readings = ".cache\recommend-readings-$id.json"
$recommendOut = ".cache\recommend-bundles-$id.json"
@"
[
  {
    "id": "flood-threshold",
    "mission": "flood-watch",
    "source": "river-gauge",
    "subject": "river-east",
    "metric": "water_level_m",
    "operator": "greater_or_equal",
    "threshold": 5.0,
    "action": "declare_incident",
    "rationale": "Water level exceeded flood threshold.",
    "min_confidence": 0.8
  }
]
"@ | Set-Content -Encoding UTF8 $rules
@"
[
  {
    "id": "reading-1",
    "source": "river-gauge",
    "subject": "river-east",
    "metric": "water_level_m",
    "value": 5.2,
    "unit": "m",
    "confidence": 0.92
  }
]
"@ | Set-Content -Encoding UTF8 $readings
cargo run -q -p astragrid -- recommend rules --rules $rules --readings $readings --output $recommendOut
```

Structured model candidates can be converted only when they cite known evidence ids:

```powershell
$modelCandidates = ".cache\model-candidates-$id.json"
@"
[
  {
    "action": "declare_incident",
    "subject": "river-east",
    "rationale": "Model reviewed the cited gauge evidence and found threshold breach.",
    "confidence": 0.86,
    "evidence_ids": ["sensor-1"]
  }
]
"@ | Set-Content -Encoding UTF8 $modelCandidates
cargo run -q -p astragrid -- recommend model-output --mission flood-watch --evidence $evidence --candidates $modelCandidates --output ".cache\model-bundles-$id.json"
```

## Durable Peer Queue Smoke Test

```powershell
$peerQueue = ".cache\peer-queue-$id.db"
$sharedKey = ".cache\peer-shared-$id.key"
$peerManifest = ".cache\peer-manifest-$id.json"
'shared queue secret' | Set-Content -Encoding UTF8 $sharedKey
@(
  @{ name = "peer-a"; addr = "127.0.0.1:17655" }
) | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 $peerManifest
cargo run -q -p astragrid -- peer-queue enqueue --queue $peerQueue --manifest $peerManifest --max-attempts 3
cargo run -q -p astragrid -- peer-queue list --queue $peerQueue
```

To process the queued job, run a one-shot peer server in another terminal:

```powershell
cargo run -q -p astragrid -- net serve-once --bind 127.0.0.1:17655 --ledger $peerLedger --shared-key-file $sharedKey
```

For a hardened local federation service loop, use `serve-daemon` with health and audit outputs.
Use finite `--max-requests` during local smoke tests and omit it for long-running service mode:

```powershell
$federationHealth = ".cache\federation-health-$id.json"
$federationAudit = ".cache\federation-audit-$id.jsonl"
$federationServer = Start-Job -ScriptBlock {
    param($ProjectRoot, $peerLedger, $sharedKey, $health, $audit)
    Set-Location $ProjectRoot
    cargo run -q -p astragrid -- net serve-daemon --bind 127.0.0.1:17656 --ledger $peerLedger --shared-key-file $sharedKey --health-file $health --audit-log $audit --max-requests 1 --idle-timeout-seconds 15
} -ArgumentList (Get-Location).Path, $peerLedger, $sharedKey, $federationHealth, $federationAudit
Start-Sleep -Seconds 2
cargo run -q -p astragrid -- net fetch --addr 127.0.0.1:17656 --shared-key-file $sharedKey --output ".cache\federation-events-$id.json"
Receive-Job $federationServer -Wait
Get-Content $federationHealth
Get-Content $federationAudit
```

Then process the queue:

```powershell
cargo run -q -p astragrid -- peer-queue process --queue $peerQueue --ledger $ledger --shared-key-file $sharedKey --limit 1
cargo run -q -p astragrid -- peer-queue summary --queue $peerQueue
cargo run -q -p astragrid -- peer-queue health --queue $peerQueue
```

For supervised runs, use finite cycles during local validation and omit `--cycles` for daemon mode:

```powershell
cargo run -q -p astragrid -- peer-queue worker --queue $peerQueue --ledger $ledger --shared-key-file $sharedKey --cycles 1 --interval-seconds 1
```

Generate service manager artifacts for a long-running worker:

```powershell
cargo run -q -p astragrid -- supervisor windows-peer-worker --output .cache\astragrid-peer-worker.ps1 --binary target\release\astragrid.exe --working-directory . --ledger $ledger --queue $peerQueue --shared-key-file $sharedKey
cargo run -q -p astragrid -- supervisor systemd-peer-worker --output .cache\astragrid-peer-worker.service --binary /usr/local/bin/astragrid --working-directory /srv/astragrid --ledger data/mission.agl --queue data/peer-sync.db --shared-key-file secrets/peer.key --user astragrid
cargo run -q -p astragrid -- supervisor windows-peer-worker-kit --output-dir .cache\worker-kit-windows --binary target\release\astragrid.exe --working-directory . --ledger $ledger --queue $peerQueue --shared-key-file $sharedKey
cargo run -q -p astragrid -- supervisor systemd-peer-worker-kit --output-dir .cache\worker-kit-systemd --binary /usr/local/bin/astragrid --working-directory /srv/astragrid --ledger data/mission.agl --queue data/peer-sync.db --shared-key-file secrets/peer.key --user astragrid
```

Exercise live worker recovery with a fail-once local worker:

```powershell
$watchdogScript = ".cache\watchdog-worker-$id.ps1"
$watchdogState = ".cache\watchdog-worker-$id.state"
$watchdogAudit = ".cache\watchdog-audit-$id.jsonl"
@'
param([string]$State)
if (-not (Test-Path $State)) {
    'first failure' | Set-Content -Encoding UTF8 $State
    exit 7
}
exit 0
'@ | Set-Content -Encoding UTF8 $watchdogScript
cargo run -q -p astragrid -- supervisor watchdog-run --name local-peer-worker --command powershell --arg -NoProfile --arg -ExecutionPolicy --arg Bypass --arg -File --arg $watchdogScript --arg $watchdogState --audit-log $watchdogAudit --max-restarts 2 --restart-delay-ms 0
Get-Content $watchdogAudit
```

## Source Profile Smoke Test

```powershell
$profile = ".cache\source-profile-$id.json"
$cache = ".cache\source-cache-$id.json"
$profileOut = ".cache\profile-features-$id.jsonl"
@"
{
  "name": "local-cache",
  "request": {
    "url": "https://example.test/ogc/features",
    "limit": 10,
    "bbox": "72.1,31.1,72.3,31.3"
  },
  "cache_path": "$($cache -replace '\\', '\\')",
  "retry_attempts": 2,
  "retry_delay_ms": 100
}
"@ | Set-Content -Encoding UTF8 $profile
@"
{
  "schema": 1,
  "profile": "local-cache",
  "final_url": "https://example.test/ogc/features?limit=10",
  "fetched_at": "2026-05-07T00:00:00Z",
  "body": "{\"type\":\"Feature\",\"id\":\"river-east\",\"properties\":{},\"geometry\":{\"type\":\"Point\",\"coordinates\":[72.2,31.2]}}"
}
"@ | Set-Content -Encoding UTF8 $cache
cargo run -q -p astragrid -- harvest profile --profile $profile --output $profileOut
```

## Seal And Report Smoke Test

```powershell
$sealed = ".cache\mission-$id.agl.sealed.json"
$opened = ".cache\mission-opened-$id.agl"
$report = ".cache\report-$id.md"
$reportBundle = ".cache\report-$id.json"
cargo run -q -p astragrid -- seal file --input $ledger --output $sealed --passphrase-file $passphrase --label mission-ledger --aad flood-watch
cargo run -q -p astragrid -- seal open --input $sealed --output $opened --passphrase-file $passphrase
cargo run -q -p astragrid -- report markdown --db $db --title "Flood Watch" --evidence-bundle $bundle --output $report
cargo run -q -p astragrid -- report bundle --db $db --title "Flood Watch" --evidence-bundle $bundle --output $reportBundle
```

## Workflow Draft Smoke Test

```powershell
$draft = ".cache\draft-$id.json"
cargo run -q -p astragrid -- workflow draft --ledger $ledger --bundle $workflowBundle --actor lead --role incident_commander --min-confidence 0.75 --output $draft
```

## Approval Queue Smoke Test

```powershell
$approvals = ".cache\approvals-$id.agl"
$approval = cargo run -q -p astragrid -- approval submit --queue $approvals --draft $draft --requested-by planner | ConvertFrom-Json
cargo run -q -p astragrid -- approval approve --queue $approvals --id $approval.id --reviewed-by lead --reason "verified against mission state"
cargo run -q -p astragrid -- approval append-approved --queue $approvals --id $approval.id --ledger $ledger --identity $key --passphrase-file $passphrase --registry $registry --executed-by lead
cargo run -q -p astragrid -- approval verify --queue $approvals
```

## Scenario Runner Smoke Test

```powershell
$scenario = ".cache\scenario-$id.json"
$scenarioWorkdir = ".cache\scenario-run-$id"
@"
{
  "name": "flood-watch",
  "ledger": "mission.agl",
  "store": "mission.db",
  "steps": [
    { "type": "init", "mission": "flood-watch", "operator": "kernel" },
    {
      "type": "append",
      "actor": "lead",
      "role": "incident_commander",
      "action": "declare_incident",
      "subject": "river-east",
      "priority": "critical",
      "payload": { "water_level_m": 5.2 }
    },
    { "type": "verify_ledger" },
    { "type": "ingest_store" },
    { "type": "assert_state", "mission": "flood-watch", "open_incidents": 1 },
    { "type": "assert_store", "event_count": 2, "critical_event_count": 1 }
  ]
}
"@ | Set-Content -Encoding UTF8 $scenario
cargo run -q -p astragrid -- scenario run --input $scenario --workdir $scenarioWorkdir
```

## Dashboard And Doctor Smoke Test

```powershell
$dashboard = ".cache\dashboard-$id.html"
cargo run -q -p astragrid -- dashboard export --ledger $ledger --db $db --output $dashboard --title "Flood Watch"
$server = Start-Job -ScriptBlock { param($ledger, $db) cargo run -q -p astragrid -- dashboard serve --ledger $ledger --db $db --bind 127.0.0.1:17880 --max-requests 1 } -ArgumentList $ledger, $db
Start-Sleep -Seconds 2
Invoke-WebRequest http://127.0.0.1:17880/dashboard.html | Select-Object -ExpandProperty StatusCode
Receive-Job $server -Wait
cargo run -q -p astragrid -- doctor workspace --ledger $ledger --db $db --identity $key --approvals $approvals --peer-queue $peerQueue
cargo run -q -p astragrid -- ops readiness-gate --ledger $ledger --db $db --identity $key --approvals $approvals --peer-queue $peerQueue --cycles 1 --output ".cache\readiness-$id.json"
```

## Operator Handoff Bundle Smoke Test

```powershell
$opsBundle = ".cache\ops-bundle-$id"
cargo run -q -p astragrid -- ops bundle --ledger $ledger --db $db --approvals $approvals --identity $key --peer-queue $peerQueue --features $geoOut --output-dir $opsBundle --title "Flood Watch Handoff"
Get-ChildItem $opsBundle
```

## Acceptance Pack Smoke Test

```powershell
$acceptance = ".cache\acceptance-pack-$id"
cargo run -q -p astragrid -- ops acceptance-pack --output-dir $acceptance --title "Flood Watch Acceptance"
powershell -ExecutionPolicy Bypass -File "$acceptance\run-acceptance.ps1" -ProjectRoot (Get-Location).Path -SkipPackage
```

## Package Smoke Test

```powershell
.\tools\local\package-release.ps1
```

The package script writes both `dist\astragrid-windows-x64-<version>.zip` and
`dist\astragrid-windows-x64-<version>.provenance.json`.

The zip includes `START-ASTRAGRID.cmd` for double-click launches and
`VERIFY-ASTRAGRID.ps1` for a local executable smoke test after extraction. It also includes
`INSTALL-ASTRAGRID.ps1`, which installs the extracted package, runs a version smoke, and writes
`astragrid-install.json`.

Verify the generated checksums before sharing the package:

```powershell
cargo run -q -p astragrid -- provenance verify --input dist\astragrid-windows-x64-0.1.0.provenance.json
cargo run -q -p astragrid -- doctor release --provenance dist\astragrid-windows-x64-0.1.0.provenance.json
.\tools\local\package-smoke.ps1 -Artifact dist\astragrid-windows-x64-0.1.0.zip
tar -tf dist\astragrid-windows-x64-0.1.0.zip
```

To sign release custody with a real local operator key, pass the identity to the package script.
The script signs the provenance file, creates quorum and policy documents, writes a custody
manifest, and requires a healthy release doctor gate with the freshly built release binary:

```powershell
.\tools\local\package-release.ps1 -SigningIdentity data\operators\release.agkey -PassphraseFile data\operators\release.pass
cargo run -q -p astragrid -- provenance verify-signature --signature dist\astragrid-windows-x64-0.1.0.provenance.sig.json
cargo run -q -p astragrid -- provenance quorum-verify --input dist\astragrid-windows-x64-0.1.0.provenance.quorum.json
cargo run -q -p astragrid -- provenance policy-verify --policy dist\astragrid-windows-x64-0.1.0.provenance.release-policy.json --provenance dist\astragrid-windows-x64-0.1.0.provenance.json --quorum dist\astragrid-windows-x64-0.1.0.provenance.quorum.json
cargo run -q -p astragrid -- doctor release --provenance dist\astragrid-windows-x64-0.1.0.provenance.json --signature dist\astragrid-windows-x64-0.1.0.provenance.sig.json --quorum dist\astragrid-windows-x64-0.1.0.provenance.quorum.json --policy dist\astragrid-windows-x64-0.1.0.provenance.release-policy.json
cargo run -q -p astragrid -- ops release-evidence-pack --output-dir dist\release-evidence --provenance dist\astragrid-windows-x64-0.1.0.provenance.json --signature dist\astragrid-windows-x64-0.1.0.provenance.sig.json --quorum dist\astragrid-windows-x64-0.1.0.provenance.quorum.json --policy dist\astragrid-windows-x64-0.1.0.provenance.release-policy.json
cargo run -q -p astragrid -- ops readiness-gate --ledger data\mission.agl --provenance dist\astragrid-windows-x64-0.1.0.provenance.json --signature dist\astragrid-windows-x64-0.1.0.provenance.sig.json --quorum dist\astragrid-windows-x64-0.1.0.provenance.quorum.json --policy dist\astragrid-windows-x64-0.1.0.provenance.release-policy.json --cycles 1
```

## Local Install and Artifact Retention

Install a release build from source into the user-local AstraGrid bin directory:

```powershell
.\tools\local\install.ps1 -SkipStartMenuShortcut
```

Install from an extracted release zip:

```powershell
.\INSTALL-ASTRAGRID.ps1 -InstallDir "$env:LOCALAPPDATA\AstraGrid\bin" -SkipStartMenuShortcut
```

Report cleanup candidates without deleting anything:

```powershell
cargo run -q -p astragrid -- ops artifact-retention --root . --max-cache-age-days 14 --keep-dist-releases 2
```

Delete only the reported generated artifacts after reviewing the dry run:

```powershell
cargo run -q -p astragrid -- ops artifact-retention --root . --max-cache-age-days 14 --keep-dist-releases 2 --include-target-cache --delete
```

The retention command refuses paths outside the workspace root and never deletes anything without
`--delete`.

## Ready-To-Use Workspace Smoke

```powershell
$root = ".cache\ready-workspace"
cargo run -q -p astragrid -- setup first-run --root $root --mission flood-watch --operator-name lead --role incident_commander
cargo run -q -p astragrid -- doctor profile --profile "$root\astragrid.profile.json"
cargo run -q -p astragrid -- ops backup --profile "$root\astragrid.profile.json" --output "$root\data\backups\workspace.sealed.json" --passphrase-file "$root\data\operators\lead.pass"
cargo run -q -p astragrid -- ops restore --input "$root\data\backups\workspace.sealed.json" --output-dir ".cache\ready-restore" --passphrase-file "$root\data\operators\lead.pass"
'deputy local passphrase' | Set-Content -Encoding UTF8 "$root\data\operators\deputy.pass"
'medic local passphrase' | Set-Content -Encoding UTF8 "$root\data\operators\medic.pass"
cargo run -q -p astragrid -- identity create --path "$root\data\operators\deputy.agkey" --name deputy --role incident_commander --passphrase-file "$root\data\operators\deputy.pass"
cargo run -q -p astragrid -- identity create --path "$root\data\operators\medic.agkey" --name medic --role operator --passphrase-file "$root\data\operators\medic.pass"
cargo run -q -p astragrid -- identity enroll --registry "$root\data\operators\operators.agregistry" --identity "$root\data\operators\deputy.agkey" --passphrase-file "$root\data\operators\deputy.pass" --issued-by bootstrap
cargo run -q -p astragrid -- identity quorum-propose --registry "$root\data\operators\operators.agregistry" --output "$root\data\operators\medic-enroll.proposal.json" --change enroll --identity "$root\data\operators\medic.agkey" --issued-by quorum --required-approvals 2
cargo run -q -p astragrid -- identity quorum-sign --proposal "$root\data\operators\medic-enroll.proposal.json" --identity "$root\data\operators\lead.agkey" --passphrase-file "$root\data\operators\lead.pass" --output "$root\data\operators\lead.quorum.sig.json"
cargo run -q -p astragrid -- identity quorum-sign --proposal "$root\data\operators\medic-enroll.proposal.json" --identity "$root\data\operators\deputy.agkey" --passphrase-file "$root\data\operators\deputy.pass" --output "$root\data\operators\deputy.quorum.sig.json"
cargo run -q -p astragrid -- identity quorum-apply --registry "$root\data\operators\operators.agregistry" --proposal "$root\data\operators\medic-enroll.proposal.json" --signature "$root\data\operators\lead.quorum.sig.json" --signature "$root\data\operators\deputy.quorum.sig.json"
cargo run -q -p astragrid -- team session-issue --identity "$root\data\operators\lead.agkey" --passphrase-file "$root\data\operators\lead.pass" --registry "$root\data\operators\operators.agregistry" --output "$root\data\operators\lead.session.json" --ttl-minutes 30
cargo run -q -p astragrid -- team session-verify --session "$root\data\operators\lead.session.json" --registry "$root\data\operators\operators.agregistry"
cargo run -q -p astragrid -- team pair-create --identity "$root\data\operators\lead.agkey" --passphrase-file "$root\data\operators\lead.pass" --registry "$root\data\operators\operators.agregistry" --device-id field-tablet-01 --device-name "Field Tablet 01" --output "$root\data\operators\field-tablet-01.pairing.json" --ttl-minutes 30
cargo run -q -p astragrid -- team pair-verify --input "$root\data\operators\field-tablet-01.pairing.json" --registry "$root\data\operators\operators.agregistry"
cargo run -q -p astragrid -- policy-pack template --output "$root\data\field-safety.policy.json" --name field-safety --version 1.0.0
cargo run -q -p astragrid -- policy-pack sign --pack "$root\data\field-safety.policy.json" --output "$root\data\field-safety.policy.sig.json" --identity "$root\data\operators\lead.agkey" --passphrase-file "$root\data\operators\lead.pass"
cargo run -q -p astragrid -- policy-pack verify --pack "$root\data\field-safety.policy.json" --signature "$root\data\field-safety.policy.sig.json" --registry "$root\data\operators\operators.agregistry"
cargo run -q -p astragrid -- vault init --ledger "$root\data\mission.vault.json" --passphrase-file "$root\data\operators\lead.pass" --mission flood-watch
cargo run -q -p astragrid -- vault verify --ledger "$root\data\mission.vault.json" --passphrase-file "$root\data\operators\lead.pass"
```

See `docs/operations/ready-to-use-runbook.md` for the complete operator workflow.
