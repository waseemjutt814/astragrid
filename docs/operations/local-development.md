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
$registry = ".cache\operators-$id.agregistry"
$payload = ".cache\payload-$id.json"

'strong local passphrase' | Set-Content -Encoding UTF8 $passphrase
cargo run -q -p astragrid -- init --mission flood-watch --ledger $ledger
cargo run -q -p astragrid -- identity create --path $key --name lead --role incident_commander --passphrase-file $passphrase
cargo run -q -p astragrid -- identity os-seal-passphrase --input $passphrase --output "$passphrase.oskey"
cargo run -q -p astragrid -- identity inspect --path $key --passphrase-os-key "$passphrase.oskey"
cargo run -q -p astragrid -- identity audit --path $key
cargo run -q -p astragrid -- identity registry-init --registry $registry --authority local-command
cargo run -q -p astragrid -- identity enroll --registry $registry --identity $key --passphrase-file $passphrase --issued-by local-command
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
cargo run -q -p astragrid -- doctor workspace --ledger $ledger --db $db --identity $key --approvals $approvals --peer-queue $peerQueue
```

## Operator Handoff Bundle Smoke Test

```powershell
$opsBundle = ".cache\ops-bundle-$id"
cargo run -q -p astragrid -- ops bundle --ledger $ledger --db $db --approvals $approvals --identity $key --peer-queue $peerQueue --features $geoOut --output-dir $opsBundle --title "Flood Watch Handoff"
Get-ChildItem $opsBundle
```

## Package Smoke Test

```powershell
.\tools\local\package-release.ps1
```

The package script writes both `dist\astragrid-windows-x64-<version>.zip` and
`dist\astragrid-windows-x64-<version>.provenance.json`.

Verify the generated checksums before sharing the package:

```powershell
cargo run -q -p astragrid -- provenance verify --input dist\astragrid-windows-x64-0.1.0.provenance.json
cargo run -q -p astragrid -- doctor release --provenance dist\astragrid-windows-x64-0.1.0.provenance.json
```

To sign release custody with a real local operator key, pass the identity to the package script.
The script signs the provenance file and immediately verifies the detached signature with the
freshly built release binary:

```powershell
.\tools\local\package-release.ps1 -SigningIdentity data\operators\release.agkey -PassphraseFile data\operators\release.pass
cargo run -q -p astragrid -- provenance verify-signature --signature dist\astragrid-windows-x64-0.1.0.provenance.sig.json
cargo run -q -p astragrid -- provenance quorum-create --threshold 1 --signature dist\astragrid-windows-x64-0.1.0.provenance.sig.json --output dist\astragrid-windows-x64-0.1.0.provenance.quorum.json
cargo run -q -p astragrid -- provenance quorum-verify --input dist\astragrid-windows-x64-0.1.0.provenance.quorum.json
cargo run -q -p astragrid -- doctor release --provenance dist\astragrid-windows-x64-0.1.0.provenance.json --signature dist\astragrid-windows-x64-0.1.0.provenance.sig.json --quorum dist\astragrid-windows-x64-0.1.0.provenance.quorum.json
```
