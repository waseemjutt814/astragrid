use std::{
    collections::BTreeSet,
    fs,
    io::{self, IsTerminal, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    time::{Duration as StdDuration, Instant},
};

use anyhow::{Context, Result, bail};
use astragrid_ai::{AiRunnerConfig, AiRunnerRequest, run_evidence_bound_runner};
use astragrid_approvals::{ApprovalLog, ApprovalStatus};
use astragrid_core::{
    Action, Actor, CommandRequest, DetachedSignature, MissionLedger, OperatorIdentity,
    OperatorKeypair, OperatorRegistry, OperatorRegistryEntry, OperatorStatus, PAYLOAD_LIMIT_BYTES,
    Priority, RegistryImportStatus, Role,
};
use astragrid_crypto::SealedArtifact;
use astragrid_dashboard::DashboardDocument;
use astragrid_doctor::{DoctorInput, ReleaseDoctorInput, run_doctor, run_release_doctor};
use astragrid_evidence::{EvidenceBundle, EvidenceItem, Recommendation};
use astragrid_geo::GeoFeatureSet;
use astragrid_harvest::{HarvestRequest, SourceProfile, harvest_geojson, harvest_profile};
use astragrid_map::{MapConsoleDocument, MapDocument};
use astragrid_net::{
    PeerEndpoint, fetch_ledger_snapshot, fetch_ledger_snapshot_with_identity, plan_multi_peer_sync,
    plan_multi_peer_sync_with_identity, serve_ledger_connection,
    serve_ledger_connection_with_peer_registry, serve_ledger_once,
    serve_ledger_once_with_peer_registry,
};
use astragrid_oskey::OsSealedSecret;
use astragrid_policy_pack::{
    PolicyRulePack, PolicyRulePackSignature, PolicyRulePackSignatureReport,
};
use astragrid_provenance::{
    PackageProvenance, ProvenanceQuorumEnvelope, ProvenanceSignatureEnvelope, ReleaseCustodyPolicy,
};
use astragrid_recommend::{
    ModelRecommendationCandidate, RecommendationRule, SensorReading,
    build_model_recommendation_bundles, run_recommendation_rules,
};
use astragrid_report::{IncidentReport, ReportBundle};
use astragrid_scenario::run_scenario_file;
use astragrid_state::{MissionState, StateExport};
use astragrid_store::{EventFilter, MissionStore};
use astragrid_supervisor::{
    FederationDaemonSupervisorSpec, PeerWorkerSupervisorSpec, SystemdFederationDaemonUnit,
    SystemdPeerWorkerUnit, WindowsFederationDaemonTask, WindowsPeerWorkerTask,
};
use astragrid_sync::{LedgerMergeOptions, SyncPlan, apply_append_only, merge_ledgers_to_output};
use astragrid_sync_queue::{
    PeerSyncQueue, ProcessOutcome, QueueHealthSnapshot, QueueHealthStatus, QueueProcessOptions,
    QueueProcessResult, QueueStatus,
};
use astragrid_ui::route_operator_console;
use astragrid_workflow::{CommandDraft, WorkflowPlanner, actor_from_parts};
use clap::{Parser, Subcommand, ValueEnum};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

const DEFAULT_OS_PASSPHRASE_PURPOSE: &str = "astragrid-operator-key-passphrase-v1";
const WORKSPACE_PROFILE_SCHEMA: u16 = 1;
const WORKSPACE_BACKUP_SCHEMA: u16 = 1;
const LEDGER_VAULT_AAD: &str = "astragrid-ledger-vault-v1";
const TEAM_SESSION_SCHEMA: u16 = 1;
const TEAM_SESSION_PURPOSE: &str = "astragrid-team-session-v1";
const DEVICE_PAIRING_SCHEMA: u16 = 1;
const DEVICE_PAIRING_PURPOSE: &str = "astragrid-device-pairing-v1";
const REGISTRY_QUORUM_PROPOSAL_SCHEMA: u16 = 1;
const REGISTRY_QUORUM_SIGNATURE_PURPOSE: &str = "astragrid-registry-quorum-v1";

#[derive(Debug, Parser)]
#[command(name = "astragrid")]
#[command(about = "AstraGrid mission control kernel CLI")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum SetupCommands {
    /// Create ledger, encrypted operator key, registry, store, folders, and profile.
    FirstRun {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long, default_value = "astragrid.profile.json")]
        profile: PathBuf,
        #[arg(long, default_value = "flood-watch")]
        mission: String,
        #[arg(long, default_value = "lead")]
        operator_name: String,
        #[arg(long, default_value_t = Role::IncidentCommander)]
        role: Role,
        #[arg(long, default_value = "local-command")]
        authority: String,
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long, default_value = "data/mission.db")]
        db: PathBuf,
        #[arg(long, default_value = "data/operators/lead.agkey")]
        identity: PathBuf,
        #[arg(long, default_value = "data/operators/lead.pass")]
        passphrase_file: PathBuf,
        #[arg(long, default_value = "data/operators/operators.agregistry")]
        registry: PathBuf,
        #[arg(long, default_value = "data/approvals.agl")]
        approvals: PathBuf,
        #[arg(long, default_value = "data/peer-sync.db")]
        peer_queue: PathBuf,
        #[arg(long, default_value = "data/reports")]
        reports_dir: PathBuf,
        #[arg(long, default_value = "data/backups")]
        backups_dir: PathBuf,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Create and validate a ready-to-use local workspace.
    Setup {
        #[command(subcommand)]
        command: SetupCommands,
    },
    /// Create a new mission ledger with a system genesis event.
    Init {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        mission: String,
        #[arg(long, default_value = "local-operator")]
        operator: String,
    },
    /// Append a policy-checked mission event.
    Append {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        role: Role,
        #[arg(long)]
        action: Action,
        #[arg(long)]
        subject: String,
        #[arg(long, default_value_t = Priority::Routine)]
        priority: Priority,
        /// JSON payload, or @path/to/payload.json.
        #[arg(long, default_value = "{}")]
        payload: String,
    },
    /// Append a mission event signed by a local operator key.
    AppendSigned {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_os_key: Option<PathBuf>,
        #[arg(long)]
        registry: Option<PathBuf>,
        #[arg(long)]
        policy_pack: Option<PathBuf>,
        #[arg(long)]
        policy_signature: Option<PathBuf>,
        #[arg(long)]
        action: Action,
        #[arg(long)]
        subject: String,
        #[arg(long, default_value_t = Priority::Routine)]
        priority: Priority,
        /// JSON payload, or @path/to/payload.json.
        #[arg(long, default_value = "{}")]
        payload: String,
    },
    /// Verify the ledger hash chain and sequence integrity.
    Verify {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
    },
    /// Print the latest mission events as JSON.
    Tail {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Evaluate admission policy without writing to the ledger.
    PolicyCheck {
        #[arg(long)]
        actor: String,
        #[arg(long)]
        role: Role,
        #[arg(long)]
        action: Action,
        #[arg(long)]
        subject: String,
        #[arg(long, default_value_t = Priority::Routine)]
        priority: Priority,
        #[arg(long, default_value = "{}")]
        payload: String,
    },
    /// Build, sign, verify, and evaluate signed policy rule packs.
    PolicyPack {
        #[command(subcommand)]
        command: PolicyPackCommands,
    },
    /// Manage local operator signing identities.
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },
    /// Manage local team sessions, permission gates, and device pairing.
    Team {
        #[command(subcommand)]
        command: TeamCommands,
    },
    /// Maintain the local SQLite mission index.
    Store {
        #[command(subcommand)]
        command: StoreCommands,
    },
    /// Derive current operational state from a verified ledger.
    State {
        #[command(subcommand)]
        command: StateCommands,
    },
    /// Ingest and summarize GeoJSON feature data.
    Geo {
        #[command(subcommand)]
        command: GeoCommands,
    },
    /// Build and verify evidence bundles.
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommands,
    },
    /// Compare ledgers and apply verified append-only sync deltas.
    Sync {
        #[command(subcommand)]
        command: SyncCommands,
    },
    /// Seal and open encrypted mission artifacts.
    Seal {
        #[command(subcommand)]
        command: SealCommands,
    },
    /// Operate on an encrypted-at-rest mission ledger vault.
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    /// Exchange verified ledgers over authenticated TCP.
    Net {
        #[command(subcommand)]
        command: NetCommands,
    },
    /// Queue and process durable peer sync work.
    PeerQueue {
        #[command(subcommand)]
        command: PeerQueueCommands,
    },
    /// Harvest remote GeoJSON or OGC API Features documents.
    Harvest {
        #[command(subcommand)]
        command: HarvestCommands,
    },
    /// Run deterministic evidence-bound recommendation rules.
    Recommend {
        #[command(subcommand)]
        command: RecommendCommands,
    },
    /// Export operator-readable incident reports.
    Report {
        #[command(subcommand)]
        command: ReportCommands,
    },
    /// Export a self-contained operator dashboard.
    Dashboard {
        #[command(subcommand)]
        command: DashboardCommands,
    },
    /// Serve a visual API-backed operator console over loopback.
    Ui {
        #[command(subcommand)]
        command: UiCommands,
    },
    /// Build operator handoff bundles from verified local artifacts.
    Ops {
        #[command(subcommand)]
        command: OpsCommands,
    },
    /// Diagnose local mission artifacts and custody health.
    Doctor {
        #[command(subcommand)]
        command: DoctorCommands,
    },
    /// Verify release provenance and artifact checksums.
    Provenance {
        #[command(subcommand)]
        command: ProvenanceCommands,
    },
    /// Manage reviewed workflow drafts before signed ledger append.
    Approval {
        #[command(subcommand)]
        command: ApprovalCommands,
    },
    /// Run executable mission acceptance scenarios.
    Scenario {
        #[command(subcommand)]
        command: ScenarioCommands,
    },
    /// Draft policy-checked commands from verified evidence and current state.
    Workflow {
        #[command(subcommand)]
        command: WorkflowCommands,
    },
    /// Generate service supervisor artifacts for long-running workers.
    Supervisor {
        #[command(subcommand)]
        command: SupervisorCommands,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyPackCommands {
    /// Write a starter field-safety policy rule pack.
    Template {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "field-safety")]
        name: String,
        #[arg(long, default_value = "1.0.0")]
        version: String,
    },
    /// Sign a policy rule pack with a local operator identity.
    Sign {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_os_key: Option<PathBuf>,
    },
    /// Verify a policy rule pack and optional detached signature.
    Verify {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        signature: Option<PathBuf>,
        #[arg(long)]
        registry: Option<PathBuf>,
    },
    /// Evaluate a command request through core policy plus a rule pack.
    Evaluate {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        signature: Option<PathBuf>,
        #[arg(long)]
        registry: Option<PathBuf>,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        role: Role,
        #[arg(long)]
        action: Action,
        #[arg(long)]
        subject: String,
        #[arg(long, default_value_t = Priority::Routine)]
        priority: Priority,
        #[arg(long, default_value = "{}")]
        payload: String,
    },
}

#[derive(Debug, Subcommand)]
enum IdentityCommands {
    /// Create a new local Ed25519 operator key file.
    Create {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        role: Role,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_os_key: Option<PathBuf>,
    },
    /// Print public identity metadata from a key file.
    Inspect {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_os_key: Option<PathBuf>,
    },
    /// Seal a passphrase file with the current OS user protection provider.
    OsSealPassphrase {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = DEFAULT_OS_PASSPHRASE_PURPOSE)]
        purpose: String,
    },
    /// Open an OS-sealed passphrase into a local file.
    OsOpenPassphrase {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect OS-sealed passphrase metadata without opening the secret.
    OsInspect {
        #[arg(long)]
        input: PathBuf,
    },
    /// Inspect key-file encryption and local file-permission signals.
    Audit {
        #[arg(long)]
        path: PathBuf,
    },
    /// Create an empty trusted operator registry.
    RegistryInit {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        authority: String,
    },
    /// Enroll a local identity into a trusted operator registry.
    Enroll {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        issued_by: String,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_os_key: Option<PathBuf>,
    },
    /// Revoke an operator from a trusted operator registry.
    Revoke {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        operator_id: String,
        #[arg(long)]
        revoked_by: String,
        #[arg(long)]
        reason: String,
    },
    /// Revoke an old operator id, create a new encrypted key, enroll it, and write proof.
    Rotate {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        old_operator_id: String,
        #[arg(long)]
        new_identity: PathBuf,
        #[arg(long)]
        new_name: String,
        #[arg(long)]
        new_role: Role,
        #[arg(long)]
        new_passphrase_file: PathBuf,
        #[arg(long)]
        issued_by: String,
        #[arg(long)]
        revoked_by: String,
        #[arg(long, default_value = "key rotation")]
        reason: String,
        #[arg(long)]
        proof_output: PathBuf,
    },
    /// List trusted operator registry entries.
    RegistryList {
        #[arg(long)]
        registry: PathBuf,
    },
    /// Export a public trust bundle for another host to verify/import.
    RegistryBundle {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a public trust bundle and optionally compare it with a registry file.
    RegistryVerifyBundle {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        registry: Option<PathBuf>,
    },
    /// Import a verified public trust bundle into a local registry.
    RegistryImportBundle {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Create a signed-change proposal for quorum-governed registry updates.
    QuorumPropose {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum)]
        change: RegistryQuorumChangeKind,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        operator_id: Option<String>,
        #[arg(long, default_value = "quorum")]
        issued_by: String,
        #[arg(long, default_value = "quorum")]
        revoked_by: String,
        #[arg(long, default_value = "quorum registry change")]
        reason: String,
        #[arg(long, default_value_t = 2)]
        required_approvals: usize,
    },
    /// Sign a registry quorum proposal with an active operator key.
    QuorumSign {
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_os_key: Option<PathBuf>,
    },
    /// Verify registry quorum signatures without changing the registry.
    QuorumVerify {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long = "signature", required = true)]
        signatures: Vec<PathBuf>,
    },
    /// Apply a verified quorum-governed registry update.
    QuorumApply {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long = "signature", required = true)]
        signatures: Vec<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum TeamCommands {
    /// Issue a signed local operator session from an enrolled identity.
    SessionIssue {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_os_key: Option<PathBuf>,
        #[arg(long, default_value_t = 480)]
        ttl_minutes: i64,
    },
    /// Verify a signed local operator session against the registry.
    SessionVerify {
        #[arg(long)]
        session: PathBuf,
        #[arg(long)]
        registry: PathBuf,
    },
    /// Check whether a session can perform a mission action.
    Authorize {
        #[arg(long)]
        session: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        action: Action,
        #[arg(long, default_value_t = Priority::Routine)]
        priority: Priority,
        #[arg(long, default_value = "authorization-check")]
        subject: String,
        #[arg(long, default_value = "{}")]
        payload: String,
    },
    /// Append a signed command only after a valid team session authorizes it.
    Append {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_os_key: Option<PathBuf>,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        session: PathBuf,
        #[arg(long)]
        policy_pack: Option<PathBuf>,
        #[arg(long)]
        policy_signature: Option<PathBuf>,
        #[arg(long)]
        action: Action,
        #[arg(long)]
        subject: String,
        #[arg(long, default_value_t = Priority::Routine)]
        priority: Priority,
        #[arg(long, default_value = "{}")]
        payload: String,
    },
    /// Create a signed device pairing grant for one enrolled operator.
    PairCreate {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        device_name: String,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_os_key: Option<PathBuf>,
        #[arg(long, default_value_t = 1440)]
        ttl_minutes: i64,
    },
    /// Verify a signed device pairing grant against the registry.
    PairVerify {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        registry: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum StoreCommands {
    /// Verify and ingest a mission ledger into SQLite.
    Ingest {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long, default_value = "data/mission.db")]
        db: PathBuf,
    },
    /// Print indexed mission summary.
    Summary {
        #[arg(long, default_value = "data/mission.db")]
        db: PathBuf,
    },
    /// Print recent indexed mission events.
    Recent {
        #[arg(long, default_value = "data/mission.db")]
        db: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Query indexed mission events with filters.
    Query {
        #[arg(long, default_value = "data/mission.db")]
        db: PathBuf,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        priority: Option<String>,
        #[arg(long)]
        actor: Option<String>,
        #[arg(long)]
        subject_contains: Option<String>,
        #[arg(long, default_value_t = false)]
        signed_only: bool,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Export indexed mission events as a verified JSON array.
    Export {
        #[arg(long, default_value = "data/mission.db")]
        db: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Import a verified JSON event array into the mission index.
    Import {
        #[arg(long, default_value = "data/mission.db")]
        db: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum StateCommands {
    /// Print current mission state summary.
    Summary {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
    },
    /// Export full materialized mission state as JSON.
    Export {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum GeoCommands {
    /// Summarize a GeoJSON file.
    Summary {
        #[arg(long)]
        input: PathBuf,
    },
    /// Ingest a GeoJSON file into JSON Lines feature records.
    Ingest {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Render feature JSON Lines as a self-contained HTML/SVG map.
    Map {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "AstraGrid Feature Map")]
        title: String,
    },
    /// Render a self-contained browser map console with mission state overlays.
    Console {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "AstraGrid Map Console")]
        title: String,
    },
    /// Serve the map console over loopback and regenerate it for each request.
    Serve {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long, default_value = "127.0.0.1:17881")]
        bind: String,
        #[arg(long, default_value = "AstraGrid Map Console")]
        title: String,
        #[arg(long, default_value_t = 5)]
        refresh_seconds: u64,
        /// Optional finite request count for smoke tests and supervised runs.
        #[arg(long)]
        max_requests: Option<u32>,
    },
}

#[derive(Debug, Subcommand)]
enum EvidenceCommands {
    /// Build a hashed evidence bundle from an evidence JSON array.
    Build {
        #[arg(long)]
        mission: String,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        action: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        rationale: String,
        #[arg(long)]
        confidence: f64,
        #[arg(long, value_delimiter = ',')]
        evidence_id: Vec<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a hashed evidence bundle.
    Verify {
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum SyncCommands {
    /// Compare two ledgers and report append-only or divergent state.
    Compare {
        #[arg(long)]
        left: PathBuf,
        #[arg(long)]
        right: PathBuf,
    },
    /// Apply append-only source ledger events into a target ledger.
    Apply {
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        source: PathBuf,
    },
    /// Merge identical, append-only, or divergent ledgers into a new verified ledger with proof.
    Merge {
        #[arg(long)]
        left: PathBuf,
        #[arg(long)]
        right: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        proof: Option<PathBuf>,
        #[arg(long)]
        overwrite: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SealCommands {
    /// Encrypt a file into a sealed artifact JSON envelope.
    File {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        #[arg(long, default_value = "artifact")]
        label: String,
        #[arg(long, default_value = "astragrid")]
        aad: String,
    },
    /// Decrypt a sealed artifact JSON envelope.
    Open {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum VaultCommands {
    /// Initialize an encrypted-at-rest ledger vault.
    Init {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        #[arg(long)]
        mission: String,
        #[arg(long, default_value = "local-operator")]
        operator: String,
    },
    /// Append a policy-checked event inside an encrypted ledger vault.
    Append {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        role: Role,
        #[arg(long)]
        action: Action,
        #[arg(long)]
        subject: String,
        #[arg(long, default_value_t = Priority::Routine)]
        priority: Priority,
        #[arg(long, default_value = "{}")]
        payload: String,
    },
    /// Verify the encrypted ledger vault hash chain.
    Verify {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
    },
    /// Print recent events from an encrypted ledger vault.
    Tail {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
enum NetCommands {
    /// Serve a verified ledger snapshot to one authenticated peer.
    ServeOnce {
        #[arg(long, default_value = "127.0.0.1:17655")]
        bind: String,
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        shared_key_file: PathBuf,
        #[arg(long)]
        peer_registry: Option<PathBuf>,
    },
    /// Run a hardened authenticated ledger snapshot daemon.
    ServeDaemon {
        #[arg(long, default_value = "127.0.0.1:17655")]
        bind: String,
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        shared_key_file: PathBuf,
        #[arg(long)]
        health_file: Option<PathBuf>,
        #[arg(long)]
        audit_log: Option<PathBuf>,
        /// Require peers to sign the session challenge with an active enrolled identity.
        #[arg(long)]
        peer_registry: Option<PathBuf>,
        /// Stop after this many accepted connections. Omit for long-running mode.
        #[arg(long)]
        max_requests: Option<u32>,
        /// Stop after idle seconds. Use 0 for no idle stop.
        #[arg(long, default_value_t = 0)]
        idle_timeout_seconds: u64,
    },
    /// Fetch a verified ledger snapshot from a peer and write it as JSON events.
    Fetch {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        shared_key_file: PathBuf,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Fetch and compare every peer from a JSON manifest.
    PlanPeers {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        shared_key_file: PathBuf,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum PeerQueueCommands {
    /// Enqueue peer sync jobs from a JSON peer manifest.
    Enqueue {
        #[arg(long, default_value = "data/peer-sync.db")]
        queue: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value_t = 3)]
        max_attempts: u32,
    },
    /// List durable peer sync jobs.
    List {
        #[arg(long, default_value = "data/peer-sync.db")]
        queue: PathBuf,
        #[arg(long)]
        status: Option<String>,
    },
    /// Print queue status counts.
    Summary {
        #[arg(long, default_value = "data/peer-sync.db")]
        queue: PathBuf,
    },
    /// Print peer sync queue health telemetry.
    Health {
        #[arg(long, default_value = "data/peer-sync.db")]
        queue: PathBuf,
        #[arg(long, default_value_t = 600)]
        stale_after_seconds: i64,
    },
    /// Process due peer sync jobs with retry accounting.
    Process {
        #[arg(long, default_value = "data/peer-sync.db")]
        queue: PathBuf,
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        shared_key_file: PathBuf,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long, default_value_t = 10)]
        limit: u32,
        #[arg(long, default_value_t = 300)]
        retry_delay_seconds: i64,
    },
    /// Run the peer sync queue worker for finite cycles or as a daemon.
    Worker {
        #[arg(long, default_value = "data/peer-sync.db")]
        queue: PathBuf,
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        shared_key_file: PathBuf,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long, default_value_t = 10)]
        limit: u32,
        #[arg(long, default_value_t = 300)]
        retry_delay_seconds: i64,
        #[arg(long, default_value_t = 30)]
        interval_seconds: u64,
        /// Number of cycles to run. Omit for daemon mode.
        #[arg(long)]
        cycles: Option<u32>,
        /// Optional health JSON path for service managers and dashboards.
        #[arg(long)]
        health_file: Option<PathBuf>,
        /// Optional JSON Lines audit log path for worker lifecycle and cycle records.
        #[arg(long)]
        audit_log: Option<PathBuf>,
        #[arg(long, default_value_t = 600)]
        stale_after_seconds: i64,
    },
}

#[derive(Debug, Subcommand)]
enum HarvestCommands {
    /// Fetch a GeoJSON/OGC Features URL and write normalized feature records.
    Geojson {
        #[arg(long)]
        url: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        bbox: Option<String>,
    },
    /// Harvest using a JSON source profile with cache and retry settings.
    Profile {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RecommendCommands {
    /// Evaluate rules over sensor readings and emit evidence bundles.
    Rules {
        #[arg(long)]
        rules: PathBuf,
        #[arg(long)]
        readings: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Convert structured model candidates into verified evidence bundles.
    ModelOutput {
        #[arg(long)]
        mission: String,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        candidates: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Run a bounded local AI command and accept only evidence-cited recommendation bundles.
    AiRun {
        #[arg(long)]
        mission: String,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        command: PathBuf,
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,
        #[arg(long)]
        working_directory: Option<PathBuf>,
        #[arg(long, default_value_t = 5_000)]
        timeout_ms: u64,
        #[arg(long, default_value_t = 64 * 1024)]
        max_stdout_bytes: usize,
        #[arg(long, default_value_t = 16 * 1024)]
        max_stderr_bytes: usize,
        #[arg(long)]
        clear_environment: bool,
        #[arg(long)]
        instructions: Option<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ReportCommands {
    /// Export a Markdown incident report from an indexed mission DB.
    Markdown {
        #[arg(long, default_value = "data/mission.db")]
        db: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long)]
        evidence_bundle: Vec<PathBuf>,
    },
    /// Export a JSON report bundle containing machine data and Markdown.
    Bundle {
        #[arg(long, default_value = "data/mission.db")]
        db: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long)]
        evidence_bundle: Vec<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum DashboardCommands {
    /// Export a self-contained HTML dashboard from local mission artifacts.
    Export {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "AstraGrid Mission Dashboard")]
        title: String,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        approvals: Option<PathBuf>,
        #[arg(long)]
        peer_queue: Option<PathBuf>,
        #[arg(long)]
        evidence_bundle: Vec<PathBuf>,
        #[arg(long)]
        map_href: Option<String>,
    },
    /// Serve the dashboard over loopback and regenerate it for each request.
    Serve {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long, default_value = "127.0.0.1:17880")]
        bind: String,
        #[arg(long, default_value = "AstraGrid Mission Dashboard")]
        title: String,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        approvals: Option<PathBuf>,
        #[arg(long)]
        peer_queue: Option<PathBuf>,
        #[arg(long)]
        evidence_bundle: Vec<PathBuf>,
        #[arg(long)]
        map_href: Option<String>,
        #[arg(long, default_value_t = 5)]
        refresh_seconds: u64,
        /// Optional finite request count for smoke tests and supervised runs.
        #[arg(long)]
        max_requests: Option<u32>,
    },
}

#[derive(Debug, Subcommand)]
enum UiCommands {
    /// Serve the API-backed operator console over loopback.
    Serve {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long, default_value = "127.0.0.1:17882")]
        bind: String,
        #[arg(long, default_value = "AstraGrid Operator Console")]
        title: String,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        approvals: Option<PathBuf>,
        #[arg(long)]
        peer_queue: Option<PathBuf>,
        #[arg(long)]
        evidence_bundle: Vec<PathBuf>,
        #[arg(long)]
        map_href: Option<String>,
        #[arg(long, default_value_t = 5)]
        refresh_seconds: u64,
        /// Optional finite request count for smoke tests and supervised runs.
        #[arg(long)]
        max_requests: Option<u32>,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum OpsCommands {
    /// Export a handoff folder with dashboard, state, doctor reports, and manifest.
    Bundle {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "AstraGrid Operations Bundle")]
        title: String,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        approvals: Option<PathBuf>,
        #[arg(long)]
        identity: Vec<PathBuf>,
        #[arg(long)]
        peer_queue: Option<PathBuf>,
        #[arg(long)]
        evidence_bundle: Vec<PathBuf>,
        #[arg(long)]
        features: Option<PathBuf>,
        #[arg(long)]
        provenance: Option<PathBuf>,
        #[arg(long)]
        signature: Vec<PathBuf>,
        #[arg(long)]
        quorum: Option<PathBuf>,
        #[arg(long)]
        release_policy: Option<PathBuf>,
    },
    /// Generate a runnable local mission acceptance pack.
    AcceptancePack {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "Flood Watch Acceptance")]
        title: String,
    },
    /// Export release evidence checksums, doctor output, and a handoff manifest.
    ReleaseEvidencePack {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        provenance: PathBuf,
        #[arg(long)]
        signature: Vec<PathBuf>,
        #[arg(long)]
        quorum: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Seal a workspace backup from a validated local profile.
    Backup {
        #[arg(long, default_value = "astragrid.profile.json")]
        profile: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
    },
    /// Restore a sealed workspace backup into a target directory.
    Restore {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        #[arg(long, default_value_t = false)]
        overwrite: bool,
    },
    /// Run finite workspace and optional release doctor cycles as a readiness gate.
    ReadinessGate {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        identity: Vec<PathBuf>,
        #[arg(long)]
        approvals: Option<PathBuf>,
        #[arg(long)]
        peer_queue: Option<PathBuf>,
        #[arg(long)]
        provenance: Option<PathBuf>,
        #[arg(long)]
        signature: Vec<PathBuf>,
        #[arg(long)]
        quorum: Option<PathBuf>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long, default_value_t = 1)]
        cycles: u32,
        #[arg(long, default_value_t = 0)]
        interval_seconds: u64,
        #[arg(long, default_value_t = true)]
        fail_on_warning: bool,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Report and optionally delete safe generated artifacts under one workspace root.
    ArtifactRetention {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long, default_value_t = 14)]
        max_cache_age_days: i64,
        #[arg(long, default_value_t = 2)]
        keep_dist_releases: usize,
        #[arg(long, default_value_t = false)]
        include_target_cache: bool,
        #[arg(long, default_value_t = false)]
        delete: bool,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum DoctorCommands {
    /// Validate a local workspace profile and its configured artifacts.
    Profile {
        #[arg(long, default_value = "astragrid.profile.json")]
        profile: PathBuf,
    },
    /// Check ledger, state, store, identities, approvals, and peer queue health.
    Workspace {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        identity: Vec<PathBuf>,
        #[arg(long)]
        approvals: Option<PathBuf>,
        #[arg(long)]
        peer_queue: Option<PathBuf>,
    },
    /// Check release package provenance, signatures, and quorum custody.
    Release {
        #[arg(long)]
        provenance: PathBuf,
        #[arg(long)]
        signature: Vec<PathBuf>,
        #[arg(long)]
        quorum: Option<PathBuf>,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ProvenanceCommands {
    /// Verify SHA-256 checksums recorded in a provenance JSON file.
    Verify {
        #[arg(long)]
        input: PathBuf,
    },
    /// Sign a provenance JSON file with a local operator identity.
    Sign {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_os_key: Option<PathBuf>,
    },
    /// Verify a detached provenance signature envelope.
    VerifySignature {
        #[arg(long)]
        signature: PathBuf,
    },
    /// Combine detached provenance signatures into a quorum envelope.
    QuorumCreate {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        threshold: usize,
        #[arg(long)]
        signature: Vec<PathBuf>,
    },
    /// Verify a multi-signature provenance quorum envelope.
    QuorumVerify {
        #[arg(long)]
        input: PathBuf,
    },
    /// Write a release custody policy JSON file.
    PolicyTemplate {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        target: Option<String>,
        #[arg(long, default_value_t = 1)]
        min_distinct_valid_signers: usize,
        #[arg(long)]
        required_signer_id: Vec<String>,
        #[arg(long)]
        allowed_signer_id: Vec<String>,
        #[arg(long, default_value_t = false)]
        require_clean_git: bool,
    },
    /// Verify a release custody policy against package provenance and quorum.
    PolicyVerify {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        provenance: PathBuf,
        #[arg(long)]
        quorum: PathBuf,
    },
    /// Sign provenance, create quorum/policy files, and run release doctor in one gate.
    CustodyPack {
        #[arg(long)]
        provenance: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, required = true)]
        identity: Vec<PathBuf>,
        #[arg(long)]
        passphrase_file: Vec<PathBuf>,
        #[arg(long)]
        passphrase_os_key: Vec<PathBuf>,
        #[arg(long, default_value_t = 1)]
        threshold: usize,
        #[arg(long, default_value_t = false)]
        require_clean_git: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ApprovalCommands {
    /// Verify the approval log hash chain.
    Verify {
        #[arg(long, default_value = "data/approvals.agl")]
        queue: PathBuf,
    },
    /// Submit a ready workflow draft into the approval queue.
    Submit {
        #[arg(long, default_value = "data/approvals.agl")]
        queue: PathBuf,
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        requested_by: String,
    },
    /// List approval queue items.
    List {
        #[arg(long, default_value = "data/approvals.agl")]
        queue: PathBuf,
        #[arg(long)]
        status: Option<String>,
    },
    /// Approve a pending workflow draft.
    Approve {
        #[arg(long, default_value = "data/approvals.agl")]
        queue: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        reviewed_by: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Reject a pending workflow draft.
    Reject {
        #[arg(long, default_value = "data/approvals.agl")]
        queue: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        reviewed_by: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Sign and append an approved draft, then mark it executed.
    AppendApproved {
        #[arg(long, default_value = "data/approvals.agl")]
        queue: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_os_key: Option<PathBuf>,
        #[arg(long)]
        registry: Option<PathBuf>,
        #[arg(long)]
        executed_by: String,
    },
    /// Mark an approved draft as executed after a separately performed append.
    MarkExecuted {
        #[arg(long, default_value = "data/approvals.agl")]
        queue: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        executed_by: String,
        #[arg(long)]
        ledger_event_hash: String,
    },
}

#[derive(Debug, Subcommand)]
enum ScenarioCommands {
    /// Run a JSON mission scenario and fail on assertion mismatch.
    Run {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value = ".cache/scenario-run")]
        workdir: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum WorkflowCommands {
    /// Draft a command from a verified evidence bundle without appending it.
    Draft {
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        actor: String,
        #[arg(long)]
        role: Role,
        #[arg(long, default_value_t = 0.75)]
        min_confidence: f64,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum SupervisorCommands {
    /// Generate a systemd unit for the peer sync worker.
    SystemdPeerWorker {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "astragrid-peer-worker.service")]
        unit_name: String,
        #[arg(long, default_value = "AstraGrid peer sync worker")]
        description: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, default_value_t = 5)]
        restart_seconds: u32,
        #[command(flatten)]
        spec: PeerWorkerSupervisorArgs,
    },
    /// Generate a Windows Scheduled Task registration script for the peer sync worker.
    WindowsPeerWorker {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "AstraGrid Peer Worker")]
        task_name: String,
        #[command(flatten)]
        spec: PeerWorkerSupervisorArgs,
    },
    /// Generate systemd unit plus install/uninstall scripts for the peer sync worker.
    SystemdPeerWorkerKit {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "astragrid-peer-worker.service")]
        unit_name: String,
        #[arg(long, default_value = "AstraGrid peer sync worker")]
        description: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, default_value_t = 5)]
        restart_seconds: u32,
        #[command(flatten)]
        spec: PeerWorkerSupervisorArgs,
    },
    /// Generate Windows Scheduled Task install/uninstall scripts for the peer sync worker.
    WindowsPeerWorkerKit {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "AstraGrid Peer Worker")]
        task_name: String,
        #[command(flatten)]
        spec: PeerWorkerSupervisorArgs,
    },
    /// Generate a systemd unit for the federation daemon.
    SystemdFederationDaemon {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "astragrid-federation-daemon.service")]
        unit_name: String,
        #[arg(long, default_value = "AstraGrid federation daemon")]
        description: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, default_value_t = 5)]
        restart_seconds: u32,
        #[command(flatten)]
        spec: FederationDaemonSupervisorArgs,
    },
    /// Generate a Windows Scheduled Task registration script for the federation daemon.
    WindowsFederationDaemon {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "AstraGrid Federation Daemon")]
        task_name: String,
        #[command(flatten)]
        spec: FederationDaemonSupervisorArgs,
    },
    /// Generate systemd unit plus install/uninstall scripts for the federation daemon.
    SystemdFederationDaemonKit {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "astragrid-federation-daemon.service")]
        unit_name: String,
        #[arg(long, default_value = "AstraGrid federation daemon")]
        description: String,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, default_value_t = 5)]
        restart_seconds: u32,
        #[command(flatten)]
        spec: FederationDaemonSupervisorArgs,
    },
    /// Generate Windows Scheduled Task install/uninstall scripts for the federation daemon.
    WindowsFederationDaemonKit {
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value = "AstraGrid Federation Daemon")]
        task_name: String,
        #[command(flatten)]
        spec: FederationDaemonSupervisorArgs,
    },
    /// Run a local worker under a finite restart watchdog with JSONL audit.
    WatchdogRun {
        #[arg(long, default_value = "astragrid-worker")]
        name: String,
        #[arg(long)]
        command: String,
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,
        #[arg(long)]
        working_directory: Option<PathBuf>,
        #[arg(long)]
        audit_log: PathBuf,
        #[arg(long, default_value_t = 3)]
        max_restarts: u32,
        #[arg(long, default_value_t = 1_000)]
        restart_delay_ms: u64,
        #[arg(long, default_value_t = 0)]
        success_exit_code: i32,
    },
}

#[derive(Debug, Clone, clap::Args)]
struct PeerWorkerSupervisorArgs {
    #[arg(long, default_value = "astragrid")]
    binary: PathBuf,
    #[arg(long, default_value = ".")]
    working_directory: PathBuf,
    #[arg(long, default_value = "data/mission.agl")]
    ledger: PathBuf,
    #[arg(long, default_value = "data/peer-sync.db")]
    queue: PathBuf,
    #[arg(long)]
    shared_key_file: PathBuf,
    #[arg(long)]
    identity: Option<PathBuf>,
    #[arg(long)]
    identity_passphrase_file: Option<PathBuf>,
    #[arg(long, default_value_t = 10)]
    limit: u32,
    #[arg(long, default_value_t = 300)]
    retry_delay_seconds: i64,
    #[arg(long, default_value_t = 30)]
    interval_seconds: u64,
    #[arg(long, default_value = "data/peer-worker-health.json")]
    health_file: Option<PathBuf>,
    #[arg(long, default_value = "data/peer-worker-audit.jsonl")]
    audit_log: Option<PathBuf>,
    #[arg(long, default_value_t = 600)]
    stale_after_seconds: i64,
}

impl From<PeerWorkerSupervisorArgs> for PeerWorkerSupervisorSpec {
    fn from(value: PeerWorkerSupervisorArgs) -> Self {
        Self {
            binary: value.binary,
            working_directory: value.working_directory,
            ledger: value.ledger,
            queue: value.queue,
            shared_key_file: value.shared_key_file,
            identity: value.identity,
            identity_passphrase_file: value.identity_passphrase_file,
            limit: value.limit,
            retry_delay_seconds: value.retry_delay_seconds,
            interval_seconds: value.interval_seconds,
            health_file: value.health_file,
            audit_log: value.audit_log,
            stale_after_seconds: value.stale_after_seconds,
        }
    }
}

#[derive(Debug, Clone, clap::Args)]
struct FederationDaemonSupervisorArgs {
    #[arg(long, default_value = "astragrid")]
    binary: PathBuf,
    #[arg(long, default_value = ".")]
    working_directory: PathBuf,
    #[arg(long, default_value = "127.0.0.1:17655")]
    bind: String,
    #[arg(long, default_value = "data/mission.agl")]
    ledger: PathBuf,
    #[arg(long)]
    shared_key_file: PathBuf,
    #[arg(long)]
    peer_registry: Option<PathBuf>,
    #[arg(long, default_value = "data/federation-health.json")]
    health_file: PathBuf,
    #[arg(long, default_value = "data/federation-audit.jsonl")]
    audit_log: PathBuf,
    #[arg(long)]
    max_requests: Option<u32>,
    #[arg(long, default_value_t = 0)]
    idle_timeout_seconds: u64,
}

impl From<FederationDaemonSupervisorArgs> for FederationDaemonSupervisorSpec {
    fn from(value: FederationDaemonSupervisorArgs) -> Self {
        Self {
            binary: value.binary,
            working_directory: value.working_directory,
            bind: value.bind,
            ledger: value.ledger,
            shared_key_file: value.shared_key_file,
            peer_registry: value.peer_registry,
            health_file: value.health_file,
            audit_log: value.audit_log,
            max_requests: value.max_requests,
            idle_timeout_seconds: value.idle_timeout_seconds,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        return run_default_launcher();
    };

    match command {
        Commands::Setup { command } => match command {
            SetupCommands::FirstRun {
                root,
                profile,
                mission,
                operator_name,
                role,
                authority,
                ledger,
                db,
                identity,
                passphrase_file,
                registry,
                approvals,
                peer_queue,
                reports_dir,
                backups_dir,
                force,
            } => print_json(&run_first_run_setup(FirstRunRequest {
                root,
                profile,
                mission,
                operator_name,
                role,
                authority,
                ledger,
                db,
                identity,
                passphrase_file,
                registry,
                approvals,
                peer_queue,
                reports_dir,
                backups_dir,
                force,
            })?),
        },
        Commands::Init {
            ledger,
            mission,
            operator,
        } => {
            if ledger.exists() && fs::metadata(&ledger)?.len() > 0 {
                bail!(
                    "ledger already exists and is not empty: {}",
                    ledger.display()
                );
            }
            let ledger = MissionLedger::open(ledger);
            let event = ledger.append(CommandRequest::new(
                Actor::new(operator, Role::System),
                Action::OpenMission,
                mission.clone(),
                Priority::Elevated,
                json!({
                    "mission": mission,
                    "kernel": "astragrid-core",
                    "schema": 1,
                }),
            ))?;
            print_json(&event)
        }
        Commands::Append {
            ledger,
            actor,
            role,
            action,
            subject,
            priority,
            payload,
        } => {
            let payload = read_payload(&payload)?;
            let ledger = MissionLedger::open(ledger);
            let event = ledger.append(CommandRequest::new(
                Actor::new(actor, role),
                action,
                subject,
                priority,
                payload,
            ))?;
            print_json(&event)
        }
        Commands::AppendSigned {
            ledger,
            identity,
            passphrase_file,
            passphrase_os_key,
            registry,
            policy_pack,
            policy_signature,
            action,
            subject,
            priority,
            payload,
        } => {
            let payload = read_payload(&payload)?;
            let keypair = load_keypair(
                &identity,
                passphrase_file.as_ref(),
                passphrase_os_key.as_ref(),
            )?;
            let request = CommandRequest::new(
                Actor::from(keypair.identity()),
                action,
                subject,
                priority,
                payload,
            );
            if let Some(policy_pack) = policy_pack {
                let decision = evaluate_policy_pack_file(
                    &policy_pack,
                    policy_signature.as_ref(),
                    registry.as_ref(),
                    &request,
                )?;
                if !decision.allowed {
                    bail!("policy rule pack denied command: {}", decision.reason);
                }
            } else if policy_signature.is_some() {
                bail!("--policy-signature requires --policy-pack");
            }
            let ledger = MissionLedger::open(ledger);
            let signed = keypair.sign_request(request)?;
            let event = match registry {
                Some(registry_path) => {
                    let registry = OperatorRegistry::load_from_file(registry_path)?;
                    ledger.append_signed_with_registry(signed, &registry)?
                }
                None => ledger.append_signed(signed)?,
            };
            print_json(&event)
        }
        Commands::Verify { ledger } => {
            let ledger = MissionLedger::open(ledger);
            print_json(&ledger.verify()?)
        }
        Commands::Tail { ledger, limit } => {
            let ledger = MissionLedger::open(ledger);
            let events = ledger.load_events()?;
            let start = events.len().saturating_sub(limit);
            print_json(&events[start..])
        }
        Commands::PolicyCheck {
            actor,
            role,
            action,
            subject,
            priority,
            payload,
        } => {
            let payload = read_payload(&payload)?;
            let request =
                CommandRequest::new(Actor::new(actor, role), action, subject, priority, payload);
            let decision = astragrid_core::AdmissionPolicy.evaluate(&request);
            print_json(&decision)
        }
        Commands::PolicyPack { command } => match command {
            PolicyPackCommands::Template {
                output,
                name,
                version,
            } => {
                let pack = PolicyRulePack::field_safety_template(name, version);
                pack.validate()?;
                write_json_file(&output, &pack)?;
                print_json(&json!({
                    "output": output,
                    "name": pack.name,
                    "version": pack.version,
                    "rules": pack.rules.len(),
                    "sha256": pack.sha256()?,
                }))
            }
            PolicyPackCommands::Sign {
                pack,
                output,
                identity,
                passphrase_file,
                passphrase_os_key,
            } => {
                let pack_doc: PolicyRulePack = read_json_file(&pack)?;
                let keypair = load_keypair(
                    &identity,
                    passphrase_file.as_ref(),
                    passphrase_os_key.as_ref(),
                )?;
                let signature = PolicyRulePackSignature::sign_pack(&pack_doc, &keypair)?;
                write_json_file(&output, &signature)?;
                print_json(&json!({
                    "pack": pack,
                    "output": output,
                    "pack_sha256": signature.pack_sha256,
                    "signer": signature.signature.identity,
                }))
            }
            PolicyPackCommands::Verify {
                pack,
                signature,
                registry,
            } => {
                let report = verify_policy_pack_file(&pack, signature.as_ref(), registry.as_ref())?;
                print_json(&report)?;
                if !report["valid"].as_bool().unwrap_or(false) {
                    bail!("policy rule pack verification failed");
                }
                Ok(())
            }
            PolicyPackCommands::Evaluate {
                pack,
                signature,
                registry,
                actor,
                role,
                action,
                subject,
                priority,
                payload,
            } => {
                let request = CommandRequest::new(
                    Actor::new(actor, role),
                    action,
                    subject,
                    priority,
                    read_payload(&payload)?,
                );
                let decision = evaluate_policy_pack_file(
                    &pack,
                    signature.as_ref(),
                    registry.as_ref(),
                    &request,
                )?;
                print_json(&decision)
            }
        },
        Commands::Identity { command } => match command {
            IdentityCommands::Create {
                path,
                name,
                role,
                passphrase_file,
                passphrase_os_key,
            } => {
                let keypair = OperatorKeypair::generate(name, role);
                match read_passphrase(passphrase_file.as_ref(), passphrase_os_key.as_ref())? {
                    Some(passphrase) => {
                        keypair.save_encrypted_to_file(path, &passphrase)?;
                    }
                    None => keypair.save_to_file(path)?,
                }
                print_json(keypair.identity())
            }
            IdentityCommands::Inspect {
                path,
                passphrase_file,
                passphrase_os_key,
            } => {
                let keypair =
                    load_keypair(&path, passphrase_file.as_ref(), passphrase_os_key.as_ref())?;
                print_json(keypair.identity())
            }
            IdentityCommands::Audit { path } => {
                print_json(&OperatorKeypair::inspect_key_file(path)?)
            }
            IdentityCommands::OsSealPassphrase {
                input,
                output,
                purpose,
            } => {
                let passphrase = read_passphrase_file(&input)?;
                let sealed = OsSealedSecret::seal_current_user(&passphrase, &purpose)?;
                sealed.save_to_file(&output)?;
                print_json(&json!({
                    "output": output,
                    "provider": sealed.provider,
                    "purpose": sealed.purpose,
                }))
            }
            IdentityCommands::OsOpenPassphrase { input, output } => {
                let sealed = OsSealedSecret::load(&input)?;
                let passphrase = sealed.open_current_user()?;
                write_bytes_file(&output, &passphrase)?;
                print_json(&json!({
                    "output": output,
                    "provider": sealed.provider,
                    "purpose": sealed.purpose,
                }))
            }
            IdentityCommands::OsInspect { input } => {
                print_json(&OsSealedSecret::inspect_file(input)?)
            }
            IdentityCommands::RegistryInit {
                registry,
                authority,
            } => {
                if registry.exists() {
                    bail!("registry already exists: {}", registry.display());
                }
                let mut operator_registry = OperatorRegistry::new(authority);
                operator_registry.save_to_file(registry)?;
                print_json(&json!({
                    "authority": operator_registry.authority(),
                    "operators": 0,
                }))
            }
            IdentityCommands::Enroll {
                registry,
                identity,
                issued_by,
                passphrase_file,
                passphrase_os_key,
            } => {
                let keypair = load_keypair(
                    &identity,
                    passphrase_file.as_ref(),
                    passphrase_os_key.as_ref(),
                )?;
                let mut operator_registry = OperatorRegistry::load_from_file(&registry)?;
                let entry = operator_registry.enroll(keypair.identity().clone(), issued_by)?;
                operator_registry.save()?;
                print_json(&entry)
            }
            IdentityCommands::Revoke {
                registry,
                operator_id,
                revoked_by,
                reason,
            } => {
                let mut operator_registry = OperatorRegistry::load_from_file(&registry)?;
                let entry = operator_registry.revoke(&operator_id, revoked_by, reason)?;
                operator_registry.save()?;
                print_json(&entry)
            }
            IdentityCommands::Rotate {
                registry,
                old_operator_id,
                new_identity,
                new_name,
                new_role,
                new_passphrase_file,
                issued_by,
                revoked_by,
                reason,
                proof_output,
            } => print_json(&rotate_operator_key(RotateOperatorRequest {
                registry,
                old_operator_id,
                new_identity,
                new_name,
                new_role,
                new_passphrase_file,
                issued_by,
                revoked_by,
                reason,
                proof_output,
            })?),
            IdentityCommands::RegistryList { registry } => {
                let operator_registry = OperatorRegistry::load_from_file(registry)?;
                let entries = operator_registry.entries().collect::<Vec<_>>();
                print_json(&json!({
                    "authority": operator_registry.authority(),
                    "operators": entries,
                }))
            }
            IdentityCommands::RegistryBundle { registry, output } => {
                let bundle = build_registry_trust_bundle(&registry)?;
                write_json_file(&output, &bundle)?;
                print_json(&json!({
                    "output": output,
                    "authority": bundle.authority,
                    "active_operators": bundle.active_operators,
                    "revoked_operators": bundle.revoked_operators,
                    "registry_sha256": bundle.registry_sha256,
                }))
            }
            IdentityCommands::RegistryVerifyBundle { input, registry } => {
                let bundle: TrustedRegistryBundle = read_json_file(&input)?;
                let report = verify_registry_trust_bundle(&bundle, registry.as_ref())?;
                print_json(&report)?;
                if !report["valid"].as_bool().unwrap_or(false) {
                    bail!("registry trust bundle verification failed");
                }
                Ok(())
            }
            IdentityCommands::RegistryImportBundle {
                registry,
                input,
                dry_run,
            } => print_json(&import_registry_trust_bundle(&registry, &input, dry_run)?),
            IdentityCommands::QuorumPropose {
                registry,
                output,
                change,
                identity,
                operator_id,
                issued_by,
                revoked_by,
                reason,
                required_approvals,
            } => print_json(&create_registry_quorum_proposal(
                RegistryQuorumProposalRequest {
                    registry,
                    output,
                    change,
                    identity,
                    operator_id,
                    issued_by,
                    revoked_by,
                    reason,
                    required_approvals,
                },
            )?),
            IdentityCommands::QuorumSign {
                proposal,
                identity,
                output,
                passphrase_file,
                passphrase_os_key,
            } => print_json(&sign_registry_quorum_proposal(
                &proposal,
                &identity,
                passphrase_file.as_ref(),
                passphrase_os_key.as_ref(),
                &output,
            )?),
            IdentityCommands::QuorumVerify {
                registry,
                proposal,
                signatures,
            } => {
                let report =
                    verify_registry_quorum_proposal_file(&registry, &proposal, &signatures)?;
                print_json(&report)?;
                if !report.valid {
                    bail!("registry quorum proposal verification failed");
                }
                Ok(())
            }
            IdentityCommands::QuorumApply {
                registry,
                proposal,
                signatures,
            } => print_json(&apply_registry_quorum_proposal(
                &registry,
                &proposal,
                &signatures,
            )?),
        },
        Commands::Team { command } => match command {
            TeamCommands::SessionIssue {
                identity,
                registry,
                output,
                passphrase_file,
                passphrase_os_key,
                ttl_minutes,
            } => print_json(&issue_team_session(TeamSessionIssueRequest {
                identity,
                registry,
                output,
                passphrase_file,
                passphrase_os_key,
                ttl_minutes,
            })?),
            TeamCommands::SessionVerify { session, registry } => {
                let report = verify_team_session_file(&session, &registry)?;
                print_json(&report)?;
                if !report.valid {
                    bail!("team session verification failed");
                }
                Ok(())
            }
            TeamCommands::Authorize {
                session,
                registry,
                action,
                priority,
                subject,
                payload,
            } => {
                let payload = read_payload(&payload)?;
                print_json(&authorize_team_action(
                    &session, &registry, action, priority, subject, payload,
                )?)
            }
            TeamCommands::Append {
                ledger,
                identity,
                passphrase_file,
                passphrase_os_key,
                registry,
                session,
                policy_pack,
                policy_signature,
                action,
                subject,
                priority,
                payload,
            } => print_json(&team_append_signed(TeamAppendRequest {
                ledger,
                identity,
                passphrase_file,
                passphrase_os_key,
                registry,
                session,
                policy_pack,
                policy_signature,
                action,
                subject,
                priority,
                payload: read_payload(&payload)?,
            })?),
            TeamCommands::PairCreate {
                identity,
                registry,
                output,
                device_id,
                device_name,
                passphrase_file,
                passphrase_os_key,
                ttl_minutes,
            } => print_json(&create_device_pairing(DevicePairingRequest {
                identity,
                registry,
                output,
                device_id,
                device_name,
                passphrase_file,
                passphrase_os_key,
                ttl_minutes,
            })?),
            TeamCommands::PairVerify { input, registry } => {
                let report = verify_device_pairing_file(&input, &registry)?;
                print_json(&report)?;
                if !report.valid {
                    bail!("device pairing verification failed");
                }
                Ok(())
            }
        },
        Commands::Store { command } => match command {
            StoreCommands::Ingest { ledger, db } => {
                let ledger = MissionLedger::open(ledger);
                let mut store = MissionStore::open(db)?;
                print_json(&store.ingest_ledger(&ledger)?)
            }
            StoreCommands::Summary { db } => {
                let store = MissionStore::open(db)?;
                print_json(&store.summary()?)
            }
            StoreCommands::Recent { db, limit } => {
                let store = MissionStore::open(db)?;
                print_json(&store.list_recent(limit)?)
            }
            StoreCommands::Query {
                db,
                action,
                priority,
                actor,
                subject_contains,
                signed_only,
                limit,
            } => {
                let store = MissionStore::open(db)?;
                print_json(&store.query_events(EventFilter {
                    action,
                    priority,
                    actor,
                    subject_contains,
                    signed_only,
                    limit,
                })?)
            }
            StoreCommands::Export { db, output } => {
                let store = MissionStore::open(db)?;
                write_json_file(&output, &store.export_events()?)?;
                print_json(&json!({
                    "output": output,
                    "events": store.summary()?.event_count,
                }))
            }
            StoreCommands::Import { db, input } => {
                let events: Vec<astragrid_core::MissionEvent> =
                    read_json_file(&input).context("import file must be a JSON event array")?;
                let mut store = MissionStore::open(db)?;
                print_json(
                    &store.ingest_events(&events, events.last().map(|event| event.hash.clone()))?,
                )
            }
        },
        Commands::State { command } => match command {
            StateCommands::Summary { ledger } => {
                let ledger = MissionLedger::open(ledger);
                let state = MissionState::from_ledger(&ledger)?;
                print_json(&state.summary())
            }
            StateCommands::Export { ledger, output } => {
                let ledger_path = ledger.clone();
                let ledger = MissionLedger::open(ledger);
                let state = MissionState::from_ledger(&ledger)?;
                write_json_file(
                    &output,
                    &StateExport {
                        source_ledger: ledger_path,
                        state,
                    },
                )?;
                print_json(&json!({
                    "output": output,
                    "exported": true,
                }))
            }
        },
        Commands::Geo { command } => match command {
            GeoCommands::Summary { input } => {
                let text = read_text_file(&input)
                    .with_context(|| format!("failed to read GeoJSON {}", input.display()))?;
                let set = GeoFeatureSet::from_geojson_str(&text)?;
                print_json(&set.summary)
            }
            GeoCommands::Ingest { input, output } => {
                let text = read_text_file(&input)
                    .with_context(|| format!("failed to read GeoJSON {}", input.display()))?;
                let set = GeoFeatureSet::from_geojson_str(&text)?;
                write_text_file(&output, &set.to_json_lines()?)?;
                print_json(&set.summary)
            }
            GeoCommands::Map {
                input,
                output,
                title,
            } => {
                let text = read_text_file(&input).with_context(|| {
                    format!("failed to read feature records {}", input.display())
                })?;
                let document = MapDocument::from_json_lines(&text, title)?;
                write_text_file(&output, &document.to_html())?;
                print_json(&json!({
                    "output": output,
                    "features": document.features.len(),
                }))
            }
            GeoCommands::Console {
                input,
                ledger,
                output,
                title,
            } => {
                let document = build_map_console_document(&input, &ledger, title)?;
                write_text_file(&output, &document.to_html())?;
                print_json(&json!({
                    "output": output,
                    "features": document.map.features.len(),
                    "incidents": document.incidents.len(),
                }))
            }
            GeoCommands::Serve {
                input,
                ledger,
                bind,
                title,
                refresh_seconds,
                max_requests,
            } => print_json(&serve_map_console(MapServeRequest {
                input,
                ledger,
                bind,
                title,
                refresh_seconds,
                max_requests,
            })?),
        },
        Commands::Evidence { command } => match command {
            EvidenceCommands::Build {
                mission,
                evidence,
                action,
                subject,
                rationale,
                confidence,
                evidence_id,
                output,
            } => {
                let items: Vec<EvidenceItem> =
                    read_json_file(&evidence).context("evidence must be a JSON array")?;
                let bundle = EvidenceBundle::new(
                    mission,
                    items,
                    Recommendation {
                        action,
                        subject,
                        rationale,
                        confidence,
                        evidence_ids: evidence_id,
                    },
                )?;
                match output {
                    Some(output) => {
                        write_json_file(&output, &bundle)?;
                        print_json(&json!({
                            "output": output,
                            "bundle_hash": bundle.bundle_hash,
                        }))
                    }
                    None => print_json(&bundle),
                }
            }
            EvidenceCommands::Verify { input } => {
                let bundle: EvidenceBundle =
                    read_json_file(&input).context("bundle must be valid JSON")?;
                bundle.verify()?;
                print_json(&json!({
                    "valid": true,
                    "bundle_hash": bundle.bundle_hash,
                }))
            }
        },
        Commands::Sync { command } => match command {
            SyncCommands::Compare { left, right } => {
                let left = MissionLedger::open(left);
                let right = MissionLedger::open(right);
                print_json(&SyncPlan::from_ledgers(&left, &right)?)
            }
            SyncCommands::Apply { target, source } => {
                let target = MissionLedger::open(target);
                let source = MissionLedger::open(source);
                print_json(&apply_append_only(&target, &source)?)
            }
            SyncCommands::Merge {
                left,
                right,
                output,
                proof,
                overwrite,
            } => {
                let left = MissionLedger::open(left);
                let right = MissionLedger::open(right);
                let output = MissionLedger::open(output);
                let report = merge_ledgers_to_output(
                    &left,
                    &right,
                    &output,
                    LedgerMergeOptions { overwrite },
                )?;
                if let Some(proof) = proof {
                    write_json_file(&proof, &report)?;
                }
                print_json(&report)
            }
        },
        Commands::Seal { command } => match command {
            SealCommands::File {
                input,
                output,
                passphrase_file,
                label,
                aad,
            } => {
                let passphrase = read_passphrase_file(&passphrase_file)?;
                let bytes = fs::read(&input)
                    .with_context(|| format!("failed to read {}", input.display()))?;
                let artifact = SealedArtifact::seal(label, &bytes, &passphrase, aad.as_bytes())?;
                write_json_file(&output, &artifact)?;
                print_json(&json!({
                    "output": output,
                    "sealed": true,
                }))
            }
            SealCommands::Open {
                input,
                output,
                passphrase_file,
            } => {
                let passphrase = read_passphrase_file(&passphrase_file)?;
                let artifact: SealedArtifact =
                    read_json_file(&input).context("sealed artifact must be JSON")?;
                let plaintext = artifact.open(&passphrase)?;
                if let Some(parent) = output.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&output, plaintext)
                    .with_context(|| format!("failed to write {}", output.display()))?;
                print_json(&json!({
                    "output": output,
                    "opened": true,
                }))
            }
        },
        Commands::Vault { command } => match command {
            VaultCommands::Init {
                ledger,
                passphrase_file,
                mission,
                operator,
            } => print_json(&vault_init(&ledger, &passphrase_file, &mission, &operator)?),
            VaultCommands::Append {
                ledger,
                passphrase_file,
                actor,
                role,
                action,
                subject,
                priority,
                payload,
            } => {
                let payload = read_payload(&payload)?;
                print_json(&vault_append(VaultAppendRequest {
                    ledger,
                    passphrase_file,
                    actor,
                    role,
                    action,
                    subject,
                    priority,
                    payload,
                })?)
            }
            VaultCommands::Verify {
                ledger,
                passphrase_file,
            } => print_json(&vault_verify(&ledger, &passphrase_file)?),
            VaultCommands::Tail {
                ledger,
                passphrase_file,
                limit,
            } => print_json(&vault_tail(&ledger, &passphrase_file, limit)?),
        },
        Commands::Net { command } => match command {
            NetCommands::ServeOnce {
                bind,
                ledger,
                shared_key_file,
                peer_registry,
            } => {
                let shared_key = read_passphrase_file(&shared_key_file)?;
                let ledger = MissionLedger::open(ledger);
                let addr = match peer_registry {
                    Some(peer_registry) => {
                        let peer_registry = OperatorRegistry::load_from_file(peer_registry)?;
                        serve_ledger_once_with_peer_registry(
                            bind,
                            &ledger,
                            &shared_key,
                            &peer_registry,
                        )?
                    }
                    None => serve_ledger_once(bind, &ledger, &shared_key)?,
                };
                print_json(&json!({
                    "served": true,
                    "addr": addr.to_string(),
                }))
            }
            NetCommands::ServeDaemon {
                bind,
                ledger,
                shared_key_file,
                health_file,
                audit_log,
                peer_registry,
                max_requests,
                idle_timeout_seconds,
            } => print_json(&run_federation_daemon(FederationDaemonRequest {
                bind,
                ledger,
                shared_key_file,
                health_file,
                audit_log,
                peer_registry,
                max_requests,
                idle_timeout_seconds,
            })?),
            NetCommands::Fetch {
                addr,
                shared_key_file,
                identity,
                passphrase_file,
                output,
            } => {
                let shared_key = read_passphrase_file(&shared_key_file)?;
                let identity =
                    load_optional_peer_identity(identity.as_ref(), passphrase_file.as_ref())?;
                let snapshot = match identity.as_ref() {
                    Some(identity) => {
                        fetch_ledger_snapshot_with_identity(addr, &shared_key, identity)?
                    }
                    None => fetch_ledger_snapshot(addr, &shared_key)?,
                };
                write_json_file(&output, &snapshot.events)?;
                print_json(&json!({
                    "output": output,
                    "events": snapshot.events.len(),
                    "valid": snapshot.verification.valid,
                    "peer_identity_signed": identity.is_some(),
                }))
            }
            NetCommands::PlanPeers {
                ledger,
                manifest,
                shared_key_file,
                identity,
                passphrase_file,
                output,
            } => {
                let ledger = MissionLedger::open(ledger);
                let verification = ledger.verify()?;
                if !verification.valid {
                    bail!("local ledger is corrupt: {:?}", verification.failures);
                }
                let peers = read_peer_manifest(&manifest)?;
                let shared_key = read_passphrase_file(&shared_key_file)?;
                let identity =
                    load_optional_peer_identity(identity.as_ref(), passphrase_file.as_ref())?;
                let events = ledger.load_events()?;
                let report = match identity.as_ref() {
                    Some(identity) => {
                        plan_multi_peer_sync_with_identity(&events, &peers, &shared_key, identity)
                    }
                    None => plan_multi_peer_sync(&events, &peers, &shared_key),
                };
                match output {
                    Some(output) => {
                        write_json_file(&output, &report)?;
                        print_json(&json!({
                            "output": output,
                            "peers": report.peers.len(),
                        }))
                    }
                    None => print_json(&report),
                }
            }
        },
        Commands::PeerQueue { command } => match command {
            PeerQueueCommands::Enqueue {
                queue,
                manifest,
                max_attempts,
            } => {
                let peers = read_peer_manifest(&manifest)?;
                let queue = PeerSyncQueue::open(queue)?;
                print_json(&queue.enqueue_peers(peers, max_attempts)?)
            }
            PeerQueueCommands::List { queue, status } => {
                let queue = PeerSyncQueue::open(queue)?;
                let status = status
                    .map(|status| {
                        status
                            .parse::<QueueStatus>()
                            .with_context(|| format!("invalid queue status '{}'", status))
                    })
                    .transpose()?;
                print_json(&queue.list(status)?)
            }
            PeerQueueCommands::Summary { queue } => {
                let queue = PeerSyncQueue::open(queue)?;
                print_json(&queue.summary()?)
            }
            PeerQueueCommands::Health {
                queue,
                stale_after_seconds,
            } => {
                if stale_after_seconds < 0 {
                    bail!("stale threshold cannot be negative");
                }
                let queue = PeerSyncQueue::open(queue)?;
                print_json(&queue.health(Duration::seconds(stale_after_seconds))?)
            }
            PeerQueueCommands::Process {
                queue,
                ledger,
                shared_key_file,
                identity,
                passphrase_file,
                limit,
                retry_delay_seconds,
            } => {
                if retry_delay_seconds < 0 {
                    bail!("retry delay cannot be negative");
                }
                let shared_key = read_passphrase_file(&shared_key_file)?;
                let identity =
                    load_optional_peer_identity(identity.as_ref(), passphrase_file.as_ref())?;
                let queue = PeerSyncQueue::open(queue)?;
                let ledger = MissionLedger::open(ledger);
                let options = QueueProcessOptions {
                    limit,
                    retry_delay: Duration::seconds(retry_delay_seconds),
                };
                let report = match identity.as_ref() {
                    Some(identity) => queue.process_due_with(&ledger, options, |peer| {
                        fetch_ledger_snapshot_with_identity(
                            peer.addr.as_str(),
                            &shared_key,
                            identity,
                        )
                    })?,
                    None => queue.process_due_with_shared_key(&ledger, &shared_key, options)?,
                };
                print_json(&report)
            }
            PeerQueueCommands::Worker {
                queue,
                ledger,
                shared_key_file,
                identity,
                passphrase_file,
                limit,
                retry_delay_seconds,
                interval_seconds,
                cycles,
                health_file,
                audit_log,
                stale_after_seconds,
            } => print_json(&run_peer_queue_worker(PeerQueueWorkerRequest {
                queue,
                ledger,
                shared_key_file,
                identity,
                passphrase_file,
                limit,
                retry_delay_seconds,
                interval_seconds,
                cycles,
                health_file,
                audit_log,
                stale_after_seconds,
            })?),
        },
        Commands::Harvest { command } => match command {
            HarvestCommands::Geojson {
                url,
                output,
                limit,
                bbox,
            } => {
                let result = harvest_geojson(HarvestRequest { url, limit, bbox })?;
                write_text_file(&output, &result.feature_set.to_json_lines()?)?;
                print_json(&json!({
                    "source_url": result.source_url,
                    "final_url": result.final_url,
                    "output": output,
                    "features": result.feature_set.summary.feature_count,
                }))
            }
            HarvestCommands::Profile { profile, output } => {
                let profile: SourceProfile =
                    read_json_file(&profile).context("source profile must be JSON")?;
                let result = harvest_profile(&profile)?;
                write_text_file(&output, &result.feature_set.to_json_lines()?)?;
                print_json(&json!({
                    "profile": result.profile,
                    "final_url": result.final_url,
                    "from_cache": result.from_cache,
                    "attempts": result.attempts,
                    "features": result.feature_set.summary.feature_count,
                    "output": output,
                }))
            }
        },
        Commands::Recommend { command } => match command {
            RecommendCommands::Rules {
                rules,
                readings,
                output,
            } => {
                let rules: Vec<RecommendationRule> =
                    read_json_file(&rules).context("rules must be a JSON array")?;
                let readings: Vec<SensorReading> =
                    read_json_file(&readings).context("readings must be a JSON array")?;
                let report = run_recommendation_rules(&rules, &readings)?;
                match output {
                    Some(output) => {
                        write_json_file(&output, &report.bundles)?;
                        print_json(&json!({
                            "output": output,
                            "rules": report.rules,
                            "readings": report.readings,
                            "bundles": report.bundles.len(),
                        }))
                    }
                    None => print_json(&report),
                }
            }
            RecommendCommands::ModelOutput {
                mission,
                evidence,
                candidates,
                output,
            } => {
                let evidence: Vec<EvidenceItem> =
                    read_json_file(&evidence).context("evidence must be a JSON array")?;
                let candidates: Vec<ModelRecommendationCandidate> =
                    read_json_file(&candidates).context("candidates must be a JSON array")?;
                let report = build_model_recommendation_bundles(mission, &evidence, &candidates)?;
                match output {
                    Some(output) => {
                        write_json_file(&output, &report.bundles)?;
                        print_json(&json!({
                            "output": output,
                            "candidates": report.candidates,
                            "evidence_items": report.evidence_items,
                            "bundles": report.bundles.len(),
                        }))
                    }
                    None => print_json(&report),
                }
            }
            RecommendCommands::AiRun {
                mission,
                evidence,
                command,
                args,
                working_directory,
                timeout_ms,
                max_stdout_bytes,
                max_stderr_bytes,
                clear_environment,
                instructions,
                output,
            } => {
                let evidence: Vec<EvidenceItem> =
                    read_json_file(&evidence).context("evidence must be a JSON array")?;
                let mut request = AiRunnerRequest::new(mission, evidence);
                request.instructions = instructions;
                let report = run_evidence_bound_runner(
                    &AiRunnerConfig {
                        command,
                        args,
                        working_directory,
                        timeout_ms,
                        max_stdout_bytes,
                        max_stderr_bytes,
                        clear_environment,
                    },
                    request,
                )?;
                match output {
                    Some(output) => {
                        write_json_file(&output, &report.bundles)?;
                        print_json(&json!({
                            "output": output,
                            "evidence_items": report.evidence_items,
                            "candidates": report.candidates,
                            "bundles": report.bundles.len(),
                            "stdout_sha256": report.stdout_sha256,
                            "duration_ms": report.duration_ms,
                        }))
                    }
                    None => print_json(&report),
                }
            }
        },
        Commands::Report { command } => match command {
            ReportCommands::Markdown {
                db,
                output,
                title,
                evidence_bundle,
            } => {
                let store = MissionStore::open(db)?;
                let bundles = evidence_bundle
                    .iter()
                    .map(read_json_file::<EvidenceBundle>)
                    .collect::<Result<Vec<_>>>()?;
                for bundle in &bundles {
                    bundle.verify()?;
                }
                let report =
                    IncidentReport::new(title, store.summary()?, store.export_events()?, bundles);
                write_text_file(&output, &report.to_markdown())?;
                print_json(&json!({
                    "output": output,
                    "report": "markdown",
                }))
            }
            ReportCommands::Bundle {
                db,
                output,
                title,
                evidence_bundle,
            } => {
                let store = MissionStore::open(db)?;
                let bundles = evidence_bundle
                    .iter()
                    .map(read_json_file::<EvidenceBundle>)
                    .collect::<Result<Vec<_>>>()?;
                for bundle in &bundles {
                    bundle.verify()?;
                }
                let report =
                    IncidentReport::new(title, store.summary()?, store.export_events()?, bundles);
                let bundle = ReportBundle::new(report);
                write_json_file(&output, &bundle)?;
                print_json(&json!({
                    "output": output,
                    "report": "bundle",
                }))
            }
        },
        Commands::Dashboard { command } => match command {
            DashboardCommands::Export {
                ledger,
                output,
                title,
                db,
                approvals,
                peer_queue,
                evidence_bundle,
                map_href,
            } => {
                let dashboard = build_dashboard_document(
                    &ledger,
                    title,
                    approvals,
                    db,
                    peer_queue,
                    &evidence_bundle,
                    map_href,
                )?;
                write_text_file(&output, &dashboard.to_html())?;
                print_json(&json!({
                    "output": output,
                    "events": dashboard.recent_events.len(),
                    "approvals": dashboard.approvals.len(),
                    "peer_health_status": dashboard.peer_health.as_ref().map(|health| health.status),
                    "peer_due": dashboard.peer_health.as_ref().map(|health| health.due).unwrap_or(0),
                    "peer_stale_retrying": dashboard.peer_health.as_ref().map(|health| health.stale_retrying).unwrap_or(0),
                    "peer_jobs": dashboard.peer_jobs.len(),
                    "evidence_bundles": dashboard.evidence_bundles.len(),
                    "audit_timeline": dashboard.audit_timeline.len(),
                }))
            }
            DashboardCommands::Serve {
                ledger,
                bind,
                title,
                db,
                approvals,
                peer_queue,
                evidence_bundle,
                map_href,
                refresh_seconds,
                max_requests,
            } => print_json(&serve_dashboard(DashboardServeRequest {
                ledger,
                bind,
                title,
                db,
                approvals,
                peer_queue,
                evidence_bundle,
                map_href,
                refresh_seconds,
                max_requests,
            })?),
        },
        Commands::Ui { command } => match command {
            UiCommands::Serve {
                ledger,
                bind,
                title,
                db,
                approvals,
                peer_queue,
                evidence_bundle,
                map_href,
                refresh_seconds,
                max_requests,
            } => print_json(&serve_operator_console(UiServeRequest {
                ledger,
                bind,
                title,
                db,
                approvals,
                peer_queue,
                evidence_bundle,
                map_href,
                refresh_seconds,
                max_requests,
            })?),
        },
        Commands::Ops { command } => match command {
            OpsCommands::Bundle {
                ledger,
                output_dir,
                title,
                db,
                approvals,
                identity,
                peer_queue,
                evidence_bundle,
                features,
                provenance,
                signature,
                quorum,
                release_policy,
            } => print_json(&export_ops_bundle(OpsBundleRequest {
                ledger,
                output_dir,
                title,
                db,
                approvals,
                identities: identity,
                peer_queue,
                evidence_bundle,
                features,
                provenance,
                signatures: signature,
                quorum,
                release_policy,
            })?),
            OpsCommands::AcceptancePack { output_dir, title } => {
                print_json(&write_acceptance_pack(&output_dir, &title)?)
            }
            OpsCommands::ReleaseEvidencePack {
                output_dir,
                provenance,
                signature,
                quorum,
                policy,
            } => print_json(&write_release_evidence_pack(ReleaseEvidencePackRequest {
                output_dir,
                provenance,
                signatures: signature,
                quorum,
                policy,
            })?),
            OpsCommands::Backup {
                profile,
                output,
                passphrase_file,
            } => print_json(&write_workspace_backup(BackupRequest {
                profile,
                output,
                passphrase_file,
            })?),
            OpsCommands::Restore {
                input,
                output_dir,
                passphrase_file,
                overwrite,
            } => print_json(&restore_workspace_backup(RestoreRequest {
                input,
                output_dir,
                passphrase_file,
                overwrite,
            })?),
            OpsCommands::ReadinessGate {
                ledger,
                db,
                identity,
                approvals,
                peer_queue,
                provenance,
                signature,
                quorum,
                policy,
                cycles,
                interval_seconds,
                fail_on_warning,
                output,
            } => {
                let report = run_readiness_gate(ReadinessGateRequest {
                    ledger,
                    db,
                    identities: identity,
                    approvals,
                    peer_queue,
                    provenance,
                    signatures: signature,
                    quorum,
                    policy,
                    cycles,
                    interval_seconds,
                    fail_on_warning,
                })?;
                if let Some(output) = output {
                    write_json_file(&output, &report)?;
                }
                print_json(&report)?;
                if !report["healthy"].as_bool().unwrap_or(false) {
                    bail!("readiness gate failed");
                }
                Ok(())
            }
            OpsCommands::ArtifactRetention {
                root,
                max_cache_age_days,
                keep_dist_releases,
                include_target_cache,
                delete,
                output,
            } => {
                let report = run_artifact_retention(ArtifactRetentionRequest {
                    root,
                    max_cache_age_days,
                    keep_dist_releases,
                    include_target_cache,
                    delete,
                })?;
                if let Some(output) = output {
                    write_json_file(&output, &report)?;
                }
                print_json(&report)
            }
        },
        Commands::Doctor { command } => match command {
            DoctorCommands::Profile { profile } => print_json(&run_profile_doctor(&profile)?),
            DoctorCommands::Workspace {
                ledger,
                db,
                identity,
                approvals,
                peer_queue,
            } => print_json(&run_doctor(DoctorInput {
                ledger,
                db,
                identities: identity,
                approvals,
                peer_queue,
            })),
            DoctorCommands::Release {
                provenance,
                signature,
                quorum,
                policy,
            } => print_json(&run_release_doctor(ReleaseDoctorInput {
                provenance,
                signatures: signature,
                quorum,
                policy,
            })),
        },
        Commands::Provenance { command } => match command {
            ProvenanceCommands::Verify { input } => {
                let provenance = PackageProvenance::load(&input)?;
                let report = provenance.verify_hashes(&input)?;
                print_json(&report)?;
                if !report.valid {
                    bail!("provenance verification failed");
                }
                Ok(())
            }
            ProvenanceCommands::Sign {
                input,
                output,
                identity,
                passphrase_file,
                passphrase_os_key,
            } => {
                let keypair = load_keypair(
                    &identity,
                    passphrase_file.as_ref(),
                    passphrase_os_key.as_ref(),
                )?;
                let envelope = ProvenanceSignatureEnvelope::sign_file(&input, &keypair)?;
                let output = output.unwrap_or_else(|| default_signature_output_path(&input));
                write_json_file(&output, &envelope)?;
                print_json(&json!({
                    "output": output,
                    "provenance": input,
                    "signer": envelope.signature.identity,
                    "provenance_sha256": envelope.provenance_sha256,
                }))
            }
            ProvenanceCommands::VerifySignature { signature } => {
                let envelope = ProvenanceSignatureEnvelope::load(&signature)?;
                let report = envelope.verify(&signature)?;
                print_json(&report)?;
                if !report.valid {
                    bail!("provenance signature verification failed");
                }
                Ok(())
            }
            ProvenanceCommands::QuorumCreate {
                output,
                threshold,
                signature,
            } => {
                let signatures = signature
                    .iter()
                    .map(ProvenanceSignatureEnvelope::load)
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let quorum = ProvenanceQuorumEnvelope::new(threshold, signatures)?;
                write_json_file(&output, &quorum)?;
                print_json(&json!({
                    "output": output,
                    "threshold": quorum.threshold,
                    "signatures": quorum.signatures.len(),
                }))
            }
            ProvenanceCommands::QuorumVerify { input } => {
                let quorum = ProvenanceQuorumEnvelope::load(&input)?;
                let report = quorum.verify(&input)?;
                print_json(&report)?;
                if !report.valid {
                    bail!("provenance quorum verification failed");
                }
                Ok(())
            }
            ProvenanceCommands::PolicyTemplate {
                output,
                package,
                version,
                target,
                min_distinct_valid_signers,
                required_signer_id,
                allowed_signer_id,
                require_clean_git,
            } => {
                let policy = ReleaseCustodyPolicy {
                    schema: 1,
                    package,
                    version,
                    target,
                    min_distinct_valid_signers,
                    required_signer_ids: required_signer_id,
                    allowed_signer_ids: allowed_signer_id,
                    require_clean_git,
                };
                policy.validate()?;
                write_json_file(&output, &policy)?;
                print_json(&json!({
                    "output": output,
                    "min_distinct_valid_signers": policy.min_distinct_valid_signers,
                    "required_signers": policy.required_signer_ids.len(),
                    "allowed_signers": policy.allowed_signer_ids.len(),
                }))
            }
            ProvenanceCommands::PolicyVerify {
                policy,
                provenance,
                quorum,
            } => {
                let policy_doc = ReleaseCustodyPolicy::load(&policy)?;
                let package = PackageProvenance::load(&provenance)?;
                let package_report = package.verify_hashes(&provenance)?;
                if !package_report.valid {
                    print_json(&package_report)?;
                    bail!("provenance verification failed");
                }
                let quorum_doc = ProvenanceQuorumEnvelope::load(&quorum)?;
                let quorum_report = quorum_doc.verify(&quorum)?;
                let report = policy_doc.verify(&package, &quorum_report)?;
                print_json(&report)?;
                if !report.valid {
                    bail!("release custody policy verification failed");
                }
                Ok(())
            }
            ProvenanceCommands::CustodyPack {
                provenance,
                output_dir,
                identity,
                passphrase_file,
                passphrase_os_key,
                threshold,
                require_clean_git,
            } => print_json(&write_release_custody_pack(ReleaseCustodyPackRequest {
                provenance,
                output_dir,
                identities: identity,
                passphrase_files: passphrase_file,
                passphrase_os_keys: passphrase_os_key,
                threshold,
                require_clean_git,
            })?),
        },
        Commands::Approval { command } => match command {
            ApprovalCommands::Verify { queue } => {
                let approvals = ApprovalLog::open(queue);
                print_json(&approvals.verify()?)
            }
            ApprovalCommands::Submit {
                queue,
                draft,
                requested_by,
            } => {
                let draft: CommandDraft =
                    read_json_file(&draft).context("draft must be valid JSON")?;
                let approvals = ApprovalLog::open(queue);
                print_json(&approvals.submit_draft(draft, requested_by)?)
            }
            ApprovalCommands::List { queue, status } => {
                let approvals = ApprovalLog::open(queue);
                let mut items = approvals.list_items()?;
                if let Some(status) = status {
                    let status = status
                        .parse::<ApprovalStatus>()
                        .with_context(|| format!("invalid approval status '{}'", status))?;
                    items.retain(|item| item.status == status);
                }
                print_json(&items)
            }
            ApprovalCommands::Approve {
                queue,
                id,
                reviewed_by,
                reason,
            } => {
                let approvals = ApprovalLog::open(queue);
                print_json(&approvals.approve(&id, reviewed_by, reason)?)
            }
            ApprovalCommands::Reject {
                queue,
                id,
                reviewed_by,
                reason,
            } => {
                let approvals = ApprovalLog::open(queue);
                print_json(&approvals.reject(&id, reviewed_by, reason)?)
            }
            ApprovalCommands::AppendApproved {
                queue,
                id,
                ledger,
                identity,
                passphrase_file,
                passphrase_os_key,
                registry,
                executed_by,
            } => {
                let approvals = ApprovalLog::open(queue);
                let request = approvals.approved_request(&id)?;
                let keypair = load_keypair(
                    &identity,
                    passphrase_file.as_ref(),
                    passphrase_os_key.as_ref(),
                )?;
                let signed = keypair.sign_request(request)?;
                let ledger = MissionLedger::open(ledger);
                let event = match registry {
                    Some(registry_path) => {
                        let registry = OperatorRegistry::load_from_file(registry_path)?;
                        ledger.append_signed_with_registry(signed, &registry)?
                    }
                    None => ledger.append_signed(signed)?,
                };
                let approval = approvals.mark_executed(&id, executed_by, event.hash.clone())?;
                print_json(&json!({
                    "approval": approval,
                    "event": event,
                }))
            }
            ApprovalCommands::MarkExecuted {
                queue,
                id,
                executed_by,
                ledger_event_hash,
            } => {
                let approvals = ApprovalLog::open(queue);
                print_json(&approvals.mark_executed(&id, executed_by, ledger_event_hash)?)
            }
        },
        Commands::Scenario { command } => match command {
            ScenarioCommands::Run {
                input,
                workdir,
                output,
            } => {
                let report = run_scenario_file(&input, &workdir)?;
                match output {
                    Some(output) => {
                        write_json_file(&output, &report)?;
                        print_json(&json!({
                            "output": output,
                            "steps": report.steps.len(),
                        }))
                    }
                    None => print_json(&report),
                }
            }
        },
        Commands::Workflow { command } => match command {
            WorkflowCommands::Draft {
                ledger,
                bundle,
                actor,
                role,
                min_confidence,
                output,
            } => {
                let ledger = MissionLedger::open(ledger);
                let state = MissionState::from_ledger(&ledger)?;
                let bundle: EvidenceBundle =
                    read_json_file(&bundle).context("evidence bundle must be JSON")?;
                let draft = WorkflowPlanner { min_confidence }.draft_command(
                    &state,
                    &bundle,
                    actor_from_parts(actor, role),
                )?;
                match output {
                    Some(output) => {
                        write_json_file(&output, &draft)?;
                        print_json(&json!({
                            "output": output,
                            "status": draft.status,
                        }))
                    }
                    None => print_json(&draft),
                }
            }
        },
        Commands::Supervisor { command } => match command {
            SupervisorCommands::SystemdPeerWorker {
                output,
                unit_name,
                description,
                user,
                restart_seconds,
                spec,
            } => {
                let unit = SystemdPeerWorkerUnit {
                    unit_name,
                    description,
                    user,
                    restart_seconds,
                    spec: spec.into(),
                };
                let rendered = unit.render()?;
                write_text_file(&output, &rendered)?;
                print_json(&json!({
                    "output": output,
                    "kind": "systemd-peer-worker",
                }))
            }
            SupervisorCommands::WindowsPeerWorker {
                output,
                task_name,
                spec,
            } => {
                let task = WindowsPeerWorkerTask {
                    task_name,
                    spec: spec.into(),
                };
                let rendered = task.render()?;
                write_text_file(&output, &rendered)?;
                print_json(&json!({
                    "output": output,
                    "kind": "windows-peer-worker",
                }))
            }
            SupervisorCommands::SystemdPeerWorkerKit {
                output_dir,
                unit_name,
                description,
                user,
                restart_seconds,
                spec,
            } => {
                let unit = SystemdPeerWorkerUnit {
                    unit_name: unit_name.clone(),
                    description,
                    user,
                    restart_seconds,
                    spec: spec.into(),
                };
                fs::create_dir_all(&output_dir)?;
                let unit_path = output_dir.join(&unit_name);
                let install_path = output_dir.join("install-systemd-peer-worker.sh");
                let uninstall_path = output_dir.join("uninstall-systemd-peer-worker.sh");
                write_text_file(&unit_path, &unit.render()?)?;
                write_text_file(&install_path, &unit.render_install_script()?)?;
                write_text_file(&uninstall_path, &unit.render_uninstall_script()?)?;
                print_json(&json!({
                    "output_dir": output_dir,
                    "unit": unit_path,
                    "install": install_path,
                    "uninstall": uninstall_path,
                    "kind": "systemd-peer-worker-kit",
                }))
            }
            SupervisorCommands::WindowsPeerWorkerKit {
                output_dir,
                task_name,
                spec,
            } => {
                let task = WindowsPeerWorkerTask {
                    task_name,
                    spec: spec.into(),
                };
                fs::create_dir_all(&output_dir)?;
                let install_path = output_dir.join("install-windows-peer-worker.ps1");
                let uninstall_path = output_dir.join("uninstall-windows-peer-worker.ps1");
                write_text_file(&install_path, &task.render()?)?;
                write_text_file(&uninstall_path, &task.render_uninstall_script()?)?;
                print_json(&json!({
                    "output_dir": output_dir,
                    "install": install_path,
                    "uninstall": uninstall_path,
                    "kind": "windows-peer-worker-kit",
                }))
            }
            SupervisorCommands::SystemdFederationDaemon {
                output,
                unit_name,
                description,
                user,
                restart_seconds,
                spec,
            } => {
                let unit = SystemdFederationDaemonUnit {
                    unit_name,
                    description,
                    user,
                    restart_seconds,
                    spec: spec.into(),
                };
                let rendered = unit.render()?;
                write_text_file(&output, &rendered)?;
                print_json(&json!({
                    "output": output,
                    "kind": "systemd-federation-daemon",
                }))
            }
            SupervisorCommands::WindowsFederationDaemon {
                output,
                task_name,
                spec,
            } => {
                let task = WindowsFederationDaemonTask {
                    task_name,
                    spec: spec.into(),
                };
                let rendered = task.render()?;
                write_text_file(&output, &rendered)?;
                print_json(&json!({
                    "output": output,
                    "kind": "windows-federation-daemon",
                }))
            }
            SupervisorCommands::SystemdFederationDaemonKit {
                output_dir,
                unit_name,
                description,
                user,
                restart_seconds,
                spec,
            } => {
                let unit = SystemdFederationDaemonUnit {
                    unit_name: unit_name.clone(),
                    description,
                    user,
                    restart_seconds,
                    spec: spec.into(),
                };
                fs::create_dir_all(&output_dir)?;
                let unit_path = output_dir.join(&unit_name);
                let install_path = output_dir.join("install-systemd-federation-daemon.sh");
                let uninstall_path = output_dir.join("uninstall-systemd-federation-daemon.sh");
                write_text_file(&unit_path, &unit.render()?)?;
                write_text_file(&install_path, &unit.render_install_script()?)?;
                write_text_file(&uninstall_path, &unit.render_uninstall_script()?)?;
                print_json(&json!({
                    "output_dir": output_dir,
                    "unit": unit_path,
                    "install": install_path,
                    "uninstall": uninstall_path,
                    "kind": "systemd-federation-daemon-kit",
                }))
            }
            SupervisorCommands::WindowsFederationDaemonKit {
                output_dir,
                task_name,
                spec,
            } => {
                let task = WindowsFederationDaemonTask {
                    task_name,
                    spec: spec.into(),
                };
                fs::create_dir_all(&output_dir)?;
                let install_path = output_dir.join("install-windows-federation-daemon.ps1");
                let uninstall_path = output_dir.join("uninstall-windows-federation-daemon.ps1");
                write_text_file(&install_path, &task.render()?)?;
                write_text_file(&uninstall_path, &task.render_uninstall_script()?)?;
                print_json(&json!({
                    "output_dir": output_dir,
                    "install": install_path,
                    "uninstall": uninstall_path,
                    "kind": "windows-federation-daemon-kit",
                }))
            }
            SupervisorCommands::WatchdogRun {
                name,
                command,
                args,
                working_directory,
                audit_log,
                max_restarts,
                restart_delay_ms,
                success_exit_code,
            } => {
                let report = run_worker_watchdog(WorkerWatchdogRequest {
                    name,
                    command,
                    args,
                    working_directory,
                    audit_log,
                    max_restarts,
                    restart_delay_ms,
                    success_exit_code,
                })?;
                print_json(&report)?;
                if !report.healthy {
                    bail!("worker watchdog exhausted restart budget");
                }
                Ok(())
            }
        },
    }
}

struct OpsBundleRequest {
    ledger: PathBuf,
    output_dir: PathBuf,
    title: String,
    db: Option<PathBuf>,
    approvals: Option<PathBuf>,
    identities: Vec<PathBuf>,
    peer_queue: Option<PathBuf>,
    evidence_bundle: Vec<PathBuf>,
    features: Option<PathBuf>,
    provenance: Option<PathBuf>,
    signatures: Vec<PathBuf>,
    quorum: Option<PathBuf>,
    release_policy: Option<PathBuf>,
}

struct FirstRunRequest {
    root: PathBuf,
    profile: PathBuf,
    mission: String,
    operator_name: String,
    role: Role,
    authority: String,
    ledger: PathBuf,
    db: PathBuf,
    identity: PathBuf,
    passphrase_file: PathBuf,
    registry: PathBuf,
    approvals: PathBuf,
    peer_queue: PathBuf,
    reports_dir: PathBuf,
    backups_dir: PathBuf,
    force: bool,
}

struct DashboardServeRequest {
    ledger: PathBuf,
    bind: String,
    title: String,
    db: Option<PathBuf>,
    approvals: Option<PathBuf>,
    peer_queue: Option<PathBuf>,
    evidence_bundle: Vec<PathBuf>,
    map_href: Option<String>,
    refresh_seconds: u64,
    max_requests: Option<u32>,
}

struct UiServeRequest {
    ledger: PathBuf,
    bind: String,
    title: String,
    db: Option<PathBuf>,
    approvals: Option<PathBuf>,
    peer_queue: Option<PathBuf>,
    evidence_bundle: Vec<PathBuf>,
    map_href: Option<String>,
    refresh_seconds: u64,
    max_requests: Option<u32>,
}

struct MapServeRequest {
    input: PathBuf,
    ledger: PathBuf,
    bind: String,
    title: String,
    refresh_seconds: u64,
    max_requests: Option<u32>,
}

struct ReleaseCustodyPackRequest {
    provenance: PathBuf,
    output_dir: PathBuf,
    identities: Vec<PathBuf>,
    passphrase_files: Vec<PathBuf>,
    passphrase_os_keys: Vec<PathBuf>,
    threshold: usize,
    require_clean_git: bool,
}

struct ReleaseEvidencePackRequest {
    output_dir: PathBuf,
    provenance: PathBuf,
    signatures: Vec<PathBuf>,
    quorum: PathBuf,
    policy: PathBuf,
}

struct ReadinessGateRequest {
    ledger: PathBuf,
    db: Option<PathBuf>,
    identities: Vec<PathBuf>,
    approvals: Option<PathBuf>,
    peer_queue: Option<PathBuf>,
    provenance: Option<PathBuf>,
    signatures: Vec<PathBuf>,
    quorum: Option<PathBuf>,
    policy: Option<PathBuf>,
    cycles: u32,
    interval_seconds: u64,
    fail_on_warning: bool,
}

struct BackupRequest {
    profile: PathBuf,
    output: PathBuf,
    passphrase_file: PathBuf,
}

struct RestoreRequest {
    input: PathBuf,
    output_dir: PathBuf,
    passphrase_file: PathBuf,
    overwrite: bool,
}

struct TeamSessionIssueRequest {
    identity: PathBuf,
    registry: PathBuf,
    output: PathBuf,
    passphrase_file: Option<PathBuf>,
    passphrase_os_key: Option<PathBuf>,
    ttl_minutes: i64,
}

struct TeamAppendRequest {
    ledger: PathBuf,
    identity: PathBuf,
    passphrase_file: Option<PathBuf>,
    passphrase_os_key: Option<PathBuf>,
    registry: PathBuf,
    session: PathBuf,
    policy_pack: Option<PathBuf>,
    policy_signature: Option<PathBuf>,
    action: Action,
    subject: String,
    priority: Priority,
    payload: Value,
}

struct DevicePairingRequest {
    identity: PathBuf,
    registry: PathBuf,
    output: PathBuf,
    device_id: String,
    device_name: String,
    passphrase_file: Option<PathBuf>,
    passphrase_os_key: Option<PathBuf>,
    ttl_minutes: i64,
}

struct RotateOperatorRequest {
    registry: PathBuf,
    old_operator_id: String,
    new_identity: PathBuf,
    new_name: String,
    new_role: Role,
    new_passphrase_file: PathBuf,
    issued_by: String,
    revoked_by: String,
    reason: String,
    proof_output: PathBuf,
}

struct VaultAppendRequest {
    ledger: PathBuf,
    passphrase_file: PathBuf,
    actor: String,
    role: Role,
    action: Action,
    subject: String,
    priority: Priority,
    payload: Value,
}

struct ArtifactRetentionRequest {
    root: PathBuf,
    max_cache_age_days: i64,
    keep_dist_releases: usize,
    include_target_cache: bool,
    delete: bool,
}

struct WorkerWatchdogRequest {
    name: String,
    command: String,
    args: Vec<String>,
    working_directory: Option<PathBuf>,
    audit_log: PathBuf,
    max_restarts: u32,
    restart_delay_ms: u64,
    success_exit_code: i32,
}

struct FederationDaemonRequest {
    bind: String,
    ledger: PathBuf,
    shared_key_file: PathBuf,
    health_file: Option<PathBuf>,
    audit_log: Option<PathBuf>,
    peer_registry: Option<PathBuf>,
    max_requests: Option<u32>,
    idle_timeout_seconds: u64,
}

struct PeerQueueWorkerRequest {
    queue: PathBuf,
    ledger: PathBuf,
    shared_key_file: PathBuf,
    identity: Option<PathBuf>,
    passphrase_file: Option<PathBuf>,
    limit: u32,
    retry_delay_seconds: i64,
    interval_seconds: u64,
    cycles: Option<u32>,
    health_file: Option<PathBuf>,
    audit_log: Option<PathBuf>,
    stale_after_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PeerQueueWorkerReport {
    healthy: bool,
    status: String,
    queue: PathBuf,
    ledger: PathBuf,
    signed_identity: bool,
    cycles: u32,
    processed_results: usize,
    succeeded: usize,
    retry_scheduled: usize,
    failed: usize,
    health_file: Option<PathBuf>,
    audit_log: Option<PathBuf>,
    stale_after_seconds: i64,
    last_health: QueueHealthSnapshot,
    cycle_summaries: Vec<Value>,
    last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FederationDaemonReport {
    healthy: bool,
    status: String,
    bind: String,
    local_addr: String,
    ledger: PathBuf,
    ledger_sha256: String,
    accepted_requests: u32,
    served_requests: u32,
    failed_requests: u32,
    max_requests: Option<u32>,
    idle_timeout_seconds: u64,
    health_file: Option<PathBuf>,
    audit_log: Option<PathBuf>,
    peer_registry: Option<PathBuf>,
    peer_authorization_required: bool,
    last_error: Option<String>,
}

struct FederationHealthSnapshot<'a> {
    status: &'a str,
    accepted_requests: u32,
    served_requests: u32,
    failed_requests: u32,
    last_error: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct WorkerWatchdogReport {
    healthy: bool,
    status: String,
    name: String,
    command: String,
    args_count: usize,
    working_directory: Option<PathBuf>,
    audit_log: PathBuf,
    attempts: Vec<WorkerWatchdogAttempt>,
    restarts: u32,
    max_restarts: u32,
    recovered: bool,
    final_exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct WorkerWatchdogAttempt {
    attempt: u32,
    exit_code: Option<i32>,
    success: bool,
    runtime_ms: u64,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum RegistryQuorumChangeKind {
    Enroll,
    Revoke,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TrustedRegistryBundle {
    schema: u16,
    authority: String,
    generated_at: String,
    registry_sha256: String,
    active_operators: usize,
    revoked_operators: usize,
    operators: Vec<OperatorRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RegistryQuorumProposal {
    schema: u16,
    authority: String,
    #[serde(with = "time::serde::rfc3339")]
    proposed_at: OffsetDateTime,
    registry_sha256: String,
    required_approvals: usize,
    nonce: String,
    change: RegistryQuorumChange,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RegistryQuorumChange {
    Enroll {
        identity: OperatorIdentity,
        issued_by: String,
    },
    Revoke {
        operator_id: String,
        revoked_by: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RegistryQuorumVerification {
    valid: bool,
    registry: PathBuf,
    proposal: PathBuf,
    authority: String,
    registry_sha256: String,
    proposal_registry_sha256: String,
    proposal_digest: String,
    required_approvals: usize,
    approved_signers: Vec<OperatorIdentity>,
    checks: Vec<Value>,
    signatures: Vec<Value>,
}

struct RegistryQuorumProposalRequest {
    registry: PathBuf,
    output: PathBuf,
    change: RegistryQuorumChangeKind,
    identity: Option<PathBuf>,
    operator_id: Option<String>,
    issued_by: String,
    revoked_by: String,
    reason: String,
    required_approvals: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct WorkspaceProfile {
    schema: u16,
    mission: String,
    created_at: String,
    root: PathBuf,
    ledger: PathBuf,
    db: PathBuf,
    registry: PathBuf,
    primary_identity: PathBuf,
    primary_passphrase_file: PathBuf,
    approvals: PathBuf,
    peer_queue: PathBuf,
    reports_dir: PathBuf,
    backups_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct WorkspaceBackup {
    schema: u16,
    created_at: String,
    profile_sha256: String,
    files: Vec<BackupEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct BackupEntry {
    path: String,
    kind: String,
    sha256: String,
    bytes_hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct KeyRotationProof {
    schema: u16,
    rotated_at: String,
    old_operator_id: String,
    new_operator_id: String,
    reason: String,
    registry: PathBuf,
    registry_sha256: String,
    revoked: OperatorRegistryEntry,
    enrolled: OperatorRegistryEntry,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TeamSession {
    schema: u16,
    identity: OperatorIdentity,
    issued_at_unix: i64,
    expires_at_unix: i64,
    registry_sha256: String,
    nonce: String,
    signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TeamSessionClaims {
    schema: u16,
    identity: OperatorIdentity,
    issued_at_unix: i64,
    expires_at_unix: i64,
    registry_sha256: String,
    nonce: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TeamSessionVerification {
    valid: bool,
    session: PathBuf,
    registry: PathBuf,
    identity: OperatorIdentity,
    expired: bool,
    checks: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DevicePairingBundle {
    schema: u16,
    device_id: String,
    device_name: String,
    operator: OperatorIdentity,
    issued_at_unix: i64,
    expires_at_unix: i64,
    registry_sha256: String,
    nonce: String,
    signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DevicePairingClaims {
    schema: u16,
    device_id: String,
    device_name: String,
    operator: OperatorIdentity,
    issued_at_unix: i64,
    expires_at_unix: i64,
    registry_sha256: String,
    nonce: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DevicePairingVerification {
    valid: bool,
    input: PathBuf,
    registry: PathBuf,
    device_id: String,
    operator: OperatorIdentity,
    expired: bool,
    checks: Vec<Value>,
}

fn run_federation_daemon(request: FederationDaemonRequest) -> Result<FederationDaemonReport> {
    validate_watchdog_value("bind", &request.bind)?;
    if let Some(max_requests) = request.max_requests
        && max_requests == 0
    {
        bail!("federation daemon max requests must be greater than zero");
    }
    let shared_key = read_passphrase_file(&request.shared_key_file)?;
    let peer_registry = request
        .peer_registry
        .as_ref()
        .map(OperatorRegistry::load_from_file)
        .transpose()?;
    let ledger = MissionLedger::open(&request.ledger);
    let verification = ledger.verify()?;
    if !verification.valid {
        bail!(
            "federation daemon refuses corrupt local ledger: {:?}",
            verification.failures
        );
    }
    let ledger_sha256 = sha256_file_hex(&request.ledger)?;
    let listener = TcpListener::bind(&request.bind)
        .with_context(|| format!("failed to bind federation daemon to {}", request.bind))?;
    listener.set_nonblocking(true)?;
    let local_addr = listener.local_addr()?.to_string();
    let mut accepted_requests = 0_u32;
    let mut served_requests = 0_u32;
    let mut failed_requests = 0_u32;
    let mut last_error = None;
    let mut last_activity = Instant::now();

    write_federation_health(
        &request,
        &local_addr,
        &ledger_sha256,
        FederationHealthSnapshot {
            status: "listening",
            accepted_requests: 0,
            served_requests: 0,
            failed_requests: 0,
            last_error: None,
        },
    )?;
    write_optional_jsonl(
        request.audit_log.as_ref(),
        json!({
            "event": "federation_daemon_started",
            "timestamp": OffsetDateTime::now_utc().to_string(),
            "bind": &request.bind,
            "local_addr": &local_addr,
            "ledger": &request.ledger,
            "ledger_sha256": &ledger_sha256,
            "peer_registry": &request.peer_registry,
            "peer_authorization_required": peer_registry.is_some(),
            "max_requests": request.max_requests,
            "idle_timeout_seconds": request.idle_timeout_seconds,
        }),
    )?;

    loop {
        if request
            .max_requests
            .is_some_and(|max_requests| accepted_requests >= max_requests)
        {
            break;
        }
        if request.idle_timeout_seconds > 0
            && last_activity.elapsed() >= StdDuration::from_secs(request.idle_timeout_seconds)
        {
            write_optional_jsonl(
                request.audit_log.as_ref(),
                json!({
                    "event": "federation_daemon_idle_timeout",
                    "timestamp": OffsetDateTime::now_utc().to_string(),
                    "local_addr": &local_addr,
                    "accepted_requests": accepted_requests,
                }),
            )?;
            break;
        }

        match listener.accept() {
            Ok((stream, peer_addr)) => {
                stream.set_nonblocking(false)?;
                accepted_requests = accepted_requests.saturating_add(1);
                last_activity = Instant::now();
                write_optional_jsonl(
                    request.audit_log.as_ref(),
                    json!({
                        "event": "peer_request_started",
                        "timestamp": OffsetDateTime::now_utc().to_string(),
                        "peer_addr": peer_addr.to_string(),
                        "accepted_requests": accepted_requests,
                    }),
                )?;
                let serve_result = match peer_registry.as_ref() {
                    Some(peer_registry) => serve_ledger_connection_with_peer_registry(
                        stream,
                        &ledger,
                        &shared_key,
                        peer_registry,
                    ),
                    None => serve_ledger_connection(stream, &ledger, &shared_key),
                };
                match serve_result {
                    Ok(()) => {
                        served_requests = served_requests.saturating_add(1);
                        write_optional_jsonl(
                            request.audit_log.as_ref(),
                            json!({
                                "event": "peer_request_served",
                                "timestamp": OffsetDateTime::now_utc().to_string(),
                                "peer_addr": peer_addr.to_string(),
                                "served_requests": served_requests,
                            }),
                        )?;
                    }
                    Err(error) => {
                        failed_requests = failed_requests.saturating_add(1);
                        let error = error.to_string();
                        last_error = Some(error.clone());
                        write_optional_jsonl(
                            request.audit_log.as_ref(),
                            json!({
                                "event": "peer_request_failed",
                                "timestamp": OffsetDateTime::now_utc().to_string(),
                                "peer_addr": peer_addr.to_string(),
                                "failed_requests": failed_requests,
                                "error": error,
                            }),
                        )?;
                    }
                }
                write_federation_health(
                    &request,
                    &local_addr,
                    &ledger_sha256,
                    FederationHealthSnapshot {
                        status: "listening",
                        accepted_requests,
                        served_requests,
                        failed_requests,
                        last_error: last_error.as_deref(),
                    },
                )?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(StdDuration::from_millis(50));
            }
            Err(error) => {
                let error = error.to_string();
                last_error = Some(error.clone());
                write_optional_jsonl(
                    request.audit_log.as_ref(),
                    json!({
                        "event": "federation_daemon_accept_failed",
                        "timestamp": OffsetDateTime::now_utc().to_string(),
                        "local_addr": &local_addr,
                        "error": error,
                    }),
                )?;
                break;
            }
        }
    }

    let healthy = last_error.is_none() || served_requests > 0;
    let status = if healthy { "stopped" } else { "failed" };
    write_federation_health(
        &request,
        &local_addr,
        &ledger_sha256,
        FederationHealthSnapshot {
            status,
            accepted_requests,
            served_requests,
            failed_requests,
            last_error: last_error.as_deref(),
        },
    )?;
    write_optional_jsonl(
        request.audit_log.as_ref(),
        json!({
            "event": "federation_daemon_stopped",
            "timestamp": OffsetDateTime::now_utc().to_string(),
            "local_addr": &local_addr,
            "accepted_requests": accepted_requests,
            "served_requests": served_requests,
            "failed_requests": failed_requests,
            "status": status,
            "last_error": &last_error,
        }),
    )?;

    Ok(FederationDaemonReport {
        healthy,
        status: status.to_owned(),
        bind: request.bind,
        local_addr,
        ledger: request.ledger,
        ledger_sha256,
        accepted_requests,
        served_requests,
        failed_requests,
        max_requests: request.max_requests,
        idle_timeout_seconds: request.idle_timeout_seconds,
        health_file: request.health_file,
        audit_log: request.audit_log,
        peer_registry: request.peer_registry,
        peer_authorization_required: peer_registry.is_some(),
        last_error,
    })
}

fn write_federation_health(
    request: &FederationDaemonRequest,
    local_addr: &str,
    ledger_sha256: &str,
    snapshot: FederationHealthSnapshot<'_>,
) -> Result<()> {
    let Some(path) = request.health_file.as_ref() else {
        return Ok(());
    };
    write_json_file(
        path,
        &json!({
            "schema": 1,
            "status": snapshot.status,
            "updated_at": OffsetDateTime::now_utc().to_string(),
            "bind": &request.bind,
            "local_addr": local_addr,
            "ledger": &request.ledger,
            "ledger_sha256": ledger_sha256,
            "peer_registry": &request.peer_registry,
            "peer_authorization_required": request.peer_registry.is_some(),
            "accepted_requests": snapshot.accepted_requests,
            "served_requests": snapshot.served_requests,
            "failed_requests": snapshot.failed_requests,
            "max_requests": request.max_requests,
            "idle_timeout_seconds": request.idle_timeout_seconds,
            "last_error": snapshot.last_error,
        }),
    )
}

fn write_optional_jsonl(path: Option<&PathBuf>, event: Value) -> Result<()> {
    if let Some(path) = path {
        write_jsonl_event(path, event)?;
    }
    Ok(())
}

fn run_worker_watchdog(request: WorkerWatchdogRequest) -> Result<WorkerWatchdogReport> {
    validate_watchdog_value("name", &request.name)?;
    validate_watchdog_value("command", &request.command)?;
    for arg in &request.args {
        validate_watchdog_value("arg", arg)?;
    }
    if let Some(working_directory) = &request.working_directory
        && !working_directory.is_dir()
    {
        bail!(
            "watchdog working directory does not exist or is not a directory: {}",
            working_directory.display()
        );
    }
    if let Some(parent) = request.audit_log.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let max_attempts = request
        .max_restarts
        .checked_add(1)
        .context("watchdog restart budget overflowed")?;
    let mut attempts = Vec::new();
    let mut restarts = 0_u32;
    let mut final_exit_code = None;

    write_watchdog_audit(
        &request.audit_log,
        json!({
            "event": "watchdog_started",
            "timestamp": OffsetDateTime::now_utc().to_string(),
            "name": &request.name,
            "command": &request.command,
            "args_count": request.args.len(),
            "max_restarts": request.max_restarts,
            "success_exit_code": request.success_exit_code,
        }),
    )?;

    for attempt in 1..=max_attempts {
        write_watchdog_audit(
            &request.audit_log,
            json!({
                "event": "attempt_started",
                "timestamp": OffsetDateTime::now_utc().to_string(),
                "name": &request.name,
                "attempt": attempt,
            }),
        )?;
        let started = Instant::now();
        let mut command = ProcessCommand::new(&request.command);
        command.args(&request.args);
        if let Some(working_directory) = &request.working_directory {
            command.current_dir(working_directory);
        }

        let (exit_code, error) = match command.spawn() {
            Ok(mut child) => match child.wait() {
                Ok(status) => (status.code(), None),
                Err(error) => (None, Some(error.to_string())),
            },
            Err(error) => (None, Some(error.to_string())),
        };
        let runtime_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let success = exit_code == Some(request.success_exit_code);
        final_exit_code = exit_code;
        let attempt_report = WorkerWatchdogAttempt {
            attempt,
            exit_code,
            success,
            runtime_ms,
            error: error.clone(),
        };
        write_watchdog_audit(
            &request.audit_log,
            json!({
                "event": "attempt_exited",
                "timestamp": OffsetDateTime::now_utc().to_string(),
                "name": &request.name,
                "attempt": attempt,
                "exit_code": exit_code,
                "success": success,
                "runtime_ms": runtime_ms,
                "error": error,
            }),
        )?;
        attempts.push(attempt_report);

        if success {
            let recovered = restarts > 0;
            write_watchdog_audit(
                &request.audit_log,
                json!({
                    "event": if recovered { "worker_recovered" } else { "worker_healthy" },
                    "timestamp": OffsetDateTime::now_utc().to_string(),
                    "name": &request.name,
                    "attempt": attempt,
                    "restarts": restarts,
                }),
            )?;
            return Ok(WorkerWatchdogReport {
                healthy: true,
                status: "healthy".to_owned(),
                name: request.name,
                command: request.command,
                args_count: request.args.len(),
                working_directory: request.working_directory,
                audit_log: request.audit_log,
                attempts,
                restarts,
                max_restarts: request.max_restarts,
                recovered,
                final_exit_code,
            });
        }

        if attempt <= request.max_restarts {
            restarts += 1;
            write_watchdog_audit(
                &request.audit_log,
                json!({
                    "event": "restart_scheduled",
                    "timestamp": OffsetDateTime::now_utc().to_string(),
                    "name": &request.name,
                    "attempt": attempt,
                    "restart": restarts,
                    "delay_ms": request.restart_delay_ms,
                }),
            )?;
            if request.restart_delay_ms > 0 {
                std::thread::sleep(StdDuration::from_millis(request.restart_delay_ms));
            }
        }
    }

    write_watchdog_audit(
        &request.audit_log,
        json!({
            "event": "watchdog_failed",
            "timestamp": OffsetDateTime::now_utc().to_string(),
            "name": &request.name,
            "attempts": attempts.len(),
            "restarts": restarts,
            "final_exit_code": final_exit_code,
        }),
    )?;
    Ok(WorkerWatchdogReport {
        healthy: false,
        status: "failed".to_owned(),
        name: request.name,
        command: request.command,
        args_count: request.args.len(),
        working_directory: request.working_directory,
        audit_log: request.audit_log,
        attempts,
        restarts,
        max_restarts: request.max_restarts,
        recovered: false,
        final_exit_code,
    })
}

fn validate_watchdog_value(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("watchdog {field} cannot be empty");
    }
    if value
        .chars()
        .any(|character| matches!(character, '\n' | '\r' | '\0'))
    {
        bail!("watchdog {field} cannot contain newline, carriage return, or NUL");
    }
    Ok(())
}

fn write_watchdog_audit(path: &PathBuf, event: Value) -> Result<()> {
    write_jsonl_event(path, event)
}

fn write_jsonl_event(path: &PathBuf, event: Value) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open JSONL audit log {}", path.display()))?;
    file.write_all(serde_json::to_string(&event)?.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn serve_dashboard(request: DashboardServeRequest) -> Result<Value> {
    let listener = TcpListener::bind(&request.bind)
        .with_context(|| format!("failed to bind dashboard server to {}", request.bind))?;
    let local_addr = listener.local_addr()?;
    eprintln!("AstraGrid dashboard serving at http://{local_addr}/dashboard.html");
    let mut served = 0_u32;
    loop {
        let (mut stream, _) = listener.accept()?;
        handle_dashboard_stream(&request, &mut stream)?;
        served += 1;
        if request
            .max_requests
            .is_some_and(|max_requests| served >= max_requests)
        {
            break;
        }
    }
    Ok(json!({
        "bind": local_addr.to_string(),
        "requests": served,
    }))
}

fn handle_dashboard_stream(request: &DashboardServeRequest, stream: &mut TcpStream) -> Result<()> {
    stream.set_read_timeout(Some(StdDuration::from_secs(5)))?;
    let mut buffer = [0_u8; 4096];
    let read = stream.read(&mut buffer)?;
    let request_text = String::from_utf8_lossy(&buffer[..read]);
    let path = http_request_path(&request_text).unwrap_or("/");
    let response = match path {
        "/" | "/dashboard.html" => {
            let dashboard = build_dashboard_document(
                &request.ledger,
                request.title.clone(),
                request.approvals.clone(),
                request.db.clone(),
                request.peer_queue.clone(),
                &request.evidence_bundle,
                request.map_href.clone(),
            )?;
            let html = inject_meta_refresh(&dashboard.to_html(), request.refresh_seconds);
            http_response("200 OK", "text/html; charset=utf-8", html.as_bytes())
        }
        "/healthz" => http_response(
            "200 OK",
            "application/json; charset=utf-8",
            br#"{"status":"ok"}"#,
        ),
        _ => http_response("404 Not Found", "text/plain; charset=utf-8", b"not found\n"),
    };
    stream.write_all(&response)?;
    stream.flush()?;
    Ok(())
}

fn serve_operator_console(request: UiServeRequest) -> Result<Value> {
    let listener = TcpListener::bind(&request.bind)
        .with_context(|| format!("failed to bind operator console server to {}", request.bind))?;
    let local_addr = listener.local_addr()?;
    eprintln!("AstraGrid operator console serving at http://{local_addr}/console.html");
    let mut served = 0_u32;
    loop {
        let (mut stream, _) = listener.accept()?;
        handle_operator_console_stream(&request, &mut stream)?;
        served += 1;
        if request
            .max_requests
            .is_some_and(|max_requests| served >= max_requests)
        {
            break;
        }
    }
    Ok(json!({
        "bind": local_addr.to_string(),
        "requests": served,
    }))
}

fn handle_operator_console_stream(request: &UiServeRequest, stream: &mut TcpStream) -> Result<()> {
    stream.set_read_timeout(Some(StdDuration::from_secs(5)))?;
    let mut buffer = [0_u8; 4096];
    let read = stream.read(&mut buffer)?;
    let request_text = String::from_utf8_lossy(&buffer[..read]);
    let path = http_request_path(&request_text).unwrap_or("/");
    let dashboard = build_dashboard_document(
        &request.ledger,
        request.title.clone(),
        request.approvals.clone(),
        request.db.clone(),
        request.peer_queue.clone(),
        &request.evidence_bundle,
        request.map_href.clone(),
    )?;
    let console_response = route_operator_console(&dashboard, path, request.refresh_seconds)?;
    let response = http_response(
        console_response.status,
        console_response.content_type,
        &console_response.body,
    );
    stream.write_all(&response)?;
    stream.flush()?;
    Ok(())
}

fn serve_map_console(request: MapServeRequest) -> Result<Value> {
    let listener = TcpListener::bind(&request.bind)
        .with_context(|| format!("failed to bind map console server to {}", request.bind))?;
    let local_addr = listener.local_addr()?;
    eprintln!("AstraGrid map console serving at http://{local_addr}/map-console.html");
    let mut served = 0_u32;
    loop {
        let (mut stream, _) = listener.accept()?;
        handle_map_console_stream(&request, &mut stream)?;
        served += 1;
        if request
            .max_requests
            .is_some_and(|max_requests| served >= max_requests)
        {
            break;
        }
    }
    Ok(json!({
        "bind": local_addr.to_string(),
        "requests": served,
    }))
}

fn handle_map_console_stream(request: &MapServeRequest, stream: &mut TcpStream) -> Result<()> {
    stream.set_read_timeout(Some(StdDuration::from_secs(5)))?;
    let mut buffer = [0_u8; 4096];
    let read = stream.read(&mut buffer)?;
    let request_text = String::from_utf8_lossy(&buffer[..read]);
    let path = http_request_path(&request_text).unwrap_or("/");
    let response = match path {
        "/" | "/map-console.html" => {
            let document =
                build_map_console_document(&request.input, &request.ledger, request.title.clone())?;
            let html = inject_meta_refresh(&document.to_html(), request.refresh_seconds);
            http_response("200 OK", "text/html; charset=utf-8", html.as_bytes())
        }
        "/state.json" => {
            let ledger = MissionLedger::open(&request.ledger);
            let state = MissionState::from_ledger(&ledger)?;
            let body = serde_json::to_vec_pretty(&state.summary())?;
            http_response("200 OK", "application/json; charset=utf-8", &body)
        }
        "/healthz" => http_response(
            "200 OK",
            "application/json; charset=utf-8",
            br#"{"status":"ok"}"#,
        ),
        _ => http_response("404 Not Found", "text/plain; charset=utf-8", b"not found\n"),
    };
    stream.write_all(&response)?;
    stream.flush()?;
    Ok(())
}

fn http_request_path(request: &str) -> Option<&str> {
    let mut parts = request.lines().next()?.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(path)) => Some(path),
        _ => None,
    }
}

fn http_response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut response = header.into_bytes();
    response.extend_from_slice(body);
    response
}

fn inject_meta_refresh(html: &str, seconds: u64) -> String {
    if seconds == 0 {
        return html.to_owned();
    }
    let tag = format!("<meta http-equiv=\"refresh\" content=\"{seconds}\">\n");
    html.replacen("</head>", &format!("{tag}</head>"), 1)
}

fn build_map_console_document(
    input: &PathBuf,
    ledger: &PathBuf,
    title: String,
) -> Result<MapConsoleDocument> {
    let text = read_text_file(input)
        .with_context(|| format!("failed to read feature records {}", input.display()))?;
    let ledger = MissionLedger::open(ledger);
    let state = MissionState::from_ledger(&ledger)?;
    MapConsoleDocument::from_json_lines_and_state(&text, title, &state).map_err(Into::into)
}

fn export_ops_bundle(request: OpsBundleRequest) -> Result<Value> {
    fs::create_dir_all(&request.output_dir)
        .with_context(|| format!("failed to create {}", request.output_dir.display()))?;

    let map_href = request
        .features
        .as_ref()
        .map(|_| "map-console.html".to_owned());
    let dashboard = build_dashboard_document(
        &request.ledger,
        request.title.clone(),
        request.approvals.clone(),
        request.db.clone(),
        request.peer_queue.clone(),
        &request.evidence_bundle,
        map_href,
    )?;

    let dashboard_path = request.output_dir.join("dashboard.html");
    write_text_file(&dashboard_path, &dashboard.to_html())?;

    let state_path = request.output_dir.join("state.json");
    write_json_file(&state_path, &dashboard.state)?;

    let workspace_report = run_doctor(DoctorInput {
        ledger: request.ledger.clone(),
        db: request.db.clone(),
        identities: request.identities.clone(),
        approvals: request.approvals.clone(),
        peer_queue: request.peer_queue.clone(),
    });
    let workspace_doctor_path = request.output_dir.join("doctor-workspace.json");
    write_json_file(&workspace_doctor_path, &workspace_report)?;

    let mut files = vec![
        json!({"name": "dashboard", "path": "dashboard.html", "kind": "html"}),
        json!({"name": "state", "path": "state.json", "kind": "json"}),
        json!({"name": "workspace_doctor", "path": "doctor-workspace.json", "kind": "json"}),
    ];

    let map_console = match request.features {
        Some(features) => {
            if !features.exists() {
                bail!(
                    "ops bundle feature records do not exist: {}",
                    features.display()
                );
            }
            let ledger = MissionLedger::open(&request.ledger);
            let state = MissionState::from_ledger(&ledger)?;
            let feature_lines = read_text_file(&features)?;
            let map = MapConsoleDocument::from_json_lines_and_state(
                &feature_lines,
                format!("{} Map Console", request.title),
                &state,
            )?;
            let map_path = request.output_dir.join("map-console.html");
            write_text_file(&map_path, &map.to_html())?;
            files.push(json!({"name": "map_console", "path": "map-console.html", "kind": "html"}));
            Some("map-console.html")
        }
        None => None,
    };

    let release_status = match request.provenance {
        Some(provenance) => {
            let report = run_release_doctor(ReleaseDoctorInput {
                provenance,
                signatures: request.signatures,
                quorum: request.quorum,
                policy: request.release_policy,
            });
            let release_doctor_path = request.output_dir.join("doctor-release.json");
            write_json_file(&release_doctor_path, &report)?;
            files.push(
                json!({"name": "release_doctor", "path": "doctor-release.json", "kind": "json"}),
            );
            Some(report.status)
        }
        None => None,
    };

    let file_count = files.len() + 1;
    let manifest = json!({
        "schema": 1,
        "title": request.title,
        "generated_at": OffsetDateTime::now_utc().to_string(),
        "mission": &dashboard.state.mission,
        "state": &dashboard.state,
        "dashboard": "dashboard.html",
        "map_console": map_console,
        "workspace_status": workspace_report.status,
        "release_status": release_status,
        "files": &files,
    });
    let manifest_path = request.output_dir.join("manifest.json");
    write_json_file(&manifest_path, &manifest)?;

    Ok(json!({
        "output_dir": request.output_dir,
        "manifest": manifest_path,
        "files": file_count,
        "workspace_status": workspace_report.status,
        "release_status": release_status,
    }))
}

fn run_first_run_setup(request: FirstRunRequest) -> Result<Value> {
    let root = ensure_workspace_root(&request.root)?;
    let profile_path = resolve_workspace_path(&root, &request.profile);
    let ledger_path = resolve_workspace_path(&root, &request.ledger);
    let db_path = resolve_workspace_path(&root, &request.db);
    let identity_path = resolve_workspace_path(&root, &request.identity);
    let passphrase_path = resolve_workspace_path(&root, &request.passphrase_file);
    let registry_path = resolve_workspace_path(&root, &request.registry);
    let approvals_path = resolve_workspace_path(&root, &request.approvals);
    let peer_queue_path = resolve_workspace_path(&root, &request.peer_queue);
    let reports_dir = resolve_workspace_path(&root, &request.reports_dir);
    let backups_dir = resolve_workspace_path(&root, &request.backups_dir);

    if profile_path.exists() && !request.force {
        bail!(
            "workspace profile already exists: {}",
            profile_path.display()
        );
    }
    for dir in [
        ledger_path.parent(),
        db_path.parent(),
        identity_path.parent(),
        passphrase_path.parent(),
        registry_path.parent(),
        Some(reports_dir.as_path()),
        Some(backups_dir.as_path()),
        approvals_path.parent(),
        peer_queue_path.parent(),
    ]
    .into_iter()
    .flatten()
    {
        fs::create_dir_all(dir)?;
    }

    let (passphrase, passphrase_created) = ensure_passphrase_file(&passphrase_path)?;

    let mut created = Vec::new();
    if !identity_path.exists() || request.force {
        if identity_path.exists() {
            fs::remove_file(&identity_path)?;
        }
        let keypair = OperatorKeypair::generate(&request.operator_name, request.role);
        keypair.save_encrypted_to_file(&identity_path, &passphrase)?;
        created.push("identity");
    }

    if !registry_path.exists() || request.force {
        if registry_path.exists() {
            fs::remove_file(&registry_path)?;
        }
        let keypair =
            OperatorKeypair::load_from_file_with_passphrase(&identity_path, Some(&passphrase))?;
        let mut registry = OperatorRegistry::new(request.authority.clone());
        registry.enroll(keypair.identity().clone(), request.authority.clone())?;
        registry.save_to_file(&registry_path)?;
        created.push("registry");
    }

    if !ledger_path.exists() || request.force {
        if ledger_path.exists() {
            fs::remove_file(&ledger_path)?;
        }
        let ledger = MissionLedger::open(&ledger_path);
        ledger.append(CommandRequest::new(
            Actor::new(&request.operator_name, Role::System),
            Action::OpenMission,
            request.mission.clone(),
            Priority::Elevated,
            json!({
                "mission": request.mission,
                "kernel": "astragrid-core",
                "schema": 1,
                "first_run": true,
            }),
        ))?;
        created.push("ledger");
    }

    let ledger = MissionLedger::open(&ledger_path);
    let mut store = MissionStore::open(&db_path)?;
    store.ingest_ledger(&ledger)?;

    let profile = WorkspaceProfile {
        schema: WORKSPACE_PROFILE_SCHEMA,
        mission: request.mission,
        created_at: OffsetDateTime::now_utc().to_string(),
        root: PathBuf::from("."),
        ledger: request.ledger,
        db: request.db,
        registry: request.registry,
        primary_identity: request.identity,
        primary_passphrase_file: request.passphrase_file,
        approvals: request.approvals,
        peer_queue: request.peer_queue,
        reports_dir: request.reports_dir,
        backups_dir: request.backups_dir,
    };
    write_json_file(&profile_path, &profile)?;

    let doctor = run_doctor(DoctorInput {
        ledger: ledger_path.clone(),
        db: Some(db_path.clone()),
        identities: vec![identity_path.clone()],
        approvals: None,
        peer_queue: None,
    });
    Ok(json!({
        "profile": profile_path,
        "root": root,
        "ledger": ledger_path,
        "db": db_path,
        "identity": identity_path,
        "registry": registry_path,
        "passphrase_file": passphrase_path,
        "passphrase_created": passphrase_created,
        "reports_dir": reports_dir,
        "backups_dir": backups_dir,
        "created": created,
        "doctor_status": doctor.status,
        "doctor": doctor,
    }))
}

fn run_profile_doctor(profile_path: &PathBuf) -> Result<Value> {
    let profile = load_workspace_profile(profile_path)?;
    let root = profile_root(profile_path, &profile)?;
    let mut checks = Vec::new();
    let mut check_path = |name: &str, path: PathBuf, required: bool, kind: &str| {
        let exists = path.exists();
        let status = if exists {
            "ok"
        } else if required {
            "failed"
        } else {
            "warning"
        };
        checks.push(json!({
            "name": name,
            "status": status,
            "path": path,
            "required": required,
            "kind": kind,
        }));
    };
    check_path("profile", profile_path.clone(), true, "file");
    check_path("ledger", root.join(&profile.ledger), true, "file");
    check_path("db", root.join(&profile.db), true, "file");
    check_path("registry", root.join(&profile.registry), true, "file");
    check_path(
        "primary_identity",
        root.join(&profile.primary_identity),
        true,
        "file",
    );
    check_path(
        "primary_passphrase_file",
        root.join(&profile.primary_passphrase_file),
        true,
        "secret",
    );
    check_path(
        "reports_dir",
        root.join(&profile.reports_dir),
        true,
        "directory",
    );
    check_path(
        "backups_dir",
        root.join(&profile.backups_dir),
        true,
        "directory",
    );

    let doctor = run_doctor(DoctorInput {
        ledger: root.join(&profile.ledger),
        db: Some(root.join(&profile.db)),
        identities: vec![root.join(&profile.primary_identity)],
        approvals: None,
        peer_queue: None,
    });
    let failed_paths = checks
        .iter()
        .filter(|check| check["status"] == "failed")
        .count();
    let healthy = failed_paths == 0 && doctor.failures == 0;
    Ok(json!({
        "profile": profile_path,
        "healthy": healthy,
        "status": if healthy { "healthy" } else { "failed" },
        "path_checks": checks,
        "workspace_doctor": doctor,
    }))
}

fn write_workspace_backup(request: BackupRequest) -> Result<Value> {
    let profile = load_workspace_profile(&request.profile)?;
    let root = profile_root(&request.profile, &profile)?;
    let passphrase = read_passphrase_file(&request.passphrase_file)?;
    let profile_sha256 = sha256_file_hex(&request.profile)?;
    let mut files = Vec::new();
    collect_backup_file(&root, &request.profile, "profile", &mut files)?;
    collect_backup_file(&root, &root.join(&profile.ledger), "ledger", &mut files)?;
    collect_backup_file(&root, &root.join(&profile.db), "store", &mut files)?;
    collect_backup_file(&root, &root.join(&profile.registry), "registry", &mut files)?;
    collect_backup_file(
        &root,
        &root.join(&profile.primary_identity),
        "operator_key",
        &mut files,
    )?;
    collect_backup_file(
        &root,
        &root.join(&profile.primary_passphrase_file),
        "operator_passphrase",
        &mut files,
    )?;
    collect_optional_backup_file(
        &root,
        &root.join(&profile.approvals),
        "approvals",
        &mut files,
    )?;
    collect_optional_backup_file(
        &root,
        &root.join(&profile.peer_queue),
        "peer_queue",
        &mut files,
    )?;
    collect_backup_directory_marker(&root, &root.join(&profile.reports_dir), &mut files)?;
    collect_backup_directory_marker(&root, &root.join(&profile.backups_dir), &mut files)?;
    collect_backup_dir(
        &root,
        &root.join(&profile.reports_dir),
        "report",
        &mut files,
    )?;

    files.sort_by(|left, right| left.path.cmp(&right.path));
    let backup = WorkspaceBackup {
        schema: WORKSPACE_BACKUP_SCHEMA,
        created_at: OffsetDateTime::now_utc().to_string(),
        profile_sha256,
        files,
    };
    let plaintext = serde_json::to_vec_pretty(&backup)?;
    let artifact = SealedArtifact::seal(
        "astragrid-workspace-backup-v1",
        &plaintext,
        &passphrase,
        b"astragrid-workspace-backup-v1",
    )?;
    write_json_file(&request.output, &artifact)?;
    Ok(json!({
        "output": request.output,
        "files": backup.files.len(),
        "sealed": true,
        "profile_sha256": backup.profile_sha256,
    }))
}

fn restore_workspace_backup(request: RestoreRequest) -> Result<Value> {
    let passphrase = read_passphrase_file(&request.passphrase_file)?;
    let artifact: SealedArtifact = read_json_file(&request.input)?;
    let plaintext = artifact.open(&passphrase)?;
    let backup: WorkspaceBackup = serde_json::from_slice(&plaintext)?;
    if backup.schema != WORKSPACE_BACKUP_SCHEMA {
        bail!("unsupported workspace backup schema {}", backup.schema);
    }
    fs::create_dir_all(&request.output_dir)?;
    let output_root = request.output_dir.canonicalize()?;
    let mut restored = Vec::new();
    for entry in backup.files {
        let relative = safe_relative_path(&entry.path)?;
        let output = output_root.join(&relative);
        if entry.kind == "directory" {
            fs::create_dir_all(&output)?;
            restored.push(json!({
                "path": relative,
                "kind": entry.kind,
                "sha256": entry.sha256,
            }));
            continue;
        }
        if output.exists() && !request.overwrite {
            bail!("restore target already exists: {}", output.display());
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = hex::decode(&entry.bytes_hex)?;
        let actual_sha256 = sha256_bytes_hex(&bytes);
        if actual_sha256 != entry.sha256 {
            bail!("backup entry hash mismatch for {}", entry.path);
        }
        fs::write(&output, bytes)?;
        restored.push(json!({
            "path": relative,
            "kind": entry.kind,
            "sha256": entry.sha256,
        }));
    }
    Ok(json!({
        "input": request.input,
        "output_dir": output_root,
        "restored_files": restored.len(),
        "files": restored,
    }))
}

fn rotate_operator_key(request: RotateOperatorRequest) -> Result<Value> {
    if request.new_identity.exists() {
        bail!(
            "new identity already exists: {}",
            request.new_identity.display()
        );
    }
    let passphrase = ensure_passphrase_file(&request.new_passphrase_file)?.0;
    let mut registry = OperatorRegistry::load_from_file(&request.registry)?;
    let old_entry = registry
        .get(&request.old_operator_id)
        .cloned()
        .with_context(|| format!("old operator is not enrolled: {}", request.old_operator_id))?;
    if old_entry.status == OperatorStatus::Revoked {
        bail!(
            "old operator is already revoked: {}",
            request.old_operator_id
        );
    }

    let new_keypair = OperatorKeypair::generate(&request.new_name, request.new_role);
    new_keypair.save_encrypted_to_file(&request.new_identity, &passphrase)?;
    let enrolled = registry.enroll(new_keypair.identity().clone(), request.issued_by)?;
    let revoked = registry.revoke(
        &request.old_operator_id,
        request.revoked_by,
        &request.reason,
    )?;
    registry.save()?;

    let registry_sha256 = sha256_file_hex(&request.registry)?;
    let proof = KeyRotationProof {
        schema: 1,
        rotated_at: OffsetDateTime::now_utc().to_string(),
        old_operator_id: request.old_operator_id.clone(),
        new_operator_id: enrolled.identity.id.clone(),
        reason: request.reason,
        registry: request.registry.clone(),
        registry_sha256,
        revoked,
        enrolled,
    };
    write_json_file(&request.proof_output, &proof)?;
    Ok(json!({
        "registry": request.registry,
        "new_identity": request.new_identity,
        "proof": request.proof_output,
        "old_operator_id": request.old_operator_id,
        "new_operator_id": proof.new_operator_id,
        "registry_sha256": proof.registry_sha256,
    }))
}

fn verify_policy_pack_file(
    pack_path: &PathBuf,
    signature_path: Option<&PathBuf>,
    registry_path: Option<&PathBuf>,
) -> Result<Value> {
    let pack: PolicyRulePack = read_json_file(pack_path)?;
    pack.validate()?;
    let pack_sha256 = pack.sha256()?;
    let signature_report = match signature_path {
        Some(signature_path) => {
            let signature: PolicyRulePackSignature = read_json_file(signature_path)?;
            Some(signature.verify_pack(&pack)?)
        }
        None => None,
    };
    let registry_report = verify_policy_pack_registry(registry_path, signature_report.as_ref())?;
    let valid = signature_report.as_ref().is_none_or(|report| report.valid)
        && registry_report["valid"].as_bool().unwrap_or(false);
    Ok(json!({
        "valid": valid,
        "pack": pack_path,
        "pack_sha256": pack_sha256,
        "rules": pack.rules.len(),
        "signature": signature_path,
        "signature_report": signature_report,
        "registry": registry_path,
        "registry_report": registry_report,
    }))
}

fn evaluate_policy_pack_file(
    pack_path: &PathBuf,
    signature_path: Option<&PathBuf>,
    registry_path: Option<&PathBuf>,
    request: &CommandRequest,
) -> Result<astragrid_policy_pack::PolicyPackDecision> {
    let verification = verify_policy_pack_file(pack_path, signature_path, registry_path)?;
    if !verification["valid"].as_bool().unwrap_or(false) {
        bail!("policy rule pack verification failed");
    }
    let pack: PolicyRulePack = read_json_file(pack_path)?;
    pack.evaluate_request(request).map_err(Into::into)
}

fn verify_policy_pack_registry(
    registry_path: Option<&PathBuf>,
    signature_report: Option<&PolicyRulePackSignatureReport>,
) -> Result<Value> {
    let Some(registry_path) = registry_path else {
        return Ok(json!({
            "valid": true,
            "checked": false,
            "reason": "no registry requested",
        }));
    };
    let Some(signature_report) = signature_report else {
        return Ok(json!({
            "valid": false,
            "checked": true,
            "reason": "registry verification requires a policy pack signature",
        }));
    };
    if !signature_report.valid {
        return Ok(json!({
            "valid": false,
            "checked": true,
            "reason": "policy pack signature is invalid",
        }));
    }
    if !signature_report.signer.role.allows(Role::Operator) {
        return Ok(json!({
            "valid": false,
            "checked": true,
            "operator_id": signature_report.signer.id,
            "reason": "policy pack signer must be operator or higher",
        }));
    }
    let registry = OperatorRegistry::load_from_file(registry_path)?;
    let active = registry_identity_status(&signature_report.signer, &registry);
    Ok(json!({
        "valid": active.is_ok(),
        "checked": true,
        "registry": registry_path,
        "operator_id": signature_report.signer.id,
        "status": active.err(),
    }))
}

fn issue_team_session(request: TeamSessionIssueRequest) -> Result<Value> {
    if request.ttl_minutes <= 0 {
        bail!("session ttl must be greater than zero");
    }
    let keypair = load_keypair(
        &request.identity,
        request.passphrase_file.as_ref(),
        request.passphrase_os_key.as_ref(),
    )?;
    let registry = OperatorRegistry::load_from_file(&request.registry)?;
    ensure_identity_active_in_registry(keypair.identity(), &registry)?;
    let registry_sha256 = sha256_file_hex(&request.registry)?;
    let issued_at_unix = OffsetDateTime::now_utc().unix_timestamp();
    let expires_at_unix = issued_at_unix
        .checked_add(request.ttl_minutes.saturating_mul(60))
        .context("session ttl overflowed")?;
    let claims = TeamSessionClaims {
        schema: TEAM_SESSION_SCHEMA,
        identity: keypair.identity().clone(),
        issued_at_unix,
        expires_at_unix,
        registry_sha256,
        nonce: random_hex(16),
    };
    let digest = sha256_bytes_hex(&serde_json::to_vec(&claims)?);
    let session = TeamSession {
        schema: TEAM_SESSION_SCHEMA,
        identity: claims.identity.clone(),
        issued_at_unix,
        expires_at_unix,
        registry_sha256: claims.registry_sha256.clone(),
        nonce: claims.nonce,
        signature: keypair.sign_digest(TEAM_SESSION_PURPOSE, "sha256", &digest)?,
    };
    write_json_file(&request.output, &session)?;
    Ok(json!({
        "output": request.output,
        "operator_id": session.identity.id,
        "role": session.identity.role,
        "issued_at_unix": session.issued_at_unix,
        "expires_at_unix": session.expires_at_unix,
        "registry_sha256": session.registry_sha256,
    }))
}

fn verify_team_session_file(
    session_path: &PathBuf,
    registry_path: &PathBuf,
) -> Result<TeamSessionVerification> {
    let session: TeamSession = read_json_file(session_path)?;
    verify_team_session(&session, session_path, registry_path)
}

fn verify_team_session(
    session: &TeamSession,
    session_path: &Path,
    registry_path: &PathBuf,
) -> Result<TeamSessionVerification> {
    let registry = OperatorRegistry::load_from_file(registry_path)?;
    let registry_sha256 = sha256_file_hex(registry_path)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let expired = now >= session.expires_at_unix;
    let claims = TeamSessionClaims {
        schema: session.schema,
        identity: session.identity.clone(),
        issued_at_unix: session.issued_at_unix,
        expires_at_unix: session.expires_at_unix,
        registry_sha256: session.registry_sha256.clone(),
        nonce: session.nonce.clone(),
    };
    let digest = sha256_bytes_hex(&serde_json::to_vec(&claims)?);
    let signature_valid = session
        .signature
        .verify_digest(TEAM_SESSION_PURPOSE, "sha256", &digest)
        .is_ok();
    let registry_status = registry_identity_status(&session.identity, &registry);
    let checks = vec![
        check_value(
            "schema",
            session.schema == TEAM_SESSION_SCHEMA,
            json!({"schema": session.schema}),
        ),
        check_value(
            "signature",
            signature_valid && session.signature.identity == session.identity,
            json!({"purpose": TEAM_SESSION_PURPOSE}),
        ),
        check_value(
            "registry_sha256",
            session.registry_sha256 == registry_sha256,
            json!({"expected": session.registry_sha256, "actual": registry_sha256}),
        ),
        check_value(
            "registry_identity",
            registry_status.is_ok(),
            json!({"operator_id": session.identity.id, "status": registry_status.err()}),
        ),
        check_value(
            "expiry",
            !expired,
            json!({"now_unix": now, "expires_at_unix": session.expires_at_unix}),
        ),
    ];
    let valid = checks
        .iter()
        .all(|check| check["status"].as_str() == Some("pass"));
    Ok(TeamSessionVerification {
        valid,
        session: session_path.to_path_buf(),
        registry: registry_path.clone(),
        identity: session.identity.clone(),
        expired,
        checks,
    })
}

fn authorize_team_action(
    session_path: &PathBuf,
    registry_path: &PathBuf,
    action: Action,
    priority: Priority,
    subject: String,
    payload: Value,
) -> Result<Value> {
    let report = verify_team_session_file(session_path, registry_path)?;
    if !report.valid {
        bail!("team session verification failed");
    }
    let request = CommandRequest::new(
        Actor::from(&report.identity),
        action,
        subject,
        priority,
        payload,
    );
    let decision = astragrid_core::AdmissionPolicy.evaluate(&request);
    Ok(json!({
        "authorized": decision.allowed,
        "session": session_path,
        "registry": registry_path,
        "operator_id": report.identity.id,
        "role": report.identity.role,
        "decision": decision,
    }))
}

fn team_append_signed(request: TeamAppendRequest) -> Result<Value> {
    let session_report = verify_team_session_file(&request.session, &request.registry)?;
    if !session_report.valid {
        bail!("team session verification failed");
    }
    let keypair = load_keypair(
        &request.identity,
        request.passphrase_file.as_ref(),
        request.passphrase_os_key.as_ref(),
    )?;
    if keypair.identity().id != session_report.identity.id {
        bail!(
            "team session operator {} does not match identity {}",
            session_report.identity.id,
            keypair.identity().id
        );
    }
    let command = CommandRequest::new(
        Actor::from(keypair.identity()),
        request.action,
        request.subject,
        request.priority,
        request.payload,
    );
    if let Some(policy_pack) = &request.policy_pack {
        let decision = evaluate_policy_pack_file(
            policy_pack,
            request.policy_signature.as_ref(),
            Some(&request.registry),
            &command,
        )?;
        if !decision.allowed {
            bail!("policy rule pack denied command: {}", decision.reason);
        }
    } else if request.policy_signature.is_some() {
        bail!("--policy-signature requires --policy-pack");
    }
    let decision = astragrid_core::AdmissionPolicy.evaluate(&command);
    if !decision.allowed {
        bail!("team session is not authorized: {}", decision.reason);
    }
    let registry = OperatorRegistry::load_from_file(&request.registry)?;
    let ledger = MissionLedger::open(&request.ledger);
    let event = ledger.append_signed_with_registry(keypair.sign_request(command)?, &registry)?;
    Ok(json!({
        "ledger": request.ledger,
        "session": request.session,
        "registry": request.registry,
        "authorized": true,
        "event": event,
    }))
}

fn create_device_pairing(request: DevicePairingRequest) -> Result<Value> {
    if request.ttl_minutes <= 0 {
        bail!("pairing ttl must be greater than zero");
    }
    validate_pairing_text("device_id", &request.device_id)?;
    validate_pairing_text("device_name", &request.device_name)?;
    let keypair = load_keypair(
        &request.identity,
        request.passphrase_file.as_ref(),
        request.passphrase_os_key.as_ref(),
    )?;
    let registry = OperatorRegistry::load_from_file(&request.registry)?;
    ensure_identity_active_in_registry(keypair.identity(), &registry)?;
    let registry_sha256 = sha256_file_hex(&request.registry)?;
    let issued_at_unix = OffsetDateTime::now_utc().unix_timestamp();
    let expires_at_unix = issued_at_unix
        .checked_add(request.ttl_minutes.saturating_mul(60))
        .context("pairing ttl overflowed")?;
    let claims = DevicePairingClaims {
        schema: DEVICE_PAIRING_SCHEMA,
        device_id: request.device_id,
        device_name: request.device_name,
        operator: keypair.identity().clone(),
        issued_at_unix,
        expires_at_unix,
        registry_sha256,
        nonce: random_hex(16),
    };
    let digest = sha256_bytes_hex(&serde_json::to_vec(&claims)?);
    let bundle = DevicePairingBundle {
        schema: DEVICE_PAIRING_SCHEMA,
        device_id: claims.device_id,
        device_name: claims.device_name,
        operator: claims.operator,
        issued_at_unix,
        expires_at_unix,
        registry_sha256: claims.registry_sha256,
        nonce: claims.nonce,
        signature: keypair.sign_digest(DEVICE_PAIRING_PURPOSE, "sha256", &digest)?,
    };
    write_json_file(&request.output, &bundle)?;
    Ok(json!({
        "output": request.output,
        "device_id": bundle.device_id,
        "device_name": bundle.device_name,
        "operator_id": bundle.operator.id,
        "expires_at_unix": bundle.expires_at_unix,
    }))
}

fn verify_device_pairing_file(
    input: &PathBuf,
    registry_path: &PathBuf,
) -> Result<DevicePairingVerification> {
    let bundle: DevicePairingBundle = read_json_file(input)?;
    let registry = OperatorRegistry::load_from_file(registry_path)?;
    let registry_sha256 = sha256_file_hex(registry_path)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let expired = now >= bundle.expires_at_unix;
    let claims = DevicePairingClaims {
        schema: bundle.schema,
        device_id: bundle.device_id.clone(),
        device_name: bundle.device_name.clone(),
        operator: bundle.operator.clone(),
        issued_at_unix: bundle.issued_at_unix,
        expires_at_unix: bundle.expires_at_unix,
        registry_sha256: bundle.registry_sha256.clone(),
        nonce: bundle.nonce.clone(),
    };
    let digest = sha256_bytes_hex(&serde_json::to_vec(&claims)?);
    let signature_valid = bundle
        .signature
        .verify_digest(DEVICE_PAIRING_PURPOSE, "sha256", &digest)
        .is_ok();
    let registry_status = registry_identity_status(&bundle.operator, &registry);
    let checks = vec![
        check_value(
            "schema",
            bundle.schema == DEVICE_PAIRING_SCHEMA,
            json!({"schema": bundle.schema}),
        ),
        check_value(
            "signature",
            signature_valid && bundle.signature.identity == bundle.operator,
            json!({"purpose": DEVICE_PAIRING_PURPOSE}),
        ),
        check_value(
            "registry_sha256",
            bundle.registry_sha256 == registry_sha256,
            json!({"expected": bundle.registry_sha256, "actual": registry_sha256}),
        ),
        check_value(
            "registry_identity",
            registry_status.is_ok(),
            json!({"operator_id": bundle.operator.id, "status": registry_status.err()}),
        ),
        check_value(
            "expiry",
            !expired,
            json!({"now_unix": now, "expires_at_unix": bundle.expires_at_unix}),
        ),
    ];
    let valid = checks
        .iter()
        .all(|check| check["status"].as_str() == Some("pass"));
    Ok(DevicePairingVerification {
        valid,
        input: input.clone(),
        registry: registry_path.clone(),
        device_id: bundle.device_id,
        operator: bundle.operator,
        expired,
        checks,
    })
}

fn ensure_identity_active_in_registry(
    identity: &OperatorIdentity,
    registry: &OperatorRegistry,
) -> Result<()> {
    registry_identity_status(identity, registry).map_err(anyhow::Error::msg)
}

fn registry_identity_status(
    identity: &OperatorIdentity,
    registry: &OperatorRegistry,
) -> Result<(), String> {
    let Some(entry) = registry.get(&identity.id) else {
        return Err("not_enrolled".to_owned());
    };
    if entry.status != OperatorStatus::Active {
        return Err("revoked".to_owned());
    }
    if entry.identity != *identity {
        return Err("identity_mismatch".to_owned());
    }
    Ok(())
}

fn validate_pairing_text(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} cannot be empty");
    }
    if value
        .chars()
        .any(|character| matches!(character, '\n' | '\r' | '\0'))
    {
        bail!("{field} cannot contain newline, carriage return, or NUL");
    }
    Ok(())
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut buffer);
    hex::encode(buffer)
}

fn vault_init(
    vault_path: &PathBuf,
    passphrase_file: &PathBuf,
    mission: &str,
    operator: &str,
) -> Result<Value> {
    if vault_path.exists() {
        bail!(
            "encrypted ledger vault already exists: {}",
            vault_path.display()
        );
    }
    let passphrase = read_passphrase_file(passphrase_file)?;
    let temp_path = temporary_ledger_path(vault_path)?;
    let ledger = MissionLedger::open(&temp_path);
    ledger.append(CommandRequest::new(
        Actor::new(operator, Role::System),
        Action::OpenMission,
        mission,
        Priority::Elevated,
        json!({
            "mission": mission,
            "kernel": "astragrid-core",
            "schema": 1,
            "encrypted_at_rest": true,
        }),
    ))?;
    let verification = ledger.verify()?;
    seal_vault_from_temp(vault_path, &temp_path, &passphrase)?;
    let _ = fs::remove_file(&temp_path);
    Ok(json!({
        "ledger": vault_path,
        "encrypted_at_rest": true,
        "events": verification.events,
        "last_hash": verification.last_hash,
    }))
}

fn vault_append(request: VaultAppendRequest) -> Result<Value> {
    let passphrase = read_passphrase_file(&request.passphrase_file)?;
    let temp_path = open_vault_to_temp(&request.ledger, &passphrase)?;
    let ledger = MissionLedger::open(&temp_path);
    let event = ledger.append(CommandRequest::new(
        Actor::new(request.actor, request.role),
        request.action,
        request.subject,
        request.priority,
        request.payload,
    ))?;
    seal_vault_from_temp(&request.ledger, &temp_path, &passphrase)?;
    let _ = fs::remove_file(&temp_path);
    Ok(json!({
        "ledger": request.ledger,
        "event": event,
        "encrypted_at_rest": true,
    }))
}

fn vault_verify(vault_path: &PathBuf, passphrase_file: &PathBuf) -> Result<Value> {
    let passphrase = read_passphrase_file(passphrase_file)?;
    let temp_path = open_vault_to_temp(vault_path, &passphrase)?;
    let ledger = MissionLedger::open(&temp_path);
    let verification = ledger.verify()?;
    let _ = fs::remove_file(&temp_path);
    Ok(json!({
        "ledger": vault_path,
        "encrypted_at_rest": true,
        "verification": verification,
    }))
}

fn vault_tail(vault_path: &PathBuf, passphrase_file: &PathBuf, limit: usize) -> Result<Value> {
    let passphrase = read_passphrase_file(passphrase_file)?;
    let temp_path = open_vault_to_temp(vault_path, &passphrase)?;
    let ledger = MissionLedger::open(&temp_path);
    let events = ledger.load_events()?;
    let start = events.len().saturating_sub(limit);
    let result = json!({
        "ledger": vault_path,
        "encrypted_at_rest": true,
        "events": &events[start..],
    });
    let _ = fs::remove_file(&temp_path);
    Ok(result)
}

fn open_vault_to_temp(vault_path: &PathBuf, passphrase: &[u8]) -> Result<PathBuf> {
    let artifact: SealedArtifact = read_json_file(vault_path)?;
    let plaintext = artifact.open(passphrase)?;
    let temp_path = temporary_ledger_path(vault_path)?;
    write_bytes_file(&temp_path, &plaintext)?;
    Ok(temp_path)
}

fn seal_vault_from_temp(
    vault_path: &PathBuf,
    temp_path: &PathBuf,
    passphrase: &[u8],
) -> Result<()> {
    let bytes = fs::read(temp_path)?;
    let artifact = SealedArtifact::seal(
        "astragrid-ledger-vault-v1",
        &bytes,
        passphrase,
        LEDGER_VAULT_AAD.as_bytes(),
    )?;
    write_json_file(vault_path, &artifact)
}

fn temporary_ledger_path(vault_path: &Path) -> Result<PathBuf> {
    let mut nonce = [0_u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let name = vault_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ledger");
    Ok(std::env::temp_dir().join(format!(
        "astragrid-vault-{}-{}.agl",
        sanitize_file_component(name),
        hex::encode(nonce)
    )))
}

fn write_acceptance_pack(output_dir: &Path, title: &str) -> Result<Value> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;
    let script_path = output_dir.join("run-acceptance.ps1");
    let scenario_path = output_dir.join("mission-scenario.json");
    let manifest_path = output_dir.join("manifest.json");
    write_text_file(&script_path, &render_acceptance_script(title))?;
    write_json_file(&scenario_path, &acceptance_scenario())?;
    let manifest = json!({
        "schema": 1,
        "title": title,
        "generated_at": OffsetDateTime::now_utc().to_string(),
        "files": [
            {"name": "runner", "path": "run-acceptance.ps1", "kind": "powershell"},
            {"name": "scenario", "path": "mission-scenario.json", "kind": "json"}
        ],
        "coverage": [
            "identity",
            "registry",
            "signed ledger append",
            "evidence bundle",
            "workflow draft",
            "approval append",
            "store ingest",
            "dashboard export",
            "operator audit timeline dashboard",
            "ops bundle",
            "workspace doctor",
            "workspace profile",
            "encrypted backup restore",
            "key rotation",
            "encrypted ledger vault",
            "team session authorization",
            "secure device pairing",
            "signed policy rule pack",
            "evidence-bound ai runner",
            "quorum registry enrollment",
            "worker watchdog recovery",
            "peer worker service health audit",
            "hardened federation daemon",
            "signed peer registry authorization",
            "federation daemon supervisor artifacts",
            "divergent ledger merge proof",
            "package provenance"
        ]
    });
    write_json_file(&manifest_path, &manifest)?;
    Ok(json!({
        "output_dir": output_dir,
        "script": script_path,
        "scenario": scenario_path,
        "manifest": manifest_path,
    }))
}

fn acceptance_scenario() -> Value {
    json!({
        "name": "flood-watch-acceptance",
        "ledger": "scenario-mission.agl",
        "store": "scenario-mission.db",
        "steps": [
            {"type": "init", "mission": "flood-watch", "operator": "kernel"},
            {
                "type": "append",
                "actor": "lead",
                "role": "incident_commander",
                "action": "declare_incident",
                "subject": "river-east",
                "priority": "critical",
                "payload": {"water_level_m": 5.2}
            },
            {"type": "verify_ledger"},
            {"type": "ingest_store"},
            {"type": "assert_state", "mission": "flood-watch", "open_incidents": 1},
            {"type": "assert_store", "event_count": 2, "critical_event_count": 1}
        ]
    })
}

fn render_acceptance_script(title: &str) -> String {
    let quoted_title = powershell_single_quote(title);
    format!(
        r#"
param(
    [string]$ProjectRoot = (Get-Location).Path,
    [switch]$SkipPackage
)

$ErrorActionPreference = 'Stop'
$PackRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Run = Join-Path $PackRoot 'run'
New-Item -ItemType Directory -Path $Run -Force | Out-Null

function Invoke-AstraGrid {{
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    & cargo run -q -p astragrid -- @Args
    if ($LASTEXITCODE -ne 0) {{
        throw "astragrid command failed: $($Args -join ' ')"
    }}
}}

function Invoke-AstraGridJson {{
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $output = & cargo run -q -p astragrid -- @Args
    if ($LASTEXITCODE -ne 0) {{
        throw "astragrid command failed: $($Args -join ' ')"
    }}
    $output | ConvertFrom-Json
}}

Push-Location $ProjectRoot
try {{
    $ledger = Join-Path $Run 'mission.agl'
    $db = Join-Path $Run 'mission.db'
    $identity = Join-Path $Run 'lead.agkey'
    $passphrase = Join-Path $Run 'lead.pass'
    $deputyIdentity = Join-Path $Run 'deputy.agkey'
    $deputyPassphrase = Join-Path $Run 'deputy.pass'
    $medicIdentity = Join-Path $Run 'medic.agkey'
    $medicPassphrase = Join-Path $Run 'medic.pass'
    $registry = Join-Path $Run 'operators.agregistry'
    $quorumProposal = Join-Path $Run 'medic-enroll.proposal.json'
    $leadQuorumSignature = Join-Path $Run 'lead.quorum.sig.json'
    $deputyQuorumSignature = Join-Path $Run 'deputy.quorum.sig.json'
    $session = Join-Path $Run 'lead.session.json'
    $pairing = Join-Path $Run 'field-device.pairing.json'
    $policyPack = Join-Path $Run 'field-safety.policy.json'
    $policySignature = Join-Path $Run 'field-safety.policy.sig.json'
    $payload = Join-Path $Run 'payload.json'
    $dispatchPayload = Join-Path $Run 'dispatch-payload.json'
    $evidence = Join-Path $Run 'evidence.json'
    $aiRunnerScript = Join-Path $Run 'ai-runner.ps1'
    $aiBundles = Join-Path $Run 'ai-bundles.json'
    $bundle = Join-Path $Run 'close-bundle.json'
    $draft = Join-Path $Run 'draft.json'
    $approvals = Join-Path $Run 'approvals.agl'
    $geo = Join-Path $Run 'features.geojson'
    $features = Join-Path $Run 'features.jsonl'
    $dashboard = Join-Path $Run 'dashboard.html'
    $opsBundle = Join-Path $Run 'ops-bundle'
    $scenario = Join-Path $PackRoot 'mission-scenario.json'
    $scenarioRun = Join-Path $Run 'scenario'
    $firstRunRoot = Join-Path $Run 'first-run'
    $firstRunProfile = Join-Path $firstRunRoot 'astragrid.profile.json'
    $firstRunPass = Join-Path $firstRunRoot 'data\operators\lead.pass'
    $firstRunIdentity = Join-Path $firstRunRoot 'data\operators\lead.agkey'
    $firstRunRegistry = Join-Path $firstRunRoot 'data\operators\operators.agregistry'
    $backup = Join-Path $Run 'workspace-backup.sealed.json'
    $restoreRoot = Join-Path $Run 'restore'
    $rotatedIdentity = Join-Path $firstRunRoot 'data\operators\lead-rotated.agkey'
    $rotatedPassphrase = Join-Path $firstRunRoot 'data\operators\lead-rotated.pass'
    $rotationProof = Join-Path $firstRunRoot 'data\operators\lead-rotation-proof.json'
    $vault = Join-Path $Run 'mission.vault.json'
    $vaultPayload = Join-Path $Run 'vault-payload.json'
    $watchdogScript = Join-Path $Run 'watchdog-worker.ps1'
    $watchdogState = Join-Path $Run 'watchdog-worker.state'
    $watchdogAudit = Join-Path $Run 'watchdog-audit.jsonl'
    $peerWorkerQueue = Join-Path $Run 'peer-worker.db'
    $peerWorkerHealth = Join-Path $Run 'peer-worker-health.json'
    $peerWorkerAudit = Join-Path $Run 'peer-worker-audit.jsonl'
    $peerWorkerSystemdKit = Join-Path $Run 'peer-worker-systemd-kit'
    $peerWorkerWindowsKit = Join-Path $Run 'peer-worker-windows-kit'
    $federationKey = Join-Path $Run 'federation.key'
    $federationOut = Join-Path $Run 'federation-events.json'
    $federationHealth = Join-Path $Run 'federation-health.json'
    $federationAudit = Join-Path $Run 'federation-audit.jsonl'
    $federationIdentity = Join-Path $Run 'federation-peer.agkey'
    $federationPassphrase = Join-Path $Run 'federation-peer.pass'
    $federationRegistry = Join-Path $Run 'federation-operators.agregistry'
    $federationSystemdKit = Join-Path $Run 'federation-systemd-kit'
    $federationWindowsKit = Join-Path $Run 'federation-windows-kit'
    $federationPort = Get-Random -Minimum 20000 -Maximum 30000
    $federationBind = "127.0.0.1:$federationPort"
    $operatorConsolePort = Get-Random -Minimum 30001 -Maximum 40000
    $operatorConsoleBind = "127.0.0.1:$operatorConsolePort"
    $mergeLeft = Join-Path $Run 'merge-left.agl'
    $mergeRight = Join-Path $Run 'merge-right.agl'
    $mergeOutput = Join-Path $Run 'merge-output.agl'
    $mergeProof = Join-Path $Run 'merge-proof.json'
    $mergeLeftPayload = Join-Path $Run 'merge-left-payload.json'
    $mergeRightPayload = Join-Path $Run 'merge-right-payload.json'

    'acceptance local passphrase' | Set-Content -Encoding UTF8 $passphrase
    'acceptance deputy passphrase' | Set-Content -Encoding UTF8 $deputyPassphrase
    'acceptance medic passphrase' | Set-Content -Encoding UTF8 $medicPassphrase
    '{{"water_level_m":5.2}}' | Set-Content -Encoding UTF8 $payload
    '{{"team_id":"alpha"}}' | Set-Content -Encoding UTF8 $dispatchPayload
    '{{"note":"vault runtime append"}}' | Set-Content -Encoding UTF8 $vaultPayload
    '{{"note":"left branch field note"}}' | Set-Content -Encoding UTF8 $mergeLeftPayload
    '{{"note":"right branch field note"}}' | Set-Content -Encoding UTF8 $mergeRightPayload
    'acceptance federation shared key' | Set-Content -Encoding UTF8 $federationKey
    'acceptance federation peer passphrase' | Set-Content -Encoding UTF8 $federationPassphrase
@'
param([string]$State)
if (-not (Test-Path $State)) {{
    'first failure' | Set-Content -Encoding UTF8 $State
    exit 7
}}
exit 0
'@ | Set-Content -Encoding UTF8 $watchdogScript
@'
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
if ($request.mission -ne 'flood-watch') {{ exit 11 }}
if ($request.evidence.Count -lt 1) {{ exit 12 }}
'[{{"action":"declare_incident","subject":"river-east","rationale":"Acceptance runner cited the provided sensor evidence.","confidence":0.89,"evidence_ids":["sensor-1"]}}]'
'@ | Set-Content -Encoding UTF8 $aiRunnerScript
    '[{{"id":"sensor-1","source":"river-gauge","kind":"sensor","confidence":0.94,"digest":"sensor-digest","excerpt":"water=5.2"}}]' | Set-Content -Encoding UTF8 $evidence
    '{{"type":"Feature","id":"river-east","properties":{{"risk":"flood"}},"geometry":{{"type":"Point","coordinates":[72.2,31.2]}}}}' | Set-Content -Encoding UTF8 $geo

    Invoke-AstraGrid setup first-run --root $firstRunRoot --profile astragrid.profile.json --mission flood-watch --operator-name lead --role incident_commander
    Invoke-AstraGrid doctor profile --profile $firstRunProfile
    Invoke-AstraGrid ops backup --profile $firstRunProfile --output $backup --passphrase-file $firstRunPass
    Invoke-AstraGrid ops restore --input $backup --output-dir $restoreRoot --passphrase-file $firstRunPass
    Invoke-AstraGrid doctor profile --profile (Join-Path $restoreRoot 'astragrid.profile.json')
    $oldIdentity = Invoke-AstraGridJson identity inspect --path $firstRunIdentity --passphrase-file $firstRunPass
    Invoke-AstraGrid identity rotate --registry $firstRunRegistry --old-operator-id $oldIdentity.id --new-identity $rotatedIdentity --new-name lead-rotated --new-role incident_commander --new-passphrase-file $rotatedPassphrase --issued-by local-command --revoked-by local-command --reason 'acceptance rotation' --proof-output $rotationProof
    Invoke-AstraGrid vault init --ledger $vault --passphrase-file $passphrase --mission flood-watch-vault
    Invoke-AstraGrid vault append --ledger $vault --passphrase-file $passphrase --actor lead --role incident_commander --action annotate_situation --subject river-east --payload "@$vaultPayload"
    Invoke-AstraGrid vault verify --ledger $vault --passphrase-file $passphrase
    Invoke-AstraGrid supervisor watchdog-run --name acceptance-worker --command powershell --arg -NoProfile --arg -ExecutionPolicy --arg Bypass --arg -File --arg $watchdogScript --arg $watchdogState --audit-log $watchdogAudit --max-restarts 2 --restart-delay-ms 0
    Invoke-AstraGrid peer-queue worker --queue $peerWorkerQueue --ledger $ledger --shared-key-file $federationKey --health-file $peerWorkerHealth --audit-log $peerWorkerAudit --cycles 1 --interval-seconds 1 --stale-after-seconds 60
    $peerWorkerHealthJson = Get-Content -Raw $peerWorkerHealth | ConvertFrom-Json
    if ($peerWorkerHealthJson.status -ne 'stopped') {{ throw "unexpected peer worker status: $($peerWorkerHealthJson.status)" }}
    if ($peerWorkerHealthJson.queue_health_status -ne 'healthy') {{ throw "unexpected peer worker queue health: $($peerWorkerHealthJson.queue_health_status)" }}
    if (-not (Select-String -LiteralPath $peerWorkerAudit -Pattern 'peer_worker_cycle' -Quiet)) {{ throw 'peer worker audit did not record cycle' }}
    Invoke-AstraGrid supervisor systemd-peer-worker-kit --output-dir $peerWorkerSystemdKit --binary /usr/local/bin/astragrid --working-directory /srv/astragrid --ledger data/mission.agl --queue data/peer-worker.db --shared-key-file secrets/peer.key --health-file data/peer-worker-health.json --audit-log data/peer-worker-audit.jsonl --user astragrid
    Invoke-AstraGrid supervisor windows-peer-worker-kit --output-dir $peerWorkerWindowsKit --binary target\release\astragrid.exe --working-directory . --ledger $ledger --queue $peerWorkerQueue --shared-key-file $federationKey --health-file $peerWorkerHealth --audit-log $peerWorkerAudit --interval-seconds 1
    if (-not (Select-String -LiteralPath (Join-Path $peerWorkerSystemdKit 'astragrid-peer-worker.service') -Pattern 'peer-worker-health' -Quiet)) {{ throw 'systemd peer worker kit does not include health file' }}
    if (-not (Select-String -LiteralPath (Join-Path $peerWorkerWindowsKit 'install-windows-peer-worker.ps1') -Pattern 'peer-worker-audit' -Quiet)) {{ throw 'windows peer worker kit does not include audit log' }}

    Invoke-AstraGrid init --mission flood-watch --ledger $ledger
    Invoke-AstraGrid identity create --path $federationIdentity --name federation-peer --role operator --passphrase-file $federationPassphrase
    Invoke-AstraGrid identity registry-init --registry $federationRegistry --authority federation-acceptance
    Invoke-AstraGrid identity enroll --registry $federationRegistry --identity $federationIdentity --passphrase-file $federationPassphrase --issued-by acceptance
    $federationServer = Start-Job -ScriptBlock {{
        param($ProjectRoot, $Bind, $Ledger, $SharedKey, $Health, $Audit, $Registry)
        Set-Location $ProjectRoot
        cargo run -q -p astragrid -- net serve-daemon --bind $Bind --ledger $Ledger --shared-key-file $SharedKey --peer-registry $Registry --health-file $Health --audit-log $Audit --max-requests 1 --idle-timeout-seconds 15
        if ($LASTEXITCODE -ne 0) {{ throw "federation daemon exited with code $LASTEXITCODE" }}
    }} -ArgumentList $ProjectRoot, $federationBind, $ledger, $federationKey, $federationHealth, $federationAudit, $federationRegistry
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path $federationHealth)) {{
        if ((Get-Date) -gt $deadline) {{ throw 'federation daemon did not write health file' }}
        Start-Sleep -Milliseconds 200
    }}
    Invoke-AstraGrid net fetch --addr $federationBind --shared-key-file $federationKey --identity $federationIdentity --passphrase-file $federationPassphrase --output $federationOut
    Receive-Job $federationServer -Wait -ErrorAction Stop
    $federationHealthJson = Get-Content -Raw $federationHealth | ConvertFrom-Json
    if ($federationHealthJson.status -ne 'stopped') {{ throw "unexpected federation daemon status: $($federationHealthJson.status)" }}
    if ($federationHealthJson.peer_authorization_required -ne $true) {{ throw 'federation daemon did not require peer registry authorization' }}
    if ($federationHealthJson.served_requests -lt 1) {{ throw 'federation daemon did not serve a peer request' }}
    if (-not (Select-String -LiteralPath $federationAudit -Pattern 'peer_request_served' -Quiet)) {{ throw 'federation audit did not record served peer request' }}
    Invoke-AstraGrid supervisor systemd-federation-daemon-kit --output-dir $federationSystemdKit --binary /usr/local/bin/astragrid --working-directory /srv/astragrid --bind 127.0.0.1:17655 --ledger data/mission.agl --shared-key-file secrets/peer.key --peer-registry data/operators.agregistry --health-file data/federation-health.json --audit-log data/federation-audit.jsonl --user astragrid
    Invoke-AstraGrid supervisor windows-federation-daemon-kit --output-dir $federationWindowsKit --binary target\release\astragrid.exe --working-directory . --bind $federationBind --ledger $ledger --shared-key-file $federationKey --peer-registry $federationRegistry --health-file $federationHealth --audit-log $federationAudit --max-requests 1 --idle-timeout-seconds 15
    if (-not (Select-String -LiteralPath (Join-Path $federationSystemdKit 'astragrid-federation-daemon.service') -Pattern 'serve-daemon' -Quiet)) {{ throw 'systemd federation kit does not call serve-daemon' }}
    if (-not (Select-String -LiteralPath (Join-Path $federationSystemdKit 'astragrid-federation-daemon.service') -Pattern 'peer-registry' -Quiet)) {{ throw 'systemd federation kit does not include peer registry' }}
    if (-not (Select-String -LiteralPath (Join-Path $federationWindowsKit 'install-windows-federation-daemon.ps1') -Pattern 'serve-daemon' -Quiet)) {{ throw 'windows federation kit does not call serve-daemon' }}
    if (-not (Select-String -LiteralPath (Join-Path $federationWindowsKit 'install-windows-federation-daemon.ps1') -Pattern 'peer-registry' -Quiet)) {{ throw 'windows federation kit does not include peer registry' }}
    Invoke-AstraGrid identity create --path $identity --name lead --role incident_commander --passphrase-file $passphrase
    Invoke-AstraGrid identity create --path $deputyIdentity --name deputy --role incident_commander --passphrase-file $deputyPassphrase
    Invoke-AstraGrid identity create --path $medicIdentity --name medic --role operator --passphrase-file $medicPassphrase
    Invoke-AstraGrid identity registry-init --registry $registry --authority local-command
    Invoke-AstraGrid identity enroll --registry $registry --identity $identity --passphrase-file $passphrase --issued-by local-command
    Invoke-AstraGrid identity enroll --registry $registry --identity $deputyIdentity --passphrase-file $deputyPassphrase --issued-by bootstrap
    Invoke-AstraGrid identity quorum-propose --registry $registry --output $quorumProposal --change enroll --identity $medicIdentity --issued-by quorum --required-approvals 2
    Invoke-AstraGrid identity quorum-sign --proposal $quorumProposal --identity $identity --passphrase-file $passphrase --output $leadQuorumSignature
    Invoke-AstraGrid identity quorum-sign --proposal $quorumProposal --identity $deputyIdentity --passphrase-file $deputyPassphrase --output $deputyQuorumSignature
    Invoke-AstraGrid identity quorum-verify --registry $registry --proposal $quorumProposal --signature $leadQuorumSignature --signature $deputyQuorumSignature
    Invoke-AstraGrid identity quorum-apply --registry $registry --proposal $quorumProposal --signature $leadQuorumSignature --signature $deputyQuorumSignature
    Invoke-AstraGrid team session-issue --identity $identity --passphrase-file $passphrase --registry $registry --output $session --ttl-minutes 30
    Invoke-AstraGrid team session-verify --session $session --registry $registry
    Invoke-AstraGrid team authorize --session $session --registry $registry --action declare_incident --subject river-east --priority critical --payload "@$payload"
    Invoke-AstraGrid team append --ledger $ledger --identity $identity --passphrase-file $passphrase --registry $registry --session $session --action declare_incident --subject river-east --priority critical --payload "@$payload"
    Invoke-AstraGrid team pair-create --identity $identity --passphrase-file $passphrase --registry $registry --device-id field-tablet-01 --device-name 'Field Tablet 01' --output $pairing --ttl-minutes 30
    Invoke-AstraGrid team pair-verify --input $pairing --registry $registry
    Invoke-AstraGrid policy-pack template --output $policyPack --name field-safety --version 1.0.0
    Invoke-AstraGrid policy-pack sign --pack $policyPack --output $policySignature --identity $identity --passphrase-file $passphrase
    Invoke-AstraGrid policy-pack verify --pack $policyPack --signature $policySignature --registry $registry
    Invoke-AstraGrid policy-pack evaluate --pack $policyPack --signature $policySignature --registry $registry --actor lead --role incident_commander --action dispatch_team --subject river-east --priority elevated --payload "@$dispatchPayload"
    Invoke-AstraGrid team append --ledger $ledger --identity $identity --passphrase-file $passphrase --registry $registry --session $session --policy-pack $policyPack --policy-signature $policySignature --action dispatch_team --subject river-east --priority elevated --payload "@$dispatchPayload"
    Invoke-AstraGrid verify --ledger $ledger
    Invoke-AstraGrid store ingest --ledger $ledger --db $db
    Invoke-AstraGrid init --mission divergent-watch --ledger $mergeLeft
    Copy-Item $mergeLeft $mergeRight
    Invoke-AstraGrid append --ledger $mergeLeft --actor left-operator --role operator --action annotate_situation --subject sector-left --priority elevated --payload "@$mergeLeftPayload"
    Invoke-AstraGrid append --ledger $mergeRight --actor right-observer --role observer --action record_observation --subject sector-right --priority routine --payload "@$mergeRightPayload"
    Invoke-AstraGrid sync merge --left $mergeLeft --right $mergeRight --output $mergeOutput --proof $mergeProof
    Invoke-AstraGrid verify --ledger $mergeOutput
    $mergeProofJson = Get-Content -Raw $mergeProof | ConvertFrom-Json
    if ($mergeProofJson.status -ne 'diverged') {{ throw "unexpected merge status: $($mergeProofJson.status)" }}
    if ($mergeProofJson.output_valid -ne $true) {{ throw 'merge proof did not mark output valid' }}
    if ($mergeProofJson.replayed_events -ne 2) {{ throw "unexpected replayed events: $($mergeProofJson.replayed_events)" }}
    if ($mergeProofJson.merged_events -ne 3) {{ throw "unexpected merged events: $($mergeProofJson.merged_events)" }}
    Invoke-AstraGrid recommend ai-run --mission flood-watch --evidence $evidence --command powershell --arg -NoProfile --arg -ExecutionPolicy --arg Bypass --arg -File --arg $aiRunnerScript --timeout-ms 5000 --max-stdout-bytes 8192 --output $aiBundles
    $aiBundleJson = Get-Content -Raw $aiBundles | ConvertFrom-Json
    if ($aiBundleJson.Count -ne 1) {{ throw "unexpected ai bundle count: $($aiBundleJson.Count)" }}
    if ($aiBundleJson[0].recommendation.evidence_ids[0] -ne 'sensor-1') {{ throw 'ai runner did not cite provided evidence' }}
    Invoke-AstraGrid evidence build --mission flood-watch --evidence $evidence --action close_incident --subject river-east --rationale 'Water receded below incident threshold.' --confidence 0.91 --evidence-id sensor-1 --output $bundle
    Invoke-AstraGrid workflow draft --ledger $ledger --bundle $bundle --actor lead --role incident_commander --min-confidence 0.75 --output $draft
    $approval = Invoke-AstraGridJson approval submit --queue $approvals --draft $draft --requested-by acceptance
    Invoke-AstraGrid approval approve --queue $approvals --id $approval.id --reviewed-by lead --reason 'acceptance evidence verified'
    Invoke-AstraGrid approval append-approved --queue $approvals --id $approval.id --ledger $ledger --identity $identity --passphrase-file $passphrase --registry $registry --executed-by lead
    Invoke-AstraGrid approval verify --queue $approvals
    Invoke-AstraGrid store ingest --ledger $ledger --db $db
    Invoke-AstraGrid geo ingest --input $geo --output $features
    Invoke-AstraGrid dashboard export --ledger $ledger --db $db --approvals $approvals --output $dashboard --title {quoted_title}
    if (-not (Select-String -LiteralPath $dashboard -Pattern 'Operator Audit Timeline' -Quiet)) {{ throw 'dashboard audit timeline missing' }}
    $operatorConsoleServer = Start-Job -ScriptBlock {{
        param($ProjectRoot, $Bind, $Ledger, $Db, $Approvals, $Title)
        Set-Location $ProjectRoot
        $operatorOutput = cargo run -q -p astragrid -- ui serve --bind $Bind --ledger $Ledger --db $Db --approvals $Approvals --title $Title --max-requests 2 --refresh-seconds 0 2>&1
        if ($LASTEXITCODE -ne 0) {{ throw "operator console exited with code $LASTEXITCODE`: $operatorOutput" }}
    }} -ArgumentList $ProjectRoot, $operatorConsoleBind, $ledger, $db, $approvals, {quoted_title}
    $operatorConsoleDeadline = (Get-Date).AddSeconds(30)
    while ($true) {{
        try {{
            $operatorSummary = Invoke-RestMethod -Uri "http://$operatorConsoleBind/api/summary" -TimeoutSec 2
            break
        }} catch {{
            if ((Get-Date) -gt $operatorConsoleDeadline) {{ throw "operator console summary API did not respond: $($_.Exception.Message)" }}
            Start-Sleep -Milliseconds 250
        }}
    }}
    if ($operatorSummary.healthy -ne $true) {{ throw 'operator console summary did not report healthy state' }}
    if ($operatorSummary.events -lt 3) {{ throw "operator console summary event count too low: $($operatorSummary.events)" }}
    if ($operatorSummary.audit_items -lt 1) {{ throw 'operator console summary did not expose audit timeline count' }}
    $operatorConsoleHtml = Invoke-WebRequest -Uri "http://$operatorConsoleBind/console.html" -UseBasicParsing -TimeoutSec 5
    if ($operatorConsoleHtml.Content -notmatch 'operator-console') {{ throw 'operator console HTML app shell missing' }}
    Receive-Job $operatorConsoleServer -Wait -ErrorAction Stop
    Invoke-AstraGrid ops bundle --ledger $ledger --db $db --approvals $approvals --identity $identity --features $features --output-dir $opsBundle --title {quoted_title}
    Invoke-AstraGrid doctor workspace --ledger $ledger --db $db --identity $identity --approvals $approvals
    Invoke-AstraGrid scenario run --input $scenario --workdir $scenarioRun

    if (-not $SkipPackage) {{
        .\tools\local\package-release.ps1
        Invoke-AstraGrid provenance verify --input dist\astragrid-windows-x64-0.1.0.provenance.json
        Invoke-AstraGrid doctor release --provenance dist\astragrid-windows-x64-0.1.0.provenance.json
    }}
}}
finally {{
    Pop-Location
}}
"#,
        quoted_title = quoted_title,
    )
    .trim_start()
    .to_owned()
}

fn powershell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn create_registry_quorum_proposal(request: RegistryQuorumProposalRequest) -> Result<Value> {
    if request.required_approvals == 0 {
        bail!("registry quorum requires at least one approval");
    }
    let registry = OperatorRegistry::load_from_file(&request.registry)?;
    let active_signers = active_registry_quorum_signer_count(&registry);
    if active_signers < request.required_approvals {
        bail!(
            "registry has {active_signers} active quorum signers, required {}",
            request.required_approvals
        );
    }

    let change = match request.change {
        RegistryQuorumChangeKind::Enroll => {
            if request.operator_id.is_some() {
                bail!("--operator-id is only valid with --change revoke");
            }
            let identity_path = request
                .identity
                .as_ref()
                .context("--identity is required with --change enroll")?;
            let identity = OperatorKeypair::inspect_key_file(identity_path)?.identity;
            RegistryQuorumChange::Enroll {
                identity,
                issued_by: request.issued_by,
            }
        }
        RegistryQuorumChangeKind::Revoke => {
            if request.identity.is_some() {
                bail!("--identity is only valid with --change enroll");
            }
            let operator_id = request
                .operator_id
                .context("--operator-id is required with --change revoke")?;
            RegistryQuorumChange::Revoke {
                operator_id,
                revoked_by: request.revoked_by,
                reason: request.reason,
            }
        }
    };

    let precondition = registry_quorum_change_precondition(&change, &registry);
    if !precondition["ready"].as_bool().unwrap_or(false) {
        bail!(
            "registry quorum proposal precondition failed: {}",
            precondition
        );
    }

    let proposal = RegistryQuorumProposal {
        schema: REGISTRY_QUORUM_PROPOSAL_SCHEMA,
        authority: registry.authority().to_owned(),
        proposed_at: OffsetDateTime::now_utc(),
        registry_sha256: sha256_file_hex(&request.registry)?,
        required_approvals: request.required_approvals,
        nonce: random_hex(16),
        change,
    };
    let digest = registry_quorum_proposal_digest(&proposal)?;
    write_json_file(&request.output, &proposal)?;
    Ok(json!({
        "output": request.output,
        "authority": proposal.authority,
        "change": registry_quorum_change_label(&proposal.change),
        "registry_sha256": proposal.registry_sha256,
        "required_approvals": proposal.required_approvals,
        "proposal_digest": digest,
    }))
}

fn sign_registry_quorum_proposal(
    proposal_path: &PathBuf,
    identity_path: &PathBuf,
    passphrase_file: Option<&PathBuf>,
    passphrase_os_key: Option<&PathBuf>,
    output: &PathBuf,
) -> Result<Value> {
    let proposal: RegistryQuorumProposal = read_json_file(proposal_path)?;
    let digest = registry_quorum_proposal_digest(&proposal)?;
    let keypair = load_keypair(identity_path, passphrase_file, passphrase_os_key)?;
    let signature = keypair.sign_digest(REGISTRY_QUORUM_SIGNATURE_PURPOSE, "sha256", &digest)?;
    write_json_file(output, &signature)?;
    Ok(json!({
        "output": output,
        "proposal": proposal_path,
        "proposal_digest": digest,
        "operator_id": keypair.identity().id,
        "purpose": REGISTRY_QUORUM_SIGNATURE_PURPOSE,
    }))
}

fn verify_registry_quorum_proposal_file(
    registry_path: &PathBuf,
    proposal_path: &PathBuf,
    signature_paths: &[PathBuf],
) -> Result<RegistryQuorumVerification> {
    let proposal: RegistryQuorumProposal = read_json_file(proposal_path)?;
    verify_registry_quorum_proposal(registry_path, proposal_path, &proposal, signature_paths)
}

fn verify_registry_quorum_proposal(
    registry_path: &PathBuf,
    proposal_path: &Path,
    proposal: &RegistryQuorumProposal,
    signature_paths: &[PathBuf],
) -> Result<RegistryQuorumVerification> {
    let registry = OperatorRegistry::load_from_file(registry_path)?;
    let registry_sha256 = sha256_file_hex(registry_path)?;
    let proposal_digest = registry_quorum_proposal_digest(proposal)?;
    let precondition = registry_quorum_change_precondition(&proposal.change, &registry);

    let mut checks = vec![
        check_value(
            "schema",
            proposal.schema == REGISTRY_QUORUM_PROPOSAL_SCHEMA,
            json!({"schema": proposal.schema}),
        ),
        check_value(
            "authority",
            proposal.authority == registry.authority(),
            json!({"expected": proposal.authority, "actual": registry.authority()}),
        ),
        check_value(
            "registry_sha256",
            proposal.registry_sha256 == registry_sha256,
            json!({"expected": proposal.registry_sha256, "actual": registry_sha256}),
        ),
        check_value(
            "required_approvals",
            proposal.required_approvals > 0,
            json!({"required_approvals": proposal.required_approvals}),
        ),
        check_value(
            "change_precondition",
            precondition["ready"].as_bool().unwrap_or(false),
            precondition,
        ),
        check_value(
            "signatures_supplied",
            !signature_paths.is_empty(),
            json!({"signatures": signature_paths.len()}),
        ),
    ];

    let mut approved_signers = Vec::new();
    let mut signer_ids = BTreeSet::new();
    let mut duplicate_signers = Vec::new();
    let mut signature_reports = Vec::new();
    for signature_path in signature_paths {
        let signature: DetachedSignature = read_json_file(signature_path)?;
        let signature_result = signature.verify_digest(
            REGISTRY_QUORUM_SIGNATURE_PURPOSE,
            "sha256",
            &proposal_digest,
        );
        let signature_valid = signature_result.is_ok();
        let signature_error = signature_result.err().map(|error| error.to_string());
        let registry_status = registry_identity_status(&signature.identity, &registry);
        let registry_error = registry_status.as_ref().err().cloned();
        let role_allowed = signature.identity.role.allows(Role::IncidentCommander);
        let duplicate = !signer_ids.insert(signature.identity.id.clone());
        if duplicate {
            duplicate_signers.push(signature.identity.id.clone());
        }
        let accepted = signature_valid && registry_status.is_ok() && role_allowed && !duplicate;
        if accepted {
            approved_signers.push(signature.identity.clone());
        }
        signature_reports.push(json!({
            "path": signature_path,
            "operator_id": signature.identity.id,
            "role": signature.identity.role,
            "signature_valid": signature_valid,
            "signature_error": signature_error,
            "registry_status": registry_error,
            "role_allowed": role_allowed,
            "duplicate": duplicate,
            "accepted": accepted,
        }));
    }

    let all_supplied_signatures_accepted = signature_reports
        .iter()
        .all(|report| report["accepted"].as_bool() == Some(true));
    checks.push(check_value(
        "signature_records",
        all_supplied_signatures_accepted,
        json!({"accepted": approved_signers.len(), "supplied": signature_paths.len()}),
    ));
    checks.push(check_value(
        "unique_signers",
        duplicate_signers.is_empty(),
        json!({"duplicates": duplicate_signers}),
    ));
    checks.push(check_value(
        "quorum_threshold",
        approved_signers.len() >= proposal.required_approvals,
        json!({
            "approved": approved_signers.len(),
            "required": proposal.required_approvals,
        }),
    ));

    let valid = checks
        .iter()
        .all(|check| check["status"].as_str() == Some("pass"));
    Ok(RegistryQuorumVerification {
        valid,
        registry: registry_path.clone(),
        proposal: proposal_path.to_path_buf(),
        authority: proposal.authority.clone(),
        registry_sha256,
        proposal_registry_sha256: proposal.registry_sha256.clone(),
        proposal_digest,
        required_approvals: proposal.required_approvals,
        approved_signers,
        checks,
        signatures: signature_reports,
    })
}

fn apply_registry_quorum_proposal(
    registry_path: &PathBuf,
    proposal_path: &PathBuf,
    signature_paths: &[PathBuf],
) -> Result<Value> {
    let proposal: RegistryQuorumProposal = read_json_file(proposal_path)?;
    let verification =
        verify_registry_quorum_proposal(registry_path, proposal_path, &proposal, signature_paths)?;
    if !verification.valid {
        bail!("registry quorum proposal verification failed");
    }

    let change_label = registry_quorum_change_label(&proposal.change);
    let registry_sha256_before = proposal.registry_sha256.clone();
    let required_approvals = proposal.required_approvals;
    let mut registry = OperatorRegistry::load_from_file(registry_path)?;
    let applied_entry = match proposal.change {
        RegistryQuorumChange::Enroll {
            identity,
            issued_by,
        } => registry.enroll(identity, issued_by)?,
        RegistryQuorumChange::Revoke {
            operator_id,
            revoked_by,
            reason,
        } => registry.revoke(&operator_id, revoked_by, reason)?,
    };
    registry.save()?;
    let registry_sha256_after = sha256_file_hex(registry_path)?;
    Ok(json!({
        "applied": true,
        "change": change_label,
        "registry": registry_path,
        "registry_sha256_before": registry_sha256_before,
        "registry_sha256_after": registry_sha256_after,
        "required_approvals": required_approvals,
        "approved_signers": verification.approved_signers,
        "entry": applied_entry,
    }))
}

fn registry_quorum_proposal_digest(proposal: &RegistryQuorumProposal) -> Result<String> {
    Ok(sha256_bytes_hex(&serde_json::to_vec(proposal)?))
}

fn registry_quorum_change_precondition(
    change: &RegistryQuorumChange,
    registry: &OperatorRegistry,
) -> Value {
    match change {
        RegistryQuorumChange::Enroll { identity, .. } => {
            let existing = registry.get(&identity.id);
            json!({
                "ready": existing.is_none(),
                "change": "enroll",
                "operator_id": identity.id,
                "existing_status": existing.map(|entry| entry.status),
            })
        }
        RegistryQuorumChange::Revoke { operator_id, .. } => {
            let existing = registry.get(operator_id);
            json!({
                "ready": existing.is_some_and(|entry| entry.status == OperatorStatus::Active),
                "change": "revoke",
                "operator_id": operator_id,
                "existing_status": existing.map(|entry| entry.status),
            })
        }
    }
}

fn registry_quorum_change_label(change: &RegistryQuorumChange) -> &'static str {
    match change {
        RegistryQuorumChange::Enroll { .. } => "enroll",
        RegistryQuorumChange::Revoke { .. } => "revoke",
    }
}

fn active_registry_quorum_signer_count(registry: &OperatorRegistry) -> usize {
    registry
        .entries()
        .filter(|entry| {
            entry.status == OperatorStatus::Active
                && entry.identity.role.allows(Role::IncidentCommander)
        })
        .count()
}

fn build_registry_trust_bundle(registry_path: &PathBuf) -> Result<TrustedRegistryBundle> {
    let registry = OperatorRegistry::load_from_file(registry_path)?;
    let operators = registry.entries().cloned().collect::<Vec<_>>();
    let active_operators = operators
        .iter()
        .filter(|entry| entry.status == OperatorStatus::Active)
        .count();
    let revoked_operators = operators
        .iter()
        .filter(|entry| entry.status == OperatorStatus::Revoked)
        .count();
    Ok(TrustedRegistryBundle {
        schema: 1,
        authority: registry.authority().to_owned(),
        generated_at: OffsetDateTime::now_utc().to_string(),
        registry_sha256: sha256_file_hex(registry_path)?,
        active_operators,
        revoked_operators,
        operators,
    })
}

fn verify_registry_trust_bundle(
    bundle: &TrustedRegistryBundle,
    registry: Option<&PathBuf>,
) -> Result<Value> {
    let mut checks = Vec::new();
    checks.push(check_value(
        "schema",
        bundle.schema == 1,
        json!({"schema": bundle.schema}),
    ));
    checks.push(check_value(
        "authority",
        !bundle.authority.trim().is_empty(),
        json!({"authority": &bundle.authority}),
    ));

    let mut ids = BTreeSet::new();
    let mut unique = true;
    for entry in &bundle.operators {
        if !ids.insert(entry.identity.id.clone()) {
            unique = false;
        }
    }
    checks.push(check_value(
        "unique_operator_ids",
        unique,
        json!({"operators": bundle.operators.len(), "unique_ids": ids.len()}),
    ));

    let active = bundle
        .operators
        .iter()
        .filter(|entry| entry.status == OperatorStatus::Active)
        .count();
    let revoked = bundle
        .operators
        .iter()
        .filter(|entry| entry.status == OperatorStatus::Revoked)
        .count();
    checks.push(check_value(
        "operator_counts",
        active == bundle.active_operators && revoked == bundle.revoked_operators,
        json!({
            "active": active,
            "declared_active": bundle.active_operators,
            "revoked": revoked,
            "declared_revoked": bundle.revoked_operators,
        }),
    ));

    if let Some(registry) = registry {
        let actual = sha256_file_hex(registry)?;
        checks.push(check_value(
            "registry_sha256",
            actual == bundle.registry_sha256,
            json!({"expected": &bundle.registry_sha256, "actual": actual}),
        ));
    }

    let valid = checks
        .iter()
        .all(|check| check["status"].as_str() == Some("pass"));
    Ok(json!({
        "valid": valid,
        "authority": &bundle.authority,
        "active_operators": active,
        "revoked_operators": revoked,
        "checks": checks,
    }))
}

fn import_registry_trust_bundle(
    registry_path: &PathBuf,
    bundle_path: &PathBuf,
    dry_run: bool,
) -> Result<Value> {
    let bundle: TrustedRegistryBundle = read_json_file(bundle_path)?;
    let report = verify_registry_trust_bundle(&bundle, None)?;
    if !report["valid"].as_bool().unwrap_or(false) {
        print_json(&report)?;
        bail!("registry trust bundle verification failed");
    }

    let mut registry = OperatorRegistry::load_from_file(registry_path)?;
    let mut added = 0_usize;
    let mut updated = 0_usize;
    let mut unchanged = 0_usize;
    let mut imports = Vec::new();
    for entry in bundle.operators {
        let operator_id = entry.identity.id.clone();
        let status = registry.import_entry(entry)?;
        match status {
            RegistryImportStatus::Added => added += 1,
            RegistryImportStatus::Updated => updated += 1,
            RegistryImportStatus::Unchanged => unchanged += 1,
        }
        imports.push(json!({
            "operator_id": operator_id,
            "status": status,
        }));
    }
    let changed = added + updated;
    if changed > 0 && !dry_run {
        registry.save()?;
    }

    Ok(json!({
        "registry": registry_path,
        "bundle": bundle_path,
        "dry_run": dry_run,
        "authority": registry.authority(),
        "added": added,
        "updated": updated,
        "unchanged": unchanged,
        "changed": changed,
        "saved": changed > 0 && !dry_run,
        "imports": imports,
    }))
}

fn check_value(name: &str, pass: bool, detail: Value) -> Value {
    json!({
        "name": name,
        "status": if pass { "pass" } else { "fail" },
        "detail": detail,
    })
}

fn write_release_custody_pack(request: ReleaseCustodyPackRequest) -> Result<Value> {
    if request.identities.is_empty() {
        bail!("at least one --identity is required");
    }
    if request.threshold == 0 {
        bail!("--threshold must be at least 1");
    }
    if request.threshold > request.identities.len() {
        bail!("--threshold cannot exceed the number of identities");
    }
    if !request.passphrase_files.is_empty() && !request.passphrase_os_keys.is_empty() {
        bail!("use either --passphrase-file or --passphrase-os-key, not both");
    }
    if !request.passphrase_files.is_empty()
        && request.passphrase_files.len() != request.identities.len()
    {
        bail!("--passphrase-file count must match --identity count");
    }
    if !request.passphrase_os_keys.is_empty()
        && request.passphrase_os_keys.len() != request.identities.len()
    {
        bail!("--passphrase-os-key count must match --identity count");
    }

    fs::create_dir_all(&request.output_dir)
        .with_context(|| format!("failed to create {}", request.output_dir.display()))?;
    let provenance_parent = request
        .provenance
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let provenance_parent = fs::canonicalize(provenance_parent)?;
    let output_dir = fs::canonicalize(&request.output_dir)?;
    if provenance_parent != output_dir {
        bail!("release custody pack output_dir must match the provenance file directory");
    }

    let package = PackageProvenance::load(&request.provenance)?;
    let package_report = package.verify_hashes(&request.provenance)?;
    if !package_report.valid {
        print_json(&package_report)?;
        bail!("provenance verification failed");
    }

    let stem = provenance_stem(&request.provenance);
    let mut signatures = Vec::new();
    let mut signature_paths = Vec::new();
    let mut signer_ids = Vec::new();
    for (index, identity) in request.identities.iter().enumerate() {
        let passphrase_file = request.passphrase_files.get(index);
        let passphrase_os_key = request.passphrase_os_keys.get(index);
        let keypair = load_keypair(identity, passphrase_file, passphrase_os_key)?;
        let envelope = ProvenanceSignatureEnvelope::sign_file(&request.provenance, &keypair)?;
        let signature_path = if request.identities.len() == 1 {
            default_signature_output_path(&request.provenance)
        } else {
            request.output_dir.join(format!(
                "{}.{}.sig.json",
                stem,
                sanitize_file_component(&envelope.signature.identity.id)
            ))
        };
        write_json_file(&signature_path, &envelope)?;
        let report = envelope.verify(&signature_path)?;
        if !report.valid {
            print_json(&report)?;
            bail!("provenance signature verification failed");
        }
        signer_ids.push(envelope.signature.identity.id.clone());
        signature_paths.push(signature_path);
        signatures.push(envelope);
    }

    let distinct_signers = signer_ids.iter().collect::<BTreeSet<_>>();
    if distinct_signers.len() < request.threshold {
        bail!("distinct signer count is below the requested threshold");
    }

    let quorum = ProvenanceQuorumEnvelope::new(request.threshold, signatures)?;
    let quorum_path = request.output_dir.join(format!("{stem}.quorum.json"));
    write_json_file(&quorum_path, &quorum)?;
    let quorum_report = quorum.verify(&quorum_path)?;
    if !quorum_report.valid {
        print_json(&quorum_report)?;
        bail!("provenance quorum verification failed");
    }

    signer_ids.sort();
    signer_ids.dedup();
    let policy = ReleaseCustodyPolicy {
        schema: 1,
        package: Some(package.package.clone()),
        version: Some(package.version.clone()),
        target: Some(package.target.clone()),
        min_distinct_valid_signers: request.threshold,
        required_signer_ids: signer_ids.clone(),
        allowed_signer_ids: signer_ids.clone(),
        require_clean_git: request.require_clean_git,
    };
    policy.validate()?;
    let policy_path = request
        .output_dir
        .join(format!("{stem}.release-policy.json"));
    write_json_file(&policy_path, &policy)?;
    let policy_report = policy.verify(&package, &quorum_report)?;
    if !policy_report.valid {
        print_json(&policy_report)?;
        bail!("release custody policy verification failed");
    }

    let doctor_report = run_release_doctor(ReleaseDoctorInput {
        provenance: request.provenance.clone(),
        signatures: signature_paths.clone(),
        quorum: Some(quorum_path.clone()),
        policy: Some(policy_path.clone()),
    });
    if doctor_report.failures > 0 || doctor_report.warnings > 0 {
        print_json(&doctor_report)?;
        bail!("release doctor did not reach healthy status");
    }

    let manifest_path = request
        .output_dir
        .join(format!("{stem}.custody-manifest.json"));
    let manifest = json!({
        "schema": 1,
        "generated_at": OffsetDateTime::now_utc().to_string(),
        "provenance": request.provenance.file_name().and_then(|name| name.to_str()).unwrap_or("provenance.json"),
        "signatures": signature_paths.iter().map(|path| path.file_name().and_then(|name| name.to_str()).unwrap_or("signature.json")).collect::<Vec<_>>(),
        "quorum": quorum_path.file_name().and_then(|name| name.to_str()).unwrap_or("quorum.json"),
        "policy": policy_path.file_name().and_then(|name| name.to_str()).unwrap_or("release-policy.json"),
        "threshold": request.threshold,
        "signer_ids": signer_ids,
        "doctor_status": doctor_report.status,
    });
    write_json_file(&manifest_path, &manifest)?;

    Ok(json!({
        "output_dir": request.output_dir,
        "manifest": manifest_path,
        "signatures": signature_paths,
        "quorum": quorum_path,
        "policy": policy_path,
        "threshold": request.threshold,
        "doctor_status": doctor_report.status,
    }))
}

fn write_release_evidence_pack(request: ReleaseEvidencePackRequest) -> Result<Value> {
    if request.signatures.is_empty() {
        bail!("at least one --signature is required for a release evidence pack");
    }
    fs::create_dir_all(&request.output_dir)
        .with_context(|| format!("failed to create {}", request.output_dir.display()))?;

    let doctor_report = run_release_doctor(ReleaseDoctorInput {
        provenance: request.provenance.clone(),
        signatures: request.signatures.clone(),
        quorum: Some(request.quorum.clone()),
        policy: Some(request.policy.clone()),
    });
    if doctor_report.failures > 0 || doctor_report.warnings > 0 {
        print_json(&doctor_report)?;
        bail!("release evidence pack requires a healthy release doctor");
    }

    let doctor_path = request.output_dir.join("doctor-release.json");
    write_json_file(&doctor_path, &doctor_report)?;

    let package = PackageProvenance::load(&request.provenance)?;
    let provenance_dir = request
        .provenance
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let mut evidence_files = Vec::new();
    evidence_files.push(("provenance".to_owned(), request.provenance.clone()));
    for (index, signature) in request.signatures.iter().enumerate() {
        evidence_files.push((format!("signature-{}", index + 1), signature.clone()));
    }
    evidence_files.push(("quorum".to_owned(), request.quorum.clone()));
    evidence_files.push(("policy".to_owned(), request.policy.clone()));
    evidence_files.push(("doctor-release".to_owned(), doctor_path.clone()));
    if let Some(artifact) = &package.artifact {
        evidence_files.push((
            "artifact".to_owned(),
            resolve_from_base(provenance_dir, &artifact.path),
        ));
    }
    if let Some(binary) = &package.binary {
        evidence_files.push((
            "binary".to_owned(),
            resolve_from_base(provenance_dir, &binary.path),
        ));
    }
    let custody_manifest = request.provenance.with_file_name(format!(
        "{}.custody-manifest.json",
        provenance_stem(&request.provenance)
    ));
    if custody_manifest.exists() {
        evidence_files.push(("custody-manifest".to_owned(), custody_manifest));
    }

    let mut checksum_lines = Vec::new();
    let mut files = Vec::new();
    for (name, path) in evidence_files {
        if !path.exists() {
            bail!("release evidence file does not exist: {}", path.display());
        }
        let sha256 = sha256_file_hex(&path)?;
        let label = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .unwrap_or_else(|| path.display().to_string());
        checksum_lines.push(format!("{sha256}  {label}"));
        files.push(json!({
            "name": name,
            "path": label,
            "sha256": sha256,
        }));
    }
    checksum_lines.sort();
    let checksums_path = request.output_dir.join("checksums.sha256");
    write_text_file(&checksums_path, &format!("{}\n", checksum_lines.join("\n")))?;

    let manifest = json!({
        "schema": 1,
        "generated_at": OffsetDateTime::now_utc().to_string(),
        "package": package.package,
        "version": package.version,
        "target": package.target,
        "doctor_status": doctor_report.status,
        "checksums": "checksums.sha256",
        "files": files,
    });
    let manifest_path = request.output_dir.join("release-evidence-manifest.json");
    write_json_file(&manifest_path, &manifest)?;

    Ok(json!({
        "output_dir": request.output_dir,
        "manifest": manifest_path,
        "checksums": checksums_path,
        "doctor_status": doctor_report.status,
        "files": manifest["files"].as_array().map_or(0, Vec::len),
    }))
}

fn run_default_launcher() -> Result<()> {
    let exe_name = std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| "astragrid.exe".to_owned());
    println!("{}", render_default_launcher(&exe_name));
    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        print!("Press Enter to close...");
        io::stdout().flush()?;
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
    }
    Ok(())
}

fn render_default_launcher(exe_name: &str) -> String {
    format!(
        "AstraGrid is installed and ready.\n\nThis is a command-line mission-control kernel. Run it from PowerShell or use START-ASTRAGRID.cmd from the release zip.\n\nQuick checks:\n  .\\{exe_name} --version\n  .\\{exe_name} --help\n  .\\{exe_name} doctor workspace --ledger data\\mission.agl\n\nCreate a first local ledger:\n  .\\{exe_name} init --mission flood-watch --ledger data\\mission.agl\n"
    )
}

fn run_readiness_gate(request: ReadinessGateRequest) -> Result<Value> {
    if request.cycles == 0 {
        bail!("--cycles must be at least 1");
    }
    if request.provenance.is_none()
        && (!request.signatures.is_empty() || request.quorum.is_some() || request.policy.is_some())
    {
        bail!("release readiness inputs require --provenance");
    }

    let mut cycles = Vec::new();
    let mut total_warnings = 0_usize;
    let mut total_failures = 0_usize;
    for cycle in 1..=request.cycles {
        let workspace = run_doctor(DoctorInput {
            ledger: request.ledger.clone(),
            db: request.db.clone(),
            identities: request.identities.clone(),
            approvals: request.approvals.clone(),
            peer_queue: request.peer_queue.clone(),
        });
        let release = request.provenance.as_ref().map(|provenance| {
            run_release_doctor(ReleaseDoctorInput {
                provenance: provenance.clone(),
                signatures: request.signatures.clone(),
                quorum: request.quorum.clone(),
                policy: request.policy.clone(),
            })
        });

        let warnings = workspace.warnings + release.as_ref().map_or(0, |report| report.warnings);
        let failures = workspace.failures + release.as_ref().map_or(0, |report| report.failures);
        let healthy = failures == 0 && (!request.fail_on_warning || warnings == 0);
        total_warnings += warnings;
        total_failures += failures;
        cycles.push(json!({
            "cycle": cycle,
            "healthy": healthy,
            "warnings": warnings,
            "failures": failures,
            "workspace": workspace,
            "release": release,
        }));

        if cycle < request.cycles && request.interval_seconds > 0 {
            std::thread::sleep(StdDuration::from_secs(request.interval_seconds));
        }
    }

    let healthy = cycles
        .iter()
        .all(|cycle| cycle["healthy"].as_bool().unwrap_or(false));
    let status = if healthy {
        "healthy"
    } else if total_failures > 0 || request.fail_on_warning {
        "failed"
    } else {
        "warning"
    };
    Ok(json!({
        "healthy": healthy,
        "status": status,
        "cycles": request.cycles,
        "fail_on_warning": request.fail_on_warning,
        "total_warnings": total_warnings,
        "total_failures": total_failures,
        "reports": cycles,
    }))
}

fn run_artifact_retention(request: ArtifactRetentionRequest) -> Result<Value> {
    if request.max_cache_age_days < 0 {
        bail!("--max-cache-age-days must be zero or greater");
    }
    let root = request
        .root
        .canonicalize()
        .with_context(|| format!("retention root does not exist: {}", request.root.display()))?;
    if !root.is_dir() {
        bail!("retention root must be a directory: {}", root.display());
    }

    let mut candidates = Vec::new();
    collect_cache_retention_candidates(&root, request.max_cache_age_days, &mut candidates)?;
    collect_dist_retention_candidates(&root, request.keep_dist_releases, &mut candidates)?;
    if request.include_target_cache {
        collect_target_cache_candidates(&root, &mut candidates);
    }

    let mut seen = BTreeSet::new();
    let mut items = Vec::new();
    let mut total_candidate_bytes = 0_u64;
    let mut deleted_count = 0_usize;
    for (path, reason) in candidates {
        if !path.exists() {
            continue;
        }
        let canonical = safe_retention_path(&root, &path)?;
        if !seen.insert(canonical.clone()) {
            continue;
        }
        let metadata = fs::symlink_metadata(&canonical)
            .with_context(|| format!("failed to inspect {}", canonical.display()))?;
        let bytes = path_size_bytes(&canonical)?;
        total_candidate_bytes = total_candidate_bytes.saturating_add(bytes);
        let kind = retention_path_kind(&metadata);
        let modified_at = metadata.modified().ok().map(|time| {
            let timestamp: OffsetDateTime = time.into();
            timestamp.to_string()
        });

        let mut deleted = false;
        if request.delete {
            delete_retention_path(&canonical, &metadata)?;
            deleted = true;
            deleted_count += 1;
        }

        let relative = canonical
            .strip_prefix(&root)
            .unwrap_or(&canonical)
            .to_string_lossy()
            .replace('\\', "/");
        items.push(json!({
            "path": relative,
            "kind": kind,
            "reason": reason,
            "bytes": bytes,
            "modified_at": modified_at,
            "deleted": deleted,
        }));
    }
    items.sort_by(|left, right| {
        left["path"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["path"].as_str().unwrap_or_default())
    });

    Ok(json!({
        "root": root,
        "delete": request.delete,
        "max_cache_age_days": request.max_cache_age_days,
        "keep_dist_releases": request.keep_dist_releases,
        "include_target_cache": request.include_target_cache,
        "candidate_count": items.len(),
        "deleted_count": deleted_count,
        "total_candidate_bytes": total_candidate_bytes,
        "candidates": items,
    }))
}

fn collect_cache_retention_candidates(
    root: &Path,
    max_cache_age_days: i64,
    candidates: &mut Vec<(PathBuf, String)>,
) -> Result<()> {
    let cache_dir = root.join(".cache");
    if !cache_dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(&cache_dir)? {
        let path = entry?.path();
        let Some(age_days) = retention_age_days(&path) else {
            continue;
        };
        if age_days >= max_cache_age_days {
            candidates.push((
                path,
                format!(
                    "cache entry is {age_days} days old; policy keeps {max_cache_age_days} days"
                ),
            ));
        }
    }
    Ok(())
}

fn collect_dist_retention_candidates(
    root: &Path,
    keep_dist_releases: usize,
    candidates: &mut Vec<(PathBuf, String)>,
) -> Result<()> {
    let dist = root.join("dist");
    if !dist.is_dir() {
        return Ok(());
    }
    let mut releases = Vec::new();
    for entry in fs::read_dir(&dist)? {
        let path = entry?.path();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if file_name.starts_with("astragrid-") && file_name.ends_with(".zip") {
            let modified = fs::symlink_metadata(&path)
                .and_then(|metadata| metadata.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            releases.push((path, modified));
        }
    }
    releases.sort_by(|left, right| right.1.cmp(&left.1));
    for (path, _) in releases.into_iter().skip(keep_dist_releases) {
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_owned)
            .unwrap_or_else(|| "astragrid-release".to_owned());
        candidates.push((
            path,
            format!(
                "dist release is older than the latest {keep_dist_releases} retained package(s)"
            ),
        ));
        let related = [
            format!("{stem}.provenance.json"),
            format!("{stem}.provenance.sig.json"),
            format!("{stem}.provenance.quorum.json"),
            format!("{stem}.provenance.release-policy.json"),
            format!("{stem}.provenance.custody-manifest.json"),
        ];
        for name in related {
            let related_path = dist.join(name);
            if related_path.exists() {
                candidates.push((
                    related_path,
                    format!(
                        "custody file belongs to a dist release older than the latest {keep_dist_releases} retained package(s)"
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn collect_target_cache_candidates(root: &Path, candidates: &mut Vec<(PathBuf, String)>) {
    let reason = "target build cache selected by --include-target-cache".to_owned();
    for relative in [
        "target/debug",
        "target/doc",
        "target/tmp",
        "target/release/build",
        "target/release/deps",
        "target/release/examples",
        "target/release/incremental",
        "target/release/.fingerprint",
    ] {
        let path = root.join(relative);
        if path.exists() {
            candidates.push((path, reason.clone()));
        }
    }
}

fn safe_retention_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to canonicalize retention path {}", path.display()))?;
    if canonical == root {
        bail!(
            "retention refuses to delete workspace root {}",
            root.display()
        );
    }
    if !canonical.starts_with(root) {
        bail!(
            "retention path escapes workspace root: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

fn retention_age_days(path: &Path) -> Option<i64> {
    let modified = fs::symlink_metadata(path).ok()?.modified().ok()?;
    let elapsed = std::time::SystemTime::now().duration_since(modified).ok()?;
    Some((elapsed.as_secs() / 86_400) as i64)
}

fn path_size_bytes(path: &Path) -> Result<u64> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || metadata.is_file() {
        return Ok(metadata.len());
    }
    if metadata.is_dir() {
        let mut total = 0_u64;
        for entry in fs::read_dir(path)? {
            total = total.saturating_add(path_size_bytes(&entry?.path())?);
        }
        return Ok(total);
    }
    Ok(0)
}

fn retention_path_kind(metadata: &fs::Metadata) -> &'static str {
    if metadata.file_type().is_symlink() {
        "symlink"
    } else if metadata.is_dir() {
        "directory"
    } else if metadata.is_file() {
        "file"
    } else {
        "other"
    }
}

fn delete_retention_path(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || metadata.is_file() {
        fs::remove_file(path).with_context(|| format!("failed to delete {}", path.display()))
    } else if metadata.is_dir() {
        fs::remove_dir_all(path).with_context(|| format!("failed to delete {}", path.display()))
    } else {
        bail!(
            "retention cannot delete unsupported path type: {}",
            path.display()
        );
    }
}

fn resolve_from_base(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn provenance_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .unwrap_or_else(|| "provenance".to_owned())
}

fn sanitize_file_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn build_dashboard_document(
    ledger_path: &PathBuf,
    title: String,
    approvals: Option<PathBuf>,
    db: Option<PathBuf>,
    peer_queue: Option<PathBuf>,
    evidence_bundle: &[PathBuf],
    map_href: Option<String>,
) -> Result<DashboardDocument> {
    let ledger = MissionLedger::open(ledger_path);
    let state = MissionState::from_ledger(&ledger)?;
    let ledger_events = ledger.load_events()?;
    let recent_from_ledger = || {
        let start = ledger_events.len().saturating_sub(20);
        ledger_events[start..].to_vec()
    };
    let (store_summary, recent_events) = match db {
        Some(db) => {
            if !db.exists() {
                bail!("dashboard DB does not exist: {}", db.display());
            }
            let store = MissionStore::open(db)?;
            (Some(store.summary()?), store.list_recent(20)?)
        }
        None => (None, recent_from_ledger()),
    };
    let approvals = match approvals {
        Some(path) => {
            if !path.exists() {
                bail!("approval log does not exist: {}", path.display());
            }
            ApprovalLog::open(path).list_items()?
        }
        None => Vec::new(),
    };
    let (queue_summary, peer_health, peer_jobs) = match peer_queue {
        Some(path) => {
            if !path.exists() {
                bail!("peer queue DB does not exist: {}", path.display());
            }
            let queue = PeerSyncQueue::open(path)?;
            (
                Some(queue.summary()?),
                Some(queue.health(Duration::seconds(600))?),
                queue.list(None)?,
            )
        }
        None => (None, None, Vec::new()),
    };
    let bundles = evidence_bundle
        .iter()
        .map(read_json_file::<EvidenceBundle>)
        .collect::<Result<Vec<_>>>()?;
    DashboardDocument::new(
        title,
        state.summary(),
        store_summary,
        recent_events,
        approvals,
        queue_summary,
        peer_health,
        peer_jobs,
        bundles,
        map_href,
    )
    .map_err(Into::into)
}

fn run_peer_queue_worker(request: PeerQueueWorkerRequest) -> Result<PeerQueueWorkerReport> {
    if request.limit == 0 {
        bail!("worker limit must be greater than zero");
    }
    if request.retry_delay_seconds < 0 {
        bail!("retry delay cannot be negative");
    }
    if request.interval_seconds == 0 {
        bail!("worker interval must be greater than zero");
    }
    if request.stale_after_seconds < 0 {
        bail!("stale threshold cannot be negative");
    }
    if request.cycles.is_some_and(|cycles| cycles == 0) {
        bail!("worker cycles must be greater than zero when supplied");
    }

    let shared_key = read_passphrase_file(&request.shared_key_file)?;
    let identity =
        load_optional_peer_identity(request.identity.as_ref(), request.passphrase_file.as_ref())?;
    let signed_identity = identity.is_some();
    let queue = PeerSyncQueue::open(&request.queue)?;
    let ledger = MissionLedger::open(&request.ledger);
    let options = QueueProcessOptions {
        limit: request.limit,
        retry_delay: Duration::seconds(request.retry_delay_seconds),
    };
    let stale_after = Duration::seconds(request.stale_after_seconds);

    let mut completed_cycles = 0_u32;
    let mut processed_results = 0_usize;
    let mut succeeded = 0_usize;
    let mut retry_scheduled = 0_usize;
    let mut failed = 0_usize;
    let mut cycle_summaries = Vec::new();
    let mut last_health = queue.health(stale_after)?;

    write_peer_worker_health(
        &request,
        PeerWorkerHealthInput {
            lifecycle_status: "running",
            completed_cycles,
            processed_results,
            succeeded,
            retry_scheduled,
            failed,
            queue_health: &last_health,
            last_error: None,
        },
    )?;
    write_peer_worker_audit(
        request.audit_log.as_ref(),
        json!({
            "event": "peer_worker_started",
            "queue": &request.queue,
            "ledger": &request.ledger,
            "limit": request.limit,
            "retry_delay_seconds": request.retry_delay_seconds,
            "interval_seconds": request.interval_seconds,
            "cycles": request.cycles,
            "health_file": &request.health_file,
            "signed_identity": signed_identity,
        }),
    )?;

    loop {
        let cycle_number = completed_cycles + 1;
        let report = match identity.as_ref() {
            Some(identity) => queue.process_due_with(&ledger, options, |peer| {
                fetch_ledger_snapshot_with_identity(peer.addr.as_str(), &shared_key, identity)
            }),
            None => queue.process_due_with_shared_key(&ledger, &shared_key, options),
        };
        let report = match report {
            Ok(report) => report,
            Err(error) => {
                let message = error.to_string();
                last_health = queue.health(stale_after)?;
                write_peer_worker_health(
                    &request,
                    PeerWorkerHealthInput {
                        lifecycle_status: "failed",
                        completed_cycles,
                        processed_results,
                        succeeded,
                        retry_scheduled,
                        failed,
                        queue_health: &last_health,
                        last_error: Some(&message),
                    },
                )?;
                write_peer_worker_audit(
                    request.audit_log.as_ref(),
                    json!({
                        "event": "peer_worker_failed",
                        "cycle": cycle_number,
                        "error": message,
                    }),
                )?;
                return Err(error.into());
            }
        };

        let cycle = summarize_queue_cycle(cycle_number, &report.results);
        processed_results += report.results.len();
        succeeded += cycle["succeeded"].as_u64().unwrap_or(0) as usize;
        retry_scheduled += cycle["retry_scheduled"].as_u64().unwrap_or(0) as usize;
        failed += cycle["failed"].as_u64().unwrap_or(0) as usize;
        completed_cycles = cycle_number;
        last_health = queue.health(stale_after)?;
        write_peer_worker_audit(
            request.audit_log.as_ref(),
            json!({
                "event": "peer_worker_cycle",
                "cycle": cycle_number,
                "processed": report.results.len(),
                "succeeded": cycle["succeeded"],
                "retry_scheduled": cycle["retry_scheduled"],
                "failed": cycle["failed"],
                "queue_health_status": queue_health_status_label(last_health.status),
                "due": last_health.due,
                "stale_retrying": last_health.stale_retrying,
            }),
        )?;
        cycle_summaries.push(cycle);

        let final_cycle = request
            .cycles
            .is_some_and(|limit| completed_cycles >= limit);
        write_peer_worker_health(
            &request,
            PeerWorkerHealthInput {
                lifecycle_status: if final_cycle { "stopped" } else { "running" },
                completed_cycles,
                processed_results,
                succeeded,
                retry_scheduled,
                failed,
                queue_health: &last_health,
                last_error: None,
            },
        )?;

        if final_cycle {
            break;
        }

        std::thread::sleep(std::time::Duration::from_secs(request.interval_seconds));
    }

    write_peer_worker_audit(
        request.audit_log.as_ref(),
        json!({
            "event": "peer_worker_stopped",
            "cycles": completed_cycles,
            "processed_results": processed_results,
            "succeeded": succeeded,
            "retry_scheduled": retry_scheduled,
            "failed": failed,
            "queue_health_status": queue_health_status_label(last_health.status),
        }),
    )?;

    Ok(PeerQueueWorkerReport {
        healthy: last_health.status != QueueHealthStatus::Failing,
        status: "stopped".to_owned(),
        queue: request.queue,
        ledger: request.ledger,
        signed_identity,
        cycles: completed_cycles,
        processed_results,
        succeeded,
        retry_scheduled,
        failed,
        health_file: request.health_file,
        audit_log: request.audit_log,
        stale_after_seconds: request.stale_after_seconds,
        last_health,
        cycle_summaries,
        last_error: None,
    })
}

struct PeerWorkerHealthInput<'a> {
    lifecycle_status: &'a str,
    completed_cycles: u32,
    processed_results: usize,
    succeeded: usize,
    retry_scheduled: usize,
    failed: usize,
    queue_health: &'a QueueHealthSnapshot,
    last_error: Option<&'a str>,
}

fn write_peer_worker_health(
    request: &PeerQueueWorkerRequest,
    input: PeerWorkerHealthInput<'_>,
) -> Result<()> {
    let Some(path) = request.health_file.as_ref() else {
        return Ok(());
    };
    write_json_file(
        path,
        &json!({
            "schema_version": 1,
            "kind": "peer_queue_worker",
            "healthy": input.last_error.is_none()
                && input.queue_health.status != QueueHealthStatus::Failing,
            "status": input.lifecycle_status,
            "queue_health_status": queue_health_status_label(input.queue_health.status),
            "queue": &request.queue,
            "ledger": &request.ledger,
            "signed_identity": request.identity.is_some(),
            "cycles": input.completed_cycles,
            "processed_results": input.processed_results,
            "succeeded": input.succeeded,
            "retry_scheduled": input.retry_scheduled,
            "failed": input.failed,
            "stale_after_seconds": request.stale_after_seconds,
            "checked_at": OffsetDateTime::now_utc(),
            "queue_health": input.queue_health,
            "last_error": input.last_error,
        }),
    )
}

fn write_peer_worker_audit(path: Option<&PathBuf>, event: Value) -> Result<()> {
    if let Some(path) = path {
        write_watchdog_audit(path, event)?;
    }
    Ok(())
}

fn queue_health_status_label(status: QueueHealthStatus) -> &'static str {
    match status {
        QueueHealthStatus::Healthy => "healthy",
        QueueHealthStatus::Degraded => "degraded",
        QueueHealthStatus::Failing => "failing",
    }
}

fn summarize_queue_cycle(cycle: u32, results: &[QueueProcessResult]) -> Value {
    let mut succeeded = 0_usize;
    let mut retry_scheduled = 0_usize;
    let mut failed = 0_usize;
    for result in results {
        match result.outcome {
            ProcessOutcome::Succeeded => succeeded += 1,
            ProcessOutcome::RetryScheduled => retry_scheduled += 1,
            ProcessOutcome::Failed => failed += 1,
        }
    }
    json!({
        "cycle": cycle,
        "processed": results.len(),
        "succeeded": succeeded,
        "retry_scheduled": retry_scheduled,
        "failed": failed,
    })
}

fn read_payload(input: &str) -> Result<Value> {
    let mut bytes = if let Some(path) = input.strip_prefix('@') {
        fs::read(path).with_context(|| format!("failed to read payload file {path}"))?
    } else {
        input.as_bytes().to_vec()
    };

    strip_utf8_bom(&mut bytes);

    if bytes.len() > PAYLOAD_LIMIT_BYTES {
        bail!(
            "payload is too large: {} bytes exceeds {} bytes",
            bytes.len(),
            PAYLOAD_LIMIT_BYTES
        );
    }

    serde_json::from_slice(&bytes).context("payload must be valid JSON")
}

fn read_text_file(path: &PathBuf) -> Result<String> {
    let mut bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    strip_utf8_bom(&mut bytes);
    String::from_utf8(bytes).with_context(|| format!("{} is not valid UTF-8", path.display()))
}

fn read_json_file<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let mut bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    strip_utf8_bom(&mut bytes);
    Ok(serde_json::from_slice(&bytes)?)
}

fn sha256_file_hex(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to read file for sha256 {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_bytes_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn ensure_workspace_root(root: &Path) -> Result<PathBuf> {
    fs::create_dir_all(root).with_context(|| format!("failed to create {}", root.display()))?;
    root.canonicalize()
        .with_context(|| format!("failed to canonicalize {}", root.display()))
}

fn resolve_workspace_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn ensure_passphrase_file(path: &PathBuf) -> Result<(Vec<u8>, bool)> {
    if path.exists() {
        return Ok((read_passphrase_file(path)?, false));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    let passphrase = hex::encode(random).into_bytes();
    write_bytes_file(path, &passphrase)?;
    Ok((passphrase, true))
}

fn load_workspace_profile(path: &PathBuf) -> Result<WorkspaceProfile> {
    let profile: WorkspaceProfile = read_json_file(path)?;
    if profile.schema != WORKSPACE_PROFILE_SCHEMA {
        bail!("unsupported workspace profile schema {}", profile.schema);
    }
    Ok(profile)
}

fn profile_root(profile_path: &Path, profile: &WorkspaceProfile) -> Result<PathBuf> {
    let base = profile_path.parent().unwrap_or_else(|| Path::new("."));
    let root = if profile.root.is_absolute() {
        profile.root.clone()
    } else {
        base.join(&profile.root)
    };
    root.canonicalize()
        .with_context(|| format!("workspace profile root does not exist: {}", root.display()))
}

fn collect_backup_file(
    root: &Path,
    path: &Path,
    kind: &str,
    files: &mut Vec<BackupEntry>,
) -> Result<()> {
    let canonical = safe_existing_workspace_path(root, path)?;
    if !canonical.is_file() {
        bail!("backup path is not a file: {}", canonical.display());
    }
    let bytes = fs::read(&canonical)?;
    let relative = canonical
        .strip_prefix(root)
        .with_context(|| format!("backup path escapes root: {}", canonical.display()))?
        .to_string_lossy()
        .replace('\\', "/");
    files.push(BackupEntry {
        path: relative,
        kind: kind.to_owned(),
        sha256: sha256_bytes_hex(&bytes),
        bytes_hex: hex::encode(bytes),
    });
    Ok(())
}

fn collect_optional_backup_file(
    root: &Path,
    path: &Path,
    kind: &str,
    files: &mut Vec<BackupEntry>,
) -> Result<()> {
    if path.exists() {
        collect_backup_file(root, path, kind, files)?;
    }
    Ok(())
}

fn collect_backup_directory_marker(
    root: &Path,
    dir: &Path,
    files: &mut Vec<BackupEntry>,
) -> Result<()> {
    let canonical = safe_existing_workspace_path(root, dir)?;
    if !canonical.is_dir() {
        bail!("backup path is not a directory: {}", canonical.display());
    }
    let relative = canonical
        .strip_prefix(root)
        .with_context(|| format!("backup path escapes root: {}", canonical.display()))?
        .to_string_lossy()
        .replace('\\', "/");
    files.push(BackupEntry {
        path: relative,
        kind: "directory".to_owned(),
        sha256: sha256_bytes_hex(&[]),
        bytes_hex: String::new(),
    });
    Ok(())
}

fn collect_backup_dir(
    root: &Path,
    dir: &Path,
    kind: &str,
    files: &mut Vec<BackupEntry>,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    let canonical = safe_existing_workspace_path(root, dir)?;
    if !canonical.is_dir() {
        bail!("backup path is not a directory: {}", canonical.display());
    }
    for entry in fs::read_dir(&canonical)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_backup_dir(root, &path, kind, files)?;
        } else if path.is_file() {
            collect_backup_file(root, &path, kind, files)?;
        }
    }
    Ok(())
}

fn safe_existing_workspace_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("path does not exist: {}", path.display()))?;
    if !canonical.starts_with(root) {
        bail!("path escapes workspace root: {}", canonical.display());
    }
    Ok(canonical)
}

fn safe_relative_path(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        bail!("backup entry path must be relative: {value}");
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("backup entry path cannot contain parent traversal: {value}");
    }
    Ok(path)
}

fn strip_utf8_bom(bytes: &mut Vec<u8>) {
    const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";
    if bytes.starts_with(UTF8_BOM) {
        bytes.drain(..UTF8_BOM.len());
    }
}

fn read_passphrase_file(path: &PathBuf) -> Result<Vec<u8>> {
    let mut bytes = fs::read(path)
        .with_context(|| format!("failed to read passphrase file {}", path.display()))?;
    strip_utf8_bom(&mut bytes);
    while matches!(bytes.last(), Some(b'\r' | b'\n')) {
        bytes.pop();
    }
    if bytes.is_empty() {
        bail!("passphrase file is empty: {}", path.display());
    }
    Ok(bytes)
}

fn read_passphrase(
    passphrase_file: Option<&PathBuf>,
    passphrase_os_key: Option<&PathBuf>,
) -> Result<Option<Vec<u8>>> {
    match (passphrase_file, passphrase_os_key) {
        (Some(_), Some(_)) => {
            bail!("use either --passphrase-file or --passphrase-os-key, not both")
        }
        (Some(passphrase_file), None) => Ok(Some(read_passphrase_file(passphrase_file)?)),
        (None, Some(passphrase_os_key)) => {
            let sealed = OsSealedSecret::load(passphrase_os_key)?;
            Ok(Some(sealed.open_current_user()?))
        }
        (None, None) => Ok(None),
    }
}

fn load_keypair(
    path: &PathBuf,
    passphrase_file: Option<&PathBuf>,
    passphrase_os_key: Option<&PathBuf>,
) -> Result<OperatorKeypair> {
    match read_passphrase(passphrase_file, passphrase_os_key)? {
        Some(passphrase) => Ok(OperatorKeypair::load_from_file_with_passphrase(
            path,
            Some(&passphrase),
        )?),
        None => Ok(OperatorKeypair::load_from_file(path)?),
    }
}

fn load_optional_peer_identity(
    identity: Option<&PathBuf>,
    passphrase_file: Option<&PathBuf>,
) -> Result<Option<OperatorKeypair>> {
    match (identity, passphrase_file) {
        (Some(identity), passphrase_file) => {
            Ok(Some(load_keypair(identity, passphrase_file, None)?))
        }
        (None, Some(_)) => bail!("--passphrase-file requires --identity"),
        (None, None) => Ok(None),
    }
}

fn read_peer_manifest(path: &PathBuf) -> Result<Vec<PeerEndpoint>> {
    let value: Value = read_json_file(path).context("peer manifest must be JSON")?;
    if value.is_array() {
        Ok(serde_json::from_value(value).context("peer manifest array is invalid")?)
    } else {
        Ok(vec![
            serde_json::from_value(value).context("peer manifest object is invalid")?,
        ])
    }
}

fn default_signature_output_path(input: &Path) -> PathBuf {
    let file_name = input
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("provenance");
    let signature_name = match file_name.strip_suffix(".json") {
        Some(stem) => format!("{stem}.sig.json"),
        None => format!("{file_name}.sig.json"),
    };
    input.with_file_name(signature_name)
}

fn write_json_file<T: serde::Serialize + ?Sized>(path: &PathBuf, value: &T) -> Result<()> {
    let text = format!("{}\n", serde_json::to_string_pretty(value)?);
    write_text_file(path, &text)
}

fn write_text_file(path: &PathBuf, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
}

fn write_bytes_file(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

fn print_json<T: serde::Serialize + ?Sized>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        net::TcpListener as TestTcpListener,
        path::{Path, PathBuf},
        thread,
        time::Duration as TestDuration,
    };

    use clap::Parser;
    use serde_json::json;
    use tempfile::{NamedTempFile, tempdir};

    use super::{
        ArtifactRetentionRequest, BackupRequest, Cli, Commands, DashboardCommands,
        DevicePairingRequest, DoctorCommands, FederationDaemonRequest, FirstRunRequest,
        GeoCommands, IdentityCommands, NetCommands, OpsBundleRequest, OpsCommands,
        PeerQueueCommands, PeerQueueWorkerRequest, PolicyPackCommands, ProvenanceCommands,
        ReadinessGateRequest, RecommendCommands, RegistryQuorumChangeKind,
        RegistryQuorumProposalRequest, ReleaseCustodyPackRequest, ReleaseEvidencePackRequest,
        RestoreRequest, RotateOperatorRequest, SetupCommands, SyncCommands, TeamAppendRequest,
        TeamSessionIssueRequest, UiCommands, VaultAppendRequest, VaultCommands,
        WorkerWatchdogRequest, WorkspaceProfile, acceptance_scenario,
        apply_registry_quorum_proposal, authorize_team_action, build_registry_trust_bundle,
        create_device_pairing, create_registry_quorum_proposal, default_signature_output_path,
        evaluate_policy_pack_file, export_ops_bundle, http_request_path, http_response,
        import_registry_trust_bundle, inject_meta_refresh, issue_team_session, read_json_file,
        read_payload, render_acceptance_script, render_default_launcher, restore_workspace_backup,
        rotate_operator_key, run_artifact_retention, run_federation_daemon, run_first_run_setup,
        run_peer_queue_worker, run_profile_doctor, run_readiness_gate, run_worker_watchdog,
        sha256_file_hex, sign_registry_quorum_proposal, team_append_signed, vault_append,
        vault_init, vault_tail, vault_verify, verify_device_pairing_file, verify_policy_pack_file,
        verify_registry_quorum_proposal_file, verify_registry_trust_bundle,
        verify_team_session_file, write_acceptance_pack, write_release_custody_pack,
        write_release_evidence_pack, write_workspace_backup,
    };

    fn save_test_key(
        root: &Path,
        name: &str,
        role: astragrid_core::Role,
    ) -> (astragrid_core::OperatorKeypair, PathBuf, PathBuf) {
        let keypair = astragrid_core::OperatorKeypair::generate(name, role);
        let key_path = root.join(format!("{name}.agkey"));
        let passphrase_path = root.join(format!("{name}.pass"));
        fs::write(&passphrase_path, b"test-pass").unwrap();
        keypair
            .save_encrypted_to_file(&key_path, b"test-pass")
            .unwrap();
        (keypair, key_path, passphrase_path)
    }

    #[cfg(windows)]
    fn watchdog_exit_command(code: i32) -> (String, Vec<String>) {
        (
            "cmd".to_owned(),
            vec!["/C".to_owned(), format!("exit /B {code}")],
        )
    }

    #[cfg(not(windows))]
    fn watchdog_exit_command(code: i32) -> (String, Vec<String>) {
        (
            "sh".to_owned(),
            vec!["-c".to_owned(), format!("exit {code}")],
        )
    }

    #[cfg(windows)]
    fn watchdog_fail_once_command(root: &Path) -> (String, Vec<String>, PathBuf) {
        let script = root.join("fail-once.cmd");
        let state = root.join("fail-once.state");
        fs::write(
            &script,
            "@echo off\r\nif not exist \"%~1\" (\r\n  echo seen>\"%~1\"\r\n  exit /b 7\r\n)\r\nexit /b 0\r\n",
        )
        .unwrap();
        (
            "cmd".to_owned(),
            vec![
                "/C".to_owned(),
                script.to_string_lossy().into_owned(),
                state.to_string_lossy().into_owned(),
            ],
            state,
        )
    }

    #[cfg(not(windows))]
    fn watchdog_fail_once_command(root: &Path) -> (String, Vec<String>, PathBuf) {
        let script = root.join("fail-once.sh");
        let state = root.join("fail-once.state");
        fs::write(
            &script,
            "#!/bin/sh\nif [ ! -f \"$1\" ]; then\n  echo seen > \"$1\"\n  exit 7\nfi\nexit 0\n",
        )
        .unwrap();
        (
            "sh".to_owned(),
            vec![
                script.to_string_lossy().into_owned(),
                state.to_string_lossy().into_owned(),
            ],
            state,
        )
    }

    #[test]
    fn parses_no_arg_default_launcher() {
        let cli = Cli::try_parse_from(["astragrid"]).unwrap();

        assert!(cli.command.is_none());
        let screen = render_default_launcher("astragrid.exe");
        assert!(screen.contains("AstraGrid is installed and ready."));
        assert!(screen.contains(".\\astragrid.exe --help"));
        assert!(screen.contains("START-ASTRAGRID.cmd"));
    }

    #[test]
    fn reads_inline_json_payload() {
        assert_eq!(
            read_payload(r#"{"water_level_m":5.2}"#).unwrap(),
            json!({"water_level_m": 5.2})
        );
    }

    #[test]
    fn reads_utf8_bom_payload_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"\xEF\xBB\xBF{\"water_level_m\":5.2}")
            .unwrap();
        let input = format!("@{}", file.path().display());

        assert_eq!(read_payload(&input).unwrap(), json!({"water_level_m": 5.2}));
    }

    #[test]
    fn parses_policy_pack_commands() {
        let template = Cli::try_parse_from([
            "astragrid",
            "policy-pack",
            "template",
            "--output",
            "ops/policy-pack.json",
            "--name",
            "field-safety",
        ])
        .unwrap();
        match template.command.expect("command") {
            Commands::PolicyPack {
                command: PolicyPackCommands::Template { output, name, .. },
            } => {
                assert_eq!(output, PathBuf::from("ops/policy-pack.json"));
                assert_eq!(name, "field-safety");
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }

        let evaluate = Cli::try_parse_from([
            "astragrid",
            "policy-pack",
            "evaluate",
            "--pack",
            "ops/policy-pack.json",
            "--signature",
            "ops/policy-pack.sig.json",
            "--registry",
            "data/operators.agregistry",
            "--actor",
            "lead",
            "--role",
            "incident_commander",
            "--action",
            "dispatch_team",
            "--subject",
            "river-east",
            "--priority",
            "elevated",
        ])
        .unwrap();
        match evaluate.command.expect("command") {
            Commands::PolicyPack {
                command:
                    PolicyPackCommands::Evaluate {
                        pack,
                        signature,
                        registry,
                        action,
                        ..
                    },
            } => {
                assert_eq!(pack, PathBuf::from("ops/policy-pack.json"));
                assert_eq!(signature, Some(PathBuf::from("ops/policy-pack.sig.json")));
                assert_eq!(registry, Some(PathBuf::from("data/operators.agregistry")));
                assert_eq!(action, astragrid_core::Action::DispatchTeam);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_provenance_verify_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "provenance",
            "verify",
            "--input",
            "dist/package.provenance.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Provenance {
                command: ProvenanceCommands::Verify { input },
            } => assert_eq!(input, PathBuf::from("dist/package.provenance.json")),
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_identity_os_seal_passphrase_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "identity",
            "os-seal-passphrase",
            "--input",
            "secrets/passphrase.txt",
            "--output",
            "secrets/passphrase.oskey.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Identity {
                command: IdentityCommands::OsSealPassphrase { input, output, .. },
            } => {
                assert_eq!(input, PathBuf::from("secrets/passphrase.txt"));
                assert_eq!(output, PathBuf::from("secrets/passphrase.oskey.json"));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_identity_registry_bundle_commands() {
        let bundle = Cli::try_parse_from([
            "astragrid",
            "identity",
            "registry-bundle",
            "--registry",
            "data/operators.agregistry",
            "--output",
            "ops/trust-bundle.json",
        ])
        .unwrap();
        match bundle.command.expect("command") {
            Commands::Identity {
                command: IdentityCommands::RegistryBundle { registry, output },
            } => {
                assert_eq!(registry, PathBuf::from("data/operators.agregistry"));
                assert_eq!(output, PathBuf::from("ops/trust-bundle.json"));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }

        let verify = Cli::try_parse_from([
            "astragrid",
            "identity",
            "registry-verify-bundle",
            "--input",
            "ops/trust-bundle.json",
            "--registry",
            "data/operators.agregistry",
        ])
        .unwrap();
        match verify.command.expect("command") {
            Commands::Identity {
                command: IdentityCommands::RegistryVerifyBundle { input, registry },
            } => {
                assert_eq!(input, PathBuf::from("ops/trust-bundle.json"));
                assert_eq!(registry, Some(PathBuf::from("data/operators.agregistry")));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_identity_quorum_commands() {
        let propose = Cli::try_parse_from([
            "astragrid",
            "identity",
            "quorum-propose",
            "--registry",
            "data/operators.agregistry",
            "--output",
            "ops/medic.proposal.json",
            "--change",
            "enroll",
            "--identity",
            "data/operators/medic.agkey",
            "--required-approvals",
            "2",
        ])
        .unwrap();
        match propose.command.expect("command") {
            Commands::Identity {
                command:
                    IdentityCommands::QuorumPropose {
                        registry,
                        output,
                        change,
                        identity,
                        required_approvals,
                        ..
                    },
            } => {
                assert_eq!(registry, PathBuf::from("data/operators.agregistry"));
                assert_eq!(output, PathBuf::from("ops/medic.proposal.json"));
                assert_eq!(change, RegistryQuorumChangeKind::Enroll);
                assert_eq!(identity, Some(PathBuf::from("data/operators/medic.agkey")));
                assert_eq!(required_approvals, 2);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }

        let apply = Cli::try_parse_from([
            "astragrid",
            "identity",
            "quorum-apply",
            "--registry",
            "data/operators.agregistry",
            "--proposal",
            "ops/medic.proposal.json",
            "--signature",
            "ops/lead.sig.json",
            "--signature",
            "ops/deputy.sig.json",
        ])
        .unwrap();
        match apply.command.expect("command") {
            Commands::Identity {
                command:
                    IdentityCommands::QuorumApply {
                        registry,
                        proposal,
                        signatures,
                    },
            } => {
                assert_eq!(registry, PathBuf::from("data/operators.agregistry"));
                assert_eq!(proposal, PathBuf::from("ops/medic.proposal.json"));
                assert_eq!(
                    signatures,
                    vec![
                        PathBuf::from("ops/lead.sig.json"),
                        PathBuf::from("ops/deputy.sig.json"),
                    ]
                );
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_setup_first_run_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "setup",
            "first-run",
            "--root",
            "ops",
            "--mission",
            "field-ready",
            "--operator-name",
            "lead",
            "--role",
            "incident_commander",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Setup {
                command:
                    SetupCommands::FirstRun {
                        root,
                        mission,
                        operator_name,
                        role,
                        ..
                    },
            } => {
                assert_eq!(root, PathBuf::from("ops"));
                assert_eq!(mission, "field-ready");
                assert_eq!(operator_name, "lead");
                assert_eq!(role, astragrid_core::Role::IncidentCommander);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_identity_rotate_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "identity",
            "rotate",
            "--registry",
            "data/operators.agregistry",
            "--old-operator-id",
            "agop_old",
            "--new-identity",
            "data/operators/new.agkey",
            "--new-name",
            "lead-rotated",
            "--new-role",
            "operator",
            "--new-passphrase-file",
            "data/operators/new.pass",
            "--issued-by",
            "local-command",
            "--revoked-by",
            "local-command",
            "--proof-output",
            "data/operators/rotation-proof.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Identity {
                command:
                    IdentityCommands::Rotate {
                        old_operator_id,
                        new_identity,
                        new_name,
                        proof_output,
                        ..
                    },
            } => {
                assert_eq!(old_operator_id, "agop_old");
                assert_eq!(new_identity, PathBuf::from("data/operators/new.agkey"));
                assert_eq!(new_name, "lead-rotated");
                assert_eq!(
                    proof_output,
                    PathBuf::from("data/operators/rotation-proof.json")
                );
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_sync_merge_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "sync",
            "merge",
            "--left",
            "data/left.agl",
            "--right",
            "data/right.agl",
            "--output",
            "data/merged.agl",
            "--proof",
            "data/merge-proof.json",
            "--overwrite",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Sync {
                command:
                    SyncCommands::Merge {
                        left,
                        right,
                        output,
                        proof,
                        overwrite,
                    },
            } => {
                assert_eq!(left, PathBuf::from("data/left.agl"));
                assert_eq!(right, PathBuf::from("data/right.agl"));
                assert_eq!(output, PathBuf::from("data/merged.agl"));
                assert_eq!(proof, Some(PathBuf::from("data/merge-proof.json")));
                assert!(overwrite);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_vault_commands() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "vault",
            "init",
            "--ledger",
            "data/mission.vault.json",
            "--passphrase-file",
            "data/vault.pass",
            "--mission",
            "field-ready",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Vault {
                command:
                    VaultCommands::Init {
                        ledger,
                        passphrase_file,
                        mission,
                        ..
                    },
            } => {
                assert_eq!(ledger, PathBuf::from("data/mission.vault.json"));
                assert_eq!(passphrase_file, PathBuf::from("data/vault.pass"));
                assert_eq!(mission, "field-ready");
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_net_serve_daemon_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "net",
            "serve-daemon",
            "--bind",
            "127.0.0.1:17655",
            "--ledger",
            "data/mission.agl",
            "--shared-key-file",
            "secrets/peer.key",
            "--health-file",
            "ops/federation-health.json",
            "--audit-log",
            "ops/federation-audit.jsonl",
            "--peer-registry",
            "ops/operators.agregistry",
            "--max-requests",
            "1",
            "--idle-timeout-seconds",
            "5",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Net {
                command:
                    NetCommands::ServeDaemon {
                        bind,
                        ledger,
                        shared_key_file,
                        health_file,
                        audit_log,
                        peer_registry,
                        max_requests,
                        idle_timeout_seconds,
                    },
            } => {
                assert_eq!(bind, "127.0.0.1:17655");
                assert_eq!(ledger, PathBuf::from("data/mission.agl"));
                assert_eq!(shared_key_file, PathBuf::from("secrets/peer.key"));
                assert_eq!(
                    health_file,
                    Some(PathBuf::from("ops/federation-health.json"))
                );
                assert_eq!(audit_log, Some(PathBuf::from("ops/federation-audit.jsonl")));
                assert_eq!(
                    peer_registry,
                    Some(PathBuf::from("ops/operators.agregistry"))
                );
                assert_eq!(max_requests, Some(1));
                assert_eq!(idle_timeout_seconds, 5);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_net_signed_peer_fetch_and_plan_commands() {
        let fetch = Cli::try_parse_from([
            "astragrid",
            "net",
            "fetch",
            "--addr",
            "127.0.0.1:17655",
            "--shared-key-file",
            "secrets/peer.key",
            "--identity",
            "secrets/peer.agkey",
            "--passphrase-file",
            "secrets/peer.pass",
            "--output",
            "ops/events.json",
        ])
        .unwrap();
        match fetch.command.expect("command") {
            Commands::Net {
                command:
                    NetCommands::Fetch {
                        addr,
                        identity,
                        passphrase_file,
                        output,
                        ..
                    },
            } => {
                assert_eq!(addr, "127.0.0.1:17655");
                assert_eq!(identity, Some(PathBuf::from("secrets/peer.agkey")));
                assert_eq!(passphrase_file, Some(PathBuf::from("secrets/peer.pass")));
                assert_eq!(output, PathBuf::from("ops/events.json"));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }

        let plan = Cli::try_parse_from([
            "astragrid",
            "net",
            "plan-peers",
            "--manifest",
            "ops/peers.json",
            "--shared-key-file",
            "secrets/peer.key",
            "--identity",
            "secrets/peer.agkey",
            "--passphrase-file",
            "secrets/peer.pass",
        ])
        .unwrap();
        match plan.command.expect("command") {
            Commands::Net {
                command:
                    NetCommands::PlanPeers {
                        manifest,
                        identity,
                        passphrase_file,
                        ..
                    },
            } => {
                assert_eq!(manifest, PathBuf::from("ops/peers.json"));
                assert_eq!(identity, Some(PathBuf::from("secrets/peer.agkey")));
                assert_eq!(passphrase_file, Some(PathBuf::from("secrets/peer.pass")));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_peer_queue_signed_worker_identity_options() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "peer-queue",
            "worker",
            "--shared-key-file",
            "secrets/peer.key",
            "--identity",
            "secrets/peer.agkey",
            "--passphrase-file",
            "secrets/peer.pass",
            "--cycles",
            "1",
            "--health-file",
            "ops/peer-worker-health.json",
            "--audit-log",
            "ops/peer-worker-audit.jsonl",
            "--stale-after-seconds",
            "120",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::PeerQueue {
                command:
                    PeerQueueCommands::Worker {
                        identity,
                        passphrase_file,
                        cycles,
                        health_file,
                        audit_log,
                        stale_after_seconds,
                        ..
                    },
            } => {
                assert_eq!(identity, Some(PathBuf::from("secrets/peer.agkey")));
                assert_eq!(passphrase_file, Some(PathBuf::from("secrets/peer.pass")));
                assert_eq!(cycles, Some(1));
                assert_eq!(
                    health_file,
                    Some(PathBuf::from("ops/peer-worker-health.json"))
                );
                assert_eq!(
                    audit_log,
                    Some(PathBuf::from("ops/peer-worker-audit.jsonl"))
                );
                assert_eq!(stale_after_seconds, 120);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn peer_queue_worker_writes_health_and_audit() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("mission.agl");
        let queue_path = dir.path().join("peer-sync.db");
        let shared_key_path = dir.path().join("peer.key");
        let health_path = dir.path().join("peer-worker-health.json");
        let audit_path = dir.path().join("peer-worker-audit.jsonl");
        fs::write(&shared_key_path, b"shared\n").unwrap();
        let ledger = astragrid_core::MissionLedger::open(&ledger_path);
        ledger
            .append(astragrid_core::CommandRequest::new(
                astragrid_core::Actor::new("kernel", astragrid_core::Role::System),
                astragrid_core::Action::OpenMission,
                "worker-ready",
                astragrid_core::Priority::Elevated,
                json!({"mission": "worker-ready"}),
            ))
            .unwrap();

        let report = run_peer_queue_worker(PeerQueueWorkerRequest {
            queue: queue_path,
            ledger: ledger_path,
            shared_key_file: shared_key_path,
            identity: None,
            passphrase_file: None,
            limit: 5,
            retry_delay_seconds: 1,
            interval_seconds: 1,
            cycles: Some(1),
            health_file: Some(health_path.clone()),
            audit_log: Some(audit_path.clone()),
            stale_after_seconds: 60,
        })
        .unwrap();

        assert!(report.healthy);
        assert_eq!(report.status, "stopped");
        assert_eq!(report.cycles, 1);
        assert_eq!(report.processed_results, 0);

        let health: serde_json::Value = read_json_file(&health_path).unwrap();
        assert_eq!(health["kind"], "peer_queue_worker");
        assert_eq!(health["status"], "stopped");
        assert_eq!(health["queue_health_status"], "healthy");
        assert_eq!(health["cycles"], 1);

        let audit = fs::read_to_string(audit_path).unwrap();
        assert!(audit.contains("\"event\":\"peer_worker_started\""));
        assert!(audit.contains("\"event\":\"peer_worker_cycle\""));
        assert!(audit.contains("\"event\":\"peer_worker_stopped\""));
    }

    #[test]
    fn federation_daemon_serves_snapshot_and_writes_health() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("mission.agl");
        let shared_key_path = dir.path().join("peer.key");
        let health_path = dir.path().join("federation-health.json");
        let audit_path = dir.path().join("federation-audit.jsonl");
        fs::write(&shared_key_path, b"shared\n").unwrap();
        let ledger = astragrid_core::MissionLedger::open(&ledger_path);
        ledger
            .append(astragrid_core::CommandRequest::new(
                astragrid_core::Actor::new("kernel", astragrid_core::Role::System),
                astragrid_core::Action::OpenMission,
                "federation-ready",
                astragrid_core::Priority::Elevated,
                json!({"mission": "federation-ready"}),
            ))
            .unwrap();
        let probe = TestTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let request = FederationDaemonRequest {
            bind: addr.to_string(),
            ledger: ledger_path.clone(),
            shared_key_file: shared_key_path,
            health_file: Some(health_path.clone()),
            audit_log: Some(audit_path.clone()),
            peer_registry: None,
            max_requests: Some(1),
            idle_timeout_seconds: 5,
        };
        let handle = thread::spawn(move || run_federation_daemon(request).unwrap());
        for _ in 0..100 {
            if health_path.exists() {
                break;
            }
            thread::sleep(TestDuration::from_millis(50));
        }
        assert!(health_path.exists());

        let snapshot = astragrid_net::fetch_ledger_snapshot(addr, b"shared").unwrap();
        let report = handle.join().unwrap();

        assert!(snapshot.verification.valid);
        assert_eq!(snapshot.events.len(), 1);
        assert!(report.healthy);
        assert_eq!(report.accepted_requests, 1);
        assert_eq!(report.served_requests, 1);
        assert_eq!(report.failed_requests, 0);
        let health: serde_json::Value = read_json_file(&health_path).unwrap();
        assert_eq!(health["status"], "stopped");
        assert_eq!(health["served_requests"], 1);
        let audit = fs::read_to_string(audit_path).unwrap();
        assert!(audit.contains("\"event\":\"federation_daemon_started\""));
        assert!(audit.contains("\"event\":\"peer_request_served\""));
        assert!(audit.contains("\"event\":\"federation_daemon_stopped\""));
    }

    #[test]
    fn federation_daemon_accepts_registry_authorized_peer() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("mission.agl");
        let shared_key_path = dir.path().join("peer.key");
        let registry_path = dir.path().join("operators.agregistry");
        let health_path = dir.path().join("federation-health.json");
        let audit_path = dir.path().join("federation-audit.jsonl");
        fs::write(&shared_key_path, b"shared\n").unwrap();
        let peer_key =
            astragrid_core::OperatorKeypair::generate("peer-a", astragrid_core::Role::Operator);
        let mut registry = astragrid_core::OperatorRegistry::new("local");
        registry
            .enroll(peer_key.identity().clone(), "test")
            .unwrap();
        registry.save_to_file(&registry_path).unwrap();
        let ledger = astragrid_core::MissionLedger::open(&ledger_path);
        ledger
            .append(astragrid_core::CommandRequest::new(
                astragrid_core::Actor::new("kernel", astragrid_core::Role::System),
                astragrid_core::Action::OpenMission,
                "registry-federation-ready",
                astragrid_core::Priority::Elevated,
                json!({"mission": "registry-federation-ready"}),
            ))
            .unwrap();
        let probe = TestTcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let request = FederationDaemonRequest {
            bind: addr.to_string(),
            ledger: ledger_path.clone(),
            shared_key_file: shared_key_path,
            health_file: Some(health_path.clone()),
            audit_log: Some(audit_path.clone()),
            peer_registry: Some(registry_path.clone()),
            max_requests: Some(1),
            idle_timeout_seconds: 5,
        };
        let handle = thread::spawn(move || run_federation_daemon(request));
        for _ in 0..100 {
            if health_path.exists() {
                break;
            }
            thread::sleep(TestDuration::from_millis(50));
        }
        assert!(health_path.exists());

        let snapshot =
            astragrid_net::fetch_ledger_snapshot_with_identity(addr, b"shared", &peer_key);
        let report = handle.join().unwrap();
        assert!(
            snapshot.is_ok() && report.is_ok(),
            "snapshot={snapshot:?} report={report:?}"
        );
        let snapshot = snapshot.unwrap();
        let report = report.unwrap();

        assert!(snapshot.verification.valid);
        assert!(report.peer_authorization_required);
        assert_eq!(report.peer_registry, Some(registry_path));
        assert_eq!(report.served_requests, 1);
        let health: serde_json::Value = read_json_file(&health_path).unwrap();
        assert_eq!(health["peer_authorization_required"], true);
        let audit = fs::read_to_string(audit_path).unwrap();
        assert!(audit.contains("\"peer_authorization_required\":true"));
    }

    #[test]
    fn federation_daemon_rejects_zero_max_requests() {
        let dir = tempdir().unwrap();
        let error = run_federation_daemon(FederationDaemonRequest {
            bind: "127.0.0.1:0".to_owned(),
            ledger: dir.path().join("missing.agl"),
            shared_key_file: dir.path().join("missing.key"),
            health_file: None,
            audit_log: None,
            peer_registry: None,
            max_requests: Some(0),
            idle_timeout_seconds: 0,
        })
        .unwrap_err();

        assert!(error.to_string().contains("max requests"));
    }

    #[test]
    fn parses_ops_backup_restore_commands() {
        let backup = Cli::try_parse_from([
            "astragrid",
            "ops",
            "backup",
            "--profile",
            "astragrid.profile.json",
            "--output",
            "data/backups/workspace.sealed.json",
            "--passphrase-file",
            "data/operators/lead.pass",
        ])
        .unwrap();
        match backup.command.expect("command") {
            Commands::Ops {
                command:
                    OpsCommands::Backup {
                        profile,
                        output,
                        passphrase_file,
                    },
            } => {
                assert_eq!(profile, PathBuf::from("astragrid.profile.json"));
                assert_eq!(output, PathBuf::from("data/backups/workspace.sealed.json"));
                assert_eq!(passphrase_file, PathBuf::from("data/operators/lead.pass"));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }

        let restore = Cli::try_parse_from([
            "astragrid",
            "ops",
            "restore",
            "--input",
            "data/backups/workspace.sealed.json",
            "--output-dir",
            "restore",
            "--passphrase-file",
            "backup.pass",
            "--overwrite",
        ])
        .unwrap();
        match restore.command.expect("command") {
            Commands::Ops {
                command:
                    OpsCommands::Restore {
                        input,
                        output_dir,
                        overwrite,
                        ..
                    },
            } => {
                assert_eq!(input, PathBuf::from("data/backups/workspace.sealed.json"));
                assert_eq!(output_dir, PathBuf::from("restore"));
                assert!(overwrite);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_doctor_profile_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "doctor",
            "profile",
            "--profile",
            "astragrid.profile.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Doctor {
                command: DoctorCommands::Profile { profile },
            } => assert_eq!(profile, PathBuf::from("astragrid.profile.json")),
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_peer_queue_health_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "peer-queue",
            "health",
            "--queue",
            "data/peer-sync.db",
            "--stale-after-seconds",
            "900",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::PeerQueue {
                command:
                    PeerQueueCommands::Health {
                        queue,
                        stale_after_seconds,
                    },
            } => {
                assert_eq!(queue, PathBuf::from("data/peer-sync.db"));
                assert_eq!(stale_after_seconds, 900);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_recommend_model_output_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "recommend",
            "model-output",
            "--mission",
            "mission-alpha",
            "--evidence",
            "evidence.json",
            "--candidates",
            "model-candidates.json",
            "--output",
            "bundles.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Recommend {
                command:
                    RecommendCommands::ModelOutput {
                        mission,
                        evidence,
                        candidates,
                        output,
                    },
            } => {
                assert_eq!(mission, "mission-alpha");
                assert_eq!(evidence, PathBuf::from("evidence.json"));
                assert_eq!(candidates, PathBuf::from("model-candidates.json"));
                assert_eq!(output, Some(PathBuf::from("bundles.json")));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_recommend_ai_run_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "recommend",
            "ai-run",
            "--mission",
            "mission-alpha",
            "--evidence",
            "evidence.json",
            "--command",
            "runner.exe",
            "--arg",
            "--strict",
            "--working-directory",
            "runners",
            "--timeout-ms",
            "900",
            "--max-stdout-bytes",
            "2048",
            "--max-stderr-bytes",
            "1024",
            "--clear-environment",
            "--instructions",
            "cite evidence only",
            "--output",
            "bundles.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Recommend {
                command:
                    RecommendCommands::AiRun {
                        mission,
                        evidence,
                        command,
                        args,
                        working_directory,
                        timeout_ms,
                        max_stdout_bytes,
                        max_stderr_bytes,
                        clear_environment,
                        instructions,
                        output,
                    },
            } => {
                assert_eq!(mission, "mission-alpha");
                assert_eq!(evidence, PathBuf::from("evidence.json"));
                assert_eq!(command, PathBuf::from("runner.exe"));
                assert_eq!(args, vec!["--strict"]);
                assert_eq!(working_directory, Some(PathBuf::from("runners")));
                assert_eq!(timeout_ms, 900);
                assert_eq!(max_stdout_bytes, 2048);
                assert_eq!(max_stderr_bytes, 1024);
                assert!(clear_environment);
                assert_eq!(instructions.as_deref(), Some("cite evidence only"));
                assert_eq!(output, Some(PathBuf::from("bundles.json")));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_geo_console_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "geo",
            "console",
            "--input",
            "features.jsonl",
            "--ledger",
            "data/mission.agl",
            "--output",
            "map-console.html",
            "--title",
            "Field Console",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Geo {
                command:
                    GeoCommands::Console {
                        input,
                        ledger,
                        output,
                        title,
                    },
            } => {
                assert_eq!(input, PathBuf::from("features.jsonl"));
                assert_eq!(ledger, PathBuf::from("data/mission.agl"));
                assert_eq!(output, PathBuf::from("map-console.html"));
                assert_eq!(title, "Field Console");
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_geo_serve_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "geo",
            "serve",
            "--input",
            "features.jsonl",
            "--ledger",
            "data/mission.agl",
            "--bind",
            "127.0.0.1:18081",
            "--refresh-seconds",
            "4",
            "--max-requests",
            "1",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Geo {
                command:
                    GeoCommands::Serve {
                        input,
                        ledger,
                        bind,
                        refresh_seconds,
                        max_requests,
                        ..
                    },
            } => {
                assert_eq!(input, PathBuf::from("features.jsonl"));
                assert_eq!(ledger, PathBuf::from("data/mission.agl"));
                assert_eq!(bind, "127.0.0.1:18081");
                assert_eq!(refresh_seconds, 4);
                assert_eq!(max_requests, Some(1));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn writes_and_verifies_registry_trust_bundle() {
        use astragrid_core::{OperatorKeypair, OperatorRegistry, Role};

        let dir = tempdir().unwrap();
        let registry_path = dir.path().join("operators.agregistry");
        let keypair = OperatorKeypair::generate("lead", Role::Operator);
        let mut registry = OperatorRegistry::new("district-ca");
        registry
            .enroll(keypair.identity().clone(), "district-ca")
            .unwrap();
        registry.save_to_file(&registry_path).unwrap();

        let bundle = build_registry_trust_bundle(&registry_path).unwrap();
        let report = verify_registry_trust_bundle(&bundle, Some(&registry_path)).unwrap();

        assert_eq!(bundle.authority, "district-ca");
        assert_eq!(bundle.active_operators, 1);
        assert!(report["valid"].as_bool().unwrap());
    }

    #[test]
    fn imports_registry_trust_bundle_into_local_registry() {
        use astragrid_core::{OperatorKeypair, OperatorRegistry, Role};

        let dir = tempdir().unwrap();
        let remote_registry_path = dir.path().join("remote.agregistry");
        let local_registry_path = dir.path().join("local.agregistry");
        let bundle_path = dir.path().join("trust-bundle.json");
        let keypair = OperatorKeypair::generate("lead", Role::Operator);
        let mut remote = OperatorRegistry::new("remote-ca");
        remote
            .enroll(keypair.identity().clone(), "remote-ca")
            .unwrap();
        remote.save_to_file(&remote_registry_path).unwrap();
        let mut local = OperatorRegistry::new("local-ca");
        local.save_to_file(&local_registry_path).unwrap();

        let bundle = build_registry_trust_bundle(&remote_registry_path).unwrap();
        fs::write(&bundle_path, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();

        let report = import_registry_trust_bundle(&local_registry_path, &bundle_path, false)
            .expect("import bundle");
        let loaded = OperatorRegistry::load_from_file(&local_registry_path).unwrap();

        assert_eq!(report["added"], 1);
        assert!(report["saved"].as_bool().unwrap());
        assert!(loaded.get(&keypair.identity().id).is_some());
    }

    #[test]
    fn parses_dashboard_export_with_peer_queue_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "dashboard",
            "export",
            "--ledger",
            "data/mission.agl",
            "--output",
            "ops/dashboard.html",
            "--peer-queue",
            "data/peer-sync.db",
            "--map-href",
            "map-console.html",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Dashboard {
                command:
                    DashboardCommands::Export {
                        output,
                        peer_queue,
                        map_href,
                        ..
                    },
            } => {
                assert_eq!(output, PathBuf::from("ops/dashboard.html"));
                assert_eq!(peer_queue, Some(PathBuf::from("data/peer-sync.db")));
                assert_eq!(map_href, Some("map-console.html".to_owned()));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_dashboard_serve_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "dashboard",
            "serve",
            "--ledger",
            "data/mission.agl",
            "--bind",
            "127.0.0.1:18080",
            "--refresh-seconds",
            "3",
            "--max-requests",
            "1",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Dashboard {
                command:
                    DashboardCommands::Serve {
                        ledger,
                        bind,
                        refresh_seconds,
                        max_requests,
                        ..
                    },
            } => {
                assert_eq!(ledger, PathBuf::from("data/mission.agl"));
                assert_eq!(bind, "127.0.0.1:18080");
                assert_eq!(refresh_seconds, 3);
                assert_eq!(max_requests, Some(1));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_ui_serve_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "ui",
            "serve",
            "--ledger",
            "data/mission.agl",
            "--db",
            "data/mission.db",
            "--approvals",
            "data/approvals.agl",
            "--bind",
            "127.0.0.1:18082",
            "--refresh-seconds",
            "2",
            "--max-requests",
            "2",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Ui {
                command:
                    UiCommands::Serve {
                        ledger,
                        db,
                        approvals,
                        bind,
                        refresh_seconds,
                        max_requests,
                        ..
                    },
            } => {
                assert_eq!(ledger, PathBuf::from("data/mission.agl"));
                assert_eq!(db, Some(PathBuf::from("data/mission.db")));
                assert_eq!(approvals, Some(PathBuf::from("data/approvals.agl")));
                assert_eq!(bind, "127.0.0.1:18082");
                assert_eq!(refresh_seconds, 2);
                assert_eq!(max_requests, Some(2));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn renders_dashboard_http_response_helpers() {
        assert_eq!(
            http_request_path("GET /dashboard.html HTTP/1.1\r\nHost: local\r\n\r\n"),
            Some("/dashboard.html")
        );
        let refreshed = inject_meta_refresh("<html><head></head><body></body></html>", 7);
        assert!(refreshed.contains("content=\"7\""));
        let response = http_response("200 OK", "text/plain", b"ok");
        let text = String::from_utf8(response).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("Content-Length: 2"));
        assert!(text.ends_with("\r\n\r\nok"));
    }

    #[test]
    fn parses_ops_bundle_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "ops",
            "bundle",
            "--ledger",
            "data/mission.agl",
            "--output-dir",
            "ops/handoff",
            "--features",
            "features.jsonl",
            "--provenance",
            "dist/package.provenance.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Ops {
                command:
                    OpsCommands::Bundle {
                        ledger,
                        output_dir,
                        features,
                        provenance,
                        ..
                    },
            } => {
                assert_eq!(ledger, PathBuf::from("data/mission.agl"));
                assert_eq!(output_dir, PathBuf::from("ops/handoff"));
                assert_eq!(features, Some(PathBuf::from("features.jsonl")));
                assert_eq!(
                    provenance,
                    Some(PathBuf::from("dist/package.provenance.json"))
                );
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_ops_acceptance_pack_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "ops",
            "acceptance-pack",
            "--output-dir",
            "ops/acceptance",
            "--title",
            "Acceptance",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Ops {
                command: OpsCommands::AcceptancePack { output_dir, title },
            } => {
                assert_eq!(output_dir, PathBuf::from("ops/acceptance"));
                assert_eq!(title, "Acceptance");
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_ops_release_evidence_pack_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "ops",
            "release-evidence-pack",
            "--output-dir",
            "ops/release-evidence",
            "--provenance",
            "dist/package.provenance.json",
            "--signature",
            "dist/package.provenance.sig.json",
            "--quorum",
            "dist/package.provenance.quorum.json",
            "--policy",
            "dist/package.release-policy.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Ops {
                command:
                    OpsCommands::ReleaseEvidencePack {
                        output_dir,
                        provenance,
                        signature,
                        quorum,
                        policy,
                    },
            } => {
                assert_eq!(output_dir, PathBuf::from("ops/release-evidence"));
                assert_eq!(provenance, PathBuf::from("dist/package.provenance.json"));
                assert_eq!(
                    signature,
                    vec![PathBuf::from("dist/package.provenance.sig.json")]
                );
                assert_eq!(quorum, PathBuf::from("dist/package.provenance.quorum.json"));
                assert_eq!(policy, PathBuf::from("dist/package.release-policy.json"));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_ops_readiness_gate_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "ops",
            "readiness-gate",
            "--ledger",
            "data/mission.agl",
            "--cycles",
            "2",
            "--interval-seconds",
            "0",
            "--output",
            "ops/readiness.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Ops {
                command:
                    OpsCommands::ReadinessGate {
                        ledger,
                        cycles,
                        interval_seconds,
                        output,
                        ..
                    },
            } => {
                assert_eq!(ledger, PathBuf::from("data/mission.agl"));
                assert_eq!(cycles, 2);
                assert_eq!(interval_seconds, 0);
                assert_eq!(output, Some(PathBuf::from("ops/readiness.json")));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_ops_artifact_retention_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "ops",
            "artifact-retention",
            "--root",
            ".",
            "--max-cache-age-days",
            "0",
            "--keep-dist-releases",
            "1",
            "--include-target-cache",
            "--output",
            "ops/retention.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Ops {
                command:
                    OpsCommands::ArtifactRetention {
                        root,
                        max_cache_age_days,
                        keep_dist_releases,
                        include_target_cache,
                        output,
                        ..
                    },
            } => {
                assert_eq!(root, PathBuf::from("."));
                assert_eq!(max_cache_age_days, 0);
                assert_eq!(keep_dist_releases, 1);
                assert!(include_target_cache);
                assert_eq!(output, Some(PathBuf::from("ops/retention.json")));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn writes_acceptance_pack_files() {
        let dir = tempdir().unwrap();

        let result = write_acceptance_pack(dir.path(), "Acceptance").unwrap();

        assert!(dir.path().join("run-acceptance.ps1").exists());
        assert!(dir.path().join("mission-scenario.json").exists());
        assert_eq!(
            result["output_dir"],
            dir.path().to_string_lossy().to_string()
        );
        let script = fs::read_to_string(dir.path().join("run-acceptance.ps1")).unwrap();
        assert!(script.contains("approval append-approved"));
        assert!(script.contains("ops bundle"));
        assert!(script.contains("package-release.ps1"));
        let scenario = acceptance_scenario();
        assert_eq!(scenario["name"], "flood-watch-acceptance");
    }

    #[test]
    fn acceptance_script_quotes_titles() {
        let script = render_acceptance_script("Lead's Acceptance");

        assert!(script.contains("'Lead''s Acceptance'"));
    }

    #[test]
    fn exports_ops_bundle_from_verified_ledger() {
        use astragrid_core::{Action, Actor, CommandRequest, MissionLedger, Priority, Role};

        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("mission.agl");
        let ledger = MissionLedger::open(&ledger_path);
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "mission-alpha",
                Priority::Elevated,
                json!({"mission": "mission-alpha"}),
            ))
            .unwrap();
        let output_dir = dir.path().join("handoff");

        let result = export_ops_bundle(OpsBundleRequest {
            ledger: ledger_path,
            output_dir: output_dir.clone(),
            title: "Mission Alpha".to_owned(),
            db: None,
            approvals: None,
            identities: Vec::new(),
            peer_queue: None,
            evidence_bundle: Vec::new(),
            features: None,
            provenance: None,
            signatures: Vec::new(),
            quorum: None,
            release_policy: None,
        })
        .unwrap();

        assert_eq!(result["files"], 4);
        assert!(output_dir.join("dashboard.html").exists());
        assert!(output_dir.join("state.json").exists());
        assert!(output_dir.join("doctor-workspace.json").exists());
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(output_dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["workspace_status"], "healthy");
        assert_eq!(manifest["mission"], "mission-alpha");
    }

    #[test]
    fn parses_doctor_release_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "doctor",
            "release",
            "--provenance",
            "dist/package.provenance.json",
            "--signature",
            "dist/package.provenance.sig.json",
            "--quorum",
            "dist/package.provenance.quorum.json",
            "--policy",
            "dist/release-policy.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Doctor {
                command:
                    DoctorCommands::Release {
                        provenance,
                        signature,
                        quorum,
                        policy,
                    },
            } => {
                assert_eq!(provenance, PathBuf::from("dist/package.provenance.json"));
                assert_eq!(
                    signature,
                    vec![PathBuf::from("dist/package.provenance.sig.json")]
                );
                assert_eq!(
                    quorum,
                    Some(PathBuf::from("dist/package.provenance.quorum.json"))
                );
                assert_eq!(policy, Some(PathBuf::from("dist/release-policy.json")));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_provenance_policy_template_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "provenance",
            "policy-template",
            "--output",
            "dist/release-policy.json",
            "--package",
            "astragrid",
            "--target",
            "windows-x64",
            "--min-distinct-valid-signers",
            "2",
            "--required-signer-id",
            "operator-a",
            "--allowed-signer-id",
            "operator-a",
            "--allowed-signer-id",
            "operator-b",
            "--require-clean-git",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Provenance {
                command:
                    ProvenanceCommands::PolicyTemplate {
                        output,
                        package,
                        target,
                        min_distinct_valid_signers,
                        required_signer_id,
                        allowed_signer_id,
                        require_clean_git,
                        ..
                    },
            } => {
                assert_eq!(output, PathBuf::from("dist/release-policy.json"));
                assert_eq!(package, Some("astragrid".to_owned()));
                assert_eq!(target, Some("windows-x64".to_owned()));
                assert_eq!(min_distinct_valid_signers, 2);
                assert_eq!(required_signer_id, vec!["operator-a".to_owned()]);
                assert_eq!(
                    allowed_signer_id,
                    vec!["operator-a".to_owned(), "operator-b".to_owned()]
                );
                assert!(require_clean_git);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_provenance_policy_verify_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "provenance",
            "policy-verify",
            "--policy",
            "dist/release-policy.json",
            "--provenance",
            "dist/package.provenance.json",
            "--quorum",
            "dist/package.provenance.quorum.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Provenance {
                command:
                    ProvenanceCommands::PolicyVerify {
                        policy,
                        provenance,
                        quorum,
                    },
            } => {
                assert_eq!(policy, PathBuf::from("dist/release-policy.json"));
                assert_eq!(provenance, PathBuf::from("dist/package.provenance.json"));
                assert_eq!(quorum, PathBuf::from("dist/package.provenance.quorum.json"));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_provenance_custody_pack_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "provenance",
            "custody-pack",
            "--provenance",
            "dist/package.provenance.json",
            "--output-dir",
            "dist",
            "--identity",
            "data/operators/release.agkey",
            "--passphrase-file",
            "data/operators/release.pass",
            "--threshold",
            "1",
            "--require-clean-git",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Provenance {
                command:
                    ProvenanceCommands::CustodyPack {
                        provenance,
                        output_dir,
                        identity,
                        passphrase_file,
                        threshold,
                        require_clean_git,
                        ..
                    },
            } => {
                assert_eq!(provenance, PathBuf::from("dist/package.provenance.json"));
                assert_eq!(output_dir, PathBuf::from("dist"));
                assert_eq!(
                    identity,
                    vec![PathBuf::from("data/operators/release.agkey")]
                );
                assert_eq!(
                    passphrase_file,
                    vec![PathBuf::from("data/operators/release.pass")]
                );
                assert_eq!(threshold, 1);
                assert!(require_clean_git);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn writes_release_custody_pack_with_healthy_doctor() {
        use astragrid_core::{OperatorKeypair, Role};
        use astragrid_provenance::{PackageProvenance, ProvenanceFile};

        let dir = tempdir().unwrap();
        let artifact = dir.path().join("artifact.zip");
        let binary = dir.path().join("astragrid.exe");
        fs::write(&artifact, b"release artifact").unwrap();
        fs::write(&binary, b"release binary").unwrap();
        let provenance_path = dir.path().join("artifact.provenance.json");
        let provenance = PackageProvenance {
            schema: 1,
            package: "astragrid".to_owned(),
            version: "0.1.0".to_owned(),
            target: "windows-x64".to_owned(),
            generated_at: "2026-05-07T00:00:00Z".to_owned(),
            artifact: Some(ProvenanceFile {
                path: PathBuf::from("artifact.zip"),
                sha256: sha256_file_hex(&artifact).unwrap(),
            }),
            binary: Some(ProvenanceFile {
                path: PathBuf::from("astragrid.exe"),
                sha256: sha256_file_hex(&binary).unwrap(),
            }),
            included_files: Vec::new(),
            toolchain: json!({}),
            git: json!({"dirty": false}),
        };
        fs::write(
            &provenance_path,
            serde_json::to_vec_pretty(&provenance).unwrap(),
        )
        .unwrap();
        let identity = dir.path().join("release.agkey");
        OperatorKeypair::generate("release", Role::Operator)
            .save_to_file(&identity)
            .unwrap();

        let result = write_release_custody_pack(ReleaseCustodyPackRequest {
            provenance: provenance_path.clone(),
            output_dir: dir.path().to_path_buf(),
            identities: vec![identity],
            passphrase_files: Vec::new(),
            passphrase_os_keys: Vec::new(),
            threshold: 1,
            require_clean_git: true,
        })
        .unwrap();

        assert_eq!(result["doctor_status"], "healthy");
        assert!(dir.path().join("artifact.provenance.sig.json").exists());
        assert!(dir.path().join("artifact.provenance.quorum.json").exists());
        assert!(
            dir.path()
                .join("artifact.provenance.release-policy.json")
                .exists()
        );
        assert!(
            dir.path()
                .join("artifact.provenance.custody-manifest.json")
                .exists()
        );
    }

    #[test]
    fn writes_release_evidence_pack_from_custody_files() {
        let dir = tempdir().unwrap();
        let (provenance, signature, quorum, policy) = write_test_custody_files(dir.path());
        let evidence_dir = dir.path().join("release-evidence");

        let result = write_release_evidence_pack(ReleaseEvidencePackRequest {
            output_dir: evidence_dir.clone(),
            provenance,
            signatures: vec![signature],
            quorum,
            policy,
        })
        .unwrap();

        assert_eq!(result["doctor_status"], "healthy");
        assert!(evidence_dir.join("doctor-release.json").exists());
        assert!(evidence_dir.join("checksums.sha256").exists());
        assert!(evidence_dir.join("release-evidence-manifest.json").exists());
    }

    #[test]
    fn runs_readiness_gate_for_workspace() {
        use astragrid_core::{Action, Actor, CommandRequest, MissionLedger, Priority, Role};

        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("mission.agl");
        let ledger = MissionLedger::open(&ledger_path);
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "mission-alpha",
                Priority::Elevated,
                json!({"mission": "mission-alpha"}),
            ))
            .unwrap();

        let report = run_readiness_gate(ReadinessGateRequest {
            ledger: ledger_path,
            db: None,
            identities: Vec::new(),
            approvals: None,
            peer_queue: None,
            provenance: None,
            signatures: Vec::new(),
            quorum: None,
            policy: None,
            cycles: 1,
            interval_seconds: 0,
            fail_on_warning: true,
        })
        .unwrap();

        assert!(report["healthy"].as_bool().unwrap());
        assert_eq!(report["status"], "healthy");
    }

    #[test]
    fn first_run_setup_writes_profile_and_passes_profile_doctor() {
        let dir = tempdir().unwrap();
        let profile = dir.path().join("astragrid.profile.json");

        let result = run_first_run_setup(FirstRunRequest {
            root: dir.path().to_path_buf(),
            profile: PathBuf::from("astragrid.profile.json"),
            mission: "field-ready".to_owned(),
            operator_name: "lead".to_owned(),
            role: astragrid_core::Role::IncidentCommander,
            authority: "local-command".to_owned(),
            ledger: PathBuf::from("data/mission.agl"),
            db: PathBuf::from("data/mission.db"),
            identity: PathBuf::from("data/operators/lead.agkey"),
            passphrase_file: PathBuf::from("data/operators/lead.pass"),
            registry: PathBuf::from("data/operators/operators.agregistry"),
            approvals: PathBuf::from("data/approvals.agl"),
            peer_queue: PathBuf::from("data/peer-sync.db"),
            reports_dir: PathBuf::from("data/reports"),
            backups_dir: PathBuf::from("data/backups"),
            force: false,
        })
        .unwrap();

        assert_eq!(result["doctor"]["failures"], 0);
        assert!(profile.exists());
        let loaded: WorkspaceProfile =
            serde_json::from_slice(&fs::read(&profile).unwrap()).unwrap();
        assert_eq!(loaded.mission, "field-ready");
        let doctor = run_profile_doctor(&profile).unwrap();
        assert!(doctor["healthy"].as_bool().unwrap());
    }

    #[test]
    fn backup_restore_round_trips_workspace_files() {
        let dir = tempdir().unwrap();
        let profile = dir.path().join("astragrid.profile.json");
        run_first_run_setup(FirstRunRequest {
            root: dir.path().to_path_buf(),
            profile: PathBuf::from("astragrid.profile.json"),
            mission: "field-ready".to_owned(),
            operator_name: "lead".to_owned(),
            role: astragrid_core::Role::IncidentCommander,
            authority: "local-command".to_owned(),
            ledger: PathBuf::from("data/mission.agl"),
            db: PathBuf::from("data/mission.db"),
            identity: PathBuf::from("data/operators/lead.agkey"),
            passphrase_file: PathBuf::from("data/operators/lead.pass"),
            registry: PathBuf::from("data/operators/operators.agregistry"),
            approvals: PathBuf::from("data/approvals.agl"),
            peer_queue: PathBuf::from("data/peer-sync.db"),
            reports_dir: PathBuf::from("data/reports"),
            backups_dir: PathBuf::from("data/backups"),
            force: false,
        })
        .unwrap();
        fs::write(dir.path().join("data/reports/incident.md"), "# incident\n").unwrap();
        let passphrase = dir.path().join("data/operators/lead.pass");
        let backup = dir.path().join("data/backups/workspace.sealed.json");

        let result = write_workspace_backup(BackupRequest {
            profile: profile.clone(),
            output: backup.clone(),
            passphrase_file: passphrase.clone(),
        })
        .unwrap();
        assert!(result["sealed"].as_bool().unwrap());

        let restore_dir = dir.path().join("restore");
        let restore = restore_workspace_backup(RestoreRequest {
            input: backup,
            output_dir: restore_dir.clone(),
            passphrase_file: passphrase,
            overwrite: false,
        })
        .unwrap();
        assert!(restore["restored_files"].as_u64().unwrap() >= 6);
        assert!(restore_dir.join("data/mission.agl").exists());
        assert!(restore_dir.join("data/reports/incident.md").exists());
    }

    #[test]
    fn rotates_operator_key_and_writes_proof() {
        let dir = tempdir().unwrap();
        let registry_path = dir.path().join("operators.agregistry");
        let old_key = dir.path().join("old.agkey");
        let old = astragrid_core::OperatorKeypair::generate(
            "lead",
            astragrid_core::Role::IncidentCommander,
        );
        old.save_encrypted_to_file(&old_key, b"old-pass").unwrap();
        let mut registry = astragrid_core::OperatorRegistry::new("local-command");
        registry
            .enroll(old.identity().clone(), "local-command")
            .unwrap();
        registry.save_to_file(&registry_path).unwrap();

        let new_key = dir.path().join("new.agkey");
        let new_pass = dir.path().join("new.pass");
        let proof = dir.path().join("rotation-proof.json");
        let result = rotate_operator_key(RotateOperatorRequest {
            registry: registry_path.clone(),
            old_operator_id: old.identity().id.clone(),
            new_identity: new_key.clone(),
            new_name: "lead-rotated".to_owned(),
            new_role: astragrid_core::Role::IncidentCommander,
            new_passphrase_file: new_pass.clone(),
            issued_by: "local-command".to_owned(),
            revoked_by: "local-command".to_owned(),
            reason: "rotation".to_owned(),
            proof_output: proof.clone(),
        })
        .unwrap();

        assert!(new_key.exists());
        assert!(new_pass.exists());
        assert!(proof.exists());
        let registry = astragrid_core::OperatorRegistry::load_from_file(&registry_path).unwrap();
        assert_eq!(
            registry.get(&old.identity().id).unwrap().status,
            astragrid_core::OperatorStatus::Revoked
        );
        let new_id = result["new_operator_id"].as_str().unwrap();
        assert_eq!(
            registry.get(new_id).unwrap().status,
            astragrid_core::OperatorStatus::Active
        );
    }

    #[test]
    fn registry_quorum_applies_enrollment_with_distinct_commanders() {
        let dir = tempdir().unwrap();
        let registry_path = dir.path().join("operators.agregistry");
        let proposal_path = dir.path().join("enroll.proposal.json");
        let lead_signature = dir.path().join("lead.sig.json");
        let deputy_signature = dir.path().join("deputy.sig.json");
        let (lead, lead_key, lead_pass) =
            save_test_key(dir.path(), "lead", astragrid_core::Role::IncidentCommander);
        let (deputy, deputy_key, deputy_pass) = save_test_key(
            dir.path(),
            "deputy",
            astragrid_core::Role::IncidentCommander,
        );
        let (candidate, candidate_key, _) =
            save_test_key(dir.path(), "medic", astragrid_core::Role::Operator);
        let mut registry = astragrid_core::OperatorRegistry::new("local-command");
        registry
            .enroll(lead.identity().clone(), "bootstrap")
            .unwrap();
        registry
            .enroll(deputy.identity().clone(), "bootstrap")
            .unwrap();
        registry.save_to_file(&registry_path).unwrap();

        create_registry_quorum_proposal(RegistryQuorumProposalRequest {
            registry: registry_path.clone(),
            output: proposal_path.clone(),
            change: RegistryQuorumChangeKind::Enroll,
            identity: Some(candidate_key),
            operator_id: None,
            issued_by: "quorum".to_owned(),
            revoked_by: "quorum".to_owned(),
            reason: "not used".to_owned(),
            required_approvals: 2,
        })
        .unwrap();
        sign_registry_quorum_proposal(
            &proposal_path,
            &lead_key,
            Some(&lead_pass),
            None,
            &lead_signature,
        )
        .unwrap();
        sign_registry_quorum_proposal(
            &proposal_path,
            &deputy_key,
            Some(&deputy_pass),
            None,
            &deputy_signature,
        )
        .unwrap();

        let report = verify_registry_quorum_proposal_file(
            &registry_path,
            &proposal_path,
            &[lead_signature.clone(), deputy_signature.clone()],
        )
        .unwrap();
        assert!(report.valid);
        assert_eq!(report.approved_signers.len(), 2);
        let applied = apply_registry_quorum_proposal(
            &registry_path,
            &proposal_path,
            &[lead_signature, deputy_signature],
        )
        .unwrap();
        assert!(applied["applied"].as_bool().unwrap());
        let registry = astragrid_core::OperatorRegistry::load_from_file(&registry_path).unwrap();
        assert_eq!(
            registry.get(&candidate.identity().id).unwrap().status,
            astragrid_core::OperatorStatus::Active
        );
    }

    #[test]
    fn registry_quorum_rejects_duplicate_signer_for_threshold() {
        let dir = tempdir().unwrap();
        let registry_path = dir.path().join("operators.agregistry");
        let proposal_path = dir.path().join("enroll.proposal.json");
        let lead_signature = dir.path().join("lead.sig.json");
        let (lead, lead_key, lead_pass) =
            save_test_key(dir.path(), "lead", astragrid_core::Role::IncidentCommander);
        let (deputy, _, _) = save_test_key(
            dir.path(),
            "deputy",
            astragrid_core::Role::IncidentCommander,
        );
        let (_, candidate_key, _) =
            save_test_key(dir.path(), "medic", astragrid_core::Role::Operator);
        let mut registry = astragrid_core::OperatorRegistry::new("local-command");
        registry
            .enroll(lead.identity().clone(), "bootstrap")
            .unwrap();
        registry
            .enroll(deputy.identity().clone(), "bootstrap")
            .unwrap();
        registry.save_to_file(&registry_path).unwrap();
        create_registry_quorum_proposal(RegistryQuorumProposalRequest {
            registry: registry_path.clone(),
            output: proposal_path.clone(),
            change: RegistryQuorumChangeKind::Enroll,
            identity: Some(candidate_key),
            operator_id: None,
            issued_by: "quorum".to_owned(),
            revoked_by: "quorum".to_owned(),
            reason: "not used".to_owned(),
            required_approvals: 2,
        })
        .unwrap();
        sign_registry_quorum_proposal(
            &proposal_path,
            &lead_key,
            Some(&lead_pass),
            None,
            &lead_signature,
        )
        .unwrap();

        let report = verify_registry_quorum_proposal_file(
            &registry_path,
            &proposal_path,
            &[lead_signature.clone(), lead_signature],
        )
        .unwrap();
        assert!(!report.valid);
        assert_eq!(report.approved_signers.len(), 1);
    }

    #[test]
    fn registry_quorum_rejects_revoked_signer() {
        let dir = tempdir().unwrap();
        let registry_path = dir.path().join("operators.agregistry");
        let proposal_path = dir.path().join("enroll.proposal.json");
        let lead_signature = dir.path().join("lead.sig.json");
        let revoked_signature = dir.path().join("revoked.sig.json");
        let (lead, lead_key, lead_pass) =
            save_test_key(dir.path(), "lead", astragrid_core::Role::IncidentCommander);
        let (deputy, _, _) = save_test_key(
            dir.path(),
            "deputy",
            astragrid_core::Role::IncidentCommander,
        );
        let (revoked, revoked_key, revoked_pass) = save_test_key(
            dir.path(),
            "former",
            astragrid_core::Role::IncidentCommander,
        );
        let (_, candidate_key, _) =
            save_test_key(dir.path(), "medic", astragrid_core::Role::Operator);
        let mut registry = astragrid_core::OperatorRegistry::new("local-command");
        registry
            .enroll(lead.identity().clone(), "bootstrap")
            .unwrap();
        registry
            .enroll(deputy.identity().clone(), "bootstrap")
            .unwrap();
        registry
            .enroll(revoked.identity().clone(), "bootstrap")
            .unwrap();
        registry
            .revoke(&revoked.identity().id, "bootstrap", "left team")
            .unwrap();
        registry.save_to_file(&registry_path).unwrap();
        create_registry_quorum_proposal(RegistryQuorumProposalRequest {
            registry: registry_path.clone(),
            output: proposal_path.clone(),
            change: RegistryQuorumChangeKind::Enroll,
            identity: Some(candidate_key),
            operator_id: None,
            issued_by: "quorum".to_owned(),
            revoked_by: "quorum".to_owned(),
            reason: "not used".to_owned(),
            required_approvals: 2,
        })
        .unwrap();
        sign_registry_quorum_proposal(
            &proposal_path,
            &lead_key,
            Some(&lead_pass),
            None,
            &lead_signature,
        )
        .unwrap();
        sign_registry_quorum_proposal(
            &proposal_path,
            &revoked_key,
            Some(&revoked_pass),
            None,
            &revoked_signature,
        )
        .unwrap();

        let report = verify_registry_quorum_proposal_file(
            &registry_path,
            &proposal_path,
            &[lead_signature, revoked_signature],
        )
        .unwrap();
        assert!(!report.valid);
        assert_eq!(report.approved_signers.len(), 1);
        assert!(report.signatures.iter().any(|signature| {
            signature["operator_id"].as_str() == Some(&revoked.identity().id)
                && signature["registry_status"].as_str() == Some("revoked")
        }));
    }

    #[test]
    fn registry_quorum_rejects_stale_registry_digest() {
        let dir = tempdir().unwrap();
        let registry_path = dir.path().join("operators.agregistry");
        let proposal_path = dir.path().join("enroll.proposal.json");
        let lead_signature = dir.path().join("lead.sig.json");
        let deputy_signature = dir.path().join("deputy.sig.json");
        let (lead, lead_key, lead_pass) =
            save_test_key(dir.path(), "lead", astragrid_core::Role::IncidentCommander);
        let (deputy, deputy_key, deputy_pass) = save_test_key(
            dir.path(),
            "deputy",
            astragrid_core::Role::IncidentCommander,
        );
        let (_, candidate_key, _) =
            save_test_key(dir.path(), "medic", astragrid_core::Role::Operator);
        let (late, _, _) =
            save_test_key(dir.path(), "late", astragrid_core::Role::IncidentCommander);
        let mut registry = astragrid_core::OperatorRegistry::new("local-command");
        registry
            .enroll(lead.identity().clone(), "bootstrap")
            .unwrap();
        registry
            .enroll(deputy.identity().clone(), "bootstrap")
            .unwrap();
        registry.save_to_file(&registry_path).unwrap();
        create_registry_quorum_proposal(RegistryQuorumProposalRequest {
            registry: registry_path.clone(),
            output: proposal_path.clone(),
            change: RegistryQuorumChangeKind::Enroll,
            identity: Some(candidate_key),
            operator_id: None,
            issued_by: "quorum".to_owned(),
            revoked_by: "quorum".to_owned(),
            reason: "not used".to_owned(),
            required_approvals: 2,
        })
        .unwrap();
        sign_registry_quorum_proposal(
            &proposal_path,
            &lead_key,
            Some(&lead_pass),
            None,
            &lead_signature,
        )
        .unwrap();
        sign_registry_quorum_proposal(
            &proposal_path,
            &deputy_key,
            Some(&deputy_pass),
            None,
            &deputy_signature,
        )
        .unwrap();
        let mut registry =
            astragrid_core::OperatorRegistry::load_from_file(&registry_path).unwrap();
        registry
            .enroll(late.identity().clone(), "bootstrap")
            .unwrap();
        registry.save().unwrap();

        let report = verify_registry_quorum_proposal_file(
            &registry_path,
            &proposal_path,
            &[lead_signature, deputy_signature],
        )
        .unwrap();
        assert!(!report.valid);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check["name"] == "registry_sha256" && check["status"] == "fail")
        );
    }

    #[test]
    fn team_session_authorizes_signed_append_and_device_pairing() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("mission.agl");
        let key_path = dir.path().join("lead.agkey");
        let passphrase_path = dir.path().join("lead.pass");
        let registry_path = dir.path().join("operators.agregistry");
        let session_path = dir.path().join("lead.session.json");
        let pairing_path = dir.path().join("device-pairing.json");
        let policy_pack_path = dir.path().join("field-safety.policy.json");
        let policy_signature_path = dir.path().join("field-safety.policy.sig.json");
        fs::write(&passphrase_path, b"team-pass").unwrap();

        let ledger = astragrid_core::MissionLedger::open(&ledger_path);
        ledger
            .append(astragrid_core::CommandRequest::new(
                astragrid_core::Actor::new("kernel", astragrid_core::Role::System),
                astragrid_core::Action::OpenMission,
                "team-ready",
                astragrid_core::Priority::Elevated,
                json!({"mission": "team-ready"}),
            ))
            .unwrap();
        let keypair = astragrid_core::OperatorKeypair::generate(
            "lead",
            astragrid_core::Role::IncidentCommander,
        );
        keypair
            .save_encrypted_to_file(&key_path, b"team-pass")
            .unwrap();
        let mut registry = astragrid_core::OperatorRegistry::new("local-command");
        registry
            .enroll(keypair.identity().clone(), "local-command")
            .unwrap();
        registry.save_to_file(&registry_path).unwrap();
        let policy_pack =
            astragrid_policy_pack::PolicyRulePack::field_safety_template("field-safety", "1.0.0");
        let policy_signature =
            astragrid_policy_pack::PolicyRulePackSignature::sign_pack(&policy_pack, &keypair)
                .unwrap();
        fs::write(
            &policy_pack_path,
            serde_json::to_vec_pretty(&policy_pack).unwrap(),
        )
        .unwrap();
        fs::write(
            &policy_signature_path,
            serde_json::to_vec_pretty(&policy_signature).unwrap(),
        )
        .unwrap();
        assert!(
            verify_policy_pack_file(
                &policy_pack_path,
                Some(&policy_signature_path),
                Some(&registry_path),
            )
            .unwrap()["valid"]
                .as_bool()
                .unwrap()
        );

        issue_team_session(TeamSessionIssueRequest {
            identity: key_path.clone(),
            registry: registry_path.clone(),
            output: session_path.clone(),
            passphrase_file: Some(passphrase_path.clone()),
            passphrase_os_key: None,
            ttl_minutes: 30,
        })
        .unwrap();
        let session_report = verify_team_session_file(&session_path, &registry_path).unwrap();
        assert!(session_report.valid);

        let authorization = authorize_team_action(
            &session_path,
            &registry_path,
            astragrid_core::Action::DeclareIncident,
            astragrid_core::Priority::Critical,
            "river-east".to_owned(),
            json!({"water_level_m": 5.2}),
        )
        .unwrap();
        assert!(authorization["authorized"].as_bool().unwrap());
        let blocked_by_pack = evaluate_policy_pack_file(
            &policy_pack_path,
            Some(&policy_signature_path),
            Some(&registry_path),
            &astragrid_core::CommandRequest::new(
                astragrid_core::Actor::new("lead", astragrid_core::Role::IncidentCommander),
                astragrid_core::Action::DispatchTeam,
                "river-east",
                astragrid_core::Priority::Elevated,
                json!({"note": "missing team id"}),
            ),
        )
        .unwrap();
        assert!(!blocked_by_pack.allowed);

        let append = team_append_signed(TeamAppendRequest {
            ledger: ledger_path.clone(),
            identity: key_path.clone(),
            passphrase_file: Some(passphrase_path.clone()),
            passphrase_os_key: None,
            registry: registry_path.clone(),
            session: session_path.clone(),
            policy_pack: Some(policy_pack_path),
            policy_signature: Some(policy_signature_path),
            action: astragrid_core::Action::DispatchTeam,
            subject: "river-east".to_owned(),
            priority: astragrid_core::Priority::Elevated,
            payload: json!({"team_id": "alpha"}),
        })
        .unwrap();
        assert!(append["authorized"].as_bool().unwrap());
        assert_eq!(
            astragrid_core::MissionLedger::open(&ledger_path)
                .load_events()
                .unwrap()
                .len(),
            2
        );

        create_device_pairing(DevicePairingRequest {
            identity: key_path,
            registry: registry_path.clone(),
            output: pairing_path.clone(),
            device_id: "field-tablet-01".to_owned(),
            device_name: "Field Tablet 01".to_owned(),
            passphrase_file: Some(passphrase_path),
            passphrase_os_key: None,
            ttl_minutes: 30,
        })
        .unwrap();
        let pairing_report = verify_device_pairing_file(&pairing_path, &registry_path).unwrap();
        assert!(pairing_report.valid);
    }

    #[test]
    fn encrypted_ledger_vault_round_trips_events() {
        let dir = tempdir().unwrap();
        let passphrase = dir.path().join("vault.pass");
        fs::write(&passphrase, b"vault-pass").unwrap();
        let vault = dir.path().join("mission.vault.json");

        vault_init(&vault, &passphrase, "field-ready", "local-operator").unwrap();
        vault_append(VaultAppendRequest {
            ledger: vault.clone(),
            passphrase_file: passphrase.clone(),
            actor: "lead".to_owned(),
            role: astragrid_core::Role::IncidentCommander,
            action: astragrid_core::Action::AnnotateSituation,
            subject: "river-east".to_owned(),
            priority: astragrid_core::Priority::Routine,
            payload: json!({"note": "encrypted runtime append"}),
        })
        .unwrap();
        let verification = vault_verify(&vault, &passphrase).unwrap();
        assert!(verification["verification"]["valid"].as_bool().unwrap());
        let tail = vault_tail(&vault, &passphrase, 10).unwrap();
        assert_eq!(tail["events"].as_array().unwrap().len(), 2);
        let text = fs::read_to_string(&vault).unwrap();
        assert!(text.contains("ciphertext"));
        assert!(!text.contains("encrypted runtime append"));
    }

    #[test]
    fn artifact_retention_dry_run_keeps_cache_files() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().join(".cache");
        fs::create_dir_all(&cache_dir).unwrap();
        let cache_file = cache_dir.join("package-smoke.log");
        fs::write(&cache_file, b"smoke").unwrap();

        let report = run_artifact_retention(ArtifactRetentionRequest {
            root: dir.path().to_path_buf(),
            max_cache_age_days: 0,
            keep_dist_releases: 2,
            include_target_cache: false,
            delete: false,
        })
        .unwrap();

        assert_eq!(report["candidate_count"], 1);
        assert_eq!(report["deleted_count"], 0);
        assert!(cache_file.exists());
    }

    #[test]
    fn artifact_retention_delete_removes_selected_cache_files() {
        let dir = tempdir().unwrap();
        let cache_dir = dir.path().join(".cache");
        fs::create_dir_all(&cache_dir).unwrap();
        let cache_file = cache_dir.join("old-cache.bin");
        fs::write(&cache_file, b"cache").unwrap();

        let report = run_artifact_retention(ArtifactRetentionRequest {
            root: dir.path().to_path_buf(),
            max_cache_age_days: 0,
            keep_dist_releases: 2,
            include_target_cache: false,
            delete: true,
        })
        .unwrap();

        assert_eq!(report["candidate_count"], 1);
        assert_eq!(report["deleted_count"], 1);
        assert!(!cache_file.exists());
    }

    #[test]
    fn artifact_retention_keeps_latest_dist_release() {
        let dir = tempdir().unwrap();
        let dist = dir.path().join("dist");
        fs::create_dir_all(&dist).unwrap();
        fs::write(dist.join("astragrid-windows-x64-0.1.0.zip"), b"old").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        fs::write(dist.join("astragrid-windows-x64-0.2.0.zip"), b"new").unwrap();

        let report = run_artifact_retention(ArtifactRetentionRequest {
            root: dir.path().to_path_buf(),
            max_cache_age_days: 14,
            keep_dist_releases: 1,
            include_target_cache: false,
            delete: false,
        })
        .unwrap();

        assert_eq!(report["candidate_count"], 1);
        assert_eq!(
            report["candidates"][0]["path"],
            "dist/astragrid-windows-x64-0.1.0.zip"
        );
    }

    fn write_test_custody_files(dir: &std::path::Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        use astragrid_core::{OperatorKeypair, Role};
        use astragrid_provenance::{PackageProvenance, ProvenanceFile};

        let artifact = dir.join("artifact.zip");
        let binary = dir.join("astragrid.exe");
        fs::write(&artifact, b"release artifact").unwrap();
        fs::write(&binary, b"release binary").unwrap();
        let provenance = dir.join("artifact.provenance.json");
        let provenance_doc = PackageProvenance {
            schema: 1,
            package: "astragrid".to_owned(),
            version: "0.1.0".to_owned(),
            target: "windows-x64".to_owned(),
            generated_at: "2026-05-07T00:00:00Z".to_owned(),
            artifact: Some(ProvenanceFile {
                path: PathBuf::from("artifact.zip"),
                sha256: sha256_file_hex(&artifact).unwrap(),
            }),
            binary: Some(ProvenanceFile {
                path: PathBuf::from("astragrid.exe"),
                sha256: sha256_file_hex(&binary).unwrap(),
            }),
            included_files: Vec::new(),
            toolchain: json!({}),
            git: json!({"dirty": false}),
        };
        fs::write(
            &provenance,
            serde_json::to_vec_pretty(&provenance_doc).unwrap(),
        )
        .unwrap();
        let identity = dir.join("release.agkey");
        OperatorKeypair::generate("release", Role::Operator)
            .save_to_file(&identity)
            .unwrap();

        write_release_custody_pack(ReleaseCustodyPackRequest {
            provenance: provenance.clone(),
            output_dir: dir.to_path_buf(),
            identities: vec![identity],
            passphrase_files: Vec::new(),
            passphrase_os_keys: Vec::new(),
            threshold: 1,
            require_clean_git: true,
        })
        .unwrap();

        (
            provenance,
            dir.join("artifact.provenance.sig.json"),
            dir.join("artifact.provenance.quorum.json"),
            dir.join("artifact.provenance.release-policy.json"),
        )
    }

    #[test]
    fn parses_provenance_quorum_verify_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "provenance",
            "quorum-verify",
            "--input",
            "dist/package.quorum.json",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Provenance {
                command: ProvenanceCommands::QuorumVerify { input },
            } => assert_eq!(input, PathBuf::from("dist/package.quorum.json")),
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn derives_default_provenance_signature_path() {
        assert_eq!(
            default_signature_output_path(&PathBuf::from("dist/package.provenance.json")),
            PathBuf::from("dist/package.provenance.sig.json")
        );
    }

    #[test]
    fn parses_supervisor_systemd_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "supervisor",
            "systemd-peer-worker",
            "--output",
            "ops/astragrid-peer-worker.service",
            "--shared-key-file",
            "secrets/peer.key",
            "--identity",
            "secrets/peer.agkey",
            "--identity-passphrase-file",
            "secrets/peer.pass",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Supervisor {
                command: super::SupervisorCommands::SystemdPeerWorker { output, spec, .. },
            } => {
                assert_eq!(output, PathBuf::from("ops/astragrid-peer-worker.service"));
                assert_eq!(spec.shared_key_file, PathBuf::from("secrets/peer.key"));
                assert_eq!(spec.identity, Some(PathBuf::from("secrets/peer.agkey")));
                assert_eq!(
                    spec.identity_passphrase_file,
                    Some(PathBuf::from("secrets/peer.pass"))
                );
                assert_eq!(
                    spec.health_file,
                    Some(PathBuf::from("data/peer-worker-health.json"))
                );
                assert_eq!(
                    spec.audit_log,
                    Some(PathBuf::from("data/peer-worker-audit.jsonl"))
                );
                assert_eq!(spec.stale_after_seconds, 600);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_supervisor_worker_kits() {
        let systemd = Cli::try_parse_from([
            "astragrid",
            "supervisor",
            "systemd-peer-worker-kit",
            "--output-dir",
            "ops/systemd",
            "--shared-key-file",
            "secrets/peer.key",
            "--identity",
            "secrets/peer.agkey",
        ])
        .unwrap();
        match systemd.command.expect("command") {
            Commands::Supervisor {
                command:
                    super::SupervisorCommands::SystemdPeerWorkerKit {
                        output_dir, spec, ..
                    },
            } => {
                assert_eq!(output_dir, PathBuf::from("ops/systemd"));
                assert_eq!(spec.shared_key_file, PathBuf::from("secrets/peer.key"));
                assert_eq!(spec.identity, Some(PathBuf::from("secrets/peer.agkey")));
                assert_eq!(
                    spec.health_file,
                    Some(PathBuf::from("data/peer-worker-health.json"))
                );
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }

        let windows = Cli::try_parse_from([
            "astragrid",
            "supervisor",
            "windows-peer-worker-kit",
            "--output-dir",
            "ops/windows",
            "--shared-key-file",
            "secrets/peer.key",
            "--identity",
            "secrets/peer.agkey",
        ])
        .unwrap();
        match windows.command.expect("command") {
            Commands::Supervisor {
                command:
                    super::SupervisorCommands::WindowsPeerWorkerKit {
                        output_dir, spec, ..
                    },
            } => {
                assert_eq!(output_dir, PathBuf::from("ops/windows"));
                assert_eq!(spec.shared_key_file, PathBuf::from("secrets/peer.key"));
                assert_eq!(spec.identity, Some(PathBuf::from("secrets/peer.agkey")));
                assert_eq!(
                    spec.audit_log,
                    Some(PathBuf::from("data/peer-worker-audit.jsonl"))
                );
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_supervisor_federation_daemon_commands() {
        let systemd = Cli::try_parse_from([
            "astragrid",
            "supervisor",
            "systemd-federation-daemon",
            "--output",
            "ops/astragrid-federation-daemon.service",
            "--shared-key-file",
            "secrets/peer.key",
            "--peer-registry",
            "ops/operators.agregistry",
            "--health-file",
            "ops/federation-health.json",
            "--audit-log",
            "ops/federation-audit.jsonl",
        ])
        .unwrap();
        match systemd.command.expect("command") {
            Commands::Supervisor {
                command: super::SupervisorCommands::SystemdFederationDaemon { output, spec, .. },
            } => {
                assert_eq!(
                    output,
                    PathBuf::from("ops/astragrid-federation-daemon.service")
                );
                assert_eq!(spec.shared_key_file, PathBuf::from("secrets/peer.key"));
                assert_eq!(
                    spec.health_file,
                    PathBuf::from("ops/federation-health.json")
                );
                assert_eq!(spec.audit_log, PathBuf::from("ops/federation-audit.jsonl"));
                assert_eq!(
                    spec.peer_registry,
                    Some(PathBuf::from("ops/operators.agregistry"))
                );
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }

        let windows = Cli::try_parse_from([
            "astragrid",
            "supervisor",
            "windows-federation-daemon-kit",
            "--output-dir",
            "ops/windows-federation",
            "--shared-key-file",
            "secrets/peer.key",
            "--peer-registry",
            "ops/operators.agregistry",
            "--max-requests",
            "1",
        ])
        .unwrap();
        match windows.command.expect("command") {
            Commands::Supervisor {
                command:
                    super::SupervisorCommands::WindowsFederationDaemonKit {
                        output_dir, spec, ..
                    },
            } => {
                assert_eq!(output_dir, PathBuf::from("ops/windows-federation"));
                assert_eq!(spec.shared_key_file, PathBuf::from("secrets/peer.key"));
                assert_eq!(
                    spec.peer_registry,
                    Some(PathBuf::from("ops/operators.agregistry"))
                );
                assert_eq!(spec.max_requests, Some(1));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn parses_supervisor_watchdog_run_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "supervisor",
            "watchdog-run",
            "--name",
            "peer-worker",
            "--command",
            "astragrid",
            "--arg",
            "peer-queue",
            "--arg",
            "worker",
            "--audit-log",
            "ops/watchdog.jsonl",
            "--max-restarts",
            "2",
            "--restart-delay-ms",
            "0",
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Supervisor {
                command:
                    super::SupervisorCommands::WatchdogRun {
                        name,
                        command,
                        args,
                        audit_log,
                        max_restarts,
                        restart_delay_ms,
                        ..
                    },
            } => {
                assert_eq!(name, "peer-worker");
                assert_eq!(command, "astragrid");
                assert_eq!(args, vec!["peer-queue", "worker"]);
                assert_eq!(audit_log, PathBuf::from("ops/watchdog.jsonl"));
                assert_eq!(max_restarts, 2);
                assert_eq!(restart_delay_ms, 0);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }

    #[test]
    fn watchdog_recovers_worker_after_restart() {
        let dir = tempdir().unwrap();
        let audit = dir.path().join("watchdog.jsonl");
        let (command, args, state) = watchdog_fail_once_command(dir.path());

        let report = run_worker_watchdog(WorkerWatchdogRequest {
            name: "recovering-worker".to_owned(),
            command,
            args,
            working_directory: None,
            audit_log: audit.clone(),
            max_restarts: 2,
            restart_delay_ms: 0,
            success_exit_code: 0,
        })
        .unwrap();

        assert!(report.healthy);
        assert!(report.recovered);
        assert_eq!(report.attempts.len(), 2);
        assert_eq!(report.restarts, 1);
        assert!(state.exists());
        let audit_text = fs::read_to_string(audit).unwrap();
        assert!(audit_text.contains("\"event\":\"restart_scheduled\""));
        assert!(audit_text.contains("\"event\":\"worker_recovered\""));
    }

    #[test]
    fn watchdog_reports_failure_after_restart_budget() {
        let dir = tempdir().unwrap();
        let audit = dir.path().join("watchdog.jsonl");
        let (command, args) = watchdog_exit_command(9);

        let report = run_worker_watchdog(WorkerWatchdogRequest {
            name: "failing-worker".to_owned(),
            command,
            args,
            working_directory: None,
            audit_log: audit.clone(),
            max_restarts: 1,
            restart_delay_ms: 0,
            success_exit_code: 0,
        })
        .unwrap();

        assert!(!report.healthy);
        assert_eq!(report.status, "failed");
        assert_eq!(report.attempts.len(), 2);
        assert_eq!(report.restarts, 1);
        assert_eq!(report.final_exit_code, Some(9));
        let audit_text = fs::read_to_string(audit).unwrap();
        assert!(audit_text.contains("\"event\":\"watchdog_failed\""));
    }
}
