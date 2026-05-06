use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use astragrid_approvals::{ApprovalLog, ApprovalStatus};
use astragrid_core::{
    Action, Actor, CommandRequest, MissionLedger, OperatorKeypair, OperatorRegistry,
    PAYLOAD_LIMIT_BYTES, Priority, Role,
};
use astragrid_crypto::SealedArtifact;
use astragrid_dashboard::DashboardDocument;
use astragrid_doctor::{DoctorInput, run_doctor};
use astragrid_evidence::{EvidenceBundle, EvidenceItem, Recommendation};
use astragrid_geo::GeoFeatureSet;
use astragrid_harvest::{HarvestRequest, SourceProfile, harvest_geojson, harvest_profile};
use astragrid_map::{MapConsoleDocument, MapDocument};
use astragrid_net::{PeerEndpoint, fetch_ledger_snapshot, plan_multi_peer_sync, serve_ledger_once};
use astragrid_oskey::OsSealedSecret;
use astragrid_provenance::{
    PackageProvenance, ProvenanceQuorumEnvelope, ProvenanceSignatureEnvelope,
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
    PeerWorkerSupervisorSpec, SystemdPeerWorkerUnit, WindowsPeerWorkerTask,
};
use astragrid_sync::{SyncPlan, apply_append_only};
use astragrid_sync_queue::{
    PeerSyncQueue, ProcessOutcome, QueueProcessOptions, QueueProcessResult, QueueStatus,
};
use astragrid_workflow::{CommandDraft, WorkflowPlanner, actor_from_parts};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use time::Duration;

const DEFAULT_OS_PASSPHRASE_PURPOSE: &str = "astragrid-operator-key-passphrase-v1";

#[derive(Debug, Parser)]
#[command(name = "astragrid")]
#[command(about = "AstraGrid mission control kernel CLI")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
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
    /// Manage local operator signing identities.
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
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
    /// List trusted operator registry entries.
    RegistryList {
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
enum NetCommands {
    /// Serve a verified ledger snapshot to one authenticated peer.
    ServeOnce {
        #[arg(long, default_value = "127.0.0.1:17655")]
        bind: String,
        #[arg(long, default_value = "data/mission.agl")]
        ledger: PathBuf,
        #[arg(long)]
        shared_key_file: PathBuf,
    },
    /// Fetch a verified ledger snapshot from a peer and write it as JSON events.
    Fetch {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        shared_key_file: PathBuf,
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
        #[arg(long, default_value_t = 10)]
        limit: u32,
        #[arg(long, default_value_t = 300)]
        retry_delay_seconds: i64,
        #[arg(long, default_value_t = 30)]
        interval_seconds: u64,
        /// Number of cycles to run. Omit for daemon mode.
        #[arg(long)]
        cycles: Option<u32>,
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
}

#[derive(Debug, Subcommand)]
enum DoctorCommands {
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
    #[arg(long, default_value_t = 10)]
    limit: u32,
    #[arg(long, default_value_t = 300)]
    retry_delay_seconds: i64,
    #[arg(long, default_value_t = 30)]
    interval_seconds: u64,
}

impl From<PeerWorkerSupervisorArgs> for PeerWorkerSupervisorSpec {
    fn from(value: PeerWorkerSupervisorArgs) -> Self {
        Self {
            binary: value.binary,
            working_directory: value.working_directory,
            ledger: value.ledger,
            queue: value.queue,
            shared_key_file: value.shared_key_file,
            limit: value.limit,
            retry_delay_seconds: value.retry_delay_seconds,
            interval_seconds: value.interval_seconds,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
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
            IdentityCommands::RegistryList { registry } => {
                let operator_registry = OperatorRegistry::load_from_file(registry)?;
                let entries = operator_registry.entries().collect::<Vec<_>>();
                print_json(&json!({
                    "authority": operator_registry.authority(),
                    "operators": entries,
                }))
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
                let text = read_text_file(&input).with_context(|| {
                    format!("failed to read feature records {}", input.display())
                })?;
                let ledger = MissionLedger::open(ledger);
                let state = MissionState::from_ledger(&ledger)?;
                let document = MapConsoleDocument::from_json_lines_and_state(&text, title, &state)?;
                write_text_file(&output, &document.to_html())?;
                print_json(&json!({
                    "output": output,
                    "features": document.map.features.len(),
                    "incidents": document.incidents.len(),
                }))
            }
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
        Commands::Net { command } => match command {
            NetCommands::ServeOnce {
                bind,
                ledger,
                shared_key_file,
            } => {
                let shared_key = read_passphrase_file(&shared_key_file)?;
                let ledger = MissionLedger::open(ledger);
                let addr = serve_ledger_once(bind, &ledger, &shared_key)?;
                print_json(&json!({
                    "served": true,
                    "addr": addr.to_string(),
                }))
            }
            NetCommands::Fetch {
                addr,
                shared_key_file,
                output,
            } => {
                let shared_key = read_passphrase_file(&shared_key_file)?;
                let snapshot = fetch_ledger_snapshot(addr, &shared_key)?;
                write_json_file(&output, &snapshot.events)?;
                print_json(&json!({
                    "output": output,
                    "events": snapshot.events.len(),
                    "valid": snapshot.verification.valid,
                }))
            }
            NetCommands::PlanPeers {
                ledger,
                manifest,
                shared_key_file,
                output,
            } => {
                let ledger = MissionLedger::open(ledger);
                let verification = ledger.verify()?;
                if !verification.valid {
                    bail!("local ledger is corrupt: {:?}", verification.failures);
                }
                let peers = read_peer_manifest(&manifest)?;
                let shared_key = read_passphrase_file(&shared_key_file)?;
                let report = plan_multi_peer_sync(&ledger.load_events()?, &peers, &shared_key);
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
                limit,
                retry_delay_seconds,
            } => {
                if retry_delay_seconds < 0 {
                    bail!("retry delay cannot be negative");
                }
                let shared_key = read_passphrase_file(&shared_key_file)?;
                let queue = PeerSyncQueue::open(queue)?;
                let ledger = MissionLedger::open(ledger);
                let report = queue.process_due_with_shared_key(
                    &ledger,
                    &shared_key,
                    QueueProcessOptions {
                        limit,
                        retry_delay: Duration::seconds(retry_delay_seconds),
                    },
                )?;
                print_json(&report)
            }
            PeerQueueCommands::Worker {
                queue,
                ledger,
                shared_key_file,
                limit,
                retry_delay_seconds,
                interval_seconds,
                cycles,
            } => {
                if retry_delay_seconds < 0 {
                    bail!("retry delay cannot be negative");
                }
                let shared_key = read_passphrase_file(&shared_key_file)?;
                let queue = PeerSyncQueue::open(queue)?;
                let ledger = MissionLedger::open(ledger);
                let options = QueueProcessOptions {
                    limit,
                    retry_delay: Duration::seconds(retry_delay_seconds),
                };
                let mut completed_cycles = 0_u32;
                let mut processed_results = 0_usize;
                let mut succeeded = 0_usize;
                let mut retry_scheduled = 0_usize;
                let mut failed = 0_usize;
                let mut cycle_summaries = Vec::new();

                loop {
                    let report =
                        queue.process_due_with_shared_key(&ledger, &shared_key, options)?;
                    let cycle = summarize_queue_cycle(completed_cycles + 1, &report.results);
                    processed_results += report.results.len();
                    succeeded += cycle["succeeded"].as_u64().unwrap_or(0) as usize;
                    retry_scheduled += cycle["retry_scheduled"].as_u64().unwrap_or(0) as usize;
                    failed += cycle["failed"].as_u64().unwrap_or(0) as usize;
                    cycle_summaries.push(cycle);
                    completed_cycles += 1;

                    if cycles.is_some_and(|limit| completed_cycles >= limit) {
                        break;
                    }

                    std::thread::sleep(std::time::Duration::from_secs(interval_seconds));
                }

                print_json(&json!({
                    "cycles": completed_cycles,
                    "processed_results": processed_results,
                    "succeeded": succeeded,
                    "retry_scheduled": retry_scheduled,
                    "failed": failed,
                    "cycle_summaries": cycle_summaries,
                }))
            }
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
                let ledger = MissionLedger::open(ledger);
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
                let dashboard = DashboardDocument::new(
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
                }))
            }
        },
        Commands::Doctor { command } => match command {
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
        },
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
    use std::{io::Write, path::PathBuf};

    use clap::Parser;
    use serde_json::json;
    use tempfile::NamedTempFile;

    use super::{
        Cli, Commands, DashboardCommands, GeoCommands, IdentityCommands, PeerQueueCommands,
        ProvenanceCommands, RecommendCommands, default_signature_output_path, read_payload,
    };

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
    fn parses_provenance_verify_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "provenance",
            "verify",
            "--input",
            "dist/package.provenance.json",
        ])
        .unwrap();

        match cli.command {
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

        match cli.command {
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

        match cli.command {
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

        match cli.command {
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

        match cli.command {
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

        match cli.command {
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
    fn parses_provenance_quorum_verify_command() {
        let cli = Cli::try_parse_from([
            "astragrid",
            "provenance",
            "quorum-verify",
            "--input",
            "dist/package.quorum.json",
        ])
        .unwrap();

        match cli.command {
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
        ])
        .unwrap();

        match cli.command {
            Commands::Supervisor {
                command: super::SupervisorCommands::SystemdPeerWorker { output, spec, .. },
            } => {
                assert_eq!(output, PathBuf::from("ops/astragrid-peer-worker.service"));
                assert_eq!(spec.shared_key_file, PathBuf::from("secrets/peer.key"));
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }
}
