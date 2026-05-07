use std::{
    collections::BTreeSet,
    fs,
    io::{self, IsTerminal, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::Duration as StdDuration,
};

use anyhow::{Context, Result, bail};
use astragrid_approvals::{ApprovalLog, ApprovalStatus};
use astragrid_core::{
    Action, Actor, CommandRequest, MissionLedger, OperatorKeypair, OperatorRegistry,
    OperatorRegistryEntry, OperatorStatus, PAYLOAD_LIMIT_BYTES, Priority, RegistryImportStatus,
    Role,
};
use astragrid_crypto::SealedArtifact;
use astragrid_dashboard::DashboardDocument;
use astragrid_doctor::{DoctorInput, ReleaseDoctorInput, run_doctor, run_release_doctor};
use astragrid_evidence::{EvidenceBundle, EvidenceItem, Recommendation};
use astragrid_geo::GeoFeatureSet;
use astragrid_harvest::{HarvestRequest, SourceProfile, harvest_geojson, harvest_profile};
use astragrid_map::{MapConsoleDocument, MapDocument};
use astragrid_net::{PeerEndpoint, fetch_ledger_snapshot, plan_multi_peer_sync, serve_ledger_once};
use astragrid_oskey::OsSealedSecret;
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
    PeerWorkerSupervisorSpec, SystemdPeerWorkerUnit, WindowsPeerWorkerTask,
};
use astragrid_sync::{SyncPlan, apply_append_only};
use astragrid_sync_queue::{
    PeerSyncQueue, ProcessOutcome, QueueProcessOptions, QueueProcessResult, QueueStatus,
};
use astragrid_workflow::{CommandDraft, WorkflowPlanner, actor_from_parts};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

const DEFAULT_OS_PASSPHRASE_PURPOSE: &str = "astragrid-operator-key-passphrase-v1";

#[derive(Debug, Parser)]
#[command(name = "astragrid")]
#[command(about = "AstraGrid mission control kernel CLI")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
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
    let Some(command) = cli.command else {
        return run_default_launcher();
    };

    match command {
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
            "ops bundle",
            "workspace doctor",
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
    $registry = Join-Path $Run 'operators.agregistry'
    $payload = Join-Path $Run 'payload.json'
    $evidence = Join-Path $Run 'evidence.json'
    $bundle = Join-Path $Run 'close-bundle.json'
    $draft = Join-Path $Run 'draft.json'
    $approvals = Join-Path $Run 'approvals.agl'
    $geo = Join-Path $Run 'features.geojson'
    $features = Join-Path $Run 'features.jsonl'
    $dashboard = Join-Path $Run 'dashboard.html'
    $opsBundle = Join-Path $Run 'ops-bundle'
    $scenario = Join-Path $PackRoot 'mission-scenario.json'
    $scenarioRun = Join-Path $Run 'scenario'

    'acceptance local passphrase' | Set-Content -Encoding UTF8 $passphrase
    '{{"water_level_m":5.2}}' | Set-Content -Encoding UTF8 $payload
    '[{{"id":"sensor-1","source":"river-gauge","kind":"sensor","confidence":0.94,"digest":"sensor-digest","excerpt":"water=5.2"}}]' | Set-Content -Encoding UTF8 $evidence
    '{{"type":"Feature","id":"river-east","properties":{{"risk":"flood"}},"geometry":{{"type":"Point","coordinates":[72.2,31.2]}}}}' | Set-Content -Encoding UTF8 $geo

    Invoke-AstraGrid init --mission flood-watch --ledger $ledger
    Invoke-AstraGrid identity create --path $identity --name lead --role incident_commander --passphrase-file $passphrase
    Invoke-AstraGrid identity registry-init --registry $registry --authority local-command
    Invoke-AstraGrid identity enroll --registry $registry --identity $identity --passphrase-file $passphrase --issued-by local-command
    Invoke-AstraGrid append-signed --ledger $ledger --identity $identity --passphrase-file $passphrase --registry $registry --action declare_incident --subject river-east --priority critical --payload "@$payload"
    Invoke-AstraGrid verify --ledger $ledger
    Invoke-AstraGrid store ingest --ledger $ledger --db $db
    Invoke-AstraGrid evidence build --mission flood-watch --evidence $evidence --action close_incident --subject river-east --rationale 'Water receded below incident threshold.' --confidence 0.91 --evidence-id sensor-1 --output $bundle
    Invoke-AstraGrid workflow draft --ledger $ledger --bundle $bundle --actor lead --role incident_commander --min-confidence 0.75 --output $draft
    $approval = Invoke-AstraGridJson approval submit --queue $approvals --draft $draft --requested-by acceptance
    Invoke-AstraGrid approval approve --queue $approvals --id $approval.id --reviewed-by lead --reason 'acceptance evidence verified'
    Invoke-AstraGrid approval append-approved --queue $approvals --id $approval.id --ledger $ledger --identity $identity --passphrase-file $passphrase --registry $registry --executed-by lead
    Invoke-AstraGrid approval verify --queue $approvals
    Invoke-AstraGrid store ingest --ledger $ledger --db $db
    Invoke-AstraGrid geo ingest --input $geo --output $features
    Invoke-AstraGrid dashboard export --ledger $ledger --db $db --approvals $approvals --output $dashboard --title {quoted_title}
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
    use std::{fs, io::Write, path::PathBuf};

    use clap::Parser;
    use serde_json::json;
    use tempfile::{NamedTempFile, tempdir};

    use super::{
        Cli, Commands, DashboardCommands, DoctorCommands, GeoCommands, IdentityCommands,
        OpsBundleRequest, OpsCommands, PeerQueueCommands, ProvenanceCommands, ReadinessGateRequest,
        RecommendCommands, ReleaseCustodyPackRequest, ReleaseEvidencePackRequest,
        acceptance_scenario, build_registry_trust_bundle, default_signature_output_path,
        export_ops_bundle, http_request_path, http_response, import_registry_trust_bundle,
        inject_meta_refresh, read_payload, render_acceptance_script, render_default_launcher,
        run_readiness_gate, sha256_file_hex, verify_registry_trust_bundle, write_acceptance_pack,
        write_release_custody_pack, write_release_evidence_pack,
    };

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
        ])
        .unwrap();

        match cli.command.expect("command") {
            Commands::Supervisor {
                command: super::SupervisorCommands::SystemdPeerWorker { output, spec, .. },
            } => {
                assert_eq!(output, PathBuf::from("ops/astragrid-peer-worker.service"));
                assert_eq!(spec.shared_key_file, PathBuf::from("secrets/peer.key"));
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
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }
    }
}
