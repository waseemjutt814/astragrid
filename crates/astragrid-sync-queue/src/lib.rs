use std::{fmt, path::Path, str::FromStr};

use astragrid_core::{LedgerVerification, MissionLedger};
use astragrid_net::{PeerEndpoint, PeerSnapshot, fetch_ledger_snapshot};
use astragrid_sync::{SyncApplyReport, SyncPlan, apply_append_only_events};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug)]
pub struct PeerSyncQueue {
    connection: Connection,
}

impl PeerSyncQueue {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, QueueError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        let queue = Self { connection };
        queue.configure()?;
        queue.migrate()?;
        Ok(queue)
    }

    pub fn enqueue_peer(
        &self,
        peer: PeerEndpoint,
        max_attempts: u32,
    ) -> Result<PeerSyncJob, QueueError> {
        if peer.name.trim().is_empty() {
            return Err(QueueError::InvalidPeer("peer name is required".to_owned()));
        }
        if peer.addr.trim().is_empty() {
            return Err(QueueError::InvalidPeer(
                "peer address is required".to_owned(),
            ));
        }
        if max_attempts == 0 {
            return Err(QueueError::InvalidAttempts);
        }

        let now = OffsetDateTime::now_utc();
        let job = PeerSyncJob {
            id: format!("agsq_{}", Uuid::now_v7().simple()),
            peer,
            status: QueueStatus::Pending,
            attempts: 0,
            max_attempts,
            created_at: now,
            updated_at: now,
            next_attempt_at: now,
            last_error: None,
            last_plan: None,
            last_apply: None,
        };
        self.connection.execute(
            r#"
            INSERT INTO peer_sync_jobs (
                id, peer_name, peer_addr, status, attempts, max_attempts,
                created_at, updated_at, next_attempt_at, last_error,
                last_plan_json, last_apply_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            job_params(&job)?,
        )?;
        Ok(job)
    }

    pub fn enqueue_peers(
        &self,
        peers: Vec<PeerEndpoint>,
        max_attempts: u32,
    ) -> Result<Vec<PeerSyncJob>, QueueError> {
        peers
            .into_iter()
            .map(|peer| self.enqueue_peer(peer, max_attempts))
            .collect()
    }

    pub fn list(&self, status: Option<QueueStatus>) -> Result<Vec<PeerSyncJob>, QueueError> {
        let mut sql = String::from(
            r#"
            SELECT id, peer_name, peer_addr, status, attempts, max_attempts,
                   created_at, updated_at, next_attempt_at, last_error,
                   last_plan_json, last_apply_json
            FROM peer_sync_jobs
            "#,
        );
        if status.is_some() {
            sql.push_str(" WHERE status = ?1");
        }
        sql.push_str(" ORDER BY created_at ASC, id ASC");

        let mut statement = self.connection.prepare(&sql)?;
        let rows = match status {
            Some(status) => statement.query_map([status.to_string()], row_to_job)?,
            None => statement.query_map([], row_to_job)?,
        };
        let mut jobs = Vec::new();
        for row in rows {
            jobs.push(row?);
        }
        Ok(jobs)
    }

    pub fn get(&self, id: &str) -> Result<PeerSyncJob, QueueError> {
        self.connection
            .query_row(
                r#"
                SELECT id, peer_name, peer_addr, status, attempts, max_attempts,
                       created_at, updated_at, next_attempt_at, last_error,
                       last_plan_json, last_apply_json
                FROM peer_sync_jobs
                WHERE id = ?1
                "#,
                [id],
                row_to_job,
            )
            .optional()?
            .ok_or_else(|| QueueError::NotFound(id.to_owned()))
    }

    pub fn summary(&self) -> Result<QueueSummary, QueueError> {
        let total =
            self.connection
                .query_row("SELECT COUNT(*) FROM peer_sync_jobs", [], |row| {
                    row.get::<_, u64>(0)
                })?;
        let count_status = |status: QueueStatus| -> Result<u64, QueueError> {
            Ok(self.connection.query_row(
                "SELECT COUNT(*) FROM peer_sync_jobs WHERE status = ?1",
                [status.to_string()],
                |row| row.get::<_, u64>(0),
            )?)
        };
        Ok(QueueSummary {
            schema_version: SCHEMA_VERSION,
            total,
            pending: count_status(QueueStatus::Pending)?,
            retrying: count_status(QueueStatus::Retrying)?,
            succeeded: count_status(QueueStatus::Succeeded)?,
            failed: count_status(QueueStatus::Failed)?,
        })
    }

    pub fn health(&self, stale_after: Duration) -> Result<QueueHealthSnapshot, QueueError> {
        let summary = self.summary()?;
        let jobs = self.list(None)?;
        let now = OffsetDateTime::now_utc();
        let due = jobs
            .iter()
            .filter(|job| {
                matches!(job.status, QueueStatus::Pending | QueueStatus::Retrying)
                    && job.next_attempt_at <= now
            })
            .count();
        let stale_retrying = jobs
            .iter()
            .filter(|job| {
                job.status == QueueStatus::Retrying && job.updated_at <= now - stale_after
            })
            .count();
        let mut last_errors = jobs
            .iter()
            .filter_map(|job| {
                job.last_error.as_ref().map(|error| QueueLastError {
                    job_id: job.id.clone(),
                    peer_name: job.peer.name.clone(),
                    status: job.status,
                    attempts: job.attempts,
                    max_attempts: job.max_attempts,
                    updated_at: job.updated_at,
                    error: error.clone(),
                })
            })
            .collect::<Vec<_>>();
        last_errors.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
        last_errors.truncate(10);
        let status = if summary.failed > 0 && summary.pending == 0 && summary.retrying == 0 {
            QueueHealthStatus::Failing
        } else if summary.failed > 0 || summary.retrying > 0 || stale_retrying > 0 {
            QueueHealthStatus::Degraded
        } else {
            QueueHealthStatus::Healthy
        };
        Ok(QueueHealthSnapshot {
            schema_version: SCHEMA_VERSION,
            status,
            checked_at: now,
            summary,
            due,
            stale_retrying,
            last_errors,
        })
    }

    pub fn process_due_with_shared_key(
        &self,
        ledger: &MissionLedger,
        shared_key: &[u8],
        options: QueueProcessOptions,
    ) -> Result<QueueProcessReport, QueueError> {
        self.process_due_with(ledger, options, |peer| {
            fetch_ledger_snapshot(peer.addr.as_str(), shared_key)
        })
    }

    pub fn process_due_with<F, E>(
        &self,
        ledger: &MissionLedger,
        options: QueueProcessOptions,
        mut fetch: F,
    ) -> Result<QueueProcessReport, QueueError>
    where
        F: FnMut(&PeerEndpoint) -> Result<PeerSnapshot, E>,
        E: fmt::Display,
    {
        let due = self.due_jobs(options.limit)?;
        let mut results = Vec::new();
        for job in due {
            results.push(self.process_job(ledger, job, options.retry_delay, &mut fetch)?);
        }
        Ok(QueueProcessReport { results })
    }

    fn process_job<F, E>(
        &self,
        ledger: &MissionLedger,
        job: PeerSyncJob,
        retry_delay: Duration,
        fetch: &mut F,
    ) -> Result<QueueProcessResult, QueueError>
    where
        F: FnMut(&PeerEndpoint) -> Result<PeerSnapshot, E>,
        E: fmt::Display,
    {
        let attempt = job.attempts.saturating_add(1);
        match fetch(&job.peer)
            .map_err(|error| error.to_string())
            .and_then(|snapshot| {
                process_snapshot(ledger, &snapshot).map_err(|error| error.to_string())
            }) {
            Ok(apply) => {
                let plan = apply.plan.clone();
                let updated = self.update_success(&job.id, attempt, plan, apply)?;
                Ok(QueueProcessResult {
                    job: updated,
                    outcome: ProcessOutcome::Succeeded,
                })
            }
            Err(error) => {
                let terminal = attempt >= job.max_attempts;
                let updated =
                    self.update_failure(&job.id, attempt, terminal, retry_delay, error)?;
                Ok(QueueProcessResult {
                    job: updated,
                    outcome: if terminal {
                        ProcessOutcome::Failed
                    } else {
                        ProcessOutcome::RetryScheduled
                    },
                })
            }
        }
    }

    fn due_jobs(&self, limit: u32) -> Result<Vec<PeerSyncJob>, QueueError> {
        let now = format_time(OffsetDateTime::now_utc())?;
        let mut statement = self.connection.prepare(
            r#"
            SELECT id, peer_name, peer_addr, status, attempts, max_attempts,
                   created_at, updated_at, next_attempt_at, last_error,
                   last_plan_json, last_apply_json
            FROM peer_sync_jobs
            WHERE status IN ('pending', 'retrying')
              AND attempts < max_attempts
              AND next_attempt_at <= ?1
            ORDER BY next_attempt_at ASC, created_at ASC, id ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![now, i64::from(limit.max(1))], row_to_job)?;
        let mut jobs = Vec::new();
        for row in rows {
            jobs.push(row?);
        }
        Ok(jobs)
    }

    fn update_success(
        &self,
        id: &str,
        attempts: u32,
        plan: SyncPlan,
        apply: SyncApplyReport,
    ) -> Result<PeerSyncJob, QueueError> {
        let now = format_time(OffsetDateTime::now_utc())?;
        self.connection.execute(
            r#"
            UPDATE peer_sync_jobs
            SET status = 'succeeded',
                attempts = ?2,
                updated_at = ?3,
                next_attempt_at = ?3,
                last_error = NULL,
                last_plan_json = ?4,
                last_apply_json = ?5
            WHERE id = ?1
            "#,
            params![
                id,
                attempts,
                now,
                serde_json::to_string(&plan)?,
                serde_json::to_string(&apply)?
            ],
        )?;
        self.get(id)
    }

    fn update_failure(
        &self,
        id: &str,
        attempts: u32,
        terminal: bool,
        retry_delay: Duration,
        error: String,
    ) -> Result<PeerSyncJob, QueueError> {
        let now = OffsetDateTime::now_utc();
        let next_attempt_at = if terminal { now } else { now + retry_delay };
        self.connection.execute(
            r#"
            UPDATE peer_sync_jobs
            SET status = ?2,
                attempts = ?3,
                updated_at = ?4,
                next_attempt_at = ?5,
                last_error = ?6
            WHERE id = ?1
            "#,
            params![
                id,
                if terminal { "failed" } else { "retrying" },
                attempts,
                format_time(now)?,
                format_time(next_attempt_at)?,
                error
            ],
        )?;
        self.get(id)
    }

    fn configure(&self) -> Result<(), QueueError> {
        self.connection.pragma_update(None, "journal_mode", "WAL")?;
        self.connection
            .pragma_update(None, "synchronous", "NORMAL")?;
        self.connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(())
    }

    fn migrate(&self) -> Result<(), QueueError> {
        self.connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS peer_sync_jobs (
                id TEXT PRIMARY KEY,
                peer_name TEXT NOT NULL,
                peer_addr TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                max_attempts INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                next_attempt_at TEXT NOT NULL,
                last_error TEXT,
                last_plan_json TEXT,
                last_apply_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_peer_sync_jobs_status_due
                ON peer_sync_jobs(status, next_attempt_at);
            "#,
        )?;
        self.connection.execute(
            r#"
            INSERT INTO metadata(key, value)
            VALUES('schema_version', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            "#,
            [SCHEMA_VERSION.to_string()],
        )?;
        Ok(())
    }
}

fn process_snapshot(
    ledger: &MissionLedger,
    snapshot: &PeerSnapshot,
) -> Result<SyncApplyReport, QueueError> {
    if !snapshot.verification.valid {
        return Err(QueueError::RemoteLedgerInvalid(
            snapshot.verification.clone(),
        ));
    }
    let local_events = ledger.load_events()?;
    Ok(apply_append_only_events(
        ledger,
        &local_events,
        &snapshot.events,
    )?)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerSyncJob {
    pub id: String,
    pub peer: PeerEndpoint,
    pub status: QueueStatus,
    pub attempts: u32,
    pub max_attempts: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub next_attempt_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_plan: Option<SyncPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_apply: Option<SyncApplyReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueStatus {
    Pending,
    Retrying,
    Succeeded,
    Failed,
}

impl fmt::Display for QueueStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::Retrying => "retrying",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        })
    }
}

impl FromStr for QueueStatus {
    type Err = QueueStatusParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.trim().to_ascii_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "retrying" => Ok(Self::Retrying),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            _ => Err(QueueStatusParseError(input.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueStatusParseError(String);

impl fmt::Display for QueueStatusParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown queue status '{}'", self.0)
    }
}

impl std::error::Error for QueueStatusParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueProcessOptions {
    pub limit: u32,
    pub retry_delay: Duration,
}

impl Default for QueueProcessOptions {
    fn default() -> Self {
        Self {
            limit: 10,
            retry_delay: Duration::minutes(5),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueProcessReport {
    pub results: Vec<QueueProcessResult>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueProcessResult {
    pub job: PeerSyncJob,
    pub outcome: ProcessOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessOutcome {
    Succeeded,
    RetryScheduled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueSummary {
    pub schema_version: u32,
    pub total: u64,
    pub pending: u64,
    pub retrying: u64,
    pub succeeded: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueHealthSnapshot {
    pub schema_version: u32,
    pub status: QueueHealthStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
    pub summary: QueueSummary,
    pub due: usize,
    pub stale_retrying: usize,
    pub last_errors: Vec<QueueLastError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueHealthStatus {
    Healthy,
    Degraded,
    Failing,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueLastError {
    pub job_id: String,
    pub peer_name: String,
    pub status: QueueStatus,
    pub attempts: u32,
    pub max_attempts: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub error: String,
}

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("sync queue I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("sync queue SQLite failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("sync queue JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("sync queue timestamp formatting failed: {0}")]
    TimeFormat(#[from] time::error::Format),
    #[error("sync queue timestamp parsing failed: {0}")]
    TimeParse(#[from] time::error::Parse),
    #[error("ledger failed: {0}")]
    Ledger(#[from] astragrid_core::LedgerError),
    #[error("sync failed: {0}")]
    Sync(#[from] astragrid_sync::SyncError),
    #[error("remote ledger is invalid: {0:?}")]
    RemoteLedgerInvalid(LedgerVerification),
    #[error("job {0} was not found")]
    NotFound(String),
    #[error("invalid peer: {0}")]
    InvalidPeer(String),
    #[error("max attempts must be at least 1")]
    InvalidAttempts,
    #[error("attempt count {0} cannot fit in u32")]
    AttemptCountOutOfRange(i64),
}

fn row_to_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<PeerSyncJob> {
    let status: String = row.get(3)?;
    let attempts: i64 = row.get(4)?;
    let max_attempts: i64 = row.get(5)?;
    let created_at: String = row.get(6)?;
    let updated_at: String = row.get(7)?;
    let next_attempt_at: String = row.get(8)?;
    let last_plan: Option<String> = row.get(10)?;
    let last_apply: Option<String> = row.get(11)?;

    Ok(PeerSyncJob {
        id: row.get(0)?,
        peer: PeerEndpoint {
            name: row.get(1)?,
            addr: row.get(2)?,
        },
        status: parse_status(&status)?,
        attempts: parse_u32(attempts)?,
        max_attempts: parse_u32(max_attempts)?,
        created_at: parse_time_row(&created_at)?,
        updated_at: parse_time_row(&updated_at)?,
        next_attempt_at: parse_time_row(&next_attempt_at)?,
        last_error: row.get(9)?,
        last_plan: parse_json_row(last_plan)?,
        last_apply: parse_json_row(last_apply)?,
    })
}

fn job_params(job: &PeerSyncJob) -> Result<[rusqlite::types::Value; 12], QueueError> {
    use rusqlite::types::Value;

    Ok([
        Value::Text(job.id.clone()),
        Value::Text(job.peer.name.clone()),
        Value::Text(job.peer.addr.clone()),
        Value::Text(job.status.to_string()),
        Value::Integer(i64::from(job.attempts)),
        Value::Integer(i64::from(job.max_attempts)),
        Value::Text(format_time(job.created_at)?),
        Value::Text(format_time(job.updated_at)?),
        Value::Text(format_time(job.next_attempt_at)?),
        match &job.last_error {
            Some(error) => Value::Text(error.clone()),
            None => Value::Null,
        },
        match &job.last_plan {
            Some(plan) => Value::Text(serde_json::to_string(plan)?),
            None => Value::Null,
        },
        match &job.last_apply {
            Some(apply) => Value::Text(serde_json::to_string(apply)?),
            None => Value::Null,
        },
    ])
}

fn parse_status(status: &str) -> rusqlite::Result<QueueStatus> {
    status.parse().map_err(|error: QueueStatusParseError| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(error))
    })
}

fn parse_u32(value: i64) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|_| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(QueueError::AttemptCountOutOfRange(value)))
    })
}

fn parse_time_row(value: &str) -> rusqlite::Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
}

fn parse_json_row<T: for<'de> Deserialize<'de>>(
    value: Option<String>,
) -> rusqlite::Result<Option<T>> {
    value
        .map(|value| serde_json::from_str(&value))
        .transpose()
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
}

fn format_time(value: OffsetDateTime) -> Result<String, QueueError> {
    Ok(value.format(&Rfc3339)?)
}

#[cfg(test)]
mod tests {
    use astragrid_core::{Action, Actor, CommandRequest, Priority, Role};
    use astragrid_net::PeerSnapshot;
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    fn append_open(ledger: &MissionLedger, mission: &str) {
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                mission,
                Priority::Elevated,
                json!({"mission": mission}),
            ))
            .unwrap();
    }

    #[test]
    fn enqueues_and_lists_peer_jobs() {
        let dir = tempdir().unwrap();
        let queue = PeerSyncQueue::open(dir.path().join("queue.db")).unwrap();

        let job = queue
            .enqueue_peer(
                PeerEndpoint {
                    name: "peer-a".to_owned(),
                    addr: "127.0.0.1:17700".to_owned(),
                },
                3,
            )
            .unwrap();
        let summary = queue.summary().unwrap();
        let listed = queue.list(Some(QueueStatus::Pending)).unwrap();

        assert_eq!(job.status, QueueStatus::Pending);
        assert_eq!(summary.pending, 1);
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn processes_due_job_and_applies_append_only_snapshot() {
        let dir = tempdir().unwrap();
        let local = MissionLedger::open(dir.path().join("local.agl"));
        let remote = MissionLedger::open(dir.path().join("remote.agl"));
        append_open(&local, "mission-a");
        std::fs::copy(local.path(), remote.path()).unwrap();
        let remote_event = remote
            .append(CommandRequest::new(
                Actor::new("operator", Role::Operator),
                Action::AnnotateSituation,
                "sector-7",
                Priority::Elevated,
                json!({"note": "peer check"}),
            ))
            .unwrap();
        let snapshot = PeerSnapshot {
            protocol: "astragrid-peer-v1".to_owned(),
            events: remote.load_events().unwrap(),
            verification: remote.verify().unwrap(),
        };
        let queue = PeerSyncQueue::open(dir.path().join("queue.db")).unwrap();
        queue
            .enqueue_peer(
                PeerEndpoint {
                    name: "peer-a".to_owned(),
                    addr: "127.0.0.1:17700".to_owned(),
                },
                3,
            )
            .unwrap();

        let report = queue
            .process_due_with(&local, QueueProcessOptions::default(), |_| {
                Ok::<_, String>(snapshot.clone())
            })
            .unwrap();
        let events = local.load_events().unwrap();

        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].outcome, ProcessOutcome::Succeeded);
        assert_eq!(report.results[0].job.status, QueueStatus::Succeeded);
        assert_eq!(events.last().unwrap().hash, remote_event.hash);
        assert!(local.verify().unwrap().valid);
    }

    #[test]
    fn schedules_retry_and_then_terminal_failure() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("local.agl"));
        append_open(&ledger, "mission-a");
        let queue = PeerSyncQueue::open(dir.path().join("queue.db")).unwrap();
        let job = queue
            .enqueue_peer(
                PeerEndpoint {
                    name: "peer-a".to_owned(),
                    addr: "127.0.0.1:17700".to_owned(),
                },
                1,
            )
            .unwrap();

        let report = queue
            .process_due_with(&ledger, QueueProcessOptions::default(), |_| {
                Err::<PeerSnapshot, _>("offline")
            })
            .unwrap();
        let updated = queue.get(&job.id).unwrap();

        assert_eq!(report.results[0].outcome, ProcessOutcome::Failed);
        assert_eq!(updated.status, QueueStatus::Failed);
        assert_eq!(updated.attempts, 1);
        assert_eq!(updated.last_error.as_deref(), Some("offline"));
    }

    #[test]
    fn reports_queue_health_with_last_errors() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("local.agl"));
        append_open(&ledger, "mission-a");
        let queue = PeerSyncQueue::open(dir.path().join("queue.db")).unwrap();
        queue
            .enqueue_peer(
                PeerEndpoint {
                    name: "peer-a".to_owned(),
                    addr: "127.0.0.1:17700".to_owned(),
                },
                1,
            )
            .unwrap();
        queue
            .process_due_with(&ledger, QueueProcessOptions::default(), |_| {
                Err::<PeerSnapshot, _>("offline")
            })
            .unwrap();

        let health = queue.health(Duration::seconds(1)).unwrap();

        assert_eq!(health.status, QueueHealthStatus::Failing);
        assert_eq!(health.summary.failed, 1);
        assert_eq!(health.last_errors.len(), 1);
        assert_eq!(health.last_errors[0].error, "offline");
    }
}
