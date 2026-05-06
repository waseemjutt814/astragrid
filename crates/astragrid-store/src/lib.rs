use std::path::{Path, PathBuf};

use astragrid_core::{LedgerVerification, MissionEvent, MissionLedger};
use rusqlite::{Connection, OptionalExtension, params, params_from_iter, types::Value as SqlValue};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug)]
pub struct MissionStore {
    path: PathBuf,
    connection: Connection,
}

impl MissionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let connection = Connection::open(&path)?;
        let store = Self { path, connection };
        store.configure()?;
        store.migrate()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn ingest_ledger(&mut self, ledger: &MissionLedger) -> Result<IngestReport, StoreError> {
        let verification = ledger.verify()?;
        if !verification.valid {
            return Err(StoreError::LedgerCorrupt(verification));
        }

        let events = ledger.load_events()?;
        self.ingest_events(&events, verification.last_hash)
    }

    pub fn ingest_events(
        &mut self,
        events: &[MissionEvent],
        verified_last_hash: Option<String>,
    ) -> Result<IngestReport, StoreError> {
        verify_event_set(events)?;
        let transaction = self.connection.transaction()?;
        let mut inserted = 0_usize;
        {
            let mut insert = transaction.prepare(
                r#"
                INSERT OR IGNORE INTO mission_events (
                    sequence,
                    event_id,
                    occurred_at,
                    actor_name,
                    actor_role,
                    action,
                    subject,
                    priority,
                    payload_json,
                    attestation_json,
                    previous_hash,
                    hash,
                    event_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                "#,
            )?;

            for event in events {
                let changed = insert.execute(params![
                    event.sequence,
                    event.id.to_string(),
                    event.occurred_at.to_string(),
                    event.actor.name.as_str(),
                    event.actor.role.to_string(),
                    event.action.to_string(),
                    event.subject.as_str(),
                    event.priority.to_string(),
                    serde_json::to_string(&event.payload)?,
                    match &event.attestation {
                        Some(attestation) => Some(serde_json::to_string(attestation)?),
                        None => None,
                    },
                    event.previous_hash.as_deref(),
                    event.hash.as_str(),
                    serde_json::to_string(event)?,
                ])?;
                inserted += changed;
            }
        }
        transaction.commit()?;

        Ok(IngestReport {
            scanned: events.len(),
            inserted,
            skipped_existing: events.len().saturating_sub(inserted),
            last_hash: verified_last_hash.or_else(|| events.last().map(|event| event.hash.clone())),
        })
    }

    pub fn summary(&self) -> Result<StoreSummary, StoreError> {
        let event_count =
            self.connection
                .query_row("SELECT COUNT(*) FROM mission_events", [], |row| {
                    row.get::<_, u64>(0)
                })?;
        let signed_event_count = self.connection.query_row(
            "SELECT COUNT(*) FROM mission_events WHERE attestation_json IS NOT NULL",
            [],
            |row| row.get::<_, u64>(0),
        )?;
        let critical_event_count = self.connection.query_row(
            "SELECT COUNT(*) FROM mission_events WHERE priority = 'critical'",
            [],
            |row| row.get::<_, u64>(0),
        )?;
        let last_hash = self
            .connection
            .query_row(
                "SELECT hash FROM mission_events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        Ok(StoreSummary {
            schema_version: SCHEMA_VERSION,
            event_count,
            signed_event_count,
            critical_event_count,
            last_hash,
        })
    }

    pub fn list_recent(&self, limit: u32) -> Result<Vec<MissionEvent>, StoreError> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT event_json
            FROM mission_events
            ORDER BY sequence DESC
            LIMIT ?1
            "#,
        )?;
        let rows = statement.query_map([limit], |row| row.get::<_, String>(0))?;
        let mut events = Vec::new();
        for row in rows {
            events.push(serde_json::from_str(&row?)?);
        }
        events.reverse();
        Ok(events)
    }

    pub fn query_events(&self, filter: EventFilter) -> Result<Vec<MissionEvent>, StoreError> {
        let mut sql = String::from("SELECT event_json FROM mission_events");
        let mut clauses = Vec::new();
        let mut values = Vec::<SqlValue>::new();

        if let Some(action) = filter.action {
            clauses.push("action = ?".to_owned());
            values.push(SqlValue::Text(action));
        }
        if let Some(priority) = filter.priority {
            clauses.push("priority = ?".to_owned());
            values.push(SqlValue::Text(priority));
        }
        if let Some(actor) = filter.actor {
            clauses.push("actor_name = ?".to_owned());
            values.push(SqlValue::Text(actor));
        }
        if let Some(subject_contains) = filter.subject_contains {
            clauses.push("subject LIKE ? ESCAPE '\\'".to_owned());
            values.push(SqlValue::Text(format!(
                "%{}%",
                escape_sql_like(&subject_contains)
            )));
        }
        if filter.signed_only {
            clauses.push("attestation_json IS NOT NULL".to_owned());
        }

        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY sequence ASC LIMIT ?");
        values.push(SqlValue::Integer(i64::from(filter.limit.max(1))));

        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values), |row| row.get::<_, String>(0))?;
        let mut events = Vec::new();
        for row in rows {
            events.push(serde_json::from_str(&row?)?);
        }
        Ok(events)
    }

    pub fn export_events(&self) -> Result<Vec<MissionEvent>, StoreError> {
        self.query_events(EventFilter {
            limit: u32::MAX,
            ..EventFilter::default()
        })
    }

    fn configure(&self) -> Result<(), StoreError> {
        self.connection.pragma_update(None, "journal_mode", "WAL")?;
        self.connection
            .pragma_update(None, "synchronous", "NORMAL")?;
        self.connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(())
    }

    fn migrate(&self) -> Result<(), StoreError> {
        self.connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mission_events (
                sequence INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                occurred_at TEXT NOT NULL,
                actor_name TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                action TEXT NOT NULL,
                subject TEXT NOT NULL,
                priority TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                attestation_json TEXT,
                previous_hash TEXT,
                hash TEXT NOT NULL UNIQUE,
                event_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_mission_events_action
                ON mission_events(action);
            CREATE INDEX IF NOT EXISTS idx_mission_events_priority
                ON mission_events(priority);
            CREATE INDEX IF NOT EXISTS idx_mission_events_subject
                ON mission_events(subject);
            CREATE INDEX IF NOT EXISTS idx_mission_events_actor
                ON mission_events(actor_name);
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

fn verify_event_set(events: &[MissionEvent]) -> Result<(), StoreError> {
    let mut previous_hash = None;
    for (index, event) in events.iter().enumerate() {
        let expected_sequence = u64::try_from(index).map_err(|_| {
            StoreError::InvalidEventSet("event index exceeds u64 sequence range".to_owned())
        })?;
        if event.sequence != expected_sequence {
            return Err(StoreError::InvalidEventSet(format!(
                "expected sequence {}, found {}",
                expected_sequence, event.sequence
            )));
        }
        if event.previous_hash != previous_hash {
            return Err(StoreError::InvalidEventSet(format!(
                "event {} previous hash does not match",
                event.sequence
            )));
        }
        if !event.has_valid_hash()? {
            return Err(StoreError::InvalidEventSet(format!(
                "event {} hash does not match content",
                event.sequence
            )));
        }
        previous_hash = Some(event.hash.clone());
    }
    Ok(())
}

fn escape_sql_like(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventFilter {
    pub action: Option<String>,
    pub priority: Option<String>,
    pub actor: Option<String>,
    pub subject_contains: Option<String>,
    pub signed_only: bool,
    pub limit: u32,
}

impl Default for EventFilter {
    fn default() -> Self {
        Self {
            action: None,
            priority: None,
            actor: None,
            subject_contains: None,
            signed_only: false,
            limit: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestReport {
    pub scanned: usize,
    pub inserted: usize,
    pub skipped_existing: usize,
    pub last_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreSummary {
    pub schema_version: u32,
    pub event_count: u64,
    pub signed_event_count: u64,
    pub critical_event_count: u64,
    pub last_hash: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("store SQLite failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("store JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ledger failed: {0}")]
    Ledger(#[from] astragrid_core::LedgerError),
    #[error("event hash failed: {0}")]
    EventHash(#[from] astragrid_core::event::EventHashError),
    #[error("ledger is corrupt: {0:?}")]
    LedgerCorrupt(LedgerVerification),
    #[error("invalid event set: {0}")]
    InvalidEventSet(String),
}

#[cfg(test)]
mod tests {
    use astragrid_core::{
        Action, Actor, CommandRequest, MissionLedger, OperatorKeypair, Priority, Role,
    };
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn ingests_verified_ledger_idempotently() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        let keypair = OperatorKeypair::generate("lead", Role::IncidentCommander);
        let request = CommandRequest::new(
            Actor::from(keypair.identity()),
            Action::DeclareIncident,
            "river-east",
            Priority::Critical,
            json!({"water_level_m": 5.2}),
        );
        ledger
            .append_signed(keypair.sign_request(request).unwrap())
            .unwrap();

        let mut store = MissionStore::open(dir.path().join("mission.db")).unwrap();
        let first = store.ingest_ledger(&ledger).unwrap();
        let second = store.ingest_ledger(&ledger).unwrap();
        let summary = store.summary().unwrap();

        assert_eq!(first.scanned, 1);
        assert_eq!(first.inserted, 1);
        assert_eq!(second.inserted, 0);
        assert_eq!(summary.event_count, 1);
        assert_eq!(summary.signed_event_count, 1);
        assert_eq!(summary.critical_event_count, 1);
    }

    #[test]
    fn refuses_corrupt_ledger() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("mission.agl");
        let ledger = MissionLedger::open(&ledger_path);
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "mission-a",
                Priority::Elevated,
                json!({"mission": "mission-a"}),
            ))
            .unwrap();
        std::fs::write(
            &ledger_path,
            std::fs::read_to_string(&ledger_path)
                .unwrap()
                .replace("mission-a", "mission-b"),
        )
        .unwrap();

        let mut store = MissionStore::open(dir.path().join("mission.db")).unwrap();

        assert!(matches!(
            store.ingest_ledger(&ledger),
            Err(StoreError::LedgerCorrupt(_))
        ));
    }

    #[test]
    fn queries_and_exports_indexed_events() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        let keypair = OperatorKeypair::generate("lead", Role::IncidentCommander);
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "flood-watch",
                Priority::Elevated,
                json!({"mission": "flood-watch"}),
            ))
            .unwrap();
        let request = CommandRequest::new(
            Actor::from(keypair.identity()),
            Action::DeclareIncident,
            "river-east",
            Priority::Critical,
            json!({"water_level_m": 5.2}),
        );
        ledger
            .append_signed(keypair.sign_request(request).unwrap())
            .unwrap();
        let mut store = MissionStore::open(dir.path().join("mission.db")).unwrap();
        store.ingest_ledger(&ledger).unwrap();

        let critical = store
            .query_events(EventFilter {
                priority: Some("critical".to_owned()),
                signed_only: true,
                ..EventFilter::default()
            })
            .unwrap();
        let exported = store.export_events().unwrap();

        assert_eq!(critical.len(), 1);
        assert_eq!(critical[0].subject, "river-east");
        assert_eq!(exported.len(), 2);
    }
}
