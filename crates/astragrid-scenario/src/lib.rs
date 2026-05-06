use std::{
    fs,
    path::{Path, PathBuf},
};

use astragrid_core::{Action, Actor, CommandRequest, MissionLedger, Priority, Role};
use astragrid_state::MissionState;
use astragrid_store::MissionStore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scenario {
    pub name: String,
    pub ledger: PathBuf,
    #[serde(default)]
    pub store: Option<PathBuf>,
    pub steps: Vec<ScenarioStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScenarioStep {
    Init {
        mission: String,
        #[serde(default = "default_operator")]
        operator: String,
    },
    Append {
        actor: String,
        role: Role,
        action: Action,
        subject: String,
        #[serde(default = "default_priority")]
        priority: Priority,
        #[serde(default)]
        payload: Value,
    },
    VerifyLedger,
    IngestStore {
        #[serde(default)]
        store: Option<PathBuf>,
    },
    AssertState {
        mission: Option<String>,
        open_incidents: Option<usize>,
        closed_incidents: Option<usize>,
        observations: Option<usize>,
        dispatches: Option<usize>,
        annotations: Option<usize>,
    },
    AssertStore {
        #[serde(default)]
        store: Option<PathBuf>,
        event_count: Option<u64>,
        signed_event_count: Option<u64>,
        critical_event_count: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioReport {
    pub name: String,
    pub ledger: PathBuf,
    pub store: Option<PathBuf>,
    pub steps: Vec<ScenarioStepReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioStepReport {
    pub index: usize,
    pub step_type: String,
    pub ok: bool,
    pub detail: Value,
}

pub fn run_scenario_file(input: &Path, workdir: &Path) -> Result<ScenarioReport, ScenarioError> {
    let mut bytes = fs::read(input)?;
    strip_utf8_bom(&mut bytes);
    let scenario: Scenario = serde_json::from_slice(&bytes)?;
    run_scenario(&scenario, workdir)
}

pub fn run_scenario(scenario: &Scenario, workdir: &Path) -> Result<ScenarioReport, ScenarioError> {
    if scenario.steps.is_empty() {
        return Err(ScenarioError::EmptyScenario);
    }
    fs::create_dir_all(workdir)?;

    let ledger_path = resolve_workdir_path(workdir, &scenario.ledger);
    let store_path = scenario
        .store
        .as_ref()
        .map(|path| resolve_workdir_path(workdir, path));
    let ledger = MissionLedger::open(&ledger_path);
    let mut reports = Vec::new();

    for (index, step) in scenario.steps.iter().enumerate() {
        let detail = run_step(step, &ledger, store_path.as_ref(), workdir)?;
        reports.push(ScenarioStepReport {
            index,
            step_type: step.kind().to_owned(),
            ok: true,
            detail,
        });
    }

    Ok(ScenarioReport {
        name: scenario.name.clone(),
        ledger: ledger_path,
        store: store_path,
        steps: reports,
    })
}

fn run_step(
    step: &ScenarioStep,
    ledger: &MissionLedger,
    default_store: Option<&PathBuf>,
    workdir: &Path,
) -> Result<Value, ScenarioError> {
    match step {
        ScenarioStep::Init { mission, operator } => {
            if ledger.path().exists() && fs::metadata(ledger.path())?.len() > 0 {
                return Err(ScenarioError::LedgerAlreadyExists(
                    ledger.path().to_path_buf(),
                ));
            }
            let event = ledger.append(CommandRequest::new(
                Actor::new(operator.clone(), Role::System),
                Action::OpenMission,
                mission.clone(),
                Priority::Elevated,
                json!({"mission": mission, "scenario": true}),
            ))?;
            Ok(json!({"sequence": event.sequence, "hash": event.hash}))
        }
        ScenarioStep::Append {
            actor,
            role,
            action,
            subject,
            priority,
            payload,
        } => {
            let event = ledger.append(CommandRequest::new(
                Actor::new(actor.clone(), *role),
                *action,
                subject.clone(),
                *priority,
                payload.clone(),
            ))?;
            Ok(json!({"sequence": event.sequence, "hash": event.hash}))
        }
        ScenarioStep::VerifyLedger => {
            let verification = ledger.verify()?;
            if !verification.valid {
                return Err(ScenarioError::AssertionFailed(format!(
                    "ledger verification failed: {:?}",
                    verification.failures
                )));
            }
            Ok(json!(verification))
        }
        ScenarioStep::IngestStore { store } => {
            let store_path = resolve_store_path(default_store, store.as_ref(), workdir)?;
            let mut store = MissionStore::open(&store_path)?;
            let report = store.ingest_ledger(ledger)?;
            Ok(json!({"store": store_path, "ingest": report}))
        }
        ScenarioStep::AssertState {
            mission,
            open_incidents,
            closed_incidents,
            observations,
            dispatches,
            annotations,
        } => {
            let state = MissionState::from_ledger(ledger)?;
            let summary = state.summary();
            assert_optional_eq("mission", summary.mission.as_ref(), mission.as_ref())?;
            assert_optional_eq(
                "open_incidents",
                Some(&summary.open_incidents),
                open_incidents.as_ref(),
            )?;
            assert_optional_eq(
                "closed_incidents",
                Some(&summary.closed_incidents),
                closed_incidents.as_ref(),
            )?;
            assert_optional_eq(
                "observations",
                Some(&summary.observations),
                observations.as_ref(),
            )?;
            assert_optional_eq("dispatches", Some(&summary.dispatches), dispatches.as_ref())?;
            assert_optional_eq(
                "annotations",
                Some(&summary.annotations),
                annotations.as_ref(),
            )?;
            Ok(json!(summary))
        }
        ScenarioStep::AssertStore {
            store,
            event_count,
            signed_event_count,
            critical_event_count,
        } => {
            let store_path = resolve_store_path(default_store, store.as_ref(), workdir)?;
            let store = MissionStore::open(&store_path)?;
            let summary = store.summary()?;
            assert_optional_eq(
                "event_count",
                Some(&summary.event_count),
                event_count.as_ref(),
            )?;
            assert_optional_eq(
                "signed_event_count",
                Some(&summary.signed_event_count),
                signed_event_count.as_ref(),
            )?;
            assert_optional_eq(
                "critical_event_count",
                Some(&summary.critical_event_count),
                critical_event_count.as_ref(),
            )?;
            Ok(json!(summary))
        }
    }
}

impl ScenarioStep {
    fn kind(&self) -> &'static str {
        match self {
            ScenarioStep::Init { .. } => "init",
            ScenarioStep::Append { .. } => "append",
            ScenarioStep::VerifyLedger => "verify_ledger",
            ScenarioStep::IngestStore { .. } => "ingest_store",
            ScenarioStep::AssertState { .. } => "assert_state",
            ScenarioStep::AssertStore { .. } => "assert_store",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScenarioError {
    #[error("scenario I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("scenario JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ledger failed: {0}")]
    Ledger(#[from] astragrid_core::LedgerError),
    #[error("state projection failed: {0}")]
    State(#[from] astragrid_state::StateError),
    #[error("store failed: {0}")]
    Store(#[from] astragrid_store::StoreError),
    #[error("scenario has no steps")]
    EmptyScenario,
    #[error("ledger already exists and is not empty: {0}")]
    LedgerAlreadyExists(PathBuf),
    #[error("scenario store path is required")]
    StorePathRequired,
    #[error("scenario assertion failed: {0}")]
    AssertionFailed(String),
}

fn resolve_store_path(
    default_store: Option<&PathBuf>,
    step_store: Option<&PathBuf>,
    workdir: &Path,
) -> Result<PathBuf, ScenarioError> {
    step_store
        .or(default_store)
        .map(|path| resolve_workdir_path(workdir, path))
        .ok_or(ScenarioError::StorePathRequired)
}

fn resolve_workdir_path(workdir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        workdir.join(path)
    }
}

fn assert_optional_eq<T>(
    name: &str,
    actual: Option<&T>,
    expected: Option<&T>,
) -> Result<(), ScenarioError>
where
    T: PartialEq + std::fmt::Debug,
{
    if let Some(expected) = expected
        && actual != Some(expected)
    {
        return Err(ScenarioError::AssertionFailed(format!(
            "{} expected {:?}, got {:?}",
            name, expected, actual
        )));
    }
    Ok(())
}

fn default_operator() -> String {
    "scenario-kernel".to_owned()
}

fn default_priority() -> Priority {
    Priority::Routine
}

fn strip_utf8_bom(bytes: &mut Vec<u8>) {
    const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";
    if bytes.starts_with(UTF8_BOM) {
        bytes.drain(..UTF8_BOM.len());
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde_json::json;
    use tempfile::NamedTempFile;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn runs_scenario_with_state_and_store_assertions() {
        let dir = tempdir().unwrap();
        let scenario = Scenario {
            name: "flood-watch".to_owned(),
            ledger: "mission.agl".into(),
            store: Some("mission.db".into()),
            steps: vec![
                ScenarioStep::Init {
                    mission: "flood-watch".to_owned(),
                    operator: "kernel".to_owned(),
                },
                ScenarioStep::Append {
                    actor: "lead".to_owned(),
                    role: Role::IncidentCommander,
                    action: Action::DeclareIncident,
                    subject: "river-east".to_owned(),
                    priority: Priority::Critical,
                    payload: json!({"water_level_m": 5.2}),
                },
                ScenarioStep::VerifyLedger,
                ScenarioStep::IngestStore { store: None },
                ScenarioStep::AssertState {
                    mission: Some("flood-watch".to_owned()),
                    open_incidents: Some(1),
                    closed_incidents: Some(0),
                    observations: None,
                    dispatches: None,
                    annotations: None,
                },
                ScenarioStep::AssertStore {
                    store: None,
                    event_count: Some(2),
                    signed_event_count: Some(0),
                    critical_event_count: Some(1),
                },
            ],
        };

        let report = run_scenario(&scenario, dir.path()).unwrap();

        assert_eq!(report.steps.len(), 6);
        assert!(report.steps.iter().all(|step| step.ok));
    }

    #[test]
    fn fails_when_state_assertion_does_not_match() {
        let dir = tempdir().unwrap();
        let scenario = Scenario {
            name: "flood-watch".to_owned(),
            ledger: "mission.agl".into(),
            store: None,
            steps: vec![
                ScenarioStep::Init {
                    mission: "flood-watch".to_owned(),
                    operator: "kernel".to_owned(),
                },
                ScenarioStep::AssertState {
                    mission: Some("flood-watch".to_owned()),
                    open_incidents: Some(1),
                    closed_incidents: None,
                    observations: None,
                    dispatches: None,
                    annotations: None,
                },
            ],
        };

        assert!(matches!(
            run_scenario(&scenario, dir.path()),
            Err(ScenarioError::AssertionFailed(message)) if message.contains("open_incidents")
        ));
    }

    #[test]
    fn reads_scenario_file_with_utf8_bom() {
        let dir = tempdir().unwrap();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            br#"{"name":"bom","ledger":"mission.agl","steps":[{"type":"init","mission":"bom"}]}"#,
        )
        .unwrap();
        let mut bytes = std::fs::read(file.path()).unwrap();
        bytes.splice(..0, b"\xEF\xBB\xBF".iter().copied());
        std::fs::write(file.path(), bytes).unwrap();

        let report = run_scenario_file(file.path(), dir.path()).unwrap();

        assert_eq!(report.name, "bom");
        assert_eq!(report.steps.len(), 1);
    }
}
