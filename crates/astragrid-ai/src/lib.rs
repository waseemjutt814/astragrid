use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use astragrid_evidence::{EvidenceBundle, EvidenceItem, digest_bytes};
use astragrid_recommend::{
    ModelRecommendationCandidate, RecommendError, build_model_recommendation_bundles,
};
use serde::{Deserialize, Serialize};

const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_MAX_STDOUT_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_STDERR_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiRunnerConfig {
    pub command: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<PathBuf>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_stdout_bytes")]
    pub max_stdout_bytes: usize,
    #[serde(default = "default_max_stderr_bytes")]
    pub max_stderr_bytes: usize,
    #[serde(default)]
    pub clear_environment: bool,
}

impl AiRunnerConfig {
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            working_directory: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_stdout_bytes: DEFAULT_MAX_STDOUT_BYTES,
            max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
            clear_environment: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiRunnerRequest {
    pub schema_version: u16,
    pub mission: String,
    pub evidence: Vec<EvidenceItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

impl AiRunnerRequest {
    pub fn new(mission: impl Into<String>, evidence: Vec<EvidenceItem>) -> Self {
        Self {
            schema_version: 1,
            mission: mission.into(),
            evidence,
            instructions: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiRunnerReport {
    pub schema_version: u16,
    pub mission: String,
    pub evidence_items: usize,
    pub candidates: usize,
    pub bundles: Vec<EvidenceBundle>,
    pub stdout_sha256: String,
    pub stderr: Option<String>,
    pub duration_ms: u64,
}

pub fn run_evidence_bound_runner(
    config: &AiRunnerConfig,
    request: AiRunnerRequest,
) -> Result<AiRunnerReport, AiRunnerError> {
    validate_config(config)?;
    validate_request(&request)?;

    let input = serde_json::to_vec(&request)?;
    let started = Instant::now();
    let captured = run_process(config, &input)?;
    let stdout_text = String::from_utf8(captured.stdout)?;
    let stderr = String::from_utf8(captured.stderr)?;
    let candidates = parse_runner_candidates(&stdout_text)?;
    let report =
        build_model_recommendation_bundles(&request.mission, &request.evidence, &candidates)?;

    Ok(AiRunnerReport {
        schema_version: 1,
        mission: report.mission,
        evidence_items: report.evidence_items,
        candidates: report.candidates,
        bundles: report.bundles,
        stdout_sha256: digest_bytes(stdout_text.as_bytes()),
        stderr: (!stderr.trim().is_empty()).then_some(stderr),
        duration_ms: saturating_duration_ms(started.elapsed()),
    })
}

fn validate_config(config: &AiRunnerConfig) -> Result<(), AiRunnerError> {
    if config.command.as_os_str().is_empty() {
        return Err(AiRunnerError::EmptyCommand);
    }
    if config.timeout_ms == 0 {
        return Err(AiRunnerError::InvalidLimit("timeout_ms"));
    }
    if config.max_stdout_bytes == 0 {
        return Err(AiRunnerError::InvalidLimit("max_stdout_bytes"));
    }
    if config.max_stderr_bytes == 0 {
        return Err(AiRunnerError::InvalidLimit("max_stderr_bytes"));
    }
    Ok(())
}

fn validate_request(request: &AiRunnerRequest) -> Result<(), AiRunnerError> {
    if request.schema_version != 1 {
        return Err(AiRunnerError::UnsupportedSchema(request.schema_version));
    }
    if request.mission.trim().is_empty() {
        return Err(AiRunnerError::EmptyMission);
    }
    if request.evidence.is_empty() {
        return Err(AiRunnerError::NoEvidence);
    }
    Ok(())
}

fn run_process(config: &AiRunnerConfig, input: &[u8]) -> Result<CapturedProcess, AiRunnerError> {
    let mut command = Command::new(&config.command);
    command
        .args(&config.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(working_directory) = &config.working_directory {
        command.current_dir(working_directory);
    }
    if config.clear_environment {
        command.env_clear();
    }

    let mut child = command.spawn().map_err(AiRunnerError::Spawn)?;
    let stdout = child.stdout.take().ok_or(AiRunnerError::MissingStdout)?;
    let stderr = child.stderr.take().ok_or(AiRunnerError::MissingStderr)?;
    let stdout_handle = read_limited(stdout, config.max_stdout_bytes);
    let stderr_handle = read_limited(stderr, config.max_stderr_bytes);

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input)?;
    }

    let deadline = Instant::now() + Duration::from_millis(config.timeout_ms);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = join_reader(stdout_handle);
            let _ = join_reader(stderr_handle);
            return Err(AiRunnerError::Timeout {
                timeout_ms: config.timeout_ms,
            });
        }
        thread::sleep(Duration::from_millis(20));
    };

    let stdout = join_reader(stdout_handle)?;
    let stderr = join_reader(stderr_handle)?;
    if stdout.truncated {
        return Err(AiRunnerError::OutputLimitExceeded {
            stream: "stdout",
            limit: config.max_stdout_bytes,
        });
    }
    if stderr.truncated {
        return Err(AiRunnerError::OutputLimitExceeded {
            stream: "stderr",
            limit: config.max_stderr_bytes,
        });
    }
    if !status.success() {
        return Err(AiRunnerError::ProcessFailed {
            code: status.code(),
            stderr: String::from_utf8_lossy(&stderr.bytes).trim().to_owned(),
        });
    }

    Ok(CapturedProcess {
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

fn read_limited<R>(mut reader: R, limit: usize) -> thread::JoinHandle<std::io::Result<LimitedRead>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut truncated = false;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let remaining = limit.saturating_sub(bytes.len());
            if remaining >= read {
                bytes.extend_from_slice(&buffer[..read]);
            } else {
                bytes.extend_from_slice(&buffer[..remaining]);
                truncated = true;
            }
            if remaining < read {
                truncated = true;
            }
        }
        Ok(LimitedRead { bytes, truncated })
    })
}

fn join_reader(
    handle: thread::JoinHandle<std::io::Result<LimitedRead>>,
) -> Result<LimitedRead, AiRunnerError> {
    handle
        .join()
        .map_err(|_| AiRunnerError::ReaderPanicked)?
        .map_err(AiRunnerError::Io)
}

fn parse_runner_candidates(
    stdout: &str,
) -> Result<Vec<ModelRecommendationCandidate>, AiRunnerError> {
    let parsed: RunnerCandidateOutput = serde_json::from_str(stdout)?;
    Ok(match parsed {
        RunnerCandidateOutput::Candidates(candidates) => candidates,
        RunnerCandidateOutput::Envelope { candidates } => candidates,
    })
}

fn saturating_duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

fn default_max_stdout_bytes() -> usize {
    DEFAULT_MAX_STDOUT_BYTES
}

fn default_max_stderr_bytes() -> usize {
    DEFAULT_MAX_STDERR_BYTES
}

#[derive(Debug)]
struct CapturedProcess {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
struct LimitedRead {
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RunnerCandidateOutput {
    Candidates(Vec<ModelRecommendationCandidate>),
    Envelope {
        candidates: Vec<ModelRecommendationCandidate>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum AiRunnerError {
    #[error("runner command cannot be empty")]
    EmptyCommand,
    #[error("{0} must be greater than zero")]
    InvalidLimit(&'static str),
    #[error("unsupported runner request schema {0}")]
    UnsupportedSchema(u16),
    #[error("mission cannot be empty")]
    EmptyMission,
    #[error("runner request must include at least one evidence item")]
    NoEvidence,
    #[error("failed to spawn runner: {0}")]
    Spawn(std::io::Error),
    #[error("runner process did not expose stdout")]
    MissingStdout,
    #[error("runner process did not expose stderr")]
    MissingStderr,
    #[error("runner timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
    #[error("runner {stream} exceeded {limit} byte limit")]
    OutputLimitExceeded { stream: &'static str, limit: usize },
    #[error("runner exited unsuccessfully with code {code:?}: {stderr}")]
    ProcessFailed { code: Option<i32>, stderr: String },
    #[error("runner output reader panicked")]
    ReaderPanicked,
    #[error("runner I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("runner JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("runner output was not UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("recommendation validation failed: {0}")]
    Recommend(#[from] RecommendError),
}

#[cfg(test)]
mod tests {
    use astragrid_evidence::{EvidenceKind, digest_bytes};
    use tempfile::tempdir;

    use super::*;

    fn evidence() -> Vec<EvidenceItem> {
        vec![EvidenceItem {
            id: "sensor-1".to_owned(),
            source: "river-gauge".to_owned(),
            kind: EvidenceKind::Sensor,
            confidence: 0.92,
            digest: digest_bytes(b"water=5.2"),
            excerpt: Some("water=5.2".to_owned()),
        }]
    }

    fn request() -> AiRunnerRequest {
        AiRunnerRequest::new("flood-watch", evidence())
    }

    #[cfg(windows)]
    fn print_file_command(path: &std::path::Path) -> AiRunnerConfig {
        let mut config = AiRunnerConfig::new("cmd");
        config.args = vec![
            "/C".to_owned(),
            "type".to_owned(),
            path.display().to_string(),
        ];
        config
    }

    #[cfg(not(windows))]
    fn print_file_command(path: &std::path::Path) -> AiRunnerConfig {
        let mut config = AiRunnerConfig::new("cat");
        config.args = vec![path.display().to_string()];
        config
    }

    #[cfg(windows)]
    fn slow_command() -> AiRunnerConfig {
        let mut config = AiRunnerConfig::new("powershell");
        config.args = vec![
            "-NoProfile".to_owned(),
            "-Command".to_owned(),
            "Start-Sleep -Milliseconds 500; Write-Output '[]'".to_owned(),
        ];
        config.timeout_ms = 1;
        config
    }

    #[cfg(not(windows))]
    fn slow_command() -> AiRunnerConfig {
        let mut config = AiRunnerConfig::new("sh");
        config.args = vec!["-c".to_owned(), "sleep 1; echo []".to_owned()];
        config.timeout_ms = 1;
        config
    }

    #[test]
    fn runner_converts_valid_candidate_output_to_bundles() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("runner-output.json");
        std::fs::write(
            &output,
            r#"[{"action":"declare_incident","subject":"river-east","rationale":"Gauge exceeded threshold.","confidence":0.88,"evidence_ids":["sensor-1"]}]"#,
        )
        .unwrap();

        let report = run_evidence_bound_runner(&print_file_command(&output), request()).unwrap();

        assert_eq!(report.candidates, 1);
        assert_eq!(report.bundles.len(), 1);
        assert_eq!(report.bundles[0].recommendation.action, "declare_incident");
        report.bundles[0].verify().unwrap();
    }

    #[test]
    fn runner_accepts_candidate_envelope() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("runner-output.json");
        std::fs::write(
            &output,
            r#"{"candidates":[{"action":"declare_incident","subject":"river-east","rationale":"Gauge exceeded threshold.","confidence":0.88,"evidence_ids":["sensor-1"]}]}"#,
        )
        .unwrap();

        let report = run_evidence_bound_runner(&print_file_command(&output), request()).unwrap();

        assert_eq!(report.candidates, 1);
        assert_eq!(report.evidence_items, 1);
    }

    #[test]
    fn runner_rejects_unknown_evidence_reference() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("runner-output.json");
        std::fs::write(
            &output,
            r#"[{"action":"declare_incident","subject":"river-east","rationale":"Gauge exceeded threshold.","confidence":0.88,"evidence_ids":["missing"]}]"#,
        )
        .unwrap();

        let error = run_evidence_bound_runner(&print_file_command(&output), request()).unwrap_err();

        assert!(matches!(
            error,
            AiRunnerError::Recommend(RecommendError::UnknownModelEvidence(id)) if id == "missing"
        ));
    }

    #[test]
    fn runner_enforces_stdout_limit() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("runner-output.json");
        std::fs::write(&output, "x".repeat(128)).unwrap();
        let mut config = print_file_command(&output);
        config.max_stdout_bytes = 8;

        let error = run_evidence_bound_runner(&config, request()).unwrap_err();

        assert!(matches!(
            error,
            AiRunnerError::OutputLimitExceeded {
                stream: "stdout",
                limit: 8
            }
        ));
    }

    #[test]
    fn runner_times_out() {
        let error = run_evidence_bound_runner(&slow_command(), request()).unwrap_err();

        assert!(matches!(error, AiRunnerError::Timeout { timeout_ms: 1 }));
    }
}
