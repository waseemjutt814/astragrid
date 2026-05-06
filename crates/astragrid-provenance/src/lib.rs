use std::{
    fs,
    io::{BufReader, Read},
    path::{Path, PathBuf},
};

use astragrid_core::{DetachedSignature, IdentityError, OperatorIdentity, OperatorKeypair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PROVENANCE_SIGNATURE_SCHEMA: u16 = 1;
const PROVENANCE_SIGNATURE_PURPOSE: &str = "astragrid-release-provenance-v1";
const DIGEST_ALGORITHM: &str = "sha256";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageProvenance {
    pub schema: u16,
    pub package: String,
    pub version: String,
    pub target: String,
    pub generated_at: String,
    pub artifact: Option<ProvenanceFile>,
    pub binary: Option<ProvenanceFile>,
    #[serde(default)]
    pub included_files: Vec<String>,
    #[serde(default)]
    pub toolchain: serde_json::Value,
    #[serde(default)]
    pub git: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceFile {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceVerificationReport {
    pub valid: bool,
    pub checks: Vec<ProvenanceCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceCheck {
    pub name: String,
    pub path: PathBuf,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub status: ProvenanceCheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceCheckStatus {
    Match,
    Missing,
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceSignatureEnvelope {
    pub schema: u16,
    pub provenance_path: PathBuf,
    pub provenance_sha256: String,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceSignatureVerificationReport {
    pub valid: bool,
    pub provenance_path: PathBuf,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub provenance_hash_match: bool,
    pub signature_valid: bool,
    pub signer: OperatorIdentity,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceQuorumEnvelope {
    pub schema: u16,
    pub threshold: usize,
    pub signatures: Vec<ProvenanceSignatureEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceQuorumVerificationReport {
    pub valid: bool,
    pub threshold: usize,
    pub signatures: usize,
    pub valid_signatures: usize,
    pub distinct_valid_signers: usize,
    pub reports: Vec<ProvenanceSignatureVerificationReport>,
    pub detail: String,
}

impl PackageProvenance {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ProvenanceError> {
        let mut bytes = fs::read(path)?;
        strip_utf8_bom(&mut bytes);
        let provenance = serde_json::from_slice(&bytes)?;
        Ok(provenance)
    }

    pub fn verify_hashes(
        &self,
        provenance_path: impl AsRef<Path>,
    ) -> Result<ProvenanceVerificationReport, ProvenanceError> {
        if self.schema != 1 {
            return Err(ProvenanceError::UnsupportedSchema(self.schema));
        }
        let base_dir = provenance_path
            .as_ref()
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let mut checks = Vec::new();
        if let Some(artifact) = &self.artifact {
            checks.push(verify_file("artifact", artifact, base_dir)?);
        }
        if let Some(binary) = &self.binary {
            checks.push(verify_file("binary", binary, base_dir)?);
        }
        if checks.is_empty() {
            return Err(ProvenanceError::NoVerifiableFiles);
        }
        Ok(ProvenanceVerificationReport {
            valid: checks
                .iter()
                .all(|check| check.status == ProvenanceCheckStatus::Match),
            checks,
        })
    }
}

impl ProvenanceSignatureEnvelope {
    pub fn sign_file(
        provenance_path: impl AsRef<Path>,
        keypair: &OperatorKeypair,
    ) -> Result<Self, ProvenanceError> {
        let provenance_path = provenance_path.as_ref();
        let digest = sha256_file(provenance_path)?;
        let signature =
            keypair.sign_digest(PROVENANCE_SIGNATURE_PURPOSE, DIGEST_ALGORITHM, &digest)?;
        Ok(Self {
            schema: PROVENANCE_SIGNATURE_SCHEMA,
            provenance_path: provenance_path
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| provenance_path.to_path_buf()),
            provenance_sha256: digest,
            signature,
        })
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ProvenanceError> {
        let mut bytes = fs::read(path)?;
        strip_utf8_bom(&mut bytes);
        let envelope = serde_json::from_slice(&bytes)?;
        Ok(envelope)
    }

    pub fn verify(
        &self,
        signature_path: impl AsRef<Path>,
    ) -> Result<ProvenanceSignatureVerificationReport, ProvenanceError> {
        if self.schema != PROVENANCE_SIGNATURE_SCHEMA {
            return Err(ProvenanceError::UnsupportedSignatureSchema(self.schema));
        }
        let base_dir = signature_path
            .as_ref()
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let provenance_path = resolve_path(base_dir, &self.provenance_path);
        let expected_sha256 = normalize_sha(&self.provenance_sha256);
        let actual_sha256 = if provenance_path.exists() {
            Some(sha256_file(&provenance_path)?)
        } else {
            None
        };
        let provenance_hash_match = actual_sha256
            .as_ref()
            .is_some_and(|actual| *actual == expected_sha256);
        let signature_result = self.signature.verify_digest(
            PROVENANCE_SIGNATURE_PURPOSE,
            DIGEST_ALGORITHM,
            &expected_sha256,
        );
        let signature_valid = signature_result.is_ok();
        let valid = provenance_hash_match && signature_valid;
        let detail = if !provenance_path.exists() {
            "provenance file is missing".to_owned()
        } else if !provenance_hash_match {
            "provenance sha256 mismatch".to_owned()
        } else if let Err(error) = signature_result {
            format!("signature verification failed: {error}")
        } else {
            "provenance signature is valid".to_owned()
        };

        Ok(ProvenanceSignatureVerificationReport {
            valid,
            provenance_path,
            expected_sha256,
            actual_sha256,
            provenance_hash_match,
            signature_valid,
            signer: self.signature.identity.clone(),
            detail,
        })
    }
}

impl ProvenanceQuorumEnvelope {
    pub fn new(
        threshold: usize,
        signatures: Vec<ProvenanceSignatureEnvelope>,
    ) -> Result<Self, ProvenanceError> {
        if threshold == 0 {
            return Err(ProvenanceError::InvalidQuorumThreshold);
        }
        if signatures.is_empty() {
            return Err(ProvenanceError::EmptyQuorum);
        }
        Ok(Self {
            schema: PROVENANCE_SIGNATURE_SCHEMA,
            threshold,
            signatures,
        })
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ProvenanceError> {
        let mut bytes = fs::read(path)?;
        strip_utf8_bom(&mut bytes);
        let envelope = serde_json::from_slice(&bytes)?;
        Ok(envelope)
    }

    pub fn verify(
        &self,
        quorum_path: impl AsRef<Path>,
    ) -> Result<ProvenanceQuorumVerificationReport, ProvenanceError> {
        if self.schema != PROVENANCE_SIGNATURE_SCHEMA {
            return Err(ProvenanceError::UnsupportedSignatureSchema(self.schema));
        }
        if self.threshold == 0 {
            return Err(ProvenanceError::InvalidQuorumThreshold);
        }
        if self.signatures.is_empty() {
            return Err(ProvenanceError::EmptyQuorum);
        }
        let mut reports = Vec::new();
        for signature in &self.signatures {
            reports.push(signature.verify(&quorum_path)?);
        }
        let valid_signatures = reports.iter().filter(|report| report.valid).count();
        let distinct_valid_signers = reports
            .iter()
            .filter(|report| report.valid)
            .map(|report| report.signer.id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let valid = distinct_valid_signers >= self.threshold;
        let detail = if valid {
            "provenance quorum is satisfied".to_owned()
        } else {
            format!(
                "provenance quorum requires {} distinct valid signer(s), found {}",
                self.threshold, distinct_valid_signers
            )
        };
        Ok(ProvenanceQuorumVerificationReport {
            valid,
            threshold: self.threshold,
            signatures: self.signatures.len(),
            valid_signatures,
            distinct_valid_signers,
            reports,
            detail,
        })
    }
}

fn verify_file(
    name: &str,
    file: &ProvenanceFile,
    base_dir: &Path,
) -> Result<ProvenanceCheck, ProvenanceError> {
    let path = resolve_path(base_dir, &file.path);
    if !path.exists() {
        return Ok(ProvenanceCheck {
            name: name.to_owned(),
            path,
            expected_sha256: normalize_sha(&file.sha256),
            actual_sha256: None,
            status: ProvenanceCheckStatus::Missing,
            detail: "file is missing".to_owned(),
        });
    }
    let actual = sha256_file(&path)?;
    let expected = normalize_sha(&file.sha256);
    let status = if actual == expected {
        ProvenanceCheckStatus::Match
    } else {
        ProvenanceCheckStatus::Mismatch
    };
    Ok(ProvenanceCheck {
        name: name.to_owned(),
        path,
        expected_sha256: expected,
        actual_sha256: Some(actual),
        status,
        detail: match status {
            ProvenanceCheckStatus::Match => "sha256 matches".to_owned(),
            ProvenanceCheckStatus::Missing => "file is missing".to_owned(),
            ProvenanceCheckStatus::Mismatch => "sha256 mismatch".to_owned(),
        },
    })
}

fn sha256_file(path: &Path) -> Result<String, ProvenanceError> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn resolve_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

fn normalize_sha(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn strip_utf8_bom(bytes: &mut Vec<u8>) {
    const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";
    if bytes.starts_with(UTF8_BOM) {
        bytes.drain(..UTF8_BOM.len());
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProvenanceError {
    #[error("provenance I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("provenance JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("provenance signature failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("unsupported provenance schema {0}")]
    UnsupportedSchema(u16),
    #[error("unsupported provenance signature schema {0}")]
    UnsupportedSignatureSchema(u16),
    #[error("provenance contains no artifact or binary file to verify")]
    NoVerifiableFiles,
    #[error("provenance quorum must include at least one signature")]
    EmptyQuorum,
    #[error("provenance quorum threshold must be at least 1")]
    InvalidQuorumThreshold,
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn verifies_matching_artifact_hash() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("artifact.bin");
        fs::write(&artifact, b"release bytes").unwrap();
        let provenance_path = dir.path().join("artifact.provenance.json");
        let provenance = PackageProvenance {
            schema: 1,
            package: "astragrid".to_owned(),
            version: "0.1.0".to_owned(),
            target: "test".to_owned(),
            generated_at: "2026-05-07T00:00:00Z".to_owned(),
            artifact: Some(ProvenanceFile {
                path: PathBuf::from("artifact.bin"),
                sha256: sha256_file(&artifact).unwrap(),
            }),
            binary: None,
            included_files: Vec::new(),
            toolchain: serde_json::Value::Null,
            git: serde_json::Value::Null,
        };
        fs::write(&provenance_path, serde_json::to_vec(&provenance).unwrap()).unwrap();

        let loaded = PackageProvenance::load(&provenance_path).unwrap();
        let report = loaded.verify_hashes(&provenance_path).unwrap();

        assert!(report.valid);
        assert_eq!(report.checks[0].status, ProvenanceCheckStatus::Match);
    }

    #[test]
    fn reports_mismatch() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("artifact.bin");
        fs::write(&artifact, b"release bytes").unwrap();
        let provenance = PackageProvenance {
            schema: 1,
            package: "astragrid".to_owned(),
            version: "0.1.0".to_owned(),
            target: "test".to_owned(),
            generated_at: "2026-05-07T00:00:00Z".to_owned(),
            artifact: Some(ProvenanceFile {
                path: artifact.clone(),
                sha256: "00".repeat(32),
            }),
            binary: None,
            included_files: Vec::new(),
            toolchain: serde_json::Value::Null,
            git: serde_json::Value::Null,
        };

        let report = provenance.verify_hashes(dir.path().join("p.json")).unwrap();

        assert!(!report.valid);
        assert_eq!(report.checks[0].status, ProvenanceCheckStatus::Mismatch);
    }

    #[test]
    fn resolves_paths_relative_to_provenance_file() {
        let dir = tempdir().unwrap();
        let dist = dir.path().join("dist");
        let binary_dir = dir.path().join("target").join("release");
        fs::create_dir_all(&dist).unwrap();
        fs::create_dir_all(&binary_dir).unwrap();
        let binary = binary_dir.join("astragrid");
        fs::write(&binary, b"release binary").unwrap();
        let provenance_path = dist.join("astragrid.provenance.json");
        let provenance = PackageProvenance {
            schema: 1,
            package: "astragrid".to_owned(),
            version: "0.1.0".to_owned(),
            target: "test".to_owned(),
            generated_at: "2026-05-07T00:00:00Z".to_owned(),
            artifact: None,
            binary: Some(ProvenanceFile {
                path: PathBuf::from("../target/release/astragrid"),
                sha256: sha256_file(&binary).unwrap(),
            }),
            included_files: Vec::new(),
            toolchain: serde_json::Value::Null,
            git: serde_json::Value::Null,
        };
        fs::write(&provenance_path, serde_json::to_vec(&provenance).unwrap()).unwrap();

        let report = provenance.verify_hashes(&provenance_path).unwrap();

        assert!(report.valid);
        assert_eq!(report.checks[0].status, ProvenanceCheckStatus::Match);
    }

    #[test]
    fn signs_and_verifies_provenance_file() {
        let dir = tempdir().unwrap();
        let provenance_path = dir.path().join("artifact.provenance.json");
        fs::write(&provenance_path, b"{\"schema\":1}").unwrap();
        let keypair = OperatorKeypair::generate("release", astragrid_core::Role::Operator);
        let envelope = ProvenanceSignatureEnvelope::sign_file(&provenance_path, &keypair).unwrap();
        let signature_path = dir.path().join("artifact.provenance.sig.json");
        fs::write(&signature_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let loaded = ProvenanceSignatureEnvelope::load(&signature_path).unwrap();

        let report = loaded.verify(&signature_path).unwrap();

        assert!(report.valid);
        assert_eq!(report.signer.name, "release");
    }

    #[test]
    fn signature_report_fails_on_provenance_tampering() {
        let dir = tempdir().unwrap();
        let provenance_path = dir.path().join("artifact.provenance.json");
        fs::write(&provenance_path, b"{\"schema\":1}").unwrap();
        let keypair = OperatorKeypair::generate("release", astragrid_core::Role::Operator);
        let envelope = ProvenanceSignatureEnvelope::sign_file(&provenance_path, &keypair).unwrap();
        let signature_path = dir.path().join("artifact.provenance.sig.json");
        fs::write(&signature_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        fs::write(&provenance_path, b"{\"schema\":2}").unwrap();
        let loaded = ProvenanceSignatureEnvelope::load(&signature_path).unwrap();

        let report = loaded.verify(&signature_path).unwrap();

        assert!(!report.valid);
        assert!(!report.provenance_hash_match);
        assert!(report.signature_valid);
    }

    #[test]
    fn verifies_distinct_signer_quorum() {
        let dir = tempdir().unwrap();
        let provenance_path = dir.path().join("artifact.provenance.json");
        fs::write(&provenance_path, b"{\"schema\":1}").unwrap();
        let one = OperatorKeypair::generate("release-one", astragrid_core::Role::Operator);
        let two = OperatorKeypair::generate("release-two", astragrid_core::Role::Operator);
        let quorum = ProvenanceQuorumEnvelope::new(
            2,
            vec![
                ProvenanceSignatureEnvelope::sign_file(&provenance_path, &one).unwrap(),
                ProvenanceSignatureEnvelope::sign_file(&provenance_path, &two).unwrap(),
            ],
        )
        .unwrap();
        let quorum_path = dir.path().join("artifact.provenance.quorum.json");
        fs::write(&quorum_path, serde_json::to_vec(&quorum).unwrap()).unwrap();

        let report = quorum.verify(&quorum_path).unwrap();

        assert!(report.valid);
        assert_eq!(report.distinct_valid_signers, 2);
    }

    #[test]
    fn rejects_duplicate_signer_quorum() {
        let dir = tempdir().unwrap();
        let provenance_path = dir.path().join("artifact.provenance.json");
        fs::write(&provenance_path, b"{\"schema\":1}").unwrap();
        let one = OperatorKeypair::generate("release-one", astragrid_core::Role::Operator);
        let signature = ProvenanceSignatureEnvelope::sign_file(&provenance_path, &one).unwrap();
        let quorum = ProvenanceQuorumEnvelope::new(2, vec![signature.clone(), signature]).unwrap();
        let quorum_path = dir.path().join("artifact.provenance.quorum.json");

        let report = quorum.verify(&quorum_path).unwrap();

        assert!(!report.valid);
        assert_eq!(report.valid_signatures, 2);
        assert_eq!(report.distinct_valid_signers, 1);
    }

    #[test]
    fn reads_utf8_bom_provenance() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("p.json");
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(b"\xEF\xBB\xBF{\"schema\":1,\"package\":\"astragrid\",\"version\":\"0.1.0\",\"target\":\"test\",\"generated_at\":\"2026-05-07T00:00:00Z\",\"artifact\":{\"path\":\"missing.bin\",\"sha256\":\"abc\"}}")
            .unwrap();

        let provenance = PackageProvenance::load(&path).unwrap();

        assert_eq!(provenance.package, "astragrid");
    }
}
