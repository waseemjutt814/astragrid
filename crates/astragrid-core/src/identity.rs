use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroize;

use crate::{
    event::{Actor, Role},
    policy::CommandRequest,
};

const KEY_SCHEMA: u16 = 1;
const ENCRYPTION_ALGORITHM: &str = "xchacha20poly1305";
const ENCRYPTION_KDF: &str = "argon2id-v1";
const ENCRYPTION_SALT_BYTES: usize = 16;
const ENCRYPTION_NONCE_BYTES: usize = 24;
const REGISTRY_SCHEMA: u16 = 1;
const SIGNATURE_SCHEMA: u16 = 1;
const DETACHED_SIGNATURE_SCHEMA: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorIdentity {
    pub id: String,
    pub name: String,
    pub role: Role,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandAttestation {
    pub schema: u16,
    pub identity: OperatorIdentity,
    #[serde(with = "time::serde::rfc3339")]
    pub signed_at: OffsetDateTime,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedCommand {
    pub schema: u16,
    pub request: CommandRequest,
    pub attestation: CommandAttestation,
}

impl SignedCommand {
    pub fn verify(&self) -> Result<(), IdentityError> {
        if self.schema != SIGNATURE_SCHEMA {
            return Err(IdentityError::UnsupportedSignatureSchema(self.schema));
        }

        if self.attestation.schema != SIGNATURE_SCHEMA {
            return Err(IdentityError::UnsupportedSignatureSchema(
                self.attestation.schema,
            ));
        }

        if self.request.actor.name != self.attestation.identity.name
            || self.request.actor.role != self.attestation.identity.role
        {
            return Err(IdentityError::ActorIdentityMismatch);
        }

        let verifying_key = verifying_key_from_hex(&self.attestation.identity.public_key)?;
        let signature = signature_from_hex(&self.attestation.signature)?;
        verifying_key.verify(&self.signing_bytes()?, &signature)?;
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let payload = SigningPayload {
            schema: SIGNATURE_SCHEMA,
            identity: &self.attestation.identity,
            signed_at: self.attestation.signed_at,
            request: &self.request,
        };
        Ok(serde_json::to_vec(&payload)?)
    }
}

#[derive(Serialize)]
struct SigningPayload<'a> {
    schema: u16,
    identity: &'a OperatorIdentity,
    #[serde(with = "time::serde::rfc3339")]
    signed_at: OffsetDateTime,
    request: &'a CommandRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedSignature {
    pub schema: u16,
    pub identity: OperatorIdentity,
    #[serde(with = "time::serde::rfc3339")]
    pub signed_at: OffsetDateTime,
    pub purpose: String,
    pub digest_algorithm: String,
    pub payload_digest: String,
    pub signature: String,
}

impl DetachedSignature {
    pub fn verify_digest(
        &self,
        purpose: &str,
        digest_algorithm: &str,
        payload_digest: &str,
    ) -> Result<(), IdentityError> {
        if self.schema != DETACHED_SIGNATURE_SCHEMA {
            return Err(IdentityError::UnsupportedSignatureSchema(self.schema));
        }

        let purpose = normalize_label(purpose);
        let digest_algorithm = normalize_label(digest_algorithm);
        let payload_digest = normalize_digest(payload_digest);
        if self.purpose != purpose {
            return Err(IdentityError::DetachedSignaturePurposeMismatch {
                expected: purpose,
                actual: self.purpose.clone(),
            });
        }
        if self.digest_algorithm != digest_algorithm || self.payload_digest != payload_digest {
            return Err(IdentityError::DetachedSignatureDigestMismatch);
        }

        let verifying_key = verifying_key_from_hex(&self.identity.public_key)?;
        let signature = signature_from_hex(&self.signature)?;
        verifying_key.verify(&self.signing_bytes()?, &signature)?;
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let payload = DetachedSigningPayload {
            schema: DETACHED_SIGNATURE_SCHEMA,
            identity: &self.identity,
            signed_at: self.signed_at,
            purpose: &self.purpose,
            digest_algorithm: &self.digest_algorithm,
            payload_digest: &self.payload_digest,
        };
        Ok(serde_json::to_vec(&payload)?)
    }
}

#[derive(Serialize)]
struct DetachedSigningPayload<'a> {
    schema: u16,
    identity: &'a OperatorIdentity,
    #[serde(with = "time::serde::rfc3339")]
    signed_at: OffsetDateTime,
    purpose: &'a str,
    digest_algorithm: &'a str,
    payload_digest: &'a str,
}

#[derive(Debug, Clone)]
pub struct OperatorKeypair {
    identity: OperatorIdentity,
    signing_key: SigningKey,
}

impl OperatorKeypair {
    pub fn generate(name: impl Into<String>, role: Role) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_signing_key(name, role, signing_key)
    }

    pub fn identity(&self) -> &OperatorIdentity {
        &self.identity
    }

    pub fn sign_request(&self, request: CommandRequest) -> Result<SignedCommand, IdentityError> {
        if request.actor.name != self.identity.name || request.actor.role != self.identity.role {
            return Err(IdentityError::ActorIdentityMismatch);
        }

        let mut command = SignedCommand {
            schema: SIGNATURE_SCHEMA,
            request,
            attestation: CommandAttestation {
                schema: SIGNATURE_SCHEMA,
                identity: self.identity.clone(),
                signed_at: OffsetDateTime::now_utc(),
                signature: String::new(),
            },
        };
        let signature = self.signing_key.sign(&command.signing_bytes()?);
        command.attestation.signature = hex::encode(signature.to_bytes());
        Ok(command)
    }

    pub fn sign_digest(
        &self,
        purpose: &str,
        digest_algorithm: &str,
        payload_digest: &str,
    ) -> Result<DetachedSignature, IdentityError> {
        let purpose = normalize_label(purpose);
        let digest_algorithm = normalize_label(digest_algorithm);
        let payload_digest = normalize_digest(payload_digest);
        if purpose.is_empty() {
            return Err(IdentityError::InvalidDetachedSignature(
                "signature purpose cannot be empty".to_owned(),
            ));
        }
        if digest_algorithm.is_empty() {
            return Err(IdentityError::InvalidDetachedSignature(
                "digest algorithm cannot be empty".to_owned(),
            ));
        }
        if payload_digest.is_empty() {
            return Err(IdentityError::InvalidDetachedSignature(
                "payload digest cannot be empty".to_owned(),
            ));
        }

        let mut detached = DetachedSignature {
            schema: DETACHED_SIGNATURE_SCHEMA,
            identity: self.identity.clone(),
            signed_at: OffsetDateTime::now_utc(),
            purpose,
            digest_algorithm,
            payload_digest,
            signature: String::new(),
        };
        let signature = self.signing_key.sign(&detached.signing_bytes()?);
        detached.signature = hex::encode(signature.to_bytes());
        Ok(detached)
    }

    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), IdentityError> {
        let key_file = OperatorKeyFile {
            schema: KEY_SCHEMA,
            identity: self.identity.clone(),
            secret_key: Some(hex::encode(self.signing_key.to_bytes())),
            encrypted_secret_key: None,
        };
        self.write_key_file(path, key_file)
    }

    pub fn save_encrypted_to_file(
        &self,
        path: impl AsRef<Path>,
        passphrase: &[u8],
    ) -> Result<(), IdentityError> {
        if passphrase.is_empty() {
            return Err(IdentityError::EmptyPassphrase);
        }

        let mut salt = [0_u8; ENCRYPTION_SALT_BYTES];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0_u8; ENCRYPTION_NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let mut key = derive_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        let aad = serde_json::to_vec(&self.identity)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &self.signing_key.to_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| IdentityError::Crypto("operator key encryption failed".to_owned()))?;
        key.zeroize();

        let key_file = OperatorKeyFile {
            schema: KEY_SCHEMA,
            identity: self.identity.clone(),
            secret_key: None,
            encrypted_secret_key: Some(EncryptedSecretKey {
                algorithm: ENCRYPTION_ALGORITHM.to_owned(),
                kdf: ENCRYPTION_KDF.to_owned(),
                salt: hex::encode(salt),
                nonce: hex::encode(nonce),
                ciphertext: hex::encode(ciphertext),
            }),
        };
        self.write_key_file(path, key_file)
    }

    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        Self::load_from_file_with_passphrase(path, None)
    }

    pub fn inspect_key_file(
        path: impl AsRef<Path>,
    ) -> Result<OperatorKeyFileSecurity, IdentityError> {
        let path = path.as_ref();
        let metadata = fs::metadata(path)?;
        let bytes = fs::read(path)?;
        let key_file: OperatorKeyFile = serde_json::from_slice(&bytes)?;
        if key_file.schema != KEY_SCHEMA {
            return Err(IdentityError::UnsupportedKeySchema(key_file.schema));
        }

        let plaintext_secret_present = key_file.secret_key.is_some();
        let encrypted = key_file.encrypted_secret_key.is_some();
        let mut warnings = Vec::new();
        if plaintext_secret_present {
            warnings.push("operator key file contains plaintext private key material".to_owned());
        }
        if !encrypted {
            warnings.push("operator key file is not passphrase encrypted".to_owned());
        }
        if plaintext_secret_present && encrypted {
            warnings.push("operator key file has ambiguous key material".to_owned());
        }

        let private_permissions = key_file_private_permissions(&metadata, &mut warnings);

        Ok(OperatorKeyFileSecurity {
            path: path.to_path_buf(),
            identity: key_file.identity,
            encrypted,
            plaintext_secret_present,
            private_permissions,
            file_size_bytes: metadata.len(),
            warnings,
        })
    }

    pub fn load_from_file_with_passphrase(
        path: impl AsRef<Path>,
        passphrase: Option<&[u8]>,
    ) -> Result<Self, IdentityError> {
        let bytes = fs::read(path)?;
        let key_file: OperatorKeyFile = serde_json::from_slice(&bytes)?;

        if key_file.schema != KEY_SCHEMA {
            return Err(IdentityError::UnsupportedKeySchema(key_file.schema));
        }

        let signing_key = match (&key_file.secret_key, &key_file.encrypted_secret_key) {
            (Some(secret_key), None) => signing_key_from_hex(secret_key)?,
            (None, Some(encrypted)) => {
                let passphrase = passphrase.ok_or(IdentityError::PassphraseRequired)?;
                decrypt_signing_key(encrypted, &key_file.identity, passphrase)?
            }
            (Some(_), Some(_)) => return Err(IdentityError::AmbiguousKeyMaterial),
            (None, None) => return Err(IdentityError::MissingKeyMaterial),
        };
        let expected_identity = Self::from_signing_key(
            key_file.identity.name.clone(),
            key_file.identity.role,
            signing_key.clone(),
        )
        .identity;
        if expected_identity.public_key != key_file.identity.public_key
            || expected_identity.id != key_file.identity.id
        {
            return Err(IdentityError::KeyIdentityMismatch);
        }

        Ok(Self {
            identity: key_file.identity,
            signing_key,
        })
    }

    fn write_key_file(
        &self,
        path: impl AsRef<Path>,
        key_file: OperatorKeyFile,
    ) -> Result<(), IdentityError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let bytes = serde_json::to_vec_pretty(&key_file)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(path)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }

    fn from_signing_key(name: impl Into<String>, role: Role, signing_key: SigningKey) -> Self {
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let id = operator_id(&public_key);
        Self {
            identity: OperatorIdentity {
                id,
                name: name.into(),
                role,
                public_key,
            },
            signing_key,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRegistryEntry {
    pub identity: OperatorIdentity,
    pub status: OperatorStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    pub issued_by: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub revoked_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OperatorRegistryFile {
    schema: u16,
    authority: String,
    entries: BTreeMap<String, OperatorRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorRegistry {
    path: Option<PathBuf>,
    document: OperatorRegistryFile,
}

impl OperatorRegistry {
    pub fn new(authority: impl Into<String>) -> Self {
        Self {
            path: None,
            document: OperatorRegistryFile {
                schema: REGISTRY_SCHEMA,
                authority: authority.into(),
                entries: BTreeMap::new(),
            },
        }
    }

    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let path = path.as_ref();
        let bytes = fs::read(path)?;
        let document: OperatorRegistryFile = serde_json::from_slice(&bytes)?;
        if document.schema != REGISTRY_SCHEMA {
            return Err(RegistryError::UnsupportedRegistrySchema(document.schema));
        }
        Ok(Self {
            path: Some(path.to_path_buf()),
            document,
        })
    }

    pub fn authority(&self) -> &str {
        &self.document.authority
    }

    pub fn entries(&self) -> impl Iterator<Item = &OperatorRegistryEntry> {
        self.document.entries.values()
    }

    pub fn get(&self, operator_id: &str) -> Option<&OperatorRegistryEntry> {
        self.document.entries.get(operator_id)
    }

    pub fn enroll(
        &mut self,
        identity: OperatorIdentity,
        issued_by: impl Into<String>,
    ) -> Result<OperatorRegistryEntry, RegistryError> {
        if let Some(entry) = self.document.entries.get(&identity.id)
            && entry.status == OperatorStatus::Active
        {
            return Err(RegistryError::AlreadyEnrolled(identity.id));
        }

        let entry = OperatorRegistryEntry {
            identity,
            status: OperatorStatus::Active,
            issued_at: OffsetDateTime::now_utc(),
            issued_by: issued_by.into(),
            revoked_at: None,
            revoked_by: None,
            revocation_reason: None,
        };
        self.document
            .entries
            .insert(entry.identity.id.clone(), entry.clone());
        Ok(entry)
    }

    pub fn revoke(
        &mut self,
        operator_id: &str,
        revoked_by: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<OperatorRegistryEntry, RegistryError> {
        let entry = self
            .document
            .entries
            .get_mut(operator_id)
            .ok_or_else(|| RegistryError::NotEnrolled(operator_id.to_owned()))?;
        entry.status = OperatorStatus::Revoked;
        entry.revoked_at = Some(OffsetDateTime::now_utc());
        entry.revoked_by = Some(revoked_by.into());
        entry.revocation_reason = Some(reason.into());
        Ok(entry.clone())
    }

    pub fn authorize_signed_command(&self, command: &SignedCommand) -> Result<(), RegistryError> {
        command.verify()?;
        let identity = &command.attestation.identity;
        let entry = self
            .document
            .entries
            .get(&identity.id)
            .ok_or_else(|| RegistryError::NotEnrolled(identity.id.clone()))?;

        if entry.status == OperatorStatus::Revoked {
            return Err(RegistryError::Revoked(identity.id.clone()));
        }

        if entry.identity.public_key != identity.public_key {
            return Err(RegistryError::PublicKeyMismatch(identity.id.clone()));
        }

        if entry.identity.name != identity.name {
            return Err(RegistryError::NameMismatch(identity.id.clone()));
        }

        if entry.identity.role != identity.role {
            return Err(RegistryError::RoleMismatch {
                operator_id: identity.id.clone(),
                expected: entry.identity.role,
                actual: identity.role,
            });
        }

        Ok(())
    }

    pub fn save_to_file(&mut self, path: impl AsRef<Path>) -> Result<(), RegistryError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        self.path = Some(path.to_path_buf());
        self.save()
    }

    pub fn save(&self) -> Result<(), RegistryError> {
        let path = self.path.as_ref().ok_or(RegistryError::MissingPath)?;
        let bytes = serde_json::to_vec_pretty(&self.document)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OperatorKeyFile {
    schema: u16,
    identity: OperatorIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encrypted_secret_key: Option<EncryptedSecretKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EncryptedSecretKey {
    algorithm: String,
    kdf: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorKeyFileSecurity {
    pub path: PathBuf,
    pub identity: OperatorIdentity,
    pub encrypted: bool,
    pub plaintext_secret_present: bool,
    pub private_permissions: Option<bool>,
    pub file_size_bytes: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("identity JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("identity key hex failed: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("identity key length is invalid: expected {expected}, found {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("identity signature verification failed: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("encrypted identity key requires a passphrase")]
    PassphraseRequired,
    #[error("identity passphrase cannot be empty")]
    EmptyPassphrase,
    #[error("identity key file has no key material")]
    MissingKeyMaterial,
    #[error("identity key file has ambiguous key material")]
    AmbiguousKeyMaterial,
    #[error("identity cryptography failed: {0}")]
    Crypto(String),
    #[error("command actor does not match signing identity")]
    ActorIdentityMismatch,
    #[error("detached signature is invalid: {0}")]
    InvalidDetachedSignature(String),
    #[error("detached signature purpose mismatch: expected {expected}, got {actual}")]
    DetachedSignaturePurposeMismatch { expected: String, actual: String },
    #[error("detached signature digest or algorithm mismatch")]
    DetachedSignatureDigestMismatch,
    #[error("key file identity does not match its private key")]
    KeyIdentityMismatch,
    #[error("unsupported key schema {0}")]
    UnsupportedKeySchema(u16),
    #[error("unsupported signature schema {0}")]
    UnsupportedSignatureSchema(u16),
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("operator registry I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("operator registry JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("identity verification failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("operator registry has no file path")]
    MissingPath,
    #[error("unsupported operator registry schema {0}")]
    UnsupportedRegistrySchema(u16),
    #[error("operator {0} is already enrolled and active")]
    AlreadyEnrolled(String),
    #[error("operator {0} is not enrolled")]
    NotEnrolled(String),
    #[error("operator {0} is revoked")]
    Revoked(String),
    #[error("operator {0} public key does not match registry")]
    PublicKeyMismatch(String),
    #[error("operator {0} name does not match registry")]
    NameMismatch(String),
    #[error(
        "operator {operator_id} role does not match registry: expected {expected}, got {actual}"
    )]
    RoleMismatch {
        operator_id: String,
        expected: Role,
        actual: Role,
    },
}

fn operator_id(public_key: &str) -> String {
    let hash = blake3::hash(public_key.as_bytes()).to_hex().to_string();
    format!("agop_{}", &hash[..24])
}

fn normalize_label(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_digest(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn signing_key_from_hex(value: &str) -> Result<SigningKey, IdentityError> {
    let bytes = hex::decode(value)?;
    let bytes = fixed_array::<32>(bytes)?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn verifying_key_from_hex(value: &str) -> Result<VerifyingKey, IdentityError> {
    let bytes = hex::decode(value)?;
    let bytes = fixed_array::<32>(bytes)?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

fn signature_from_hex(value: &str) -> Result<Signature, IdentityError> {
    let bytes = hex::decode(value)?;
    let bytes = fixed_array::<64>(bytes)?;
    Ok(Signature::from_bytes(&bytes))
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], IdentityError> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|error| IdentityError::Crypto(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|error| IdentityError::Crypto(error.to_string()))?;
    Ok(key)
}

fn decrypt_signing_key(
    encrypted: &EncryptedSecretKey,
    identity: &OperatorIdentity,
    passphrase: &[u8],
) -> Result<SigningKey, IdentityError> {
    if passphrase.is_empty() {
        return Err(IdentityError::EmptyPassphrase);
    }

    if encrypted.algorithm != ENCRYPTION_ALGORITHM {
        return Err(IdentityError::Crypto(format!(
            "unsupported key encryption algorithm {}",
            encrypted.algorithm
        )));
    }

    if encrypted.kdf != ENCRYPTION_KDF {
        return Err(IdentityError::Crypto(format!(
            "unsupported key encryption KDF {}",
            encrypted.kdf
        )));
    }

    let salt = hex::decode(&encrypted.salt)?;
    let nonce = fixed_array::<ENCRYPTION_NONCE_BYTES>(hex::decode(&encrypted.nonce)?)?;
    let ciphertext = hex::decode(&encrypted.ciphertext)?;
    let mut key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let aad = serde_json::to_vec(identity)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| IdentityError::Crypto("operator key decryption failed".to_owned()))?;
    key.zeroize();
    let signing_key = SigningKey::from_bytes(&fixed_array::<32>(plaintext)?);
    Ok(signing_key)
}

fn fixed_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], IdentityError> {
    let actual = bytes.len();
    bytes.try_into().map_err(|_| IdentityError::InvalidLength {
        expected: N,
        actual,
    })
}

#[cfg(unix)]
fn key_file_private_permissions(
    metadata: &std::fs::Metadata,
    warnings: &mut Vec<String>,
) -> Option<bool> {
    let private = metadata.permissions().mode() & 0o077 == 0;
    if !private {
        warnings.push("operator key file is readable or writable by group/other users".to_owned());
    }
    Some(private)
}

#[cfg(not(unix))]
fn key_file_private_permissions(
    _metadata: &std::fs::Metadata,
    warnings: &mut Vec<String>,
) -> Option<bool> {
    warnings.push("file ACL privacy is not inspected on this operating system".to_owned());
    None
}

impl From<&OperatorIdentity> for Actor {
    fn from(identity: &OperatorIdentity) -> Self {
        Actor::new(identity.name.clone(), identity.role)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::tempdir;

    use crate::event::{Action, Priority};

    use super::*;

    #[test]
    fn generated_identity_signs_and_verifies_command() {
        let keypair = OperatorKeypair::generate("lead", Role::IncidentCommander);
        let request = CommandRequest::new(
            Actor::from(keypair.identity()),
            Action::DeclareIncident,
            "river-east",
            Priority::Critical,
            json!({"water_level_m": 5.2}),
        );

        let signed = keypair.sign_request(request).unwrap();

        signed.verify().unwrap();
        assert_eq!(signed.attestation.identity.name, "lead");
    }

    #[test]
    fn signature_fails_after_request_tampering() {
        let keypair = OperatorKeypair::generate("lead", Role::IncidentCommander);
        let request = CommandRequest::new(
            Actor::from(keypair.identity()),
            Action::DeclareIncident,
            "river-east",
            Priority::Critical,
            json!({"water_level_m": 5.2}),
        );

        let mut signed = keypair.sign_request(request).unwrap();
        signed.request.subject = "river-west".to_owned();

        assert!(matches!(signed.verify(), Err(IdentityError::Signature(_))));
    }

    #[test]
    fn detached_digest_signature_verifies() {
        let keypair = OperatorKeypair::generate("release", Role::Operator);
        let signature = keypair
            .sign_digest("astragrid-release-provenance-v1", "sha256", "ABCDEF123456")
            .unwrap();

        signature
            .verify_digest("astragrid-release-provenance-v1", "sha256", "abcdef123456")
            .unwrap();
    }

    #[test]
    fn detached_digest_signature_rejects_wrong_digest() {
        let keypair = OperatorKeypair::generate("release", Role::Operator);
        let signature = keypair
            .sign_digest("astragrid-release-provenance-v1", "sha256", "abcdef")
            .unwrap();

        assert!(matches!(
            signature.verify_digest("astragrid-release-provenance-v1", "sha256", "000000"),
            Err(IdentityError::DetachedSignatureDigestMismatch)
        ));
    }

    #[test]
    fn key_file_round_trips_without_overwrite() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("lead.agkey");
        let keypair = OperatorKeypair::generate("lead", Role::IncidentCommander);
        keypair.save_to_file(&path).unwrap();

        let loaded = OperatorKeypair::load_from_file(&path).unwrap();

        assert_eq!(loaded.identity(), keypair.identity());
        assert!(matches!(
            keypair.save_to_file(&path),
            Err(IdentityError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
        ));

        let security = OperatorKeypair::inspect_key_file(&path).unwrap();
        assert!(security.plaintext_secret_present);
        assert!(!security.encrypted);
        assert!(!security.warnings.is_empty());
    }

    #[test]
    fn encrypted_key_file_requires_passphrase_and_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("lead.agkey");
        let keypair = OperatorKeypair::generate("lead", Role::IncidentCommander);
        keypair
            .save_encrypted_to_file(&path, b"correct horse battery staple")
            .unwrap();

        assert!(matches!(
            OperatorKeypair::load_from_file(&path),
            Err(IdentityError::PassphraseRequired)
        ));
        let loaded = OperatorKeypair::load_from_file_with_passphrase(
            &path,
            Some(b"correct horse battery staple"),
        )
        .unwrap();

        assert_eq!(loaded.identity(), keypair.identity());

        let security = OperatorKeypair::inspect_key_file(&path).unwrap();
        assert!(security.encrypted);
        assert!(!security.plaintext_secret_present);
    }

    #[test]
    fn encrypted_key_file_rejects_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("lead.agkey");
        let keypair = OperatorKeypair::generate("lead", Role::IncidentCommander);
        keypair.save_encrypted_to_file(&path, b"right").unwrap();

        assert!(matches!(
            OperatorKeypair::load_from_file_with_passphrase(&path, Some(b"wrong")),
            Err(IdentityError::Crypto(_))
        ));
    }

    #[test]
    fn registry_authorizes_enrolled_active_identity() {
        let keypair = OperatorKeypair::generate("lead", Role::IncidentCommander);
        let request = CommandRequest::new(
            Actor::from(keypair.identity()),
            Action::DeclareIncident,
            "river-east",
            Priority::Critical,
            json!({"water_level_m": 5.2}),
        );
        let signed = keypair.sign_request(request).unwrap();
        let mut registry = OperatorRegistry::new("local");
        registry
            .enroll(keypair.identity().clone(), "root")
            .expect("enroll");

        registry.authorize_signed_command(&signed).unwrap();
    }

    #[test]
    fn registry_rejects_unenrolled_identity() {
        let keypair = OperatorKeypair::generate("lead", Role::IncidentCommander);
        let request = CommandRequest::new(
            Actor::from(keypair.identity()),
            Action::DeclareIncident,
            "river-east",
            Priority::Critical,
            json!({"water_level_m": 5.2}),
        );
        let signed = keypair.sign_request(request).unwrap();
        let registry = OperatorRegistry::new("local");

        assert!(matches!(
            registry.authorize_signed_command(&signed),
            Err(RegistryError::NotEnrolled(_))
        ));
    }

    #[test]
    fn registry_rejects_revoked_identity() {
        let keypair = OperatorKeypair::generate("lead", Role::IncidentCommander);
        let mut registry = OperatorRegistry::new("local");
        registry.enroll(keypair.identity().clone(), "root").unwrap();
        registry
            .revoke(&keypair.identity().id, "root", "rotation")
            .unwrap();
        let signed = keypair
            .sign_request(CommandRequest::new(
                Actor::from(keypair.identity()),
                Action::DeclareIncident,
                "river-east",
                Priority::Critical,
                json!({"water_level_m": 5.2}),
            ))
            .unwrap();

        assert!(matches!(
            registry.authorize_signed_command(&signed),
            Err(RegistryError::Revoked(_))
        ));
    }

    #[test]
    fn registry_file_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("operators.agregistry");
        let keypair = OperatorKeypair::generate("lead", Role::IncidentCommander);
        let mut registry = OperatorRegistry::new("local");
        registry.enroll(keypair.identity().clone(), "root").unwrap();
        registry.save_to_file(&path).unwrap();

        let loaded = OperatorRegistry::load_from_file(&path).unwrap();

        assert_eq!(loaded.authority(), "local");
        assert_eq!(
            loaded.get(&keypair.identity().id).unwrap().identity,
            *keypair.identity()
        );
    }
}
