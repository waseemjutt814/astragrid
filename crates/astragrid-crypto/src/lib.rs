use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroize;

const ALGORITHM: &str = "xchacha20poly1305";
const KDF: &str = "argon2id-v1";
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedArtifact {
    pub schema: u16,
    pub algorithm: String,
    pub kdf: String,
    #[serde(with = "time::serde::rfc3339")]
    pub sealed_at: OffsetDateTime,
    pub label: String,
    pub aad: String,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl SealedArtifact {
    pub fn seal(
        label: impl Into<String>,
        plaintext: &[u8],
        passphrase: &[u8],
        aad: &[u8],
    ) -> Result<Self, CryptoError> {
        if passphrase.is_empty() {
            return Err(CryptoError::EmptyPassphrase);
        }
        let mut salt = [0_u8; SALT_BYTES];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let mut key = derive_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::SealFailed)?;
        key.zeroize();

        Ok(Self {
            schema: 1,
            algorithm: ALGORITHM.to_owned(),
            kdf: KDF.to_owned(),
            sealed_at: OffsetDateTime::now_utc(),
            label: label.into(),
            aad: hex::encode(aad),
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        })
    }

    pub fn open(&self, passphrase: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if passphrase.is_empty() {
            return Err(CryptoError::EmptyPassphrase);
        }
        if self.schema != 1 {
            return Err(CryptoError::UnsupportedSchema(self.schema));
        }
        if self.algorithm != ALGORITHM {
            return Err(CryptoError::UnsupportedAlgorithm(self.algorithm.clone()));
        }
        if self.kdf != KDF {
            return Err(CryptoError::UnsupportedKdf(self.kdf.clone()));
        }
        let salt = hex::decode(&self.salt)?;
        let nonce = fixed_array::<NONCE_BYTES>(hex::decode(&self.nonce)?)?;
        let aad = hex::decode(&self.aad)?;
        let ciphertext = hex::decode(&self.ciphertext)?;
        let mut key = derive_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::OpenFailed)?;
        key.zeroize();
        Ok(plaintext)
    }
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|error| CryptoError::Kdf(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|error| CryptoError::Kdf(error.to_string()))?;
    Ok(key)
}

fn fixed_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], CryptoError> {
    let actual = bytes.len();
    bytes.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: N,
        actual,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("passphrase cannot be empty")]
    EmptyPassphrase,
    #[error("unsupported sealed artifact schema {0}")]
    UnsupportedSchema(u16),
    #[error("unsupported encryption algorithm {0}")]
    UnsupportedAlgorithm(String),
    #[error("unsupported key derivation function {0}")]
    UnsupportedKdf(String),
    #[error("hex decoding failed: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("encryption failed")]
    SealFailed,
    #[error("decryption failed")]
    OpenFailed,
    #[error("invalid byte length: expected {expected}, found {actual}")]
    InvalidLength { expected: usize, actual: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_opens_artifact() {
        let artifact =
            SealedArtifact::seal("ledger", b"mission bytes", b"passphrase", b"mission-a").unwrap();

        assert_eq!(artifact.open(b"passphrase").unwrap(), b"mission bytes");
    }

    #[test]
    fn rejects_wrong_passphrase() {
        let artifact =
            SealedArtifact::seal("ledger", b"mission bytes", b"passphrase", b"mission-a").unwrap();

        assert!(matches!(
            artifact.open(b"wrong"),
            Err(CryptoError::OpenFailed)
        ));
    }
}
