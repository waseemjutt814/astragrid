use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsSecretProvider {
    WindowsDpapiCurrentUser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsSealedSecret {
    pub schema: u16,
    pub provider: OsSecretProvider,
    pub purpose: String,
    pub ciphertext_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsSecretInspection {
    pub path: PathBuf,
    pub schema: u16,
    pub provider: OsSecretProvider,
    pub purpose: String,
    pub ciphertext_bytes: usize,
}

impl OsSealedSecret {
    pub fn seal_current_user(secret: &[u8], purpose: &str) -> Result<Self, OsKeyError> {
        validate_secret(secret)?;
        let purpose = normalize_purpose(purpose)?;
        let sealed = platform_seal(secret, &purpose)?;
        Ok(Self {
            schema: SCHEMA_VERSION,
            provider: sealed.provider,
            purpose,
            ciphertext_hex: hex::encode(sealed.ciphertext),
        })
    }

    pub fn open_current_user(&self) -> Result<Vec<u8>, OsKeyError> {
        self.validate()?;
        let ciphertext = hex::decode(&self.ciphertext_hex)?;
        platform_open(self.provider, &ciphertext, &self.purpose)
    }

    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), OsKeyError> {
        self.validate()?;
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = format!("{}\n", serde_json::to_string_pretty(self)?);
        fs::write(path, text)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, OsKeyError> {
        let mut bytes = fs::read(path)?;
        strip_utf8_bom(&mut bytes);
        let secret: Self = serde_json::from_slice(&bytes)?;
        secret.validate()?;
        Ok(secret)
    }

    pub fn inspect_file(path: impl AsRef<Path>) -> Result<OsSecretInspection, OsKeyError> {
        let path = path.as_ref();
        let secret = Self::load(path)?;
        Ok(OsSecretInspection {
            path: path.to_path_buf(),
            schema: secret.schema,
            provider: secret.provider,
            purpose: secret.purpose,
            ciphertext_bytes: hex::decode(secret.ciphertext_hex)?.len(),
        })
    }

    fn validate(&self) -> Result<(), OsKeyError> {
        if self.schema != SCHEMA_VERSION {
            return Err(OsKeyError::UnsupportedSchema(self.schema));
        }
        normalize_purpose(&self.purpose)?;
        if self.ciphertext_hex.trim().is_empty() {
            return Err(OsKeyError::EmptyCiphertext);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PlatformSealedSecret {
    provider: OsSecretProvider,
    ciphertext: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum OsKeyError {
    #[error("OS key I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("OS key JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("OS key hex failed: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("OS key provider is unsupported on this operating system")]
    UnsupportedPlatform,
    #[error("unsupported OS key schema {0}")]
    UnsupportedSchema(u16),
    #[error("OS key purpose cannot be empty")]
    EmptyPurpose,
    #[error("OS key plaintext secret cannot be empty")]
    EmptySecret,
    #[error("OS key ciphertext cannot be empty")]
    EmptyCiphertext,
    #[error("OS key purpose contains newline, carriage return, or NUL")]
    UnsafePurpose,
    #[error("OS key operation failed: {0}")]
    Platform(String),
}

fn validate_secret(secret: &[u8]) -> Result<(), OsKeyError> {
    if secret.is_empty() {
        return Err(OsKeyError::EmptySecret);
    }
    Ok(())
}

fn normalize_purpose(purpose: &str) -> Result<String, OsKeyError> {
    let purpose = purpose.trim();
    if purpose.is_empty() {
        return Err(OsKeyError::EmptyPurpose);
    }
    if purpose
        .chars()
        .any(|character| matches!(character, '\n' | '\r' | '\0'))
    {
        return Err(OsKeyError::UnsafePurpose);
    }
    Ok(purpose.to_owned())
}

fn strip_utf8_bom(bytes: &mut Vec<u8>) {
    const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";
    if bytes.starts_with(UTF8_BOM) {
        bytes.drain(..UTF8_BOM.len());
    }
}

#[cfg(windows)]
fn platform_seal(secret: &[u8], purpose: &str) -> Result<PlatformSealedSecret, OsKeyError> {
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData},
    };

    let input = data_blob(secret)?;
    let entropy = data_blob(purpose.as_bytes())?;
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let description = wide_null("AstraGrid OS-sealed secret")?;
    let ok = unsafe {
        CryptProtectData(
            &input,
            description.as_ptr(),
            &entropy,
            null_mut(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(OsKeyError::Io(std::io::Error::last_os_error()));
    }
    let bytes = unsafe {
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let copied = slice.to_vec();
        LocalFree(output.pbData as _);
        copied
    };
    Ok(PlatformSealedSecret {
        provider: OsSecretProvider::WindowsDpapiCurrentUser,
        ciphertext: bytes,
    })
}

#[cfg(windows)]
fn platform_open(
    provider: OsSecretProvider,
    ciphertext: &[u8],
    purpose: &str,
) -> Result<Vec<u8>, OsKeyError> {
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
        },
    };

    if provider != OsSecretProvider::WindowsDpapiCurrentUser {
        return Err(OsKeyError::UnsupportedPlatform);
    }
    let input = data_blob(ciphertext)?;
    let entropy = data_blob(purpose.as_bytes())?;
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            &entropy,
            null_mut(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(OsKeyError::Io(std::io::Error::last_os_error()));
    }
    let bytes = unsafe {
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let copied = slice.to_vec();
        LocalFree(output.pbData as _);
        copied
    };
    Ok(bytes)
}

#[cfg(windows)]
fn data_blob(
    bytes: &[u8],
) -> Result<windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB, OsKeyError> {
    let cb_data = u32::try_from(bytes.len())
        .map_err(|_| OsKeyError::Platform("secret is too large for DPAPI".to_owned()))?;
    Ok(
        windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
            cbData: cb_data,
            pbData: bytes.as_ptr() as *mut u8,
        },
    )
}

#[cfg(windows)]
fn wide_null(input: &str) -> Result<Vec<u16>, OsKeyError> {
    if input.contains('\0') {
        return Err(OsKeyError::Platform("wide string contains NUL".to_owned()));
    }
    Ok(input.encode_utf16().chain([0]).collect())
}

#[cfg(not(windows))]
fn platform_seal(_secret: &[u8], _purpose: &str) -> Result<PlatformSealedSecret, OsKeyError> {
    Err(OsKeyError::UnsupportedPlatform)
}

#[cfg(not(windows))]
fn platform_open(
    _provider: OsSecretProvider,
    _ciphertext: &[u8],
    _purpose: &str,
) -> Result<Vec<u8>, OsKeyError> {
    Err(OsKeyError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn rejects_empty_secret_and_purpose() {
        assert!(matches!(
            OsSealedSecret::seal_current_user(b"", "purpose"),
            Err(OsKeyError::EmptySecret)
        ));
        assert!(matches!(
            OsSealedSecret::seal_current_user(b"secret", " "),
            Err(OsKeyError::EmptyPurpose)
        ));
    }

    #[test]
    fn validates_serialized_envelope() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret.oskey");
        let secret = OsSealedSecret {
            schema: 1,
            provider: OsSecretProvider::WindowsDpapiCurrentUser,
            purpose: "astragrid-test".to_owned(),
            ciphertext_hex: "aabbcc".to_owned(),
        };
        secret.save_to_file(&path).unwrap();

        let inspection = OsSealedSecret::inspect_file(&path).unwrap();

        assert_eq!(inspection.ciphertext_bytes, 3);
        assert_eq!(inspection.purpose, "astragrid-test");
    }

    #[cfg(windows)]
    #[test]
    fn windows_dpapi_round_trips_secret() {
        let sealed =
            OsSealedSecret::seal_current_user(b"operator passphrase", "astragrid-test").unwrap();

        let opened = sealed.open_current_user().unwrap();

        assert_eq!(opened, b"operator passphrase");
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_reports_unsupported_platform() {
        assert!(matches!(
            OsSealedSecret::seal_current_user(b"operator passphrase", "astragrid-test"),
            Err(OsKeyError::UnsupportedPlatform)
        ));
    }
}
