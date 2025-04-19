#[cfg(test)]
mod tests;

use crate::app::AppError;
use base64::{DecodeError, Engine as _, engine::general_purpose::URL_SAFE};

impl From<DecodeError> for AppError {
    fn from(error: DecodeError) -> Self {
        AppError::from_error("base64 decode error", &error)
    }
}

pub trait EncryptionSystem {
    fn encrypt(&self, plaintext: &str) -> Result<String, AppError>;
    fn decrypt(&self, ciphertext: &str) -> Result<String, AppError>;
}

struct InsecureEncryptionSystem;

impl EncryptionSystem for InsecureEncryptionSystem {
    fn encrypt(&self, plaintext: &str) -> Result<String, AppError> {
        base64_encode(&plaintext)
    }

    fn decrypt(&self, ciphertext: &str) -> Result<String, AppError> {
        base64_decode(ciphertext)
    }
}

/// Decode the UTF-8 string represented by the Base64 encoded value in `source`.
/// 
/// ```
/// let original = String::new("hello, world!");
/// let encoded = base64_encode(original.as_str());
/// let decoded = base64_decode(encoded.as_str());
/// assert_eq!(decoded, original);
/// ```
fn base64_encode(source: &str) -> Result<String, AppError> {
    let r = URL_SAFE.encode(source.as_bytes());
    Ok(r)
}

/// Base64 encode the UTF-8 bytes comprising the provided string.
fn base64_decode(source: &str) -> Result<String, AppError> {
    let v = URL_SAFE.decode(source.as_bytes())?;
    let s = String::from_utf8(v)?;
    Ok(s)
}

/// Create a new `Encryption` compatible struct that uses base64 encoding to simulate encryption.
///
/// **DO NOT USE THIS FOR REAL WORK!  It is only intended for testing.  It does
/// not actually encrypt values but just base64 encodes them.**
pub fn new_insecure_encryption() -> Result<Box<dyn EncryptionSystem>, AppError> {
    Ok(Box::new(InsecureEncryptionSystem))
}
