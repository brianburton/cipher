#[cfg(test)]
mod tests;

use crate::app::AppError;
use base64::{DecodeError, Engine as _, engine::general_purpose::URL_SAFE};

impl From<DecodeError> for AppError {
    fn from(error: DecodeError) -> Self {
        AppError::from_error("base64 decode error", &error)
    }
}

/// Trait for structs that can encrypt and decrypt strings.
/// Not all implementations are secure.  Be sure to check the doc comments
/// for the function that creates them for details on the algorithm used.
/// Encrypted strings are expected to be base64 encoded but can use other
/// encodings as long as a round trip is possible between `encrypt()` and `decrypt().
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
/// let original = "hello, world!".to_string();
/// let encoded = cipher::encryption::base64_encode(original.as_str()).unwrap();
/// let decoded = cipher::encryption::base64_decode(encoded.as_str()).unwrap();
/// assert_eq!(decoded, original);
/// ```
pub fn base64_encode(source: &str) -> Result<String, AppError> {
    let r = URL_SAFE.encode(source.as_bytes());
    Ok(r)
}

/// Base64 encode the UTF-8 bytes comprising the provided string.
pub fn base64_decode(source: &str) -> Result<String, AppError> {
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
