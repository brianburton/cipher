#[cfg(test)]
mod tests;

use crate::app::AppError;
use aws_esdk;
use aws_esdk::client as esdk_client;
use aws_esdk::error::BuildError;
use aws_esdk::material_providers::client as mpl_client;
use aws_esdk::material_providers::types::keyring::KeyringRef;
use aws_esdk::material_providers::types::material_providers_config::MaterialProvidersConfig;
use aws_esdk::types::aws_encryption_sdk_config::AwsEncryptionSdkConfig;
use base64::{DecodeError, Engine as _, engine::general_purpose::URL_SAFE};
use std::collections::HashMap;

impl From<DecodeError> for AppError {
    fn from(error: DecodeError) -> Self {
        AppError::from_error("base64 decode error", &error)
    }
}

impl From<BuildError> for AppError {
    fn from(error: BuildError) -> Self {
        AppError::from_error("aws build error", &error)
    }
}

impl From<aws_esdk::types::error::Error> for AppError {
    fn from(error: aws_esdk::types::error::Error) -> Self {
        AppError::from_error("aws sdk error", &error)
    }
}

impl From<aws_esdk::material_providers::types::error::Error> for AppError {
    fn from(error: aws_esdk::material_providers::types::error::Error) -> Self {
        AppError::from_error("aws mat prov error", &error)
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

struct AwsEncryptionSystem {
    esdk_client: esdk_client::Client,
    mpl: mpl_client::Client,
    kms_keyring: KeyringRef,
}

impl EncryptionSystem for AwsEncryptionSystem {
    fn encrypt(&self, plaintext: &str) -> Result<String, AppError> {
        let encryption_response = trpl::run(async {
            self.esdk_client
                .encrypt()
                .plaintext(plaintext.as_bytes())
                .keyring(self.kms_keyring.clone())
                .encryption_context(HashMap::new())
                .send()
                .await
        })?;

        let ciphertext_bytes = encryption_response
            .ciphertext
            .ok_or_else(|| {
                AppError::from_str(
                    "aws encrypt",
                    "Unable to unwrap ciphertext from encryption response",
                )
            })?
            .into_inner();

        Ok(URL_SAFE.encode(ciphertext_bytes.as_slice()))
    }

    fn decrypt(&self, base64_ciphertext: &str) -> Result<String, AppError> {
        let ciphertext_bytes = URL_SAFE.decode(base64_ciphertext.as_bytes())?;
        let decryption_response = trpl::run(async {
            self.esdk_client
                .decrypt()
                .ciphertext(ciphertext_bytes)
                .keyring(self.kms_keyring.clone())
                .encryption_context(HashMap::new())
                .send()
                .await
        })?;

        let decrypted_plaintext = decryption_response
            .plaintext
            .ok_or_else(|| {
                AppError::from_str(
                    "aws encrypt",
                    "Unable to unwrap plaintext from decryption response",
                )
            })?
            .into_inner();

        let s = String::from_utf8(decrypted_plaintext)?;
        Ok(s)
    }
}

pub fn create_kms_encryption(key_id: &str) -> Result<Box<dyn EncryptionSystem>, AppError> {
    let esdk_config = AwsEncryptionSdkConfig::builder().build()?;
    let esdk_client = esdk_client::Client::from_conf(esdk_config)?;

    let sdk_config =
        trpl::run(async { aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await });
    let kms_client = aws_sdk_kms::Client::new(&sdk_config);

    let mpl_config = MaterialProvidersConfig::builder().build()?;
    let mpl = mpl_client::Client::from_conf(mpl_config)?;

    let kms_keyring = trpl::run(async {
        mpl.create_aws_kms_keyring()
            .kms_client(kms_client.clone())
            .kms_key_id(key_id)
            .send()
            .await
    })?;

    Ok(Box::new(AwsEncryptionSystem {
        esdk_client,
        mpl,
        kms_keyring,
    }))
}
