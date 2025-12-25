//! Redaction utilities for sensitive PKCS#11 data
//!
//! Security rules:
//! - Never log PINs
//! - Never log raw buffers (plaintext, ciphertext, keys)
//! - Never log sensitive attributes (CKA_VALUE, private key components)
//! - Hash labels/IDs instead of logging plaintext

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A redacted value that shows metadata but hides content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedValue {
    /// Length of the original data
    pub len: usize,

    /// SHA-256 hash of the data (hex encoded)
    pub sha256: String,
}

/// Redact a buffer by returning length and hash
pub fn redact_buffer(data: &[u8]) -> RedactedValue {
    RedactedValue {
        len: data.len(),
        sha256: hash_bytes(data),
    }
}

/// Hash a label for safe logging
/// Returns hex-encoded SHA-256 hash
pub fn hash_label(label: &str) -> String {
    hash_bytes(label.as_bytes())
}

/// Hash arbitrary bytes and return hex-encoded string
fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Check if an attribute name is sensitive and should never be logged
pub fn is_sensitive_attribute(attr_name: &str) -> bool {
    matches!(
        attr_name,
        "CKA_VALUE"
            | "CKA_PRIVATE_EXPONENT"
            | "CKA_PRIME_1"
            | "CKA_PRIME_2"
            | "CKA_EXPONENT_1"
            | "CKA_EXPONENT_2"
            | "CKA_COEFFICIENT"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_buffer() {
        let data = b"sensitive data";
        let redacted = redact_buffer(data);

        assert_eq!(redacted.len, 14);
        assert_eq!(redacted.sha256.len(), 64); // SHA-256 hex = 64 chars

        // Same data should produce same hash
        let redacted2 = redact_buffer(data);
        assert_eq!(redacted.sha256, redacted2.sha256);
    }

    #[test]
    fn test_hash_label() {
        let label = "my-test-key";
        let hash = hash_label(label);

        assert_eq!(hash.len(), 64); // SHA-256 hex

        // Same label should produce same hash
        let hash2 = hash_label(label);
        assert_eq!(hash, hash2);

        // Different labels should produce different hashes
        let hash3 = hash_label("different-key");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_is_sensitive_attribute() {
        assert!(is_sensitive_attribute("CKA_VALUE"));
        assert!(is_sensitive_attribute("CKA_PRIVATE_EXPONENT"));
        assert!(is_sensitive_attribute("CKA_PRIME_1"));

        assert!(!is_sensitive_attribute("CKA_CLASS"));
        assert!(!is_sensitive_attribute("CKA_KEY_TYPE"));
        assert!(!is_sensitive_attribute("CKA_LABEL"));
        assert!(!is_sensitive_attribute("CKA_SIGN"));
    }

    #[test]
    fn test_empty_data() {
        let redacted = redact_buffer(b"");
        assert_eq!(redacted.len, 0);
        assert_eq!(redacted.sha256.len(), 64); // Still valid hash
    }
}
