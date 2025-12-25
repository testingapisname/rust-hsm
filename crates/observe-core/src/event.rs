//! PKCS#11 event schema for structured logging

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single PKCS#11 operation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pkcs11Event {
    /// Timestamp (RFC3339 format)
    pub ts: DateTime<Utc>,

    /// Process ID
    pub pid: u32,

    /// Thread ID
    pub tid: u64,

    /// PKCS#11 function name (e.g., "C_Sign", "C_Initialize")
    pub func: String,

    /// Return value (numeric)
    pub rv: u64,

    /// Return value name (e.g., "CKR_OK", "CKR_PIN_INCORRECT")
    pub rv_name: String,

    /// Duration in milliseconds
    pub dur_ms: f64,

    /// Slot ID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_id: Option<u64>,

    /// Session handle (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<u64>,

    /// Mechanism name (optional, e.g., "CKM_RSA_PKCS", "CKM_SHA256_RSA_PKCS")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mech: Option<String>,

    /// Operation correlation ID (optional, for multi-step operations)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_id: Option<String>,

    /// Template summary (optional, for object creation/search)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_summary: Option<HashMap<String, serde_json::Value>>,

    /// Human-friendly hint (optional, for troubleshooting)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl Pkcs11Event {
    /// Create a new event with minimal required fields
    pub fn new(func: impl Into<String>, rv: u64) -> Self {
        Self {
            ts: Utc::now(),
            pid: std::process::id(),
            tid: get_thread_id(),
            func: func.into(),
            rv,
            rv_name: format_return_value(rv),
            dur_ms: 0.0,
            slot_id: None,
            session: None,
            mech: None,
            op_id: None,
            template_summary: None,
            hint: None,
        }
    }

    /// Set duration in milliseconds
    pub fn with_duration(mut self, dur_ms: f64) -> Self {
        self.dur_ms = dur_ms;
        self
    }

    /// Set slot ID
    pub fn with_slot_id(mut self, slot_id: u64) -> Self {
        self.slot_id = Some(slot_id);
        self
    }

    /// Set session handle
    pub fn with_session(mut self, session: u64) -> Self {
        self.session = Some(session);
        self
    }

    /// Set mechanism name
    pub fn with_mechanism(mut self, mech: impl Into<String>) -> Self {
        self.mech = Some(mech.into());
        self
    }

    /// Set operation correlation ID
    pub fn with_op_id(mut self, op_id: impl Into<String>) -> Self {
        self.op_id = Some(op_id.into());
        self
    }

    /// Set troubleshooting hint
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// Get current thread ID (platform-specific)
fn get_thread_id() -> u64 {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::syscall(libc::SYS_gettid) as u64 }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Fallback: use thread::current().id() hash
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        hasher.finish()
    }
}

/// Format PKCS#11 return value to human-readable name
/// For now, just handle the most common ones
fn format_return_value(rv: u64) -> String {
    match rv {
        0x00000000 => "CKR_OK".to_string(),
        0x00000001 => "CKR_CANCEL".to_string(),
        0x00000003 => "CKR_SLOT_ID_INVALID".to_string(),
        0x00000005 => "CKR_GENERAL_ERROR".to_string(),
        0x00000006 => "CKR_FUNCTION_FAILED".to_string(),
        0x00000007 => "CKR_ARGUMENTS_BAD".to_string(),
        0x00000028 => "CKR_USER_PIN_NOT_INITIALIZED".to_string(),
        0x00000041 => "CKR_SESSION_READ_ONLY_EXISTS".to_string(),
        0x00000060 => "CKR_KEY_HANDLE_INVALID".to_string(),
        0x00000070 => "CKR_MECHANISM_INVALID".to_string(),
        0x000000A0 => "CKR_PIN_INCORRECT".to_string(),
        0x000000A4 => "CKR_PIN_LOCKED".to_string(),
        0x000000C0 => "CKR_SIGNATURE_INVALID".to_string(),
        0x00000100 => "CKR_USER_ALREADY_LOGGED_IN".to_string(),
        0x00000101 => "CKR_USER_NOT_LOGGED_IN".to_string(),
        _ => format!("CKR_UNKNOWN(0x{:08X})", rv),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = Pkcs11Event::new("C_Initialize", 0);
        assert_eq!(event.func, "C_Initialize");
        assert_eq!(event.rv, 0);
        assert_eq!(event.rv_name, "CKR_OK");
        assert!(event.pid > 0);
        assert!(event.tid > 0);
    }

    #[test]
    fn test_event_builder() {
        let event = Pkcs11Event::new("C_Sign", 0)
            .with_duration(5.5)
            .with_slot_id(0)
            .with_session(42)
            .with_mechanism("CKM_RSA_PKCS")
            .with_op_id("sign-001");

        assert_eq!(event.dur_ms, 5.5);
        assert_eq!(event.slot_id, Some(0));
        assert_eq!(event.session, Some(42));
        assert_eq!(event.mech, Some("CKM_RSA_PKCS".to_string()));
        assert_eq!(event.op_id, Some("sign-001".to_string()));
    }

    #[test]
    fn test_return_value_formatting() {
        assert_eq!(format_return_value(0x00000000), "CKR_OK");
        assert_eq!(format_return_value(0x000000A0), "CKR_PIN_INCORRECT");
        assert_eq!(format_return_value(0x00000101), "CKR_USER_NOT_LOGGED_IN");
        assert_eq!(format_return_value(0xDEADBEEF), "CKR_UNKNOWN(0xDEADBEEF)");
    }

    #[test]
    fn test_event_serialization() {
        let event = Pkcs11Event::new("C_Login", 0)
            .with_session(1)
            .with_duration(2.5);

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"func\":\"C_Login\""));
        assert!(json.contains("\"rv\":0"));
        assert!(json.contains("\"rv_name\":\"CKR_OK\""));
        assert!(json.contains("\"session\":1"));
        assert!(json.contains("\"dur_ms\":2.5"));
    }
}
