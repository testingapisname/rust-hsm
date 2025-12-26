//! Observed wrapper for Pkcs11

use crate::config::ObserveConfig;
use crate::session::ObservedSession;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::error::Error;
use cryptoki::session::Session;
use cryptoki::slot::Slot;
use observe_core::Pkcs11Event;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

/// Wrapper around cryptoki::Pkcs11 that emits observability events
pub struct ObservedPkcs11 {
    inner: Pkcs11,
    config: Arc<ObserveConfig>,
}

impl ObservedPkcs11 {
    /// Create a new observed PKCS#11 context
    pub fn new(filename: impl AsRef<Path>, config: ObserveConfig) -> Result<Self, Error> {
        let start = Instant::now();
        let inner = Pkcs11::new(filename)?;
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let config = Arc::new(config);

        // Log the module load
        let event = Pkcs11Event::new("Pkcs11::new", 0).with_duration(duration);
        config.write(&event);

        Ok(Self { inner, config })
    }

    /// Initialize the PKCS#11 library
    pub fn initialize(&self, args: CInitializeArgs) -> Result<(), Error> {
        let start = Instant::now();
        tracing::debug!("→ Calling C_Initialize");

        let result = self.inner.initialize(args);
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let rv = match &result {
            Ok(_) => 0,
            Err(e) => error_to_rv(e),
        };

        let event = Pkcs11Event::new("C_Initialize", rv).with_duration(duration);
        self.config.write(&event);

        result
    }

    /// Finalize the PKCS#11 library
    pub fn finalize(self) {
        let start = Instant::now();
        tracing::debug!("→ Calling C_Finalize");

        self.inner.finalize();
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let event = Pkcs11Event::new("C_Finalize", 0).with_duration(duration);
        self.config.write(&event);
        self.config.flush();
    }

    /// Get reference to inner Pkcs11 for direct access
    pub fn inner(&self) -> &Pkcs11 {
        &self.inner
    }

    /// Open a read-write session
    pub fn open_rw_session(&self, slot: Slot) -> Result<ObservedSession, Error> {
        let start = Instant::now();
        let slot_id = slot.id();
        tracing::debug!("→ Calling C_OpenSession (slot {})", slot_id);

        let result = self.inner.open_rw_session(slot);
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let (rv, session_handle) = match &result {
            Ok(session) => {
                let handle = session_to_handle(session);
                (0, Some(handle))
            }
            Err(e) => (error_to_rv(e), None),
        };

        let mut event = Pkcs11Event::new("C_OpenSession", rv)
            .with_slot_id(slot_id)
            .with_duration(duration);

        if let Some(handle) = session_handle {
            event = event.with_session(handle);
        }

        self.config.write(&event);

        result.map(|session| ObservedSession::new(session, self.config.clone(), slot_id))
    }

    /// Open a read-only session
    pub fn open_ro_session(&self, slot: Slot) -> Result<ObservedSession, Error> {
        let start = Instant::now();
        let slot_id = slot.id();
        tracing::debug!("→ Calling C_OpenSession (read-only, slot {})", slot_id);

        let result = self.inner.open_ro_session(slot);
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let (rv, session_handle) = match &result {
            Ok(session) => {
                let handle = session_to_handle(session);
                (0, Some(handle))
            }
            Err(e) => (error_to_rv(e), None),
        };

        let mut event = Pkcs11Event::new("C_OpenSession", rv)
            .with_slot_id(slot_id)
            .with_duration(duration);

        if let Some(handle) = session_handle {
            event = event.with_session(handle);
        }

        self.config.write(&event);

        result.map(|session| ObservedSession::new(session, self.config.clone(), slot_id))
    }
}

/// Convert cryptoki Error to CK_RV value (best effort)
fn error_to_rv(error: &Error) -> u64 {
    match error {
        Error::Pkcs11(rv, _) => *rv as u64,
        _ => 0x00000006, // CKR_FUNCTION_FAILED
    }
}

/// Extract session handle from Session (cryptoki doesn't expose this directly)
/// We use a workaround: format Debug and parse the handle
fn session_to_handle(session: &Session) -> u64 {
    // Session Debug format: "Session { handle: X, ... }"
    let debug_str = format!("{:?}", session);
    debug_str
        .split("handle: ")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}
