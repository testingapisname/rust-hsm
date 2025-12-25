//! Observed wrapper for Session

use crate::config::ObserveConfig;
use cryptoki::error::Error;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use observe_core::Pkcs11Event;
use std::sync::Arc;
use std::time::Instant;

/// Wrapper around cryptoki::Session that emits observability events
pub struct ObservedSession {
    inner: Session,
    config: Arc<ObserveConfig>,
    slot_id: u64,
}

impl ObservedSession {
    pub(crate) fn new(inner: Session, config: Arc<ObserveConfig>, slot_id: u64) -> Self {
        Self {
            inner,
            config,
            slot_id,
        }
    }

    /// Get reference to inner Session for direct access
    pub fn inner(&self) -> &Session {
        &self.inner
    }

    /// Login to the session
    pub fn login(&self, user_type: UserType, pin: Option<&AuthPin>) -> Result<(), Error> {
        let start = Instant::now();
        tracing::debug!("→ Calling C_Login");

        let result = self.inner.login(user_type, pin);
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let rv = match &result {
            Ok(_) => 0,
            Err(e) => error_to_rv(e),
        };

        let event = Pkcs11Event::new("C_Login", rv)
            .with_slot_id(self.slot_id)
            .with_session(session_handle(&self.inner))
            .with_duration(duration);

        self.config.write(&event);

        result
    }

    /// Logout from the session
    pub fn logout(&self) -> Result<(), Error> {
        let start = Instant::now();
        tracing::debug!("→ Calling C_Logout");

        let result = self.inner.logout();
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let rv = match &result {
            Ok(_) => 0,
            Err(e) => error_to_rv(e),
        };

        let event = Pkcs11Event::new("C_Logout", rv)
            .with_slot_id(self.slot_id)
            .with_session(session_handle(&self.inner))
            .with_duration(duration);

        self.config.write(&event);

        result
    }

    /// Initialize user PIN (SO must be logged in)
    pub fn init_pin(&self, pin: &AuthPin) -> Result<(), Error> {
        let start = Instant::now();
        tracing::debug!("→ Calling C_InitPIN");

        let result = self.inner.init_pin(pin);
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let rv = match &result {
            Ok(_) => 0,
            Err(e) => error_to_rv(e),
        };

        let event = Pkcs11Event::new("C_InitPIN", rv)
            .with_slot_id(self.slot_id)
            .with_session(session_handle(&self.inner))
            .with_duration(duration);

        self.config.write(&event);

        result
    }

    /// Find objects matching a template
    pub fn find_objects(
        &self,
        template: &[cryptoki::object::Attribute],
    ) -> Result<Vec<ObjectHandle>, Error> {
        // This wraps C_FindObjectsInit + C_FindObjects + C_FindObjectsFinal
        let start = Instant::now();
        let op_id = format!(
            "find-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        tracing::debug!("→ Calling C_FindObjectsInit");
        let event_init = Pkcs11Event::new("C_FindObjectsInit", 0)
            .with_slot_id(self.slot_id)
            .with_session(session_handle(&self.inner))
            .with_op_id(&op_id);
        self.config.write(&event_init);

        let result = self.inner.find_objects(template);
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let (rv, count) = match &result {
            Ok(handles) => (0, handles.len()),
            Err(e) => (error_to_rv(e), 0),
        };

        tracing::debug!("→ C_FindObjects found {} objects", count);
        let event_final = Pkcs11Event::new("C_FindObjectsFinal", rv)
            .with_slot_id(self.slot_id)
            .with_session(session_handle(&self.inner))
            .with_op_id(&op_id)
            .with_duration(duration)
            .with_hint(format!("Found {} objects", count));

        self.config.write(&event_final);

        result
    }
    /// Sign data with a key (wraps C_Sign)
    pub fn sign(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let start = Instant::now();
        let op_id = format!(
            "sign-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        tracing::debug!("→ Calling C_Sign");
        let result = self.inner.sign(mechanism, key, data);
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let rv = result.as_ref().map(|_| 0u64).unwrap_or_else(error_to_rv);

        let event = Pkcs11Event::new("C_Sign", rv)
            .with_slot_id(self.slot_id)
            .with_session(session_handle(&self.inner))
            .with_mechanism(format!("{:?}", mechanism))
            .with_op_id(&op_id)
            .with_duration(duration);

        self.config.write(&event);

        result
    }

    /// Verify signature (wraps C_Verify)
    pub fn verify(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let start = Instant::now();

        tracing::debug!("→ Calling C_Verify");
        let result = self.inner.verify(mechanism, key, data, signature);
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let rv = result.as_ref().map(|_| 0u64).unwrap_or_else(error_to_rv);

        let event = Pkcs11Event::new("C_Verify", rv)
            .with_slot_id(self.slot_id)
            .with_session(session_handle(&self.inner))
            .with_mechanism(format!("{:?}", mechanism))
            .with_duration(duration);

        self.config.write(&event);

        result
    }

    /// Get object attributes (wraps C_GetAttributeValue)
    pub fn get_attribute_value(
        &self,
        object: ObjectHandle,
        attributes: &[AttributeType],
    ) -> Result<Vec<Attribute>, Error> {
        let start = Instant::now();

        tracing::debug!("→ Calling C_GetAttributeValue");
        let result = self.inner.get_attributes(object, attributes);
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let rv = result.as_ref().map(|_| 0u64).unwrap_or_else(error_to_rv);

        let event = Pkcs11Event::new("C_GetAttributeValue", rv)
            .with_slot_id(self.slot_id)
            .with_session(session_handle(&self.inner))
            .with_duration(duration);

        self.config.write(&event);

        result
    }

    /// Generate a keypair (wraps C_GenerateKeyPair)
    pub fn generate_key_pair(
        &self,
        mechanism: &Mechanism,
        pub_key_template: &[Attribute],
        priv_key_template: &[Attribute],
    ) -> Result<(ObjectHandle, ObjectHandle), Error> {
        let start = Instant::now();

        tracing::debug!("→ Calling C_GenerateKeyPair");
        let result = self
            .inner
            .generate_key_pair(mechanism, pub_key_template, priv_key_template);
        let duration = start.elapsed().as_secs_f64() * 1000.0;

        let rv = result.as_ref().map(|_| 0u64).unwrap_or_else(error_to_rv);

        let event = Pkcs11Event::new("C_GenerateKeyPair", rv)
            .with_slot_id(self.slot_id)
            .with_session(session_handle(&self.inner))
            .with_mechanism(format!("{:?}", mechanism))
            .with_duration(duration);

        self.config.write(&event);

        result
    }
}

/// Convert cryptoki Error to CK_RV value
fn error_to_rv(error: &Error) -> u64 {
    match error {
        Error::Pkcs11(rv, _) => *rv as u64,
        _ => 0x00000006, // CKR_FUNCTION_FAILED
    }
}

/// Extract session handle from Session
fn session_handle(session: &Session) -> u64 {
    let debug_str = format!("{:?}", session);
    debug_str
        .split("handle: ")
        .nth(1)
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}
