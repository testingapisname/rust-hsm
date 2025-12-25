//! observe-core - Shared logging and redaction utilities for PKCS#11 observability
//!
//! This crate provides:
//! - Event schema for PKCS#11 operations
//! - Redaction utilities for sensitive data
//! - Sinks for writing logs (JSON Lines, stderr)
//!
//! Security-first: Never logs PINs, raw buffers, or sensitive attributes.

pub mod event;
pub mod redaction;
pub mod sink;

pub use event::Pkcs11Event;
pub use redaction::{hash_label, redact_buffer, RedactedValue};
pub use sink::{FileSink, Sink};
