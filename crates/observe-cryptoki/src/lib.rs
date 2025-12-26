//! Observability wrapper around cryptoki for PKCS#11 tracing
//!
//! This crate provides thin wrappers around cryptoki types that automatically
//! emit structured events to observe-core sinks.
//!
//! # Example
//! ```no_run
//! use observe_cryptoki::{ObservedPkcs11, ObserveConfig};
//! use cryptoki::context::CInitializeArgs;
//!
//! let config = ObserveConfig::enabled("/app/observe.jsonl")?;
//! let pkcs11 = ObservedPkcs11::new("/usr/lib/softhsm/libsofthsm2.so", config)?;
//!
//! // All operations are automatically logged
//! pkcs11.initialize(CInitializeArgs::OsThreads)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

mod config;
mod pkcs11;
mod session;

pub use config::ObserveConfig;
pub use pkcs11::ObservedPkcs11;
pub use session::ObservedSession;
