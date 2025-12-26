//! PKCS#11 Log Analysis Library
//!
//! Provides parsing and analysis of PKCS#11 operation logs from:
//! - observe-core JSON Lines format
//! - pkcs11-spy plaintext format (future)
//!
//! # Example
//! ```no_run
//! use rust_hsm_analyze::{parser, analyzer};
//!
//! let events = parser::parse_observe_json("observe.json")?;
//! let analyzer = analyzer::Analyzer::new(events);
//! let stats = analyzer.analyze();
//! println!("Total operations: {}", stats.total_ops);
//! # Ok::<(), anyhow::Error>(())
//! ```

pub mod analyzer;
pub mod parser;

pub use analyzer::{Analyzer, SessionAnalysis};
pub use parser::{parse_observe_json, LogFormat};
