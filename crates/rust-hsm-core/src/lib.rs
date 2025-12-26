//! rust-hsm-core: Core PKCS#11 library for HSM operations
//!
//! This library provides a high-level interface to PKCS#11 Hardware Security Modules (HSMs).
//! It handles token management, key generation, cryptographic operations, and more.
//!
//! Built on top of [cryptoki](https://crates.io/crates/cryptoki), the Rust PKCS#11 bindings,
//! this library provides a more ergonomic API focused on common HSM workflows.
//!
//! ## Features
//!
//! - **Token Management**: Initialize tokens, manage PINs
//! - **Key Generation**: RSA, ECDSA, AES key generation
//! - **Cryptographic Operations**: Sign, verify, encrypt, decrypt
//! - **Key Management**: Wrap, unwrap, export, delete keys
//! - **Object Inspection**: List and inspect HSM objects with detailed attributes
//! - **Mechanism Discovery**: Query supported PKCS#11 mechanisms
//! - **JSON Serialization**: Export data in machine-parseable format
//! - **Troubleshooting**: Error explanations, key search, and comparison tools
//!
//! ## Example
//!
//! ```rust,no_run
//! use rust_hsm_core::keys;
//!
//! // Generate an RSA keypair on an HSM
//! keys::gen_keypair(
//!     "/usr/lib/softhsm/libsofthsm2.so",
//!     "MY_TOKEN",
//!     "user-pin",
//!     "signing-key",
//!     "rsa",
//!     2048,
//!     false,
//!     false,
//! ).expect("Failed to generate keypair");
//! ```

// Re-export the pkcs11 module as the public API
mod pkcs11;

// Re-export all public modules at the top level
pub use pkcs11::audit;
pub use pkcs11::benchmark;
pub use pkcs11::errors;
pub use pkcs11::info;
pub use pkcs11::keys;
pub use pkcs11::mechanisms;
pub use pkcs11::objects;
pub use pkcs11::random;
pub use pkcs11::slots;
pub use pkcs11::token;
pub use pkcs11::troubleshoot;

// Re-export commonly used types
pub use pkcs11::errors::Pkcs11Error;
