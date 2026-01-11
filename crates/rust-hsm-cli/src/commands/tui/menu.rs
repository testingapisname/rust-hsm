//! TUI menu definitions and navigation logic

/// Main menu categories
#[derive(Debug, Clone, PartialEq)]
pub enum MenuCategory {
    TokenManagement,
    KeyOperations,
    CryptoOperations,
    SymmetricOperations,
    Troubleshooting,
    Information,
    Quit,
}

impl MenuCategory {
    pub fn all() -> Vec<Self> {
        vec![
            Self::Information,
            Self::TokenManagement,
            Self::KeyOperations,
            Self::CryptoOperations,
            Self::SymmetricOperations,
            Self::Troubleshooting,
            Self::Quit,
        ]
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Information => "📊 Information & Status",
            Self::TokenManagement => "🔧 Token Management",
            Self::KeyOperations => "🔑 Key Operations",
            Self::CryptoOperations => "🔐 Cryptographic Operations",
            Self::SymmetricOperations => "⚡ Symmetric Operations",
            Self::Troubleshooting => "🔍 Troubleshooting",
            Self::Quit => "❌ Quit",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Self::Information => "View HSM info, list slots, mechanisms, and objects",
            Self::TokenManagement => "Initialize, configure, and manage HSM tokens",
            Self::KeyOperations => "Generate, export, inspect, and delete keys",
            Self::CryptoOperations => "Sign, verify, encrypt, decrypt operations",
            Self::SymmetricOperations => "AES encryption, key wrapping, HMAC operations",
            Self::Troubleshooting => "Explain errors, find keys, compare attributes",
            Self::Quit => "Exit the interactive interface",
        }
    }

    pub fn commands(&self) -> Vec<(&str, &str)> {
        match self {
            Self::Information => vec![
                ("info", "Display PKCS#11 module information"),
                ("list-slots", "Show available slots and tokens"),
                ("list-mechanisms", "Show supported mechanisms"),
                ("list-objects", "Show objects on token"),
            ],
            Self::TokenManagement => vec![
                ("init-token", "Initialize a new token"),
                ("init-pin", "Set user PIN on token"),
                ("delete-token", "Delete/reinitialize token"),
            ],
            Self::KeyOperations => vec![
                ("gen-keypair", "Generate RSA/ECDSA keypair"),
                ("export-pubkey", "Export public key as PEM"),
                ("inspect-key", "Show detailed key attributes"),
                ("delete-key", "Delete keypair from token"),
            ],
            Self::CryptoOperations => vec![
                ("sign", "Sign data with private key"),
                ("verify", "Verify signature"),
                ("encrypt", "Encrypt data with public key"),
                ("decrypt", "Decrypt data with private key"),
                ("gen-csr", "Generate certificate signing request"),
                ("hash", "Hash data using HSM"),
            ],
            Self::SymmetricOperations => vec![
                ("gen-symmetric-key", "Generate AES key"),
                ("encrypt-symmetric", "AES-GCM encryption"),
                ("decrypt-symmetric", "AES-GCM decryption"),
                ("wrap-key", "Export key using AES Key Wrap"),
                ("unwrap-key", "Import wrapped key"),
                ("hmac-sign", "Generate HMAC"),
                ("cmac-sign", "Generate AES-CMAC"),
            ],
            Self::Troubleshooting => vec![
                ("explain-error", "Decode PKCS#11 error codes"),
                ("find-key", "Search for keys with fuzzy matching"),
                ("diff-keys", "Compare two key attributes"),
                ("audit-keys", "Security audit of all keys"),
            ],
            Self::Quit => vec![],
        }
    }
}
