//! Common utilities and structures for command handling

use anyhow::Result;
use std::env;
use std::io::{self, BufRead};

use crate::config::Config;

/// Shared context for all command handlers
pub struct CommandContext {
    pub config: Config,
    pub module_path: String,
}

impl CommandContext {
    pub fn new(config: Config) -> Result<Self> {
        let module_path =
            env::var("PKCS11_MODULE").unwrap_or_else(|_| config.get_pkcs11_module().to_string());

        tracing::info!("Using PKCS#11 module: {}", module_path);

        Ok(CommandContext {
            config,
            module_path,
        })
    }

    /// Get token label, using CLI value or config default
    pub fn token_label(&self, cli_value: Option<String>) -> Result<String> {
        self.config
            .token_label(cli_value.as_deref())
            .ok_or_else(|| anyhow::anyhow!("Token label required"))
    }
}

/// Read a PIN from stdin, trimming whitespace
pub fn read_pin_from_stdin() -> Result<String> {
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Common PIN handling logic
pub fn get_pin(pin: Option<String>, use_stdin: bool, error_msg: &str) -> Result<String> {
    if use_stdin {
        read_pin_from_stdin()
    } else {
        pin.ok_or_else(|| anyhow::anyhow!("{}", error_msg))
    }
}

/// Get user PIN with consistent error handling
pub fn get_user_pin(pin: Option<String>, use_stdin: bool) -> Result<String> {
    get_pin(pin, use_stdin, "User PIN required")
}

/// Get SO PIN with consistent error handling
pub fn get_so_pin(pin: Option<String>, use_stdin: bool) -> Result<String> {
    get_pin(pin, use_stdin, "SO PIN required")
}
