use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Default token label to use when --label is not specified
    #[serde(default)]
    pub default_token_label: Option<String>,

    /// Default PKCS#11 module path (defaults to SoftHSM2 location)
    #[serde(default = "default_pkcs11_module")]
    pub pkcs11_module: String,

    /// Enable PKCS#11 observability logging
    #[serde(default)]
    pub observe_enabled: bool,

    /// Path to observability log file (JSON Lines format)
    #[serde(default = "default_observe_log_file")]
    pub observe_log_file: String,
}

fn default_pkcs11_module() -> String {
    "/usr/lib/softhsm/libsofthsm2.so".to_string()
}

fn default_observe_log_file() -> String {
    "/app/rust-hsm-observe.json".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_token_label: None,
            pkcs11_module: default_pkcs11_module(),
            observe_enabled: false,
            observe_log_file: default_observe_log_file(),
        }
    }
}

impl Config {
    /// Load configuration from a file path
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        info!("Loaded configuration from {}", path.display());
        debug!("Config: {:?}", config);

        Ok(config)
    }

    /// Try to load config from default locations, or return default config
    pub fn load() -> Self {
        Self::load_with_custom_path(None)
    }

    /// Load config with optional custom path. Falls back to default locations if path is None.
    pub fn load_with_custom_path(custom_path: Option<PathBuf>) -> Self {
        // If custom path is provided, try to load it
        if let Some(path) = custom_path {
            match Self::from_file(&path) {
                Ok(config) => return config,
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to load config from {}: {}",
                        path.display(),
                        e
                    );
                    eprintln!("Using default configuration");
                    return Self::default();
                }
            }
        }

        // Try default locations in order
        let mut default_paths: Vec<PathBuf> = vec![
            // Current directory
            PathBuf::from(".rust-hsm.toml"),
            PathBuf::from("rust-hsm.toml"),
        ];

        // Add home directory paths if available
        if let Some(home) = dirs::home_dir() {
            default_paths.push(home.join(".config/rust-hsm/config.toml"));
            default_paths.push(home.join(".rust-hsm.toml"));
        }

        // Add container/app directory paths
        default_paths.push(PathBuf::from("/app/.rust-hsm.toml"));
        default_paths.push(PathBuf::from("/app/rust-hsm.toml"));

        for path in default_paths {
            if path.exists() {
                debug!("Found config file at {}", path.display());
                match Self::from_file(&path) {
                    Ok(config) => return config,
                    Err(e) => {
                        debug!("Failed to load config from {}: {}", path.display(), e);
                        continue;
                    }
                }
            }
        }

        debug!("No config file found, using defaults");
        Self::default()
    }

    /// Get the token label, using provided value or default from config
    pub fn token_label(&self, cli_value: Option<&str>) -> Option<String> {
        cli_value
            .map(|s| s.to_string())
            .or_else(|| self.default_token_label.clone())
    }

    /// Get the PKCS#11 module path
    pub fn get_pkcs11_module(&self) -> &str {
        &self.pkcs11_module
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.default_token_label, None);
        // Default module path is platform-specific, just ensure it's set
        assert!(!config.pkcs11_module.is_empty());
    }

    #[test]
    fn test_parse_config() {
        let toml_content = r#"
            default_token_label = "MY_TOKEN"
            pkcs11_module = "/custom/path/libsofthsm2.so"
        "#;

        let config: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(config.default_token_label, Some("MY_TOKEN".to_string()));
        assert_eq!(config.pkcs11_module, "/custom/path/libsofthsm2.so");
    }

    #[test]
    fn test_load_from_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "default_token_label = \"TEST_TOKEN\"").unwrap();
        writeln!(temp_file, "pkcs11_module = \"/usr/lib/test.so\"").unwrap();

        let config = Config::from_file(&temp_file.path().to_path_buf()).unwrap();
        assert_eq!(config.default_token_label, Some("TEST_TOKEN".to_string()));
        assert_eq!(config.pkcs11_module, "/usr/lib/test.so");
    }

    #[test]
    fn test_token_label_precedence() {
        let mut config = Config::default();
        config.default_token_label = Some("DEFAULT_TOKEN".to_string());

        // CLI value takes precedence
        assert_eq!(
            config.token_label(Some("CLI_TOKEN")),
            Some("CLI_TOKEN".to_string())
        );

        // Falls back to config default
        assert_eq!(config.token_label(None), Some("DEFAULT_TOKEN".to_string()));

        // No default in config
        let empty_config = Config::default();
        assert_eq!(empty_config.token_label(None), None);
    }
}
