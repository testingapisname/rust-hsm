use clap::{Parser, Subcommand};
use std::env;
use std::io::{self, BufRead};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber;

mod config;
mod pkcs11;

use config::Config;

/// Read a PIN from stdin, trimming whitespace
fn read_pin_from_stdin() -> anyhow::Result<String> {
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

#[derive(Parser)]
#[command(name = "rust-hsm-cli")]
#[command(about = "Rust PKCS#11 CLI for SoftHSM2", long_about = None)]
struct Cli {
    /// Path to configuration file (optional)
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display PKCS#11 module and token information
    Info,
    
    /// List all available slots and tokens
    ListSlots,
    
    /// List supported mechanisms for a slot
    ListMechanisms {
        /// Slot ID (uses first slot if not specified)
        #[arg(long)]
        slot: Option<u64>,
    },
    
    /// Initialize a token
    InitToken {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        so_pin: Option<String>,
        /// Read SO PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Initialize user PIN on a token
    InitPin {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "so_pin_stdin")]
        so_pin: Option<String>,
        #[arg(long, conflicts_with = "user_pin_stdin")]
        user_pin: Option<String>,
        /// Read SO PIN from stdin (first line)
        #[arg(long = "so-pin-stdin")]
        so_pin_stdin: bool,
        /// Read user PIN from stdin (second line if so-pin-stdin, else first line)
        #[arg(long = "user-pin-stdin")]
        user_pin_stdin: bool,
    },
    
    /// Delete a token (reinitializes the slot, erasing all data)
    DeleteToken {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        so_pin: Option<String>,
        /// Read SO PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// List objects on a token
    ListObjects {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Generate a keypair on the token
    GenKeypair {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long, default_value = "rsa")]
        key_type: String,
        #[arg(long, default_value = "2048")]
        bits: u32,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Sign data with a private key
    Sign {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Verify a signature
    Verify {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        signature: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Export a public key in PEM format
    ExportPubkey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Delete a keypair from the token
    DeleteKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Inspect detailed key attributes (CKA_* values)
    InspectKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Encrypt data with an RSA public key
    Encrypt {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Decrypt data with an RSA private key
    Decrypt {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Generate a symmetric key (AES) on the token
    GenSymmetricKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// Key size in bits (128, 192, or 256)
        #[arg(long, default_value = "256")]
        bits: u32,
        /// Allow the key to be wrapped/exported (sets CKA_EXTRACTABLE=true)
        #[arg(long)]
        extractable: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Encrypt data with AES-GCM
    EncryptSymmetric {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Decrypt data with AES-GCM
    DecryptSymmetric {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Wrap (export) a key using AES Key Wrap
    WrapKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Label of the key to wrap (the key being exported)
        #[arg(long)]
        key_label: String,
        /// Label of the wrapping key (AES KEK - Key Encryption Key)
        #[arg(long)]
        wrapping_key_label: String,
        /// Output file for the wrapped key data
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Unwrap (import) a key using AES Key Wrap
    UnwrapKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Label for the imported key
        #[arg(long)]
        key_label: String,
        /// Label of the wrapping key (AES KEK - Key Encryption Key)
        #[arg(long)]
        wrapping_key_label: String,
        /// Input file containing the wrapped key data
        #[arg(long)]
        input: String,
        /// Key type: aes (for symmetric keys)
        #[arg(long, default_value = "aes")]
        key_type: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Generate a Certificate Signing Request (CSR) for a keypair
    GenCsr {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Label of the keypair to generate CSR for
        #[arg(long)]
        key_label: String,
        /// Subject Distinguished Name (e.g., "CN=example.com,O=MyOrg,C=US")
        #[arg(long)]
        subject: String,
        /// Output file for the CSR in PEM format
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Hash data using SHA-256, SHA-512, or other hash algorithms
    Hash {
        /// Hash algorithm (sha256, sha512, sha224, sha1)
        #[arg(long, default_value = "sha256")]
        algorithm: String,
        /// Input file to hash
        #[arg(long)]
        input: String,
        /// Output file for the hash
        #[arg(long)]
        output: String,
    },
    
    /// Generate an HMAC key
    GenHmacKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// Key size in bits (typically 256)
        #[arg(long, default_value = "256")]
        bits: u32,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Compute HMAC for data (message authentication)
    HmacSign {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// HMAC algorithm (sha256, sha512, sha384, sha224, sha1)
        #[arg(long, default_value = "sha256")]
        algorithm: String,
        /// Input file to authenticate
        #[arg(long)]
        input: String,
        /// Output file for the HMAC
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Verify HMAC for data
    HmacVerify {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// HMAC algorithm (sha256, sha512, sha384, sha224, sha1)
        #[arg(long, default_value = "sha256")]
        algorithm: String,
        /// Input file to verify
        #[arg(long)]
        input: String,
        /// HMAC file to verify against
        #[arg(long)]
        hmac: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Generate an AES-CMAC key
    GenCmacKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// AES key size in bits (128, 192, or 256)
        #[arg(long, default_value = "256")]
        bits: u32,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Compute CMAC for data (AES-based message authentication)
    CmacSign {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// Input file to authenticate
        #[arg(long)]
        input: String,
        /// Output file for the CMAC
        #[arg(long)]
        output: String,
        /// MAC length in bytes (default: 16 for full AES block)
        #[arg(long)]
        mac_len: Option<usize>,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Verify CMAC for data
    CmacVerify {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// Input file to verify
        #[arg(long)]
        input: String,
        /// CMAC file to verify against
        #[arg(long)]
        cmac: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Generate random bytes using HSM's RNG
    GenRandom {
        /// Number of bytes to generate
        #[arg(long, default_value = "32")]
        bytes: usize,
        /// Output file (if not specified, outputs hex to stdout)
        #[arg(long)]
        output: Option<PathBuf>,
        /// Output as hex string instead of binary (only applies to file output)
        #[arg(long)]
        hex: bool,
    },

    /// Run comprehensive performance benchmarks
    Benchmark {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Number of iterations per test
        #[arg(long, default_value = "100")]
        iterations: usize,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Load configuration (CLI --config flag takes precedence over default locations)
    let config = Config::load_with_custom_path(cli.config);

    // Get PKCS#11 module path from environment, or config, or default
    let module_path = env::var("PKCS11_MODULE")
        .unwrap_or_else(|_| config.get_pkcs11_module().to_string());

    info!("Using PKCS#11 module: {}", module_path);

    match cli.command {
        Commands::Info => {
            pkcs11::info::display_info(&module_path)?;
        }
        Commands::ListSlots => {
            pkcs11::slots::list_slots(&module_path)?;
        }
        Commands::ListMechanisms { slot } => {
            pkcs11::info::list_mechanisms(&module_path, slot)?;
        }
        Commands::InitToken { label, so_pin, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let so_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                so_pin.ok_or_else(|| anyhow::anyhow!("Either --so-pin or --pin-stdin must be provided"))?
            };
            pkcs11::token::init_token(&module_path, &token_label, &so_pin_value)?;
        }
        Commands::InitPin { label, so_pin, user_pin, so_pin_stdin, user_pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let so_pin_value = if so_pin_stdin {
                read_pin_from_stdin()?
            } else {
                so_pin.ok_or_else(|| anyhow::anyhow!("Either --so-pin or --so-pin-stdin must be provided"))?
            };
            
            let user_pin_value = if user_pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --user-pin-stdin must be provided"))?
            };
            
            pkcs11::token::init_pin(&module_path, &token_label, &so_pin_value, &user_pin_value)?;
        }
        Commands::DeleteToken { label, so_pin, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let so_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                so_pin.ok_or_else(|| anyhow::anyhow!("Either --so-pin or --pin-stdin must be provided"))?
            };
            pkcs11::token::delete_token(&module_path, &token_label, &so_pin_value)?;
        }
        Commands::ListObjects { label, user_pin, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::objects::list_objects(&module_path, &token_label, &user_pin_value)?;
        }
        Commands::GenKeypair { label, user_pin, key_label, key_type, bits, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::gen_keypair(&module_path, &token_label, &user_pin_value, &key_label, &key_type, bits)?;
        }
        Commands::Sign { label, user_pin, key_label, input, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::sign(&module_path, &token_label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::Verify { label, user_pin, key_label, input, signature, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::verify(&module_path, &token_label, &user_pin_value, &key_label, &input, &signature)?;
        }
        Commands::ExportPubkey { label, user_pin, key_label, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::export_pubkey(&module_path, &token_label, &user_pin_value, &key_label, &output)?;
        }
        Commands::DeleteKey { label, user_pin, key_label, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::delete_key(&module_path, &token_label, &user_pin_value, &key_label)?;
        }
        Commands::InspectKey { label, user_pin, key_label, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::inspect_key(&module_path, &token_label, &user_pin_value, &key_label)?;
        }
        Commands::Encrypt { label, user_pin, key_label, input, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::encrypt(&module_path, &token_label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::Decrypt { label, user_pin, key_label, input, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::decrypt(&module_path, &token_label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::GenSymmetricKey { label, user_pin, key_label, bits, extractable, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::gen_symmetric_key(&module_path, &token_label, &user_pin_value, &key_label, bits, extractable)?;
        }
        Commands::EncryptSymmetric { label, user_pin, key_label, input, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::encrypt_symmetric(&module_path, &token_label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::DecryptSymmetric { label, user_pin, key_label, input, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::decrypt_symmetric(&module_path, &token_label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::WrapKey { label, user_pin, key_label, wrapping_key_label, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::wrap_key(&module_path, &token_label, &user_pin_value, &key_label, &wrapping_key_label, &output)?;
        }
        Commands::UnwrapKey { label, user_pin, key_label, wrapping_key_label, input, key_type, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::unwrap_key(&module_path, &token_label, &user_pin_value, &key_label, &wrapping_key_label, &input, &key_type)?;
        }
        Commands::GenCsr { label, user_pin, key_label, subject, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::generate_csr(&module_path, &token_label, &user_pin_value, &key_label, &subject, &output)?;
        }
        Commands::Hash { algorithm, input, output } => {
            let input_path = PathBuf::from(&input);
            let output_path = PathBuf::from(&output);
            pkcs11::keys::hash_data(&module_path, &algorithm, &input_path, &output_path)?;
        }
        Commands::GenHmacKey { label, user_pin, key_label, bits, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::gen_hmac_key(&module_path, &token_label, &user_pin_value, &key_label, bits)?;
        }
        Commands::HmacSign { label, user_pin, key_label, algorithm, input, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            let input_path = PathBuf::from(&input);
            let output_path = PathBuf::from(&output);
            pkcs11::keys::hmac_sign(&module_path, &token_label, &user_pin_value, &key_label, &algorithm, &input_path, &output_path)?;
        }
        Commands::HmacVerify { label, user_pin, key_label, algorithm, input, hmac, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            let input_path = PathBuf::from(&input);
            let hmac_path = PathBuf::from(&hmac);
            pkcs11::keys::hmac_verify(&module_path, &token_label, &user_pin_value, &key_label, &algorithm, &input_path, &hmac_path)?;
        }
        Commands::GenCmacKey { label, user_pin, key_label, bits, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::gen_cmac_key(&module_path, &token_label, &user_pin_value, &key_label, bits)?;
        }
        Commands::CmacSign { label, user_pin, key_label, input, output, mac_len, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            let input_path = PathBuf::from(&input);
            let output_path = PathBuf::from(&output);
            pkcs11::keys::cmac_sign(&module_path, &token_label, &user_pin_value, &key_label, &input_path, &output_path, mac_len)?;
        }
        Commands::CmacVerify { label, user_pin, key_label, input, cmac, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            let input_path = PathBuf::from(&input);
            let cmac_path = PathBuf::from(&cmac);
            pkcs11::keys::cmac_verify(&module_path, &token_label, &user_pin_value, &key_label, &input_path, &cmac_path)?;
        }
        Commands::GenRandom { bytes, output, hex } => {
            pkcs11::random::generate_random(&module_path, bytes, output.as_ref(), hex)?;
        }
        Commands::Benchmark { label, user_pin, iterations, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified with --label or in config file"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::benchmark::run_full_benchmark(&module_path, &token_label, &user_pin_value, iterations)?;
        }
    }

    Ok(())
}
