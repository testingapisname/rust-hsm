use clap::{Parser, Subcommand};
use std::env;
use std::io::{self, BufRead};
use tracing::info;
use tracing_subscriber;

mod pkcs11;

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
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display PKCS#11 module and token information
    Info,
    
    /// List all available slots and tokens
    ListSlots,
    
    /// Initialize a token
    InitToken {
        #[arg(long)]
        label: String,
        #[arg(long, conflicts_with = "pin_stdin")]
        so_pin: Option<String>,
        /// Read SO PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Initialize user PIN on a token
    InitPin {
        #[arg(long)]
        label: String,
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
    
    /// List objects on a token
    ListObjects {
        #[arg(long)]
        label: String,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },
    
    /// Generate a keypair on the token
    GenKeypair {
        #[arg(long)]
        label: String,
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
        #[arg(long)]
        label: String,
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
        #[arg(long)]
        label: String,
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
        #[arg(long)]
        label: String,
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
        #[arg(long)]
        label: String,
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
        #[arg(long)]
        label: String,
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
        #[arg(long)]
        label: String,
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
        #[arg(long)]
        label: String,
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
        #[arg(long)]
        label: String,
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
        #[arg(long)]
        label: String,
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
        #[arg(long)]
        label: String,
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
        #[arg(long)]
        label: String,
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
        #[arg(long)]
        label: String,
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

    // Get PKCS#11 module path from environment
    let module_path = env::var("PKCS11_MODULE")
        .unwrap_or_else(|_| "/usr/lib/softhsm/libsofthsm2.so".to_string());

    info!("Using PKCS#11 module: {}", module_path);

    match cli.command {
        Commands::Info => {
            pkcs11::info::display_info(&module_path)?;
        }
        Commands::ListSlots => {
            pkcs11::slots::list_slots(&module_path)?;
        }
        Commands::InitToken { label, so_pin, pin_stdin } => {
            let so_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                so_pin.ok_or_else(|| anyhow::anyhow!("Either --so-pin or --pin-stdin must be provided"))?
            };
            pkcs11::token::init_token(&module_path, &label, &so_pin_value)?;
        }
        Commands::InitPin { label, so_pin, user_pin, so_pin_stdin, user_pin_stdin } => {
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
            
            pkcs11::token::init_pin(&module_path, &label, &so_pin_value, &user_pin_value)?;
        }
        Commands::ListObjects { label, user_pin, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::objects::list_objects(&module_path, &label, &user_pin_value)?;
        }
        Commands::GenKeypair { label, user_pin, key_label, key_type, bits, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::gen_keypair(&module_path, &label, &user_pin_value, &key_label, &key_type, bits)?;
        }
        Commands::Sign { label, user_pin, key_label, input, output, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::sign(&module_path, &label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::Verify { label, user_pin, key_label, input, signature, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::verify(&module_path, &label, &user_pin_value, &key_label, &input, &signature)?;
        }
        Commands::ExportPubkey { label, user_pin, key_label, output, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::export_pubkey(&module_path, &label, &user_pin_value, &key_label, &output)?;
        }
        Commands::DeleteKey { label, user_pin, key_label, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::delete_key(&module_path, &label, &user_pin_value, &key_label)?;
        }
        Commands::Encrypt { label, user_pin, key_label, input, output, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::encrypt(&module_path, &label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::Decrypt { label, user_pin, key_label, input, output, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::decrypt(&module_path, &label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::GenSymmetricKey { label, user_pin, key_label, bits, extractable, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::gen_symmetric_key(&module_path, &label, &user_pin_value, &key_label, bits, extractable)?;
        }
        Commands::EncryptSymmetric { label, user_pin, key_label, input, output, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::encrypt_symmetric(&module_path, &label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::DecryptSymmetric { label, user_pin, key_label, input, output, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::decrypt_symmetric(&module_path, &label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::WrapKey { label, user_pin, key_label, wrapping_key_label, output, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::wrap_key(&module_path, &label, &user_pin_value, &key_label, &wrapping_key_label, &output)?;
        }
        Commands::UnwrapKey { label, user_pin, key_label, wrapping_key_label, input, key_type, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::unwrap_key(&module_path, &label, &user_pin_value, &key_label, &wrapping_key_label, &input, &key_type)?;
        }
        Commands::GenCsr { label, user_pin, key_label, subject, output, pin_stdin } => {
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("Either --user-pin or --pin-stdin must be provided"))?
            };
            pkcs11::keys::generate_csr(&module_path, &label, &user_pin_value, &key_label, &subject, &output)?;
        }
    }

    Ok(())
}
