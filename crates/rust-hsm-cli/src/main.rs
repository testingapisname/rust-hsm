use clap::Parser;
use std::env;
use std::io::{self, BufRead};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber;

mod cli;
mod config;
mod pkcs11;

use cli::{Cli, Commands};
use config::Config;

/// Read a PIN from stdin, trimming whitespace
fn read_pin_from_stdin() -> anyhow::Result<String> {
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
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

    // Load configuration
    let config = Config::load_with_custom_path(cli.config);

    // Get PKCS#11 module path
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
        Commands::ListMechanisms { slot, detailed } => {
            pkcs11::info::list_mechanisms(&module_path, slot, detailed)?;
        }
        Commands::InitToken { label, so_pin, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified"))?;
            let so_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                so_pin.ok_or_else(|| anyhow::anyhow!("SO PIN required"))?
            };
            pkcs11::token::init_token(&module_path, &token_label, &so_pin_value)?;
        }
        Commands::InitPin { label, so_pin, user_pin, so_pin_stdin, user_pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let so_pin_value = if so_pin_stdin {
                read_pin_from_stdin()?
            } else {
                so_pin.ok_or_else(|| anyhow::anyhow!("SO PIN required"))?
            };
            let user_pin_value = if user_pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::token::init_pin(&module_path, &token_label, &so_pin_value, &user_pin_value)?;
        }
        Commands::DeleteToken { label, so_pin, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let so_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                so_pin.ok_or_else(|| anyhow::anyhow!("SO PIN required"))?
            };
            pkcs11::token::delete_token(&module_path, &token_label, &so_pin_value)?;
        }
        Commands::ListObjects { label, user_pin, pin_stdin, detailed } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::objects::list_objects(&module_path, &token_label, &user_pin_value, detailed)?;
        }
        Commands::GenKeypair { label, user_pin, key_label, key_type, bits, extractable, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::gen_keypair(&module_path, &token_label, &user_pin_value, &key_label, &key_type, bits, extractable)?;
        }
        Commands::Sign { label, user_pin, key_label, input, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::sign(&module_path, &token_label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::Verify { label, user_pin, key_label, input, signature, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::verify(&module_path, &token_label, &user_pin_value, &key_label, &input, &signature)?;
        }
        Commands::ExportPubkey { label, user_pin, key_label, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::export_pubkey(&module_path, &token_label, &user_pin_value, &key_label, &output)?;
        }
        Commands::DeleteKey { label, user_pin, key_label, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::delete_key(&module_path, &token_label, &user_pin_value, &key_label)?;
        }
        Commands::InspectKey { label, user_pin, key_label, json, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::inspect_key(&module_path, &token_label, &user_pin_value, &key_label, json)?;
        }
        Commands::Encrypt { label, user_pin, key_label, input, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::encrypt(&module_path, &token_label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::Decrypt { label, user_pin, key_label, input, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::decrypt(&module_path, &token_label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::GenSymmetricKey { label, user_pin, key_label, bits, extractable, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::gen_symmetric_key(&module_path, &token_label, &user_pin_value, &key_label, bits, extractable)?;
        }
        Commands::EncryptSymmetric { label, user_pin, key_label, input, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::encrypt_symmetric(&module_path, &token_label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::DecryptSymmetric { label, user_pin, key_label, input, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::decrypt_symmetric(&module_path, &token_label, &user_pin_value, &key_label, &input, &output)?;
        }
        Commands::WrapKey { label, user_pin, key_label, wrapping_key_label, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::wrap_key(&module_path, &token_label, &user_pin_value, &key_label, &wrapping_key_label, &output)?;
        }
        Commands::UnwrapKey { label, user_pin, key_label, wrapping_key_label, input, key_type, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::unwrap_key(&module_path, &token_label, &user_pin_value, &key_label, &wrapping_key_label, &input, &key_type)?;
        }
        Commands::GenCsr { label, user_pin, key_label, subject, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::generate_csr(&module_path, &token_label, &user_pin_value, &key_label, &subject, &output)?;
        }
        Commands::Hash { algorithm, input, output } => {
            pkcs11::keys::hash_data(&module_path, &algorithm, &PathBuf::from(&input), &PathBuf::from(&output))?;
        }
        Commands::GenHmacKey { label, user_pin, key_label, bits, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::gen_hmac_key(&module_path, &token_label, &user_pin_value, &key_label, bits)?;
        }
        Commands::HmacSign { label, user_pin, key_label, algorithm, input, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::hmac_sign(&module_path, &token_label, &user_pin_value, &key_label, &algorithm, &PathBuf::from(&input), &PathBuf::from(&output))?;
        }
        Commands::HmacVerify { label, user_pin, key_label, algorithm, input, hmac, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::hmac_verify(&module_path, &token_label, &user_pin_value, &key_label, &algorithm, &PathBuf::from(&input), &PathBuf::from(&hmac))?;
        }
        Commands::GenCmacKey { label, user_pin, key_label, bits, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::gen_cmac_key(&module_path, &token_label, &user_pin_value, &key_label, bits)?;
        }
        Commands::CmacSign { label, user_pin, key_label, input, output, mac_len, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::cmac_sign(&module_path, &token_label, &user_pin_value, &key_label, &PathBuf::from(&input), &PathBuf::from(&output), mac_len)?;
        }
        Commands::CmacVerify { label, user_pin, key_label, input, cmac, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::keys::cmac_verify(&module_path, &token_label, &user_pin_value, &key_label, &PathBuf::from(&input), &PathBuf::from(&cmac))?;
        }
        Commands::GenRandom { bytes, output, hex } => {
            pkcs11::random::generate_random(&module_path, bytes, output.as_ref(), hex)?;
        }
        Commands::Benchmark { label, user_pin, key_label, iterations, format, warmup, output, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::benchmark::run_full_benchmark(
                &module_path, 
                &token_label, 
                &user_pin_value, 
                key_label.as_deref(), 
                iterations,
                &format,
                warmup,
                output.as_deref(),
            )?;
        }
        Commands::AuditKeys { label, user_pin, json, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::audit::audit_keys(&module_path, &token_label, &user_pin_value, json)?;
        }
        Commands::ExplainError { error_code, context } => {
            pkcs11::troubleshoot::explain_error(&error_code, context.as_deref())?;
        }
        Commands::FindKey { label, user_pin, key_label, show_similar, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::troubleshoot::find_key(&module_path, &token_label, &user_pin_value, &key_label, show_similar)?;
        }
        Commands::DiffKeys { label, user_pin, key1_label, key2_label, pin_stdin } => {
            let token_label = config.token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            pkcs11::troubleshoot::diff_keys(&module_path, &token_label, &user_pin_value, &key1_label, &key2_label)?;
        }
    }

    Ok(())
}
