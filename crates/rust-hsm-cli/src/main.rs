#![allow(clippy::print_literal)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::empty_line_after_doc_comments)]
#![allow(clippy::unwrap_or_default)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::match_ref_pats)]
#![allow(clippy::to_string_in_format_args)]
#![allow(clippy::type_complexity)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::unnecessary_cast)]
#![allow(dead_code)]
#![allow(unused_imports)]

use clap::Parser;
use std::env;
use std::io::{self, BufRead};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod cli;
mod config;

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
    let module_path =
        env::var("PKCS11_MODULE").unwrap_or_else(|_| config.get_pkcs11_module().to_string());

    info!("Using PKCS#11 module: {}", module_path);

    match cli.command {
        Commands::Info { json } => {
            rust_hsm_core::info::display_info(&module_path, json)?;
        }
        Commands::ListSlots { json } => {
            rust_hsm_core::slots::list_slots(&module_path, json)?;
        }
        Commands::ListMechanisms {
            slot,
            detailed,
            json,
        } => {
            rust_hsm_core::info::list_mechanisms(&module_path, slot, detailed, json)?;
        }
        Commands::InitToken {
            label,
            so_pin,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label must be specified"))?;
            let so_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                so_pin.ok_or_else(|| anyhow::anyhow!("SO PIN required"))?
            };
            rust_hsm_core::token::init_token(&module_path, &token_label, &so_pin_value)?;
        }
        Commands::InitPin {
            label,
            so_pin,
            user_pin,
            so_pin_stdin,
            user_pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
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
            rust_hsm_core::token::init_pin(
                &module_path,
                &token_label,
                &so_pin_value,
                &user_pin_value,
            )?;
        }
        Commands::DeleteToken {
            label,
            so_pin,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let so_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                so_pin.ok_or_else(|| anyhow::anyhow!("SO PIN required"))?
            };
            rust_hsm_core::token::delete_token(&module_path, &token_label, &so_pin_value)?;
        }
        Commands::ListObjects {
            label,
            user_pin,
            pin_stdin,
            detailed,
            json,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::objects::list_objects(
                &module_path,
                &token_label,
                &user_pin_value,
                detailed,
                json,
            )?;
        }
        Commands::GenKeypair {
            label,
            user_pin,
            key_label,
            key_type,
            bits,
            extractable,
            json,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::gen_keypair(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &key_type,
                bits,
                extractable,
                json,
            )?;
        }
        Commands::Sign {
            label,
            user_pin,
            key_label,
            input,
            output,
            json,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::sign(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &input,
                &output,
                json,
                config.observe_enabled,
                &config.observe_log_file,
            )?;
        }
        Commands::Verify {
            label,
            user_pin,
            key_label,
            input,
            signature,
            json,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::verify(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &input,
                &signature,
                json,
            )?;
        }
        Commands::ExportPubkey {
            label,
            user_pin,
            key_label,
            output,
            json,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::export_pubkey(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &output,
                json,
            )?;
        }
        Commands::DeleteKey {
            label,
            user_pin,
            key_label,
            json,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::delete_key(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                json,
            )?;
        }
        Commands::InspectKey {
            label,
            user_pin,
            key_label,
            json,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::inspect_key(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                json,
            )?;
        }
        Commands::Encrypt {
            label,
            user_pin,
            key_label,
            input,
            output,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::encrypt(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &input,
                &output,
            )?;
        }
        Commands::Decrypt {
            label,
            user_pin,
            key_label,
            input,
            output,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::decrypt(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &input,
                &output,
            )?;
        }
        Commands::GenSymmetricKey {
            label,
            user_pin,
            key_label,
            bits,
            extractable,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::gen_symmetric_key(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                bits,
                extractable,
            )?;
        }
        Commands::EncryptSymmetric {
            label,
            user_pin,
            key_label,
            input,
            output,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::encrypt_symmetric(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &input,
                &output,
            )?;
        }
        Commands::DecryptSymmetric {
            label,
            user_pin,
            key_label,
            input,
            output,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::decrypt_symmetric(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &input,
                &output,
            )?;
        }
        Commands::WrapKey {
            label,
            user_pin,
            key_label,
            wrapping_key_label,
            output,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::wrap_key(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &wrapping_key_label,
                &output,
            )?;
        }
        Commands::UnwrapKey {
            label,
            user_pin,
            key_label,
            wrapping_key_label,
            input,
            key_type,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::unwrap_key(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &wrapping_key_label,
                &input,
                &key_type,
            )?;
        }
        Commands::GenCsr {
            label,
            user_pin,
            key_label,
            subject,
            output,
            json,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::generate_csr(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &subject,
                &output,
                json,
            )?;
        }
        Commands::Hash {
            algorithm,
            input,
            output,
        } => {
            rust_hsm_core::keys::hash_data(
                &module_path,
                &algorithm,
                &PathBuf::from(&input),
                &PathBuf::from(&output),
            )?;
        }
        Commands::GenHmacKey {
            label,
            user_pin,
            key_label,
            bits,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::gen_hmac_key(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                bits,
            )?;
        }
        Commands::HmacSign {
            label,
            user_pin,
            key_label,
            algorithm,
            input,
            output,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::hmac_sign(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &algorithm,
                &PathBuf::from(&input),
                &PathBuf::from(&output),
            )?;
        }
        Commands::HmacVerify {
            label,
            user_pin,
            key_label,
            algorithm,
            input,
            hmac,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::hmac_verify(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &algorithm,
                &PathBuf::from(&input),
                &PathBuf::from(&hmac),
            )?;
        }
        Commands::GenCmacKey {
            label,
            user_pin,
            key_label,
            bits,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::gen_cmac_key(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                bits,
            )?;
        }
        Commands::CmacSign {
            label,
            user_pin,
            key_label,
            input,
            output,
            mac_len,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::cmac_sign(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &PathBuf::from(&input),
                &PathBuf::from(&output),
                mac_len,
            )?;
        }
        Commands::CmacVerify {
            label,
            user_pin,
            key_label,
            input,
            cmac,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::keys::cmac_verify(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                &PathBuf::from(&input),
                &PathBuf::from(&cmac),
            )?;
        }
        Commands::GenRandom {
            bytes,
            output,
            hex,
            json,
        } => {
            rust_hsm_core::random::generate_random(
                &module_path,
                bytes,
                output.as_ref(),
                hex,
                json,
            )?;
        }
        Commands::Benchmark {
            label,
            user_pin,
            key_label,
            iterations,
            format,
            warmup,
            output,
            compare,
            data_sizes,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::benchmark::run_full_benchmark(
                &module_path,
                &token_label,
                &user_pin_value,
                key_label.as_deref(),
                iterations,
                &format,
                warmup,
                output.as_deref(),
                compare.as_deref(),
                data_sizes,
            )?;
        }
        Commands::AuditKeys {
            label,
            user_pin,
            json,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::audit::audit_keys(&module_path, &token_label, &user_pin_value, json)?;
        }
        Commands::ExplainError {
            error_code,
            context,
        } => {
            rust_hsm_core::troubleshoot::explain_error(&error_code, context.as_deref())?;
        }
        Commands::FindKey {
            label,
            user_pin,
            key_label,
            show_similar,
            json,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::troubleshoot::find_key(
                &module_path,
                &token_label,
                &user_pin_value,
                &key_label,
                show_similar,
                json,
            )?;
        }
        Commands::DiffKeys {
            label,
            user_pin,
            key1_label,
            key2_label,
            json,
            pin_stdin,
        } => {
            let token_label = config
                .token_label(label.as_deref())
                .ok_or_else(|| anyhow::anyhow!("Token label required"))?;
            let user_pin_value = if pin_stdin {
                read_pin_from_stdin()?
            } else {
                user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
            };
            rust_hsm_core::troubleshoot::diff_keys(
                &module_path,
                &token_label,
                &user_pin_value,
                &key1_label,
                &key2_label,
                json,
            )?;
        }
        Commands::Analyze { log_file, format } => {
            use rust_hsm_analyze::{parse_observe_json, Analyzer};

            // Parse the log file
            let events = parse_observe_json(&log_file)?;

            if events.is_empty() {
                println!("No events found in log file");
                return Ok(());
            }

            // Analyze the events
            let analyzer = Analyzer::new(events);
            let analysis = analyzer.analyze();

            // Output results
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&analysis)?);
            } else {
                println!("\n=== PKCS#11 Session Analysis ===\n");
                println!("Total Operations: {}", analysis.total_ops);
                println!("Success Rate: {:.2}%", analysis.success_rate);
                println!("Error Count: {}", analysis.error_count);

                println!("\n--- Overall Timing ---");
                println!("Total Duration: {:.2}ms", analysis.duration_stats.total_ms);
                println!("Average: {:.2}ms", analysis.duration_stats.avg_ms);
                println!("Min: {:.2}ms", analysis.duration_stats.min_ms);
                println!("Max: {:.2}ms", analysis.duration_stats.max_ms);
                println!("P50: {:.2}ms", analysis.duration_stats.p50_ms);
                println!("P95: {:.2}ms", analysis.duration_stats.p95_ms);
                println!("P99: {:.2}ms", analysis.duration_stats.p99_ms);

                if !analysis.by_function.is_empty() {
                    println!("\n--- Per-Function Statistics ---");
                    for (func, stats) in &analysis.by_function {
                        println!("\n{}", func);
                        println!("  Calls: {}", stats.count);
                        let success_rate = if stats.count > 0 {
                            (stats.success_count as f64 / stats.count as f64) * 100.0
                        } else {
                            0.0
                        };
                        let error_rate = if stats.count > 0 {
                            (stats.error_count as f64 / stats.count as f64) * 100.0
                        } else {
                            0.0
                        };
                        println!("  Success: {} ({:.1}%)", stats.success_count, success_rate);
                        println!("  Errors: {} ({:.1}%)", stats.error_count, error_rate);
                        println!("  Avg Duration: {:.2}ms", stats.avg_duration_ms);
                    }
                }

                if !analysis.errors.is_empty() {
                    println!("\n--- Errors ---");
                    for error in &analysis.errors {
                        println!("\n{} → {} ({})", error.func, error.rv_name, error.rv);
                        println!("  Count: {}", error.count);
                        println!("  First seen: {}", error.timestamp);
                    }
                }
            }
        }
    }

    Ok(())
}
