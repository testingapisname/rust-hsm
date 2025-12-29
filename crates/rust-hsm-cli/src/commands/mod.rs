//! Command handlers for rust-hsm-cli
//!
//! This module contains organized command handlers that were previously
//! all in main.rs. Each module handles a specific category of operations.

use anyhow::Result;

use crate::cli::Commands;
use crate::config::Config;

pub mod analyze;
pub mod common;
pub mod crypto;
pub mod info;
pub mod key_wrap;
pub mod keys;
pub mod mac;
pub mod symmetric;
pub mod token;
pub mod util;

use common::CommandContext;

/// Main command dispatcher that routes commands to appropriate handlers
pub fn dispatch_command(command: Commands, config: Config) -> Result<()> {
    let ctx = CommandContext::new(config)?;

    match command {
        // Information commands
        Commands::Info { json } => info::handle_info(ctx, json),
        Commands::ListSlots { json } => info::handle_list_slots(ctx, json),
        Commands::ListMechanisms {
            slot,
            detailed,
            json,
        } => info::handle_list_mechanisms(ctx, slot, detailed, json),
        Commands::ListObjects {
            label,
            user_pin,
            pin_stdin,
            detailed,
            json,
        } => info::handle_list_objects(ctx, label, user_pin, pin_stdin, detailed, json),

        // Token management
        Commands::InitToken {
            label,
            so_pin,
            pin_stdin,
        } => token::handle_init_token(ctx, label, so_pin, pin_stdin),
        Commands::InitPin {
            label,
            so_pin,
            user_pin,
            so_pin_stdin,
            user_pin_stdin,
        } => token::handle_init_pin(ctx, label, so_pin, user_pin, so_pin_stdin, user_pin_stdin),
        Commands::DeleteToken {
            label,
            so_pin,
            pin_stdin,
        } => token::handle_delete_token(ctx, label, so_pin, pin_stdin),

        // Key management
        Commands::GenKeypair {
            label,
            user_pin,
            key_label,
            key_type,
            bits,
            extractable,
            json,
            pin_stdin,
        } => keys::handle_gen_keypair(
            ctx,
            label,
            user_pin,
            key_label,
            key_type,
            bits,
            extractable,
            json,
            pin_stdin,
        ),
        Commands::DeleteKey {
            label,
            user_pin,
            key_label,
            json,
            pin_stdin,
        } => keys::handle_delete_key(ctx, label, user_pin, key_label, json, pin_stdin),
        Commands::InspectKey {
            label,
            user_pin,
            key_label,
            json,
            pin_stdin,
        } => keys::handle_inspect_key(ctx, label, user_pin, key_label, json, pin_stdin),
        Commands::ExportPubkey {
            label,
            user_pin,
            key_label,
            output,
            json,
            pin_stdin,
        } => keys::handle_export_pubkey(ctx, label, user_pin, key_label, output, json, pin_stdin),

        // Cryptographic operations
        Commands::Sign {
            label,
            user_pin,
            key_label,
            input,
            output,
            json,
            pin_stdin,
        } => crypto::handle_sign(
            ctx, label, user_pin, key_label, input, output, json, pin_stdin,
        ),
        Commands::Verify {
            label,
            user_pin,
            key_label,
            input,
            signature,
            json,
            pin_stdin,
        } => crypto::handle_verify(
            ctx, label, user_pin, key_label, input, signature, json, pin_stdin,
        ),
        Commands::Encrypt {
            label,
            user_pin,
            key_label,
            input,
            output,
            pin_stdin,
        } => crypto::handle_encrypt(ctx, label, user_pin, key_label, input, output, pin_stdin),
        Commands::Decrypt {
            label,
            user_pin,
            key_label,
            input,
            output,
            pin_stdin,
        } => crypto::handle_decrypt(ctx, label, user_pin, key_label, input, output, pin_stdin),

        // Symmetric operations
        Commands::GenSymmetricKey {
            label,
            user_pin,
            key_label,
            bits,
            extractable,
            pin_stdin,
        } => symmetric::handle_gen_symmetric_key(
            ctx,
            label,
            user_pin,
            key_label,
            bits,
            extractable,
            pin_stdin,
        ),
        Commands::EncryptSymmetric {
            label,
            user_pin,
            key_label,
            input,
            output,
            pin_stdin,
        } => symmetric::handle_encrypt_symmetric(
            ctx, label, user_pin, key_label, input, output, pin_stdin,
        ),
        Commands::DecryptSymmetric {
            label,
            user_pin,
            key_label,
            input,
            output,
            pin_stdin,
        } => symmetric::handle_decrypt_symmetric(
            ctx, label, user_pin, key_label, input, output, pin_stdin,
        ),

        // Key wrapping
        Commands::WrapKey {
            label,
            user_pin,
            key_label,
            wrapping_key_label,
            output,
            pin_stdin,
        } => key_wrap::handle_wrap_key(
            ctx,
            label,
            user_pin,
            key_label,
            wrapping_key_label,
            output,
            pin_stdin,
        ),
        Commands::UnwrapKey {
            label,
            user_pin,
            key_label,
            wrapping_key_label,
            input,
            key_type,
            pin_stdin,
        } => key_wrap::handle_unwrap_key(
            ctx,
            label,
            user_pin,
            key_label,
            wrapping_key_label,
            input,
            key_type,
            pin_stdin,
        ),

        // MAC operations
        Commands::GenHmacKey {
            label,
            user_pin,
            key_label,
            bits,
            pin_stdin,
        } => mac::handle_gen_hmac_key(ctx, label, user_pin, key_label, bits, pin_stdin),
        Commands::HmacSign {
            label,
            user_pin,
            key_label,
            algorithm,
            input,
            output,
            pin_stdin,
        } => mac::handle_hmac_sign(
            ctx, label, user_pin, key_label, algorithm, input, output, pin_stdin,
        ),
        Commands::HmacVerify {
            label,
            user_pin,
            key_label,
            algorithm,
            input,
            hmac,
            pin_stdin,
        } => mac::handle_hmac_verify(
            ctx, label, user_pin, key_label, algorithm, input, hmac, pin_stdin,
        ),
        Commands::GenCmacKey {
            label,
            user_pin,
            key_label,
            bits,
            pin_stdin,
        } => mac::handle_gen_cmac_key(ctx, label, user_pin, key_label, bits, pin_stdin),
        Commands::CmacSign {
            label,
            user_pin,
            key_label,
            input,
            output,
            mac_len,
            pin_stdin,
        } => mac::handle_cmac_sign(
            ctx, label, user_pin, key_label, input, output, mac_len, pin_stdin,
        ),
        Commands::CmacVerify {
            label,
            user_pin,
            key_label,
            input,
            cmac,
            pin_stdin,
        } => mac::handle_cmac_verify(ctx, label, user_pin, key_label, input, cmac, pin_stdin),

        // Utility commands
        Commands::GenCsr {
            label,
            user_pin,
            key_label,
            subject,
            output,
            json,
            pin_stdin,
        } => util::handle_gen_csr(
            ctx, label, user_pin, key_label, subject, output, json, pin_stdin,
        ),
        Commands::Hash {
            algorithm,
            input,
            output,
        } => util::handle_hash(ctx, algorithm, input, output),
        Commands::GenRandom {
            bytes,
            output,
            hex,
            json,
        } => util::handle_gen_random(ctx, bytes, output, hex, json),
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
        } => util::handle_benchmark(
            ctx, label, user_pin, key_label, iterations, format, warmup, output, compare,
            data_sizes, pin_stdin,
        ),
        Commands::AuditKeys {
            label,
            user_pin,
            json,
            pin_stdin,
        } => util::handle_audit_keys(ctx, label, user_pin, json, pin_stdin),
        Commands::ExplainError {
            error_code,
            context,
        } => util::handle_explain_error(error_code, context),
        Commands::FindKey {
            label,
            user_pin,
            key_label,
            show_similar,
            json,
            pin_stdin,
        } => util::handle_find_key(
            ctx,
            label,
            user_pin,
            key_label,
            show_similar,
            json,
            pin_stdin,
        ),
        Commands::DiffKeys {
            label,
            user_pin,
            key1_label,
            key2_label,
            json,
            pin_stdin,
        } => util::handle_diff_keys(
            ctx, label, user_pin, key1_label, key2_label, json, pin_stdin,
        ),

        // Analysis command
        Commands::Analyze { log_file, format } => analyze::handle_analyze(log_file, format),
    }
}
