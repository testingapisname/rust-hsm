//! Utility and miscellaneous commands

use anyhow::Result;
use std::path::PathBuf;

use super::common::{get_user_pin, CommandContext};

pub fn handle_gen_csr(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    subject: String,
    output: String,
    json: bool,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::generate_csr(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &subject,
        &output,
        json,
    )
}

pub fn handle_hash(
    ctx: CommandContext,
    algorithm: String,
    input: String,
    output: String,
) -> Result<()> {
    rust_hsm_core::keys::hash_data(
        &ctx.module_path,
        &algorithm,
        &PathBuf::from(&input),
        &PathBuf::from(&output),
    )
}

pub fn handle_gen_random(
    ctx: CommandContext,
    bytes: usize,
    output: Option<PathBuf>,
    hex: bool,
    json: bool,
) -> Result<()> {
    rust_hsm_core::random::generate_random(&ctx.module_path, bytes, output.as_ref(), hex, json)
}

pub fn handle_benchmark(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: Option<String>,
    iterations: usize,
    format: String,
    warmup: usize,
    output: Option<String>,
    compare: Option<String>,
    data_sizes: bool,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::benchmark::run_full_benchmark(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        key_label.as_deref(),
        iterations,
        &format,
        warmup,
        output.as_deref(),
        compare.as_deref(),
        data_sizes,
    )
}

pub fn handle_audit_keys(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    json: bool,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::audit::audit_keys(&ctx.module_path, &token_label, &user_pin_value, json)
}

pub fn handle_explain_error(error_code: String, context: Option<String>) -> Result<()> {
    rust_hsm_core::troubleshoot::explain_error(&error_code, context.as_deref())
}

pub fn handle_find_key(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    show_similar: bool,
    json: bool,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::troubleshoot::find_key(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        show_similar,
        json,
    )
}

pub fn handle_diff_keys(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key1_label: String,
    key2_label: String,
    json: bool,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::troubleshoot::diff_keys(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key1_label,
        &key2_label,
        json,
    )
}
