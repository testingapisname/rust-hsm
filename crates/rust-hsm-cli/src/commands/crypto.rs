//! Cryptographic operation commands

use anyhow::Result;

use super::common::{get_user_pin, CommandContext};

pub fn handle_sign(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    input: String,
    output: String,
    json: bool,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::sign(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &input,
        &output,
        json,
        ctx.config.observe_enabled,
        &ctx.config.observe_log_file,
    )
}

pub fn handle_verify(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    input: String,
    signature: String,
    json: bool,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::verify(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &input,
        &signature,
        json,
    )
}

pub fn handle_encrypt(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    input: String,
    output: String,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::encrypt(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &input,
        &output,
    )
}

pub fn handle_decrypt(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    input: String,
    output: String,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::decrypt(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &input,
        &output,
    )
}
