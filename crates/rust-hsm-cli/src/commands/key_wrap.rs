//! Key wrapping operation commands

use anyhow::Result;

use super::common::{get_user_pin, CommandContext};

pub fn handle_wrap_key(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    wrapping_key_label: String,
    output: String,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::wrap_key(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &wrapping_key_label,
        &output,
    )
}

pub fn handle_unwrap_key(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    wrapping_key_label: String,
    input: String,
    key_type: String,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::unwrap_key(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &wrapping_key_label,
        &input,
        &key_type,
    )
}
