//! Symmetric key operation commands

use anyhow::Result;

use super::common::{get_user_pin, CommandContext};

pub fn handle_gen_symmetric_key(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    bits: u32,
    extractable: bool,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::gen_symmetric_key(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        bits,
        extractable,
    )
}

pub fn handle_encrypt_symmetric(
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

    rust_hsm_core::keys::encrypt_symmetric(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &input,
        &output,
    )
}

pub fn handle_decrypt_symmetric(
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

    rust_hsm_core::keys::decrypt_symmetric(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &input,
        &output,
    )
}
