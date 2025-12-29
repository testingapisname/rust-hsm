//! Key management commands

use anyhow::Result;

use super::common::{get_user_pin, CommandContext};

pub fn handle_gen_keypair(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    key_type: String,
    bits: u32,
    extractable: bool,
    json: bool,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::gen_keypair(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &key_type,
        bits,
        extractable,
        json,
    )
}

pub fn handle_delete_key(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    json: bool,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::delete_key(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        json,
    )
}

pub fn handle_inspect_key(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    json: bool,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::inspect_key(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        json,
    )
}

pub fn handle_export_pubkey(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    output: String,
    json: bool,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::export_pubkey(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &output,
        json,
    )
}
