//! MAC (Message Authentication Code) operation commands

use anyhow::Result;
use std::path::PathBuf;

use super::common::{get_user_pin, CommandContext};

pub fn handle_gen_hmac_key(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    bits: u32,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::gen_hmac_key(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        bits,
    )
}

pub fn handle_hmac_sign(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    algorithm: String,
    input: String,
    output: String,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::hmac_sign(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &algorithm,
        &PathBuf::from(&input),
        &PathBuf::from(&output),
    )
}

pub fn handle_hmac_verify(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    algorithm: String,
    input: String,
    hmac: String,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::hmac_verify(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &algorithm,
        &PathBuf::from(&input),
        &PathBuf::from(&hmac),
    )
}

pub fn handle_gen_cmac_key(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    bits: u32,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::gen_cmac_key(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        bits,
    )
}

pub fn handle_cmac_sign(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    input: String,
    output: String,
    mac_len: Option<usize>,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::cmac_sign(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &PathBuf::from(&input),
        &PathBuf::from(&output),
        mac_len,
    )
}

pub fn handle_cmac_verify(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    key_label: String,
    input: String,
    cmac: String,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::keys::cmac_verify(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        &key_label,
        &PathBuf::from(&input),
        &PathBuf::from(&cmac),
    )
}
