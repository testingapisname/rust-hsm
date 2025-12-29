//! Token management commands

use anyhow::Result;

use super::common::{get_so_pin, get_user_pin, read_pin_from_stdin, CommandContext};

pub fn handle_init_token(
    ctx: CommandContext,
    label: Option<String>,
    so_pin: Option<String>,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let so_pin_value = get_so_pin(so_pin, pin_stdin)?;

    rust_hsm_core::token::init_token(&ctx.module_path, &token_label, &so_pin_value)
}

pub fn handle_init_pin(
    ctx: CommandContext,
    label: Option<String>,
    so_pin: Option<String>,
    user_pin: Option<String>,
    so_pin_stdin: bool,
    user_pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let so_pin_value = get_so_pin(so_pin, so_pin_stdin)?;
    let user_pin_value = if user_pin_stdin {
        read_pin_from_stdin()?
    } else {
        user_pin.ok_or_else(|| anyhow::anyhow!("User PIN required"))?
    };

    rust_hsm_core::token::init_pin(
        &ctx.module_path,
        &token_label,
        &so_pin_value,
        &user_pin_value,
    )
}

pub fn handle_delete_token(
    ctx: CommandContext,
    label: Option<String>,
    so_pin: Option<String>,
    pin_stdin: bool,
) -> Result<()> {
    let token_label = ctx.token_label(label)?;
    let so_pin_value = get_so_pin(so_pin, pin_stdin)?;

    rust_hsm_core::token::delete_token(&ctx.module_path, &token_label, &so_pin_value)
}
