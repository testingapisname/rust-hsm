//! Information and listing commands

use anyhow::Result;

use super::common::CommandContext;

pub fn handle_info(ctx: CommandContext, json: bool) -> Result<()> {
    rust_hsm_core::info::display_info(&ctx.module_path, json)
}

pub fn handle_list_slots(ctx: CommandContext, json: bool) -> Result<()> {
    rust_hsm_core::slots::list_slots(&ctx.module_path, json)
}

pub fn handle_list_mechanisms(
    ctx: CommandContext,
    slot: Option<u64>,
    detailed: bool,
    json: bool,
) -> Result<()> {
    rust_hsm_core::info::list_mechanisms(&ctx.module_path, slot, detailed, json)
}

pub fn handle_list_objects(
    ctx: CommandContext,
    label: Option<String>,
    user_pin: Option<String>,
    pin_stdin: bool,
    detailed: bool,
    json: bool,
) -> Result<()> {
    use super::common::get_user_pin;

    let token_label = ctx.token_label(label)?;
    let user_pin_value = get_user_pin(user_pin, pin_stdin)?;

    rust_hsm_core::objects::list_objects(
        &ctx.module_path,
        &token_label,
        &user_pin_value,
        detailed,
        json,
    )
}
