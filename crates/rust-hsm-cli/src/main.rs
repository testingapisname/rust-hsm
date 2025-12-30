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
use tracing_subscriber::EnvFilter;

mod cli;
mod commands;
mod config;

use cli::Cli;
use config::Config;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing only if not running interactive command
    // (interactive TUI doesn't work with tracing output to stderr)
    match &cli.command {
        cli::Commands::Interactive { .. } => {
            // No logging for TUI to prevent display corruption
        }
        _ => {
            // Initialize tracing for all other commands
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                )
                .init();
        }
    }

    // Load configuration
    let config = Config::load_with_custom_path(cli.config);

    // Dispatch to command handlers
    commands::dispatch_command(cli.command, config)?;

    Ok(())
}
