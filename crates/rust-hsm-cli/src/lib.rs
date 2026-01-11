//! rust-hsm-cli library
//! 
//! This library provides the core functionality of the rust-hsm CLI tool,
//! exposed for testing and potential library usage.

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

pub mod cli;
pub mod commands;
pub mod config;