//! Interactive Terminal User Interface modules
//!
//! Provides a menu-driven interface for HSM operations using ratatui.
//! Great for exploration, learning, and guided workflows.

pub mod app;
pub mod commands;
pub mod menu;
pub mod ui;

pub use app::run_interactive;
