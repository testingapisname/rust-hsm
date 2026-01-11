//! TUI rendering and UI components

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use super::{app::InteractiveApp, menu::MenuCategory};

/// Main UI rendering function
pub fn draw(f: &mut Frame, app: &mut InteractiveApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Min(0),    // Main content
            Constraint::Length(3), // Status bar
        ])
        .split(f.area());

    // Title
    let title = Paragraph::new("🔐 rust-hsm Interactive Interface")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Main content area
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40), // Menu
            Constraint::Percentage(60), // Content/Details
        ])
        .split(chunks[1]);

    // Left panel - Main menu or submenu
    if let Some(category) = app.selected_category.clone() {
        render_submenu(f, main_chunks[0], app, &category);
    } else {
        render_main_menu(f, main_chunks[0], app);
    }

    // Right panel - Description or help
    render_details(f, main_chunks[1], app);

    // Status bar
    let status = Paragraph::new(app.status.clone())
        .style(Style::default().fg(Color::Yellow))
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status, chunks[2]);
}

/// Render main menu
fn render_main_menu(f: &mut Frame, area: ratatui::layout::Rect, app: &mut InteractiveApp) {
    let categories = MenuCategory::all();
    let items: Vec<ListItem> = categories
        .iter()
        .map(|cat| ListItem::new(cat.name()))
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Main Menu"))
        .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.menu_state);
}

/// Render submenu for selected category
fn render_submenu(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    app: &mut InteractiveApp,
    category: &MenuCategory,
) {
    let commands = category.commands();
    let items: Vec<ListItem> = commands
        .iter()
        .map(|(cmd, desc)| ListItem::new(format!("{} - {}", cmd, desc)))
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(category.name()),
        )
        .highlight_style(Style::default().bg(Color::Green).fg(Color::White))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.submenu_state);
}

/// Render details panel
fn render_details(f: &mut Frame, area: ratatui::layout::Rect, app: &mut InteractiveApp) {
    let (content, title) = if !app.command_output.is_empty() {
        // Priority: Show command output if available with scrolling
        let visible_height = area.height.saturating_sub(3) as usize; // Account for borders and padding
        let end_line = (app.scroll_offset + visible_height).min(app.command_output.len());
        let visible_lines = &app.command_output[app.scroll_offset..end_line];

        let min_lines_for_scroll = 10; // Same threshold as scroll methods
        let scroll_info = if app.command_output.len() > min_lines_for_scroll {
            format!(
                " (Lines {}-{} of {}, PgUp/PgDn to scroll)",
                app.scroll_offset + 1,
                end_line,
                app.command_output.len()
            )
        } else {
            format!(" ({} lines)", app.command_output.len())
        };

        (
            visible_lines.join("\n"),
            format!("Command Output{}", scroll_info),
        )
    } else if let Some(category) = &app.selected_category {
        // Show submenu help
        if let Some(i) = app.submenu_state.selected() {
            let commands = category.commands();
            if let Some((command, description)) = commands.get(i) {
                (
                    format!(
                        "Command: {}\n\nDescription: {}\n\nPress Enter to execute this command.\n\n{}",
                        command,
                        description,
                        get_command_help(command)
                    ),
                    "Command Details".to_string(),
                )
            } else {
                (category.description().to_string(), "Description".to_string())
            }
        } else {
            (category.description().to_string(), "Description".to_string())
        }
    } else {
        // Show main menu help
        if let Some(i) = app.menu_state.selected() {
            let categories = MenuCategory::all();
            if let Some(category) = categories.get(i) {
                let commands_list = category
                    .commands()
                    .iter()
                    .map(|(cmd, desc)| format!("  • {} - {}", cmd, desc))
                    .collect::<Vec<_>>()
                    .join("\n");

                let content = if commands_list.is_empty() {
                    category.description().to_string()
                } else {
                    format!(
                        "{}\n\nAvailable commands:\n{}",
                        category.description(),
                        commands_list
                    )
                };
                (content, "Category Details".to_string())
            } else {
                (
                    "Select a category to view available commands.".to_string(),
                    "Help".to_string(),
                )
            }
        } else {
            (
                "Select a category to view available commands.".to_string(),
                "Help".to_string(),
            )
        }
    };

    let details = Paragraph::new(content)
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title(title));

    f.render_widget(details, area);
}

/// Get detailed help text for a specific command
fn get_command_help(command: &str) -> String {
    match command {
        "info" => "Displays PKCS#11 module information including library version, manufacturer, and capabilities.".to_string(),
        "list-slots" => "Shows all available PKCS#11 slots and their status (token present/absent).".to_string(),
        "list-mechanisms" => "Lists all cryptographic mechanisms supported by the HSM (RSA, AES, SHA, etc.).".to_string(),
        "list-objects" => "Shows all objects (keys, certificates) stored on the selected token.".to_string(),
        "init-token" => "Initializes a new token with a label and SO PIN. This erases all existing data!".to_string(),
        "init-pin" => "Sets the user PIN for the token. Required before most cryptographic operations.".to_string(),
        "delete-token" => "Completely erases a token and all its contents. Cannot be undone!".to_string(),
        "gen-keypair" => "Generates a new RSA or ECDSA keypair and stores it on the token.".to_string(),
        "export-pubkey" => "Exports a public key in PEM format for external use or verification.".to_string(),
        "inspect-key" => "Shows detailed attributes of a key including size, capabilities, and security flags.".to_string(),
        "delete-key" => "Removes a keypair from the token. This cannot be undone!".to_string(),
        "sign" => "Signs data using a private key. Supports RSA-PKCS#1 and ECDSA algorithms.".to_string(),
        "verify" => "Verifies a digital signature using the corresponding public key.".to_string(),
        "encrypt" => "Encrypts data using RSA public key encryption (PKCS#1 padding).".to_string(),
        "decrypt" => "Decrypts data using RSA private key decryption.".to_string(),
        "gen-csr" => "Generates a Certificate Signing Request (CSR) for X.509 certificate issuance.".to_string(),
        "hash" => "Computes cryptographic hashes (SHA-256, SHA-512, etc.) using the HSM.".to_string(),
        "gen-symmetric-key" => "Generates an AES symmetric key (128, 192, or 256 bits).".to_string(),
        "encrypt-symmetric" => "Encrypts data using AES-GCM authenticated encryption.".to_string(),
        "decrypt-symmetric" => "Decrypts data that was encrypted with AES-GCM.".to_string(),
        "wrap-key" => "Exports a key by wrapping it with another key (AES Key Wrap).".to_string(),
        "unwrap-key" => "Imports a wrapped key into the token.".to_string(),
        "hmac-sign" => "Computes HMAC (Hash-based Message Authentication Code) for data integrity.".to_string(),
        "cmac-sign" => "Computes CMAC (Cipher-based Message Authentication Code) using AES.".to_string(),
        "explain-error" => "Provides detailed explanations of PKCS#11 error codes and troubleshooting steps.".to_string(),
        "find-key" => "Searches for keys using fuzzy matching when exact label is unknown.".to_string(),
        "diff-keys" => "Compares two keys side-by-side to identify attribute differences.".to_string(),
        "audit-keys" => "Performs security audit of all keys, checking for weak configurations.".to_string(),
        _ => "Execute this command to see its functionality.".to_string(),
    }
}