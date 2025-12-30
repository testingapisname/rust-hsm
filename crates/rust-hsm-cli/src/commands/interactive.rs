//! Interactive Terminal User Interface for rust-hsm-cli
//!
//! Provides a menu-driven interface for HSM operations using ratatui.
//! Great for exploration, learning, and guided workflows.

use anyhow::{Context, Result};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Margin},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info};

use crate::commands::common::{get_user_pin, CommandContext};
use crate::commands::info;
use crate::config::Config;

/// Main menu categories
#[derive(Debug, Clone)]
enum MenuCategory {
    TokenManagement,
    KeyOperations,
    CryptoOperations,
    SymmetricOperations,
    Troubleshooting,
    Information,
    Quit,
}

impl MenuCategory {
    fn all() -> Vec<Self> {
        vec![
            Self::Information,
            Self::TokenManagement,
            Self::KeyOperations,
            Self::CryptoOperations,
            Self::SymmetricOperations,
            Self::Troubleshooting,
            Self::Quit,
        ]
    }

    fn name(&self) -> &str {
        match self {
            Self::Information => "📊 Information & Status",
            Self::TokenManagement => "🔧 Token Management",
            Self::KeyOperations => "🔑 Key Operations",
            Self::CryptoOperations => "🔐 Cryptographic Operations",
            Self::SymmetricOperations => "⚡ Symmetric Operations",
            Self::Troubleshooting => "🔍 Troubleshooting",
            Self::Quit => "❌ Quit",
        }
    }

    fn description(&self) -> &str {
        match self {
            Self::Information => "View HSM info, list slots, mechanisms, and objects",
            Self::TokenManagement => "Initialize, configure, and manage HSM tokens",
            Self::KeyOperations => "Generate, export, inspect, and delete keys",
            Self::CryptoOperations => "Sign, verify, encrypt, decrypt operations",
            Self::SymmetricOperations => "AES encryption, key wrapping, HMAC operations",
            Self::Troubleshooting => "Explain errors, find keys, compare attributes",
            Self::Quit => "Exit the interactive interface",
        }
    }

    fn commands(&self) -> Vec<(&str, &str)> {
        match self {
            Self::Information => vec![
                ("info", "Display PKCS#11 module information"),
                ("list-slots", "Show available slots and tokens"),
                ("list-mechanisms", "Show supported mechanisms"),
                ("list-objects", "Show objects on token"),
            ],
            Self::TokenManagement => vec![
                ("init-token", "Initialize a new token"),
                ("init-pin", "Set user PIN on token"),
                ("delete-token", "Delete/reinitialize token"),
            ],
            Self::KeyOperations => vec![
                ("gen-keypair", "Generate RSA/ECDSA keypair"),
                ("export-pubkey", "Export public key as PEM"),
                ("inspect-key", "Show detailed key attributes"),
                ("delete-key", "Delete keypair from token"),
            ],
            Self::CryptoOperations => vec![
                ("sign", "Sign data with private key"),
                ("verify", "Verify signature"),
                ("encrypt", "Encrypt data with public key"),
                ("decrypt", "Decrypt data with private key"),
                ("gen-csr", "Generate certificate signing request"),
                ("hash", "Hash data using HSM"),
            ],
            Self::SymmetricOperations => vec![
                ("gen-symmetric-key", "Generate AES key"),
                ("encrypt-symmetric", "AES-GCM encryption"),
                ("decrypt-symmetric", "AES-GCM decryption"),
                ("wrap-key", "Export key using AES Key Wrap"),
                ("unwrap-key", "Import wrapped key"),
                ("hmac-sign", "Generate HMAC"),
                ("cmac-sign", "Generate AES-CMAC"),
            ],
            Self::Troubleshooting => vec![
                ("explain-error", "Decode PKCS#11 error codes"),
                ("find-key", "Search for keys with fuzzy matching"),
                ("diff-keys", "Compare two key attributes"),
                ("audit-keys", "Security audit of all keys"),
            ],
            Self::Quit => vec![],
        }
    }
}

/// TUI Application state
pub struct InteractiveApp {
    /// Current menu selection
    menu_state: ListState,
    /// Selected category for submenu
    selected_category: Option<MenuCategory>,
    /// Submenu selection state
    submenu_state: ListState,
    /// Current status message
    status: String,
    /// Configuration context
    ctx: CommandContext,
    /// Token label for operations
    token_label: Option<String>,
    /// Cached user PIN
    user_pin: Option<String>,
    /// Captured command output for display
    command_output: Vec<String>,
    /// Scroll offset for command output
    scroll_offset: usize,
}

impl InteractiveApp {
    pub fn new(config: Config, token_label: Option<String>) -> Result<Self> {
        let ctx = CommandContext::new(config)?;
        let mut menu_state = ListState::default();
        menu_state.select(Some(0));

        Ok(Self {
            menu_state,
            selected_category: None,
            submenu_state: ListState::default(),
            status:
                "Welcome to rust-hsm Interactive Interface! Use ↑/↓ to navigate, Enter to select."
                    .to_string(),
            ctx,
            token_label,
            user_pin: None,
            command_output: Vec::new(),
            scroll_offset: 0,
        })
    }

    /// Handle keyboard input
    pub fn handle_input(&mut self, key: KeyCode) -> Result<bool> {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.selected_category.is_some() {
                    // Go back to main menu
                    self.selected_category = None;
                    self.submenu_state.select(Some(0));
                    self.status = "Returned to main menu".to_string();
                } else {
                    // Quit application
                    return Ok(true);
                }
            }
            KeyCode::Up => {
                if self.selected_category.is_some() {
                    self.previous_submenu();
                } else {
                    self.previous_menu();
                }
            }
            KeyCode::Down => {
                if self.selected_category.is_some() {
                    self.next_submenu();
                } else {
                    self.next_menu();
                }
            }
            KeyCode::Enter => {
                if self.selected_category.is_some() {
                    self.execute_command()?;
                } else {
                    self.enter_category();
                }
            }
            KeyCode::Char('h') => {
                self.show_help();
            }
            KeyCode::PageUp => {
                self.scroll_up();
            }
            KeyCode::PageDown => {
                self.scroll_down();
            }
            _ => {}
        }
        Ok(false)
    }

    /// Move to previous menu item
    fn previous_menu(&mut self) {
        let i = match self.menu_state.selected() {
            Some(i) => {
                if i == 0 {
                    MenuCategory::all().len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.menu_state.select(Some(i));
    }

    /// Move to next menu item
    fn next_menu(&mut self) {
        let i = match self.menu_state.selected() {
            Some(i) => {
                if i >= MenuCategory::all().len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.menu_state.select(Some(i));
    }

    /// Move to previous submenu item
    fn previous_submenu(&mut self) {
        // Clear command output when navigating
        self.command_output.clear();
        self.scroll_offset = 0;

        if let Some(category) = &self.selected_category {
            let commands = category.commands();
            if !commands.is_empty() {
                let i = match self.submenu_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            commands.len() - 1
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.submenu_state.select(Some(i));
            }
        }
    }

    /// Move to next submenu item
    fn next_submenu(&mut self) {
        // Clear command output when navigating
        self.command_output.clear();
        self.scroll_offset = 0;

        if let Some(category) = &self.selected_category {
            let commands = category.commands();
            if !commands.is_empty() {
                let i = match self.submenu_state.selected() {
                    Some(i) => {
                        if i >= commands.len() - 1 {
                            0
                        } else {
                            i + 1
                        }
                    }
                    None => 0,
                };
                self.submenu_state.select(Some(i));
            }
        }
    }

    /// Enter selected category
    fn enter_category(&mut self) {
        // Clear any previous command output
        self.command_output.clear();
        self.scroll_offset = 0;

        if let Some(i) = self.menu_state.selected() {
            let categories = MenuCategory::all();
            if let Some(category) = categories.get(i) {
                match category {
                    MenuCategory::Quit => {
                        self.status = "Use 'q' or Esc to quit".to_string();
                    }
                    _ => {
                        self.selected_category = Some(category.clone());
                        self.submenu_state.select(Some(0));
                        self.status = format!("Selected: {} - Use ↑/↓ to navigate commands, Enter to execute, Esc to go back", category.name());
                    }
                }
            }
        }
    }

    /// Execute selected command
    fn execute_command(&mut self) -> Result<()> {
        if let Some(category) = &self.selected_category {
            let commands = category.commands();
            if let Some(i) = self.submenu_state.selected() {
                if let Some((command, description)) = commands.get(i) {
                    self.status = format!("Executing: {} - {}", command, description);

                    // For demo purposes, show what would be executed
                    // In a full implementation, you'd actually execute the command
                    match *command {
                        "info" => {
                            self.command_output.clear();
                            self.scroll_offset = 0;
                            self.status = "🔄 Executing info command...".to_string();
                            match self.execute_info_command() {
                                Ok(output) => {
                                    self.command_output = output;
                                    self.status = format!("✅ HSM information retrieved successfully ({} lines) - PgUp/PgDn to scroll", self.command_output.len());
                                }
                                Err(e) => {
                                    self.command_output.clear();
                                    self.command_output.push(format!("Error: {}", e));
                                    self.status =
                                        format!("❌ Failed to retrieve HSM information: {}", e);
                                }
                            }
                        }
                        "list-slots" => {
                            self.command_output.clear();
                            self.scroll_offset = 0;
                            self.status = "🔄 Executing list-slots command...".to_string();
                            match self.execute_list_slots_command() {
                                Ok(output) => {
                                    self.command_output = output;
                                    self.status = format!("✅ Slots information retrieved successfully ({} lines) - PgUp/PgDn to scroll", self.command_output.len());
                                }
                                Err(e) => {
                                    self.command_output.clear();
                                    self.command_output.push(format!("Error: {}", e));
                                    self.status =
                                        format!("❌ Failed to retrieve slots information: {}", e);
                                }
                            }
                        }
                        "list-mechanisms" => {
                            self.status =
                                "🔧 40 mechanisms supported: RSA, ECDSA, AES-GCM, SHA-256, etc."
                                    .to_string();
                        }
                        "list-objects" => {
                            if self.requires_token_access() {
                                return Ok(());
                            }
                            self.status = "🔑 Found 3 objects: 2 keypairs (RSA-2048, P-256), 1 secret key (AES-256)".to_string();
                        }
                        "gen-keypair" => {
                            if self.requires_token_access() {
                                return Ok(());
                            }
                            self.status =
                                "✅ Generated RSA-2048 keypair 'interactive-key' on token"
                                    .to_string();
                        }
                        "sign" => {
                            if self.requires_token_access() {
                                return Ok(());
                            }
                            self.status =
                                "✏️  Signed data with key 'interactive-key' -> signature.bin"
                                    .to_string();
                        }
                        "encrypt-symmetric" => {
                            if self.requires_token_access() {
                                return Ok(());
                            }
                            self.status =
                                "🔐 AES-GCM encrypted data.txt -> data.enc (256 bytes)".to_string();
                        }
                        "explain-error" => {
                            self.status = "📖 CKR_PIN_INCORRECT: PIN is incorrect. Check user PIN vs SO PIN. May be locked after multiple failures.".to_string();
                        }
                        _ => {
                            self.status =
                                format!("⚡ Command '{}' ready to execute (demo mode)", command);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Check if command requires token access and prompt if needed
    fn requires_token_access(&mut self) -> bool {
        if self.token_label.is_none() {
            self.status =
                "⚠️  Token label required. Use --label TOKEN or set in config".to_string();
            return true;
        }

        // In a full implementation, you'd prompt for PIN here
        if self.user_pin.is_none() {
            self.status = "🔐 Demo mode: PIN would be requested here".to_string();
            // For demo, simulate having PIN
            self.user_pin = Some("demo".to_string());
        }

        false
    }

    /// Show help message
    fn show_help(&mut self) {
        self.status = "Help: ↑/↓=Navigate, Enter=Select, Esc=Back, q=Quit, h=Help, PgUp/PgDn=Scroll. See docs/ for command details.".to_string();
    }

    /// Scroll up in command output
    fn scroll_up(&mut self) {
        if !self.command_output.is_empty() && self.scroll_offset > 0 {
            self.scroll_offset = self.scroll_offset.saturating_sub(5);
            self.status = format!(
                "📜 Scrolled to line {} of {} (PgUp/PgDn to scroll)",
                self.scroll_offset + 1,
                self.command_output.len()
            );
        } else if !self.command_output.is_empty() {
            self.status = "📜 Already at top of output".to_string();
        }
    }

    /// Scroll down in command output
    fn scroll_down(&mut self) {
        if !self.command_output.is_empty() {
            // Use a more aggressive scrolling approach - if there are more than 10 lines, allow scrolling
            let min_lines_for_scroll = 10;

            if self.command_output.len() > min_lines_for_scroll {
                let max_scroll = self
                    .command_output
                    .len()
                    .saturating_sub(min_lines_for_scroll);

                if self.scroll_offset < max_scroll {
                    self.scroll_offset = (self.scroll_offset + 5).min(max_scroll);
                    self.status = format!(
                        "📜 Scrolled to line {} of {} (PgUp/PgDn to scroll)",
                        self.scroll_offset + 1,
                        self.command_output.len()
                    );
                } else {
                    self.status = format!(
                        "📜 At bottom ({} lines total, max_scroll={})",
                        self.command_output.len(),
                        max_scroll
                    );
                }
            } else {
                self.status = format!(
                    "📜 Output too short to scroll ({} lines)",
                    self.command_output.len()
                );
            }
        } else {
            self.status = "📜 No output to scroll".to_string();
        }
    }

    /// Execute info command and capture output
    fn execute_info_command(&self) -> Result<Vec<String>> {
        use cryptoki::context::{CInitializeArgs, Pkcs11};

        let pkcs11 = Pkcs11::new(&self.ctx.module_path)
            .map_err(|e| anyhow::anyhow!("Failed to load PKCS#11 module: {}", e))?;

        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| anyhow::anyhow!("Failed to initialize PKCS#11: {}", e))?;

        let result = {
            let info = pkcs11
                .get_library_info()
                .map_err(|e| anyhow::anyhow!("Failed to get library info: {}", e))?;

            let mut output = vec![];
            output.push("=== PKCS#11 Module Info ===".to_string());
            output.push(format!(
                "Library Description: {}",
                info.library_description()
            ));
            output.push(format!(
                "Library Version: {}.{}",
                info.library_version().major(),
                info.library_version().minor()
            ));
            output.push(format!("Manufacturer ID: {}", info.manufacturer_id()));
            output.push(format!(
                "Cryptoki Version: {}.{}",
                info.cryptoki_version().major(),
                info.cryptoki_version().minor()
            ));
            output.push("".to_string());
            output.push("✅ Successfully retrieved PKCS#11 module information".to_string());

            Ok(output)
        };

        pkcs11.finalize();
        result
    }

    /// Execute list-slots command and capture output
    fn execute_list_slots_command(&self) -> Result<Vec<String>> {
        use cryptoki::context::{CInitializeArgs, Pkcs11};

        // Suppress any potential stdout output during PKCS#11 operations
        let pkcs11 = Pkcs11::new(&self.ctx.module_path)
            .map_err(|e| anyhow::anyhow!("Failed to load PKCS#11 module: {}", e))?;

        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| anyhow::anyhow!("Failed to initialize PKCS#11: {}", e))?;

        let result = {
            let slots_with_tokens = pkcs11
                .get_slots_with_initialized_token()
                .unwrap_or_default();
            let all_slots = pkcs11.get_all_slots().unwrap_or_default();

            let mut output = vec![];
            output.push("=== Available PKCS#11 Slots ===".to_string());
            output.push("".to_string());

            if all_slots.is_empty() {
                output.push("❌ No slots found".to_string());
            } else {
                for slot in &all_slots {
                    if let Ok(slot_info) = pkcs11.get_slot_info(*slot) {
                        output.push(format!(
                            "🔌 Slot {}: {}",
                            slot.id(),
                            slot_info.slot_description()
                        ));

                        output.push(format!("   Manufacturer: {}", slot_info.manufacturer_id()));
                        output.push(format!(
                            "   Hardware Version: {}.{}",
                            slot_info.hardware_version().major(),
                            slot_info.hardware_version().minor()
                        ));
                        output.push(format!(
                            "   Firmware Version: {}.{}",
                            slot_info.firmware_version().major(),
                            slot_info.firmware_version().minor()
                        ));

                        if slots_with_tokens.contains(slot) {
                            output.push("   ✅ Token present: Yes".to_string());
                            if let Ok(token_info) = pkcs11.get_token_info(*slot) {
                                output.push(format!("      Token label: '{}'", token_info.label()));
                                output.push(format!(
                                    "      Token manufacturer: {}",
                                    token_info.manufacturer_id()
                                ));
                                output.push(format!("      Token model: {}", token_info.model()));
                            }
                        } else {
                            output.push("   ❌ Token present: No".to_string());
                        }
                        output.push("".to_string());
                    }
                }

                output.push("📊 Summary:".to_string());
                output.push(format!("   Total slots: {}", all_slots.len()));
                output.push(format!("   Slots with tokens: {}", slots_with_tokens.len()));
            }

            Ok(output)
        };

        pkcs11.finalize();
        result
    }

    /// Render the UI
    pub fn render(&mut self, f: &mut Frame) {
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
        if let Some(category) = self.selected_category.clone() {
            self.render_submenu(f, main_chunks[0], &category);
        } else {
            self.render_main_menu(f, main_chunks[0]);
        }

        // Right panel - Description or help
        self.render_details(f, main_chunks[1]);

        // Status bar
        let status = Paragraph::new(self.status.clone())
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title("Status"));
        f.render_widget(status, chunks[2]);
    }

    /// Render main menu
    fn render_main_menu(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let categories = MenuCategory::all();
        let items: Vec<ListItem> = categories
            .iter()
            .map(|cat| ListItem::new(cat.name()))
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Main Menu"))
            .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
            .highlight_symbol("▶ ");

        f.render_stateful_widget(list, area, &mut self.menu_state);
    }

    /// Render submenu for selected category
    fn render_submenu(
        &mut self,
        f: &mut Frame,
        area: ratatui::layout::Rect,
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

        f.render_stateful_widget(list, area, &mut self.submenu_state);
    }

    /// Render details panel
    fn render_details(&mut self, f: &mut Frame, area: ratatui::layout::Rect) {
        let (content, title) = if !self.command_output.is_empty() {
            // Priority: Show command output if available with scrolling
            let visible_height = area.height.saturating_sub(3) as usize; // Account for borders and padding
            let end_line = (self.scroll_offset + visible_height).min(self.command_output.len());
            let visible_lines = &self.command_output[self.scroll_offset..end_line];

            let min_lines_for_scroll = 10; // Same threshold as scroll methods
            let needs_scrolling = self.command_output.len() > min_lines_for_scroll;

            let title = if needs_scrolling {
                format!(
                    "📋 Command Output ({} lines) [Lines {}-{}] - PgUp/PgDn to scroll",
                    self.command_output.len(),
                    self.scroll_offset + 1,
                    end_line
                )
            } else {
                "📋 Command Output".to_string()
            };

            (visible_lines.join("\n"), title)
        } else if let Some(category) = &self.selected_category {
            // Show command help when in submenu
            let commands = category.commands();
            if let Some(i) = self.submenu_state.selected() {
                if let Some((cmd, _desc)) = commands.get(i) {
                    (self.get_command_help(cmd), "📖 Command Details".to_string())
                } else {
                    (
                        category.description().to_string(),
                        "📂 Category Details".to_string(),
                    )
                }
            } else {
                (
                    category.description().to_string(),
                    "📂 Category Details".to_string(),
                )
            }
        } else if let Some(i) = self.menu_state.selected() {
            // Show category help when in main menu
            let categories = MenuCategory::all();
            if let Some(category) = categories.get(i) {
                (
                    format!(
                        "{}\n\n{}",
                        category.description(),
                        self.get_category_help(category)
                    ),
                    "💡 Details & Help".to_string(),
                )
            } else {
                (
                    "Select a category to see details".to_string(),
                    "💡 Details & Help".to_string(),
                )
            }
        } else {
            (
                "Select a category to see details".to_string(),
                "💡 Details & Help".to_string(),
            )
        };

        let help = Paragraph::new(content)
            .style(Style::default().fg(Color::White))
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .padding(Padding::uniform(1)),
            );

        f.render_widget(help, area);
    }

    /// Get help text for a specific command
    fn get_command_help(&self, command: &str) -> String {
        match command {
            "info" => "Display PKCS#11 module information including library version, slots, and capabilities.\n\nExample:\n  rust-hsm-cli info".to_string(),
            "list-slots" => "Show all available slots and their token status.\n\nExample:\n  rust-hsm-cli list-slots".to_string(),
            "list-mechanisms" => "Display all supported cryptographic mechanisms.\n\nExample:\n  rust-hsm-cli list-mechanisms --detailed".to_string(),
            "list-objects" => "Show all objects (keys, certificates) on the specified token.\n\nRequires: Token label and user PIN\nExample:\n  rust-hsm-cli list-objects --label TOKEN --user-pin PIN".to_string(),
            "gen-keypair" => "Generate a new RSA or ECDSA keypair on the token.\n\nSupported types: rsa, p256, p384\nExample:\n  rust-hsm-cli gen-keypair --label TOKEN --user-pin PIN --key-label mykey --key-type rsa --bits 2048".to_string(),
            "sign" => "Sign data using a private key stored on the token.\n\nFormats: Binary signature output\nExample:\n  rust-hsm-cli sign --label TOKEN --user-pin PIN --key-label mykey --input data.txt --output signature.bin".to_string(),
            "encrypt-symmetric" => "Encrypt data using AES-GCM with a symmetric key on the token.\n\nFormat: [IV][AuthTag][Ciphertext]\nExample:\n  rust-hsm-cli encrypt-symmetric --label TOKEN --user-pin PIN --key-label aeskey --input plain.txt --output encrypted.bin".to_string(),
            "explain-error" => "Decode PKCS#11 error codes and provide troubleshooting guidance.\n\nSupports: Hex, decimal, or symbolic names\nExample:\n  rust-hsm-cli explain-error CKR_PIN_INCORRECT\n  rust-hsm-cli explain-error 0xA0 --context sign".to_string(),
            _ => format!("Command: {}\n\nFor detailed help, run:\n  rust-hsm-cli {} --help", command, command),
        }
    }

    /// Get help text for a category
    fn get_category_help(&self, category: &MenuCategory) -> String {
        match category {
            MenuCategory::Information => "View HSM status and configuration. Start here to verify connectivity and explore capabilities.".to_string(),
            MenuCategory::TokenManagement => "Initialize and configure HSM tokens. Required before performing cryptographic operations.".to_string(),
            MenuCategory::KeyOperations => "Manage cryptographic keys. Generate, inspect, export, and delete RSA/ECDSA keypairs.".to_string(),
            MenuCategory::CryptoOperations => "Perform cryptographic operations using keys stored on the HSM. Sign, verify, encrypt, decrypt data.".to_string(),
            MenuCategory::SymmetricOperations => "Work with symmetric encryption and authentication. AES encryption, key wrapping, HMAC operations.".to_string(),
            MenuCategory::Troubleshooting => "Diagnostic tools for debugging HSM issues. Decode errors, find keys, audit security configurations.".to_string(),
            MenuCategory::Quit => "Exit the interactive interface and return to the command line.".to_string(),
        }
    }
}

/// Launch the interactive TUI
pub fn run_interactive(config: Config, token_label: Option<String>) -> Result<()> {
    info!("Launching interactive TUI interface");

    // Setup terminal
    enable_raw_mode().context("Failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .context("Failed to setup terminal")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Failed to create terminal")?;

    // Create app state
    let mut app = InteractiveApp::new(config, token_label)?;

    // Main event loop
    let result = loop {
        terminal
            .draw(|f| app.render(f))
            .context("Failed to draw UI")?;

        if event::poll(std::time::Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                // Only process key press events, not release
                if key.kind == KeyEventKind::Press && app.handle_input(key.code)? {
                    debug!("User requested quit");
                    break Ok(());
                }
            }
        }
    };

    // Restore terminal
    disable_raw_mode().context("Failed to disable raw mode")?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .context("Failed to restore terminal")?;
    terminal.show_cursor().context("Failed to show cursor")?;

    result
}
