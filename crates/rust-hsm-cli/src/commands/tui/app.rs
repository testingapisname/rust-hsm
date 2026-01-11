//! Main TUI application state and event loop

use anyhow::{Context, Result};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    widgets::ListState,
    Terminal,
};
use std::io;
use tracing::{debug, error, info};

use crate::commands::common::CommandContext;
use crate::config::Config;

use super::{commands, menu::MenuCategory, ui};

/// TUI Application state
pub struct InteractiveApp {
    /// Current menu selection
    pub menu_state: ListState,
    /// Selected category for submenu
    pub selected_category: Option<MenuCategory>,
    /// Submenu selection state
    pub submenu_state: ListState,
    /// Current status message
    pub status: String,
    /// Configuration context
    pub ctx: CommandContext,
    /// Token label for operations
    pub token_label: Option<String>,
    /// Cached user PIN
    pub user_pin: Option<String>,
    /// Captured command output for display
    pub command_output: Vec<String>,
    /// Scroll offset for command output
    pub scroll_offset: usize,
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
            status: String::from(
                "Welcome to rust-hsm Interactive Interface! Use ↑/↓ to navigate, Enter to select."
            ),
            ctx,
            token_label,
            user_pin: None,
            command_output: vec![],
            scroll_offset: 0,
        })
    }

    pub fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        loop {
            terminal.draw(|f| ui::draw(f, self))?;

            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc if self.selected_category.is_none() => {
                            debug!("User requested quit");
                            break;
                        }
                        KeyCode::Esc if self.selected_category.is_some() => {
                            self.go_back();
                        }
                        KeyCode::Down => {
                            self.next_item();
                        }
                        KeyCode::Up => {
                            self.previous_item();
                        }
                        KeyCode::Enter => {
                            if self.selected_category.is_none() {
                                self.select_category();
                            } else {
                                if let Err(e) = self.execute_command() {
                                    error!("Command execution failed: {}", e);
                                    self.status = format!("❌ Error: {}", e);
                                }
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
                }
            }
        }

        Ok(())
    }

    fn next_item(&mut self) {
        if self.selected_category.is_some() {
            let i = match self.submenu_state.selected() {
                Some(i) => {
                    if let Some(category) = &self.selected_category {
                        let commands = category.commands();
                        if i >= commands.len().saturating_sub(1) {
                            0
                        } else {
                            i + 1
                        }
                    } else {
                        0
                    }
                }
                None => 0,
            };
            self.submenu_state.select(Some(i));
        } else {
            let categories = MenuCategory::all();
            let i = match self.menu_state.selected() {
                Some(i) => {
                    if i >= categories.len().saturating_sub(1) {
                        0
                    } else {
                        i + 1
                    }
                }
                None => 0,
            };
            self.menu_state.select(Some(i));
        }
    }

    fn previous_item(&mut self) {
        if self.selected_category.is_some() {
            let i = match self.submenu_state.selected() {
                Some(i) => {
                    if i == 0 {
                        if let Some(category) = &self.selected_category {
                            let commands = category.commands();
                            commands.len().saturating_sub(1)
                        } else {
                            0
                        }
                    } else {
                        i - 1
                    }
                }
                None => 0,
            };
            self.submenu_state.select(Some(i));
        } else {
            let categories = MenuCategory::all();
            let i = match self.menu_state.selected() {
                Some(i) => {
                    if i == 0 {
                        categories.len().saturating_sub(1)
                    } else {
                        i - 1
                    }
                }
                None => 0,
            };
            self.menu_state.select(Some(i));
        }
    }

    pub fn go_back(&mut self) {
        self.selected_category = None;
        self.submenu_state.select(None);
        self.command_output.clear();
        self.scroll_offset = 0;
        self.status = "Back to main menu. Use ↑/↓ to navigate, Enter to select.".to_string();
    }

    pub fn select_category(&mut self) {
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

    fn execute_command(&mut self) -> Result<()> {
        commands::execute(self)
    }

    fn show_help(&mut self) {
        self.status = "Help: ↑/↓=Navigate, Enter=Select, Esc=Back, q=Quit, h=Help, PgUp/PgDn=Scroll. See docs/ for command details.".to_string();
    }

    pub fn scroll_up(&mut self) {
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

    pub fn scroll_down(&mut self) {
        if !self.command_output.is_empty() {
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
}

/// Launch the interactive TUI
pub fn run_interactive(config: Config, token_label: Option<String>) -> Result<()> {
    info!("Launching interactive TUI interface");

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = InteractiveApp::new(config, token_label)?;
    let result = app.run(&mut terminal);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn create_mock_app() -> InteractiveApp {
        let config = Config::default();
        InteractiveApp::new(config, None).expect("Failed to create test app")
    }

    #[test]
    fn test_app_initialization() {
        let app = create_mock_app();
        
        // Initial state should be main menu
        assert_eq!(app.selected_category, None);
        assert_eq!(app.menu_state.selected(), Some(0));
        assert!(app.status.contains("Welcome"));
        assert!(app.command_output.is_empty());
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn test_menu_navigation() {
        let mut app = create_mock_app();
        
        // Test initial state
        assert_eq!(app.menu_state.selected(), Some(0));
        
        // Test navigation down
        app.next_item();
        assert_eq!(app.menu_state.selected(), Some(1));
        
        // Test navigation up
        app.previous_item();
        assert_eq!(app.menu_state.selected(), Some(0));
        
        // Test wrap-around (go to last item)
        app.previous_item();
        let categories = MenuCategory::all();
        assert_eq!(app.menu_state.selected(), Some(categories.len() - 1));
        
        // Test wrap-around (go to first item)
        app.next_item();
        assert_eq!(app.menu_state.selected(), Some(0));
    }

    #[test]
    fn test_category_selection() {
        let mut app = create_mock_app();
        
        // Select first category (Information & Status)
        app.menu_state.select(Some(0));
        app.select_category();
        
        assert_eq!(app.selected_category, Some(MenuCategory::Information));
        assert_eq!(app.submenu_state.selected(), Some(0));
        assert!(app.status.contains("Information"));
    }

    #[test]
    fn test_submenu_navigation() {
        let mut app = create_mock_app();
        
        // Enter a category first
        app.selected_category = Some(MenuCategory::Information);
        app.submenu_state.select(Some(0));
        
        // Test submenu navigation
        app.next_item();
        assert_eq!(app.submenu_state.selected(), Some(1));
        
        app.previous_item();
        assert_eq!(app.submenu_state.selected(), Some(0));
    }

    #[test]
    fn test_go_back() {
        let mut app = create_mock_app();
        
        // Enter a category
        app.selected_category = Some(MenuCategory::Information);
        app.submenu_state.select(Some(2));
        app.command_output = vec!["test output".to_string()];
        app.scroll_offset = 5;
        
        // Go back to main menu
        app.go_back();
        
        assert_eq!(app.selected_category, None);
        assert_eq!(app.submenu_state.selected(), None);
        assert!(app.command_output.is_empty());
        assert_eq!(app.scroll_offset, 0);
        assert!(app.status.contains("Back to main menu"));
    }

    #[test]
    fn test_scrolling_empty_output() {
        let mut app = create_mock_app();
        
        // Test scrolling with no output
        app.scroll_down();
        assert_eq!(app.scroll_offset, 0);
        assert!(app.status.contains("No output to scroll"));
        
        app.scroll_up();
        assert_eq!(app.scroll_offset, 0);
    }

    #[test]
    fn test_scrolling_short_output() {
        let mut app = create_mock_app();
        
        // Add short output (less than scroll threshold)
        app.command_output = vec![
            "line1".to_string(),
            "line2".to_string(),
            "line3".to_string(),
        ];
        
        app.scroll_down();
        assert_eq!(app.scroll_offset, 0);
        assert!(app.status.contains("too short to scroll"));
    }

    #[test]
    fn test_scrolling_long_output() {
        let mut app = create_mock_app();
        
        // Add long output (more than scroll threshold)
        app.command_output = (0..50).map(|i| format!("Line {}", i)).collect();
        
        // Test scroll down
        app.scroll_down();
        assert!(app.scroll_offset > 0);
        
        let first_scroll = app.scroll_offset;
        
        // Test scroll down again
        app.scroll_down();
        assert!(app.scroll_offset > first_scroll);
        
        // Test scroll up
        app.scroll_up();
        assert!(app.scroll_offset < first_scroll + 5);
        
        // Test scroll bounds - can't go below 0
        app.scroll_offset = 0;
        app.scroll_up();
        assert_eq!(app.scroll_offset, 0);
        assert!(app.status.contains("Already at top"));
    }

    #[test]
    fn test_scroll_bounds_enforcement() {
        let mut app = create_mock_app();
        
        // Add output and test maximum scroll bounds
        app.command_output = (0..20).map(|i| format!("Line {}", i)).collect();
        
        // Set offset to a valid position but near the end
        app.scroll_offset = 8; // Valid offset: less than max_scroll of 10
        
        // The actual max_scroll logic from scroll_down method
        let min_lines_for_scroll = 10;
        let expected_max_scroll = app.command_output.len().saturating_sub(min_lines_for_scroll);
        
        // Current scroll: 8, max_scroll: 20-10 = 10
        // After scroll_down: min(8+5, 10) = min(13, 10) = 10
        // So scroll_offset should be 10, which equals max_scroll
        
        // Try to scroll down - should not exceed max scroll
        app.scroll_down();
        
        assert!(app.scroll_offset <= expected_max_scroll, 
                "scroll_offset={} should be <= max_scroll={}", 
                app.scroll_offset, expected_max_scroll);
                
        // Try scrolling again - should stay at max_scroll
        app.scroll_down();
        assert!(app.scroll_offset <= expected_max_scroll, 
                "scroll_offset={} should still be <= max_scroll={} after second scroll", 
                app.scroll_offset, expected_max_scroll);
    }

    #[test]
    fn test_help_display() {
        let mut app = create_mock_app();
        
        app.show_help();
        
        assert!(app.status.contains("Help:"));
        assert!(app.status.contains("↑/↓=Navigate"));
        assert!(app.status.contains("Enter=Select"));
        assert!(app.status.contains("Esc=Back"));
    }

    #[test]
    fn test_quit_category_handling() {
        let mut app = create_mock_app();
        
        // Select quit category
        let categories = MenuCategory::all();
        let quit_index = categories.iter().position(|c| matches!(c, MenuCategory::Quit)).unwrap();
        app.menu_state.select(Some(quit_index));
        app.select_category();
        
        // Should not enter the category, just show message
        assert_eq!(app.selected_category, None);
        assert!(app.status.contains("Use 'q' or Esc to quit"));
    }
}
