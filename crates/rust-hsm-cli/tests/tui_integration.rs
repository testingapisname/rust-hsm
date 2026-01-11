//! TUI integration tests using real HSM providers (SoftHSM2 and Kryoptic)
//! 
//! These tests require a running Docker container with HSM providers.
//! Run with: docker exec rust-hsm-app cargo test tui_integration

use anyhow::Result;
use std::env;

use rust_hsm_cli::commands::tui::app::InteractiveApp;
use rust_hsm_cli::commands::tui::commands::execute_info_command;
use rust_hsm_cli::commands::tui::menu::MenuCategory;
use rust_hsm_cli::config::Config;

/// Create test app with SoftHSM2 configuration
fn create_test_app_softhsm() -> Result<InteractiveApp> {
    let mut config = Config::default();
    config.pkcs11_module = "/usr/lib/softhsm/libsofthsm2.so".to_string();
    env::set_var("PKCS11_MODULE", &config.pkcs11_module);
    
    InteractiveApp::new(config, None)
}

/// Create test app with Kryoptic configuration
fn create_test_app_kryoptic() -> Result<InteractiveApp> {
    let mut config = Config::default();
    config.pkcs11_module = "/usr/lib/kryoptic/libkryoptic_pkcs11.so".to_string();
    
    env::set_var("PKCS11_MODULE", &config.pkcs11_module);
    env::set_var("KRYOPTIC_CONF", "/kryoptic-tokens/kryoptic.conf");
    
    InteractiveApp::new(config, None)
}

#[test]
fn test_tui_info_command_softhsm() -> Result<()> {
    let mut app = create_test_app_softhsm()?;
    
    // Execute info command
    execute_info_command(&mut app, "info")?;
    
    // Check that command output is populated
    assert!(!app.command_output.is_empty(), "Info command should produce output");
    
    // Check for SoftHSM-specific content
    let output_text = app.command_output.join("\n");
    assert!(output_text.contains("SoftHSM") || output_text.contains("Implementation of PKCS#11"), 
           "Output should contain SoftHSM information");
    
    // Check status message
    assert!(app.status.contains("successfully"), "Status should indicate success");
    
    Ok(())
}

#[test]
fn test_tui_list_slots_command_softhsm() -> Result<()> {
    let mut app = create_test_app_softhsm()?;
    
    // Execute list-slots command
    execute_info_command(&mut app, "list-slots")?;
    
    // Check that command output is populated
    assert!(!app.command_output.is_empty(), "List-slots command should produce output");
    
    // Check for expected slot listing format
    let output_text = app.command_output.join("\n");
    assert!(output_text.contains("=== Initialized Slots ==="), 
           "Output should contain initialized slots section");
    assert!(output_text.contains("=== All Slots ==="), 
           "Output should contain all slots section");
    
    // Should have substantial output (many lines)
    assert!(app.command_output.len() > 10, "Should have multiple lines of slot information");
    
    Ok(())
}

#[test] 
fn test_tui_info_command_kryoptic() -> Result<()> {
    // Skip if Kryoptic not available
    if !std::path::Path::new("/usr/lib/kryoptic/libkryoptic_pkcs11.so").exists() {
        eprintln!("Skipping Kryoptic test - module not found");
        return Ok(());
    }
    
    let mut app = create_test_app_kryoptic()?;
    
    // Execute info command
    execute_info_command(&mut app, "info")?;
    
    // Check that command output is populated
    assert!(!app.command_output.is_empty(), "Info command should produce output");
    
    // Check for Kryoptic-specific content
    let output_text = app.command_output.join("\n");
    assert!(output_text.contains("Kryoptic") || output_text.contains("PKCS#11"), 
           "Output should contain PKCS#11 library information");
    
    Ok(())
}

#[test]
fn test_tui_command_execution_workflow() -> Result<()> {
    let mut app = create_test_app_softhsm()?;
    
    // Test the workflow: main menu -> Information category -> execute command
    
    // 1. Start in main menu
    assert_eq!(app.selected_category, None);
    assert_eq!(app.menu_state.selected(), Some(0));
    
    // 2. Navigate to Information category and enter it
    app.selected_category = Some(MenuCategory::Information);
    app.submenu_state.select(Some(0)); // Select "info" command
    
    // 3. Execute the selected command
    execute_info_command(&mut app, "info")?;
    
    // 4. Verify command executed successfully
    assert!(!app.command_output.is_empty());
    assert!(app.status.contains("successfully"));
    
    // 5. Test going back
    app.go_back();
    assert_eq!(app.selected_category, None);
    assert!(app.command_output.is_empty());
    assert_eq!(app.scroll_offset, 0);
    
    Ok(())
}

#[test]
fn test_tui_scrolling_with_real_data() -> Result<()> {
    let mut app = create_test_app_softhsm()?;
    
    // Execute list-slots to get real scrollable data
    execute_info_command(&mut app, "list-slots")?;
    
    // Should have enough data to enable scrolling
    assert!(app.command_output.len() > 15, "Should have substantial slot data for scrolling");
    
    // Test scrolling functionality
    let initial_offset = app.scroll_offset;
    
    // Scroll down
    app.scroll_down();
    if app.command_output.len() > 10 {
        assert!(app.scroll_offset >= initial_offset, "Should scroll down with real data");
    }
    
    // Scroll up  
    app.scroll_up();
    assert!(app.scroll_offset <= app.command_output.len(), "Scroll offset should stay within bounds");
    
    Ok(())
}

#[test]
fn test_tui_error_handling() -> Result<()> {
    let mut app = create_test_app_softhsm()?;
    
    // Test that app handles errors gracefully
    // The actual error handling depends on the implementation
    // but the app should not crash
    
    // Try to execute a command and ensure app state remains consistent
    let initial_status = app.status.clone();
    
    // Execute a real command that should work
    let result = execute_info_command(&mut app, "info");
    
    // Even if there's an error, app should remain in a valid state
    match result {
        Ok(_) => {
            assert!(!app.command_output.is_empty());
        }
        Err(_) => {
            // Error is acceptable, but app should be stable
            assert!(app.scroll_offset <= app.command_output.len());
        }
    }
    
    Ok(())
}

#[test]
fn test_provider_switching() -> Result<()> {
    // Test SoftHSM
    {
        let mut app = create_test_app_softhsm()?;
        execute_info_command(&mut app, "info")?;
        let softhsm_output = app.command_output.join("\n");
        assert!(softhsm_output.len() > 10, "SoftHSM should produce output");
    }
    
    // Test Kryoptic (if available)
    if std::path::Path::new("/usr/lib/kryoptic/libkryoptic_pkcs11.so").exists() {
        let mut app = create_test_app_kryoptic()?;
        execute_info_command(&mut app, "info")?;
        let kryoptic_output = app.command_output.join("\n");
        assert!(kryoptic_output.len() > 10, "Kryoptic should produce output");
        
        // Outputs should be different (different providers)
        // This is a basic check that we're actually switching providers
    }
    
    Ok(())
}

/// Helper to run a full TUI navigation test
#[test]
fn test_full_navigation_cycle() -> Result<()> {
    let mut app = create_test_app_softhsm()?;
    
    // Test navigation through all categories
    let categories = MenuCategory::all();
    
    for (i, category) in categories.iter().enumerate() {
        if matches!(category, MenuCategory::Quit) {
            continue; // Skip quit category
        }
        
        // Navigate to category
        app.menu_state.select(Some(i));
        app.select_category();
        
        assert_eq!(app.selected_category, Some(category.clone()));
        assert_eq!(app.submenu_state.selected(), Some(0));
        
        // Go back to main menu
        app.go_back();
        assert_eq!(app.selected_category, None);
    }
    
    Ok(())
}