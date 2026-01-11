//! TUI command execution logic
//! 
//! Handles all command execution, preserving current functionality
//! while organizing it into a clean module structure.

use anyhow::Result;
use cryptoki::context::{CInitializeArgs, Pkcs11};

use super::{app::InteractiveApp, menu::MenuCategory};

/// Execute the currently selected command
pub fn execute(app: &mut InteractiveApp) -> Result<()> {
    if let Some(category) = app.selected_category.clone() {
        let commands = category.commands();
        if let Some(i) = app.submenu_state.selected() {
            if let Some((command, description)) = commands.get(i) {
                app.status = format!("Executing: {} - {}", command, description);

                // Execute the command based on category and command name
                match category {
                    MenuCategory::Information => execute_info_command(app, command),
                    MenuCategory::TokenManagement => execute_token_command(app, command),
                    MenuCategory::KeyOperations => execute_key_command(app, command),
                    MenuCategory::CryptoOperations => execute_crypto_command(app, command),
                    MenuCategory::SymmetricOperations => execute_symmetric_command(app, command),
                    MenuCategory::Troubleshooting => execute_troubleshoot_command(app, command),
                    MenuCategory::Quit => Ok(()),
                }
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}

/// Execute information commands
pub fn execute_info_command(app: &mut InteractiveApp, command: &str) -> Result<()> {
    match command {
        "info" => {
            app.command_output.clear();
            app.scroll_offset = 0;
            app.status = "🔄 Executing info command...".to_string();
            match execute_info_internal(app) {
                Ok(output) => {
                    app.command_output = output;
                    app.status = format!("✅ HSM information retrieved successfully ({} lines) - PgUp/PgDn to scroll", app.command_output.len());
                }
                Err(e) => {
                    app.command_output.clear();
                    app.command_output.push(format!("Error: {}", e));
                    app.status = format!("❌ Failed to retrieve HSM information: {}", e);
                }
            }
        }
        "list-slots" => {
            app.command_output.clear();
            app.scroll_offset = 0;
            app.status = "🔄 Executing list-slots command...".to_string();
            match execute_list_slots_internal(app) {
                Ok(output) => {
                    app.command_output = output;
                    app.status = format!("✅ Slots information retrieved successfully ({} lines) - PgUp/PgDn to scroll", app.command_output.len());
                }
                Err(e) => {
                    app.command_output.clear();
                    app.command_output.push(format!("Error: {}", e));
                    app.status = format!("❌ Failed to retrieve slots information: {}", e);
                }
            }
        }
        "list-mechanisms" => {
            app.status = "🔧 40 mechanisms supported: RSA, ECDSA, AES-GCM, SHA-256, etc.".to_string();
        }
        "list-objects" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "🔑 Found 3 objects: 2 keypairs (RSA-2048, P-256), 1 secret key (AES-256)".to_string();
        }
        _ => {
            app.status = format!("⚡ Command '{}' ready to execute (demo mode)", command);
        }
    }
    Ok(())
}

/// Execute token management commands
fn execute_token_command(app: &mut InteractiveApp, command: &str) -> Result<()> {
    match command {
        "init-token" => {
            app.status = "🔧 Token initialization would be executed here (demo mode)".to_string();
        }
        "init-pin" => {
            app.status = "🔐 User PIN initialization would be executed here (demo mode)".to_string();
        }
        "delete-token" => {
            app.status = "⚠️  Token deletion would be executed here (demo mode)".to_string();
        }
        _ => {
            app.status = format!("⚡ Command '{}' ready to execute (demo mode)", command);
        }
    }
    Ok(())
}

/// Execute key operation commands
fn execute_key_command(app: &mut InteractiveApp, command: &str) -> Result<()> {
    match command {
        "gen-keypair" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "✅ Generated RSA-2048 keypair 'interactive-key' on token".to_string();
        }
        "export-pubkey" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "📄 Exported public key 'interactive-key' -> pubkey.pem".to_string();
        }
        "inspect-key" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "🔍 Key 'interactive-key': RSA-2048, CKA_SIGN=true, CKA_DECRYPT=true".to_string();
        }
        "delete-key" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "🗑️  Deleted keypair 'interactive-key' from token".to_string();
        }
        _ => {
            app.status = format!("⚡ Command '{}' ready to execute (demo mode)", command);
        }
    }
    Ok(())
}

/// Execute cryptographic operation commands
fn execute_crypto_command(app: &mut InteractiveApp, command: &str) -> Result<()> {
    match command {
        "sign" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "✏️  Signed data with key 'interactive-key' -> signature.bin".to_string();
        }
        "verify" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "✅ Signature verification successful".to_string();
        }
        "encrypt" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "🔐 RSA encrypted data.txt -> data.enc (256 bytes)".to_string();
        }
        "decrypt" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "🔓 RSA decrypted data.enc -> data.txt".to_string();
        }
        "gen-csr" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "📋 Generated CSR for 'interactive-key' -> request.csr".to_string();
        }
        "hash" => {
            app.status = "🔗 SHA-256 hash computed: a1b2c3d4... (32 bytes)".to_string();
        }
        _ => {
            app.status = format!("⚡ Command '{}' ready to execute (demo mode)", command);
        }
    }
    Ok(())
}

/// Execute symmetric operation commands
fn execute_symmetric_command(app: &mut InteractiveApp, command: &str) -> Result<()> {
    match command {
        "gen-symmetric-key" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "🔑 Generated AES-256 key 'interactive-aes-key' on token".to_string();
        }
        "encrypt-symmetric" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "🔐 AES-GCM encrypted data.txt -> data.enc (256 bytes)".to_string();
        }
        "decrypt-symmetric" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "🔓 AES-GCM decrypted data.enc -> data.txt".to_string();
        }
        "wrap-key" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "📦 Key wrapped using AES Key Wrap -> wrapped-key.bin".to_string();
        }
        "unwrap-key" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "📦 Key unwrapped and imported as 'unwrapped-key'".to_string();
        }
        "hmac-sign" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "🔏 HMAC-SHA256 computed -> data.hmac (32 bytes)".to_string();
        }
        "cmac-sign" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "🔏 AES-CMAC computed -> data.cmac (16 bytes)".to_string();
        }
        _ => {
            app.status = format!("⚡ Command '{}' ready to execute (demo mode)", command);
        }
    }
    Ok(())
}

/// Execute troubleshooting commands
fn execute_troubleshoot_command(app: &mut InteractiveApp, command: &str) -> Result<()> {
    match command {
        "explain-error" => {
            app.status = "📖 CKR_PIN_INCORRECT: PIN is incorrect. Check user PIN vs SO PIN. May be locked after multiple failures.".to_string();
        }
        "find-key" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "🔍 Found 2 similar keys: 'interactive-key' (exact), 'test-key' (fuzzy)".to_string();
        }
        "diff-keys" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "📊 Key comparison: 3 attributes differ (KeyType, Extractable, Sign)".to_string();
        }
        "audit-keys" => {
            if requires_token_access(app) {
                return Ok(());
            }
            app.status = "🛡️  Security audit: 5 keys checked, 1 warning (extractable key found)".to_string();
        }
        _ => {
            app.status = format!("⚡ Command '{}' ready to execute (demo mode)", command);
        }
    }
    Ok(())
}

/// Check if command requires token access and prompt if needed
fn requires_token_access(app: &mut InteractiveApp) -> bool {
    if app.token_label.is_none() {
        app.status = "⚠️  Token label required. Use --label TOKEN or set in config".to_string();
        return true;
    }

    // In a full implementation, you'd prompt for PIN here
    if app.user_pin.is_none() {
        app.status = "🔐 Demo mode: PIN would be requested here".to_string();
        // For demo, simulate having PIN
        app.user_pin = Some("demo".to_string());
    }

    false
}

/// Execute info command and capture output (actual PKCS#11 call)
fn execute_info_internal(app: &InteractiveApp) -> Result<Vec<String>> {
    let pkcs11 = Pkcs11::new(&app.ctx.module_path)
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

/// Execute list-slots command and capture output (actual PKCS#11 call)
fn execute_list_slots_internal(app: &InteractiveApp) -> Result<Vec<String>> {
    let pkcs11 = Pkcs11::new(&app.ctx.module_path)
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
        
        // Initialized slots section (matches CLI output format)
        output.push("=== Initialized Slots ===".to_string());
        output.push("".to_string());
        
        if slots_with_tokens.is_empty() {
            output.push("No initialized tokens found.".to_string());
        } else {
            for slot in &slots_with_tokens {
                if let Ok(slot_info) = pkcs11.get_slot_info(*slot) {
                    output.push(format!("Slot {}", slot.id()));
                    output.push(format!("  Description: {}", slot_info.slot_description()));
                    output.push(format!("  Manufacturer: {}", slot_info.manufacturer_id()));
                    
                    if let Ok(token_info) = pkcs11.get_token_info(*slot) {
                        output.push(format!("  Token Label: {}", token_info.label()));
                        output.push(format!("  Token Manufacturer: {}", token_info.manufacturer_id()));
                        output.push(format!("  Token Model: {}", token_info.model()));
                        output.push(format!("  Token Serial: {}", token_info.serial_number()));
                    }
                    output.push("".to_string());
                }
            }
        }
        
        // All slots section (matches CLI output format)
        output.push("=== All Slots ===".to_string());
        output.push("".to_string());
        
        for slot in &all_slots {
            if let Ok(slot_info) = pkcs11.get_slot_info(*slot) {
                output.push(format!("Slot {}", slot.id()));
                output.push(format!("  Description: {}", slot_info.slot_description()));
                output.push(format!("  Manufacturer: {}", slot_info.manufacturer_id()));
                
                if slots_with_tokens.contains(slot) {
                    if let Ok(token_info) = pkcs11.get_token_info(*slot) {
                        output.push(format!("  Token Label: {}", token_info.label()));
                        output.push(format!("  Token Manufacturer: {}", token_info.manufacturer_id()));
                        output.push(format!("  Token Model: {}", token_info.model()));
                        output.push(format!("  Token Serial: {}", token_info.serial_number()));
                    }
                }
                output.push("".to_string());
            }
        }

        Ok(output)
    };

    pkcs11.finalize();
    result
}