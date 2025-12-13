use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::types::AuthPin;
use tracing::{info, debug, trace};

pub fn init_token(module_path: &str, label: &str, so_pin: &str) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    // Find an uninitialized slot
    debug!("Retrieving all available slots");
    debug!("→ Calling C_GetSlotList");
    let all_slots = pkcs11.get_all_slots()?;
    debug!("Found {} total slots", all_slots.len());
    trace!("All slots: {:?}", all_slots);
    
    debug!("Retrieving slots with initialized tokens");
    let initialized_slots = pkcs11.get_slots_with_initialized_token().unwrap_or_default();
    debug!("Found {} initialized slots", initialized_slots.len());
    trace!("Initialized slots: {:?}", initialized_slots);
    
    debug!("Searching for uninitialized slot");
    let slot = all_slots.iter()
        .find(|s| !initialized_slots.contains(s))
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No uninitialized slots available. All slots have tokens."))?;
    
    info!("Initializing token in slot {}", usize::from(slot));
    debug!("Selected uninitialized slot: {}", usize::from(slot));

    // Initialize token with SO PIN
    let so_pin = AuthPin::new(so_pin.to_string());
    debug!("Calling PKCS#11 init_token with label: {}", label);
    debug!("→ Calling C_InitToken");
    pkcs11.init_token(slot, &so_pin, label)?;
    debug!("Token initialized successfully");
    
    println!("Token '{}' initialized successfully in slot {}", label, usize::from(slot));

    debug!("Finalizing PKCS#11 library");
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    
    Ok(())
}

pub fn init_pin(module_path: &str, label: &str, so_pin: &str, user_pin: &str) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    // Find slot with matching token label
    debug!("Finding token slot for label: {}", label);
    let slot = find_token_slot(&pkcs11, label)?;
    debug!("Token found at slot: {}", usize::from(slot));
    
    info!("Initializing user PIN on token '{}' in slot {}", label, usize::from(slot));

    // Open RW session and login as SO
    debug!("Opening read-write session on slot {}", usize::from(slot));
    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_rw_session(slot)?;
    debug!("Session opened successfully");
    
    let so_pin = AuthPin::new(so_pin.to_string());
    debug!("Logging in as Security Officer (SO)");
    debug!("→ Calling C_Login");
    session.login(cryptoki::session::UserType::So, Some(&so_pin))?;
    debug!("SO login successful");
    
    // Initialize user PIN
    let user_pin = AuthPin::new(user_pin.to_string());
    debug!("Calling PKCS#11 init_pin to set user PIN");
    debug!("→ Calling C_InitPIN");
    session.init_pin(&user_pin)?;
    debug!("User PIN initialized successfully");
    
    println!("User PIN initialized successfully for token '{}'", label);
    
    debug!("Logging out from session");
    debug!("→ Calling C_Logout");
    session.logout()?;
    debug!("Finalizing PKCS#11 library");
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    
    Ok(())
}

fn find_token_slot(pkcs11: &Pkcs11, label: &str) -> anyhow::Result<cryptoki::slot::Slot> {
    let slots = pkcs11.get_slots_with_initialized_token()?;
    
    for slot in slots {
        if let Ok(token_info) = pkcs11.get_token_info(slot) {
            if token_info.label().trim() == label {
                return Ok(slot);
            }
        }
    }
    
    anyhow::bail!("Token '{}' not found", label)
}

pub fn delete_token(module_path: &str, label: &str, so_pin: &str) -> anyhow::Result<()> {
    // Try SoftHSM-specific deletion first (actually removes token files)
    debug!("Attempting SoftHSM-specific token deletion with softhsm2-util");
    if let Ok(output) = std::process::Command::new("softhsm2-util")
        .args(&["--delete-token", "--token", label])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("deleted") {
                info!("Token '{}' deleted successfully using softhsm2-util", label);
                println!("Token '{}' deleted successfully", label);
                return Ok(());
            }
        }
        debug!("softhsm2-util deletion failed or token not found, falling back to PKCS#11");
    } else {
        debug!("softhsm2-util not available, using PKCS#11 method");
    }

    // Fallback: Use PKCS#11 to reinitialize the slot (works with any HSM)
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    // Find slot with matching token label
    debug!("Finding token slot for label: {}", label);
    let slot = find_token_slot(&pkcs11, label)?;
    debug!("Token found at slot: {}", usize::from(slot));
    
    info!("Deleting token '{}' from slot {} using PKCS#11", label, usize::from(slot));

    // Re-initialize the token with an empty label to effectively delete it
    // Note: PKCS#11 doesn't have a direct "delete token" operation,
    // so we reinitialize the token which erases all data
    let so_pin_auth = AuthPin::new(so_pin.to_string());
    debug!("Calling PKCS#11 init_token to reset slot");
    debug!("→ Calling C_InitToken");
    pkcs11.init_token(slot, &so_pin_auth, "")?;
    debug!("Token reinitialized successfully");
    
    println!("Token '{}' deleted successfully from slot {}", label, usize::from(slot));

    debug!("Finalizing PKCS#11 library");
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    
    Ok(())
}
