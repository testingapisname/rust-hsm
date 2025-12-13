use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use tracing::info;

pub fn init_token(module_path: &str, label: &str, so_pin: &str) -> anyhow::Result<()> {
    let pkcs11 = Pkcs11::new(module_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    // Find an uninitialized slot
    let all_slots = pkcs11.get_all_slots()?;
    let initialized_slots = pkcs11.get_slots_with_initialized_token().unwrap_or_default();
    
    let slot = all_slots.iter()
        .find(|s| !initialized_slots.contains(s))
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No uninitialized slots available. All slots have tokens."))?;
    
    info!("Initializing token in slot {}", usize::from(slot));

    // Initialize token with SO PIN
    let so_pin = AuthPin::new(so_pin.to_string());
    pkcs11.init_token(slot, &so_pin, label)?;
    
    println!("Token '{}' initialized successfully in slot {}", label, usize::from(slot));

    pkcs11.finalize();
    
    Ok(())
}

pub fn init_pin(module_path: &str, label: &str, so_pin: &str, user_pin: &str) -> anyhow::Result<()> {
    let pkcs11 = Pkcs11::new(module_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    // Find slot with matching token label
    let slot = find_token_slot(&pkcs11, label)?;
    
    info!("Initializing user PIN on token '{}' in slot {}", label, usize::from(slot));

    // Open RW session and login as SO
    let session = pkcs11.open_rw_session(slot)?;
    let so_pin = AuthPin::new(so_pin.to_string());
    session.login(cryptoki::session::UserType::So, Some(&so_pin))?;
    
    // Initialize user PIN
    let user_pin = AuthPin::new(user_pin.to_string());
    session.init_pin(&user_pin)?;
    
    println!("User PIN initialized successfully for token '{}'", label);
    
    session.logout()?;
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
