use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::slot::Slot;
use tracing::{debug, trace};

pub fn list_slots(module_path: &str) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    debug!("Retrieving slots with initialized tokens");
    let slots = pkcs11.get_slots_with_initialized_token()?;
    debug!("Found {} initialized slots", slots.len());
    trace!("Initialized slots: {:?}", slots);
    
    println!("\n=== Initialized Slots ===");
    if slots.is_empty() {
        println!("No initialized tokens found.");
    } else {
        for slot in &slots {
            print_slot_info(&pkcs11, *slot)?;
        }
    }

    debug!("Retrieving all available slots");
    let all_slots = pkcs11.get_all_slots()?;
    debug!("Found {} total slots", all_slots.len());
    trace!("All slots: {:?}", all_slots);
    
    println!("\n=== All Slots ===");
    for slot in &all_slots {
        print_slot_info(&pkcs11, *slot)?;
    }

    debug!("Finalizing PKCS#11 library");
    pkcs11.finalize();
    
    Ok(())
}

fn print_slot_info(pkcs11: &Pkcs11, slot: Slot) -> anyhow::Result<()> {
    debug!("Retrieving info for slot {}", usize::from(slot));
    let slot_info = pkcs11.get_slot_info(slot)?;
    trace!("Slot info: {:?}", slot_info);
    
    println!("\nSlot {}", usize::from(slot));
    println!("  Description: {}", slot_info.slot_description());
    println!("  Manufacturer: {}", slot_info.manufacturer_id());
    
    // Check if token is present by trying to get token info
    debug!("Retrieving token info for slot {}", usize::from(slot));
    match pkcs11.get_token_info(slot) {
        Ok(token_info) => {
            trace!("Token info: {:?}", token_info);
            println!("  Token Label: {}", token_info.label());
            println!("  Token Manufacturer: {}", token_info.manufacturer_id());
            println!("  Token Model: {}", token_info.model());
            println!("  Token Serial: {}", token_info.serial_number());
        }
        Err(e) => {
            debug!("Error reading token info: {:?}", e);
            println!("  Token: Error reading token info: {}", e);
        }
    }
    
    Ok(())
}
