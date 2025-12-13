use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::slot::Slot;

pub fn list_slots(module_path: &str) -> anyhow::Result<()> {
    let pkcs11 = Pkcs11::new(module_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    let slots = pkcs11.get_slots_with_initialized_token()?;
    
    println!("\n=== Initialized Slots ===");
    if slots.is_empty() {
        println!("No initialized tokens found.");
    } else {
        for slot in &slots {
            print_slot_info(&pkcs11, *slot)?;
        }
    }

    let all_slots = pkcs11.get_all_slots()?;
    println!("\n=== All Slots ===");
    for slot in &all_slots {
        print_slot_info(&pkcs11, *slot)?;
    }

    pkcs11.finalize();
    
    Ok(())
}

fn print_slot_info(pkcs11: &Pkcs11, slot: Slot) -> anyhow::Result<()> {
    let slot_info = pkcs11.get_slot_info(slot)?;
    
    println!("\nSlot {}", usize::from(slot));
    println!("  Description: {}", slot_info.slot_description());
    println!("  Manufacturer: {}", slot_info.manufacturer_id());
    
    // Check if token is present by trying to get token info
    match pkcs11.get_token_info(slot) {
        Ok(token_info) => {
            println!("  Token Label: {}", token_info.label());
            println!("  Token Manufacturer: {}", token_info.manufacturer_id());
            println!("  Token Model: {}", token_info.model());
            println!("  Token Serial: {}", token_info.serial_number());
        }
        Err(e) => {
            println!("  Token: Error reading token info: {}", e);
        }
    }
    
    Ok(())
}
