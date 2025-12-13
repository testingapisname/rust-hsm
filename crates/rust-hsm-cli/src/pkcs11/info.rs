use cryptoki::context::{CInitializeArgs, Pkcs11};
use tracing::{debug, trace};
use super::mechanisms;

pub fn display_info(module_path: &str) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    debug!("Retrieving library information");
    debug!("→ Calling C_GetInfo");
    let info = pkcs11.get_library_info()?;
    trace!("Library info: {:?}", info);
    
    println!("\n=== PKCS#11 Module Info ===");
    println!("Library Description: {}", info.library_description());
    println!("Library Version: {}.{}", info.library_version().major(), info.library_version().minor());
    println!("Manufacturer ID: {}", info.manufacturer_id());
    
    debug!("Finalizing PKCS#11 library");
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    
    Ok(())
}

pub fn list_mechanisms(module_path: &str, slot_id: Option<u64>) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    let slots = pkcs11.get_slots_with_token()?;
    
    if slots.is_empty() {
        println!("No slots with tokens found");
        pkcs11.finalize();
        return Ok(());
    }

    // Use specified slot or first available
    let target_slot = if let Some(id) = slot_id {
        slots.iter().find(|s| s.id() == id).ok_or_else(|| anyhow::anyhow!("Slot {} not found", id))?
    } else {
        &slots[0]
    };

    println!("\n=== Mechanisms for Slot {} ===", target_slot.id());
    
    let mechanisms = pkcs11.get_mechanism_list(*target_slot)?;
    
    println!("Total mechanisms supported: {}\n", mechanisms.len());
    
    // Extract mechanism values and lookup names
    use std::collections::HashMap;
    let mut by_category: HashMap<&str, Vec<(u64, String)>> = HashMap::new();
    
    for mech in mechanisms {
        let mech_str = format!("{:?}", mech);
        // Extract numeric value from "MechanismType { val: 1234 }" format
        let val = if let Some(start) = mech_str.find("val: ") {
            let val_str = &mech_str[start + 5..];
            let end = val_str.find(' ').unwrap_or(val_str.len());
            val_str[..end].trim_end_matches('}').parse::<u64>().ok()
        } else {
            None
        };
        
        if let Some(val) = val {
            let name = mechanisms::mechanism_name(val)
                .unwrap_or("Unknown")
                .to_string();
            let category = mechanisms::mechanism_category(val);
            
            by_category.entry(category)
                .or_insert_with(Vec::new)
                .push((val, name));
        }
    }
    
    // Sort categories and display
    let mut categories: Vec<_> = by_category.keys().collect();
    categories.sort();
    
    for category in categories {
        let mut mechs = by_category.get(category).unwrap().clone();
        mechs.sort_by_key(|(val, _)| *val);
        
        println!("{} ({} mechanisms):", category, mechs.len());
        for (val, name) in mechs {
            if name == "Unknown" {
                println!("  0x{:08x} - {}", val, name);
            } else {
                println!("  {} (0x{:04x})", name, val);
            }
        }
        println!();
    }
    
    pkcs11.finalize();
    Ok(())
}
