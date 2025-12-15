use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::slot::Slot;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

#[derive(Debug, Serialize, Deserialize)]
pub struct SlotInfo {
    pub slot_id: usize,
    pub description: String,
    pub manufacturer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenInfo {
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListSlotsOutput {
    pub initialized_slot_count: usize,
    pub total_slot_count: usize,
    pub initialized_slots: Vec<SlotInfo>,
    pub all_slots: Vec<SlotInfo>,
}

pub fn list_slots(module_path: &str, json: bool) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    debug!("Retrieving slots with initialized tokens");
    debug!("→ Calling C_GetSlotList (with tokens)");
    let slots = pkcs11.get_slots_with_initialized_token()?;
    debug!("Found {} initialized slots", slots.len());
    trace!("Initialized slots: {:?}", slots);

    debug!("Retrieving all available slots");
    debug!("→ Calling C_GetSlotList (all)");
    let all_slots = pkcs11.get_all_slots()?;
    debug!("Found {} total slots", all_slots.len());
    trace!("All slots: {:?}", all_slots);

    if json {
        // JSON output
        let initialized_slot_infos: Vec<SlotInfo> = slots
            .iter()
            .filter_map(|slot| extract_slot_info(&pkcs11, *slot))
            .collect();

        let all_slot_infos: Vec<SlotInfo> = all_slots
            .iter()
            .filter_map(|slot| extract_slot_info(&pkcs11, *slot))
            .collect();

        let output = ListSlotsOutput {
            initialized_slot_count: initialized_slot_infos.len(),
            total_slot_count: all_slot_infos.len(),
            initialized_slots: initialized_slot_infos,
            all_slots: all_slot_infos,
        };

        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("\n=== Initialized Slots ===");
        if slots.is_empty() {
            println!("No initialized tokens found.");
        } else {
            for slot in &slots {
                print_slot_info(&pkcs11, *slot)?;
            }
        }

        println!("\n=== All Slots ===");
        for slot in &all_slots {
            print_slot_info(&pkcs11, *slot)?;
        }
    }

    debug!("Finalizing PKCS#11 library");
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();

    Ok(())
}

fn print_slot_info(pkcs11: &Pkcs11, slot: Slot) -> anyhow::Result<()> {
    debug!("Retrieving info for slot {}", usize::from(slot));
    debug!("→ Calling C_GetSlotInfo");
    let slot_info = pkcs11.get_slot_info(slot)?;
    trace!("Slot info: {:?}", slot_info);

    println!("\nSlot {}", usize::from(slot));
    println!("  Description: {}", slot_info.slot_description());
    println!("  Manufacturer: {}", slot_info.manufacturer_id());

    // Check if token is present by trying to get token info
    debug!("Retrieving token info for slot {}", usize::from(slot));
    debug!("→ Calling C_GetTokenInfo");
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

/// Find the first available slot (for operations that don't require a specific token)
pub fn find_first_slot(pkcs11: &Pkcs11) -> anyhow::Result<Slot> {
    debug!("Finding first available slot");
    let slots = pkcs11.get_all_slots()?;

    slots
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No slots available"))
}

fn extract_slot_info(pkcs11: &Pkcs11, slot: Slot) -> Option<SlotInfo> {
    let slot_info = pkcs11.get_slot_info(slot).ok()?;

    let token = pkcs11
        .get_token_info(slot)
        .ok()
        .map(|token_info| TokenInfo {
            label: token_info.label().trim().to_string(),
            manufacturer: token_info.manufacturer_id().trim().to_string(),
            model: token_info.model().trim().to_string(),
            serial_number: token_info.serial_number().trim().to_string(),
        });

    Some(SlotInfo {
        slot_id: usize::from(slot),
        description: slot_info.slot_description().trim().to_string(),
        manufacturer: slot_info.manufacturer_id().trim().to_string(),
        token,
    })
}
