use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use tracing::{info, debug, trace};

pub fn list_objects(module_path: &str, label: &str, user_pin: &str) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    // Find slot with matching token label
    debug!("Finding token slot for label: {}", label);
    let slot = find_token_slot(&pkcs11, label)?;
    debug!("Token found at slot: {}", usize::from(slot));
    
    info!("Opening session on slot {}", usize::from(slot));
    debug!("Opening read-only session");
    let session = pkcs11.open_ro_session(slot)?;
    debug!("Session opened successfully");
    
    // Login as user
    let pin = AuthPin::new(user_pin.to_string());
    debug!("Logging in as User");
    session.login(UserType::User, Some(&pin))?;
    debug!("User login successful");
    
    println!("\n=== Objects on token '{}' ===", label);
    
    // Find all objects
    debug!("Searching for all objects (empty template)");
    let objects = session.find_objects(&[])?;
    debug!("Found {} objects", objects.len());
    trace!("Object handles: {:?}", objects);
    
    if objects.is_empty() {
        println!("No objects found.");
    } else {
        for (idx, obj) in objects.iter().enumerate() {
            debug!("Retrieving attributes for object {}: {:?}", idx + 1, obj);
            println!("\nObject {}:", idx + 1);
            
            // Try to get common attributes
            if let Ok(attrs) = session.get_attributes(*obj, &[
                AttributeType::Label,
                AttributeType::Class,
                AttributeType::Id,
            ]) {
                trace!("Retrieved {} attributes", attrs.len());
                for attr in attrs {
                    match attr {
                        Attribute::Label(bytes) => {
                            if let Ok(label) = String::from_utf8(bytes) {
                                println!("  Label: {}", label);
                            }
                        }
                        Attribute::Class(class) => {
                            println!("  Class: {:?}", class);
                        }
                        Attribute::Id(id) => {
                            println!("  ID: {}", hex::encode(id));
                        }
                        _ => {}
                    }
                }
            } else {
                debug!("Failed to retrieve attributes for object {:?}", obj);
            }
        }
    }
    
    debug!("Logging out from session");
    session.logout()?;
    debug!("Finalizing PKCS#11 library");
    pkcs11.finalize();
    
    Ok(())
}

fn find_token_slot(pkcs11: &Pkcs11, label: &str) -> anyhow::Result<Slot> {
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
