use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use tracing::info;

pub fn list_objects(module_path: &str, label: &str, user_pin: &str) -> anyhow::Result<()> {
    let pkcs11 = Pkcs11::new(module_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    // Find slot with matching token label
    let slot = find_token_slot(&pkcs11, label)?;
    
    info!("Opening session on slot {}", usize::from(slot));
    let session = pkcs11.open_ro_session(slot)?;
    
    // Login as user
    let pin = AuthPin::new(user_pin.to_string());
    session.login(UserType::User, Some(&pin))?;
    
    println!("\n=== Objects on token '{}' ===", label);
    
    // Find all objects
    let objects = session.find_objects(&[])?;
    
    if objects.is_empty() {
        println!("No objects found.");
    } else {
        for (idx, obj) in objects.iter().enumerate() {
            println!("\nObject {}:", idx + 1);
            
            // Try to get common attributes
            if let Ok(attrs) = session.get_attributes(*obj, &[
                AttributeType::Label,
                AttributeType::Class,
                AttributeType::Id,
            ]) {
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
            }
        }
    }
    
    session.logout()?;
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
