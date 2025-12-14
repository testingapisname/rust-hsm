use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use tracing::{debug, info, trace};

pub fn list_objects(
    module_path: &str,
    label: &str,
    user_pin: &str,
    detailed: bool,
) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    // Find slot with matching token label
    debug!("Finding token slot for label: {}", label);
    let slot = find_token_slot(&pkcs11, label)?;
    debug!("Token found at slot: {}", usize::from(slot));

    info!("Opening session on slot {}", usize::from(slot));
    debug!("Opening read-only session");
    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_ro_session(slot)?;
    debug!("Session opened successfully");

    // Login as user
    let pin = AuthPin::new(user_pin.to_string());
    debug!("Logging in as User");
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;
    debug!("User login successful");

    println!("\n=== Objects on token '{}' ===", label);

    // Find all objects
    debug!("Searching for all objects (empty template)");
    debug!("→ Calling C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal");
    let objects = session.find_objects(&[])?;
    debug!("Found {} objects", objects.len());
    trace!("Object handles: {:?}", objects);

    if objects.is_empty() {
        println!("No objects found.");
    } else {
        if detailed {
            // Detailed output like p11ls
            for obj in &objects {
                if let Some(details) = get_detailed_object_info(&session, *obj) {
                    println!("{}", details);
                }
            }
        } else {
            // Simple output
            for (idx, obj) in objects.iter().enumerate() {
                debug!("Retrieving attributes for object {}: {:?}", idx + 1, obj);
                println!("\nObject {}:", idx + 1);

                // Try to get common attributes
                debug!("→ Calling C_GetAttributeValue");
                if let Ok(attrs) = session.get_attributes(
                    *obj,
                    &[
                        AttributeType::Label,
                        AttributeType::Class,
                        AttributeType::Id,
                    ],
                ) {
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
    }

    debug!("Logging out from session");
    debug!("→ Calling C_Logout");
    session.logout()?;
    debug!("Finalizing PKCS#11 library");
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();

    Ok(())
}

fn get_detailed_object_info(
    session: &cryptoki::session::Session,
    obj: cryptoki::object::ObjectHandle,
) -> Option<String> {
    // Get all the attributes we might need
    let attrs = session
        .get_attributes(
            obj,
            &[
                AttributeType::Label,
                AttributeType::Class,
                AttributeType::KeyType,
                AttributeType::Token,
                AttributeType::Private,
                AttributeType::Modifiable,
                AttributeType::Local,
                AttributeType::Sensitive,
                AttributeType::AlwaysSensitive,
                AttributeType::NeverExtractable,
                AttributeType::Extractable,
                AttributeType::Sign,
                AttributeType::Verify,
                AttributeType::Encrypt,
                AttributeType::Decrypt,
                AttributeType::Wrap,
                AttributeType::Unwrap,
                AttributeType::Derive,
                AttributeType::ModulusBits,
                AttributeType::ValueLen,
            ],
        )
        .ok()?;

    // Extract values
    let mut label = String::new();
    let mut class_str = String::new();
    let mut key_type_str = String::new();
    let mut flags = Vec::new();
    let mut key_size = None;

    for attr in attrs {
        match attr {
            Attribute::Label(bytes) => {
                label = String::from_utf8(bytes).unwrap_or_default();
            }
            Attribute::Class(class) => {
                class_str = match class {
                    ObjectClass::PUBLIC_KEY => "pubk".to_string(),
                    ObjectClass::PRIVATE_KEY => "prvk".to_string(),
                    ObjectClass::SECRET_KEY => "seck".to_string(),
                    ObjectClass::DATA => "data".to_string(),
                    ObjectClass::CERTIFICATE => "cert".to_string(),
                    _ => "unkn".to_string(),
                };
            }
            Attribute::KeyType(ktype) => {
                key_type_str = match ktype {
                    KeyType::RSA => "rsa".to_string(),
                    KeyType::EC => "ec".to_string(),
                    KeyType::AES => "aes".to_string(),
                    KeyType::DES => "des".to_string(),
                    KeyType::DES3 => "des3".to_string(),
                    KeyType::GENERIC_SECRET => "gen".to_string(),
                    _ => "?".to_string(),
                };
            }
            Attribute::Token(val) => {
                if val {
                    flags.push("tok");
                }
            }
            Attribute::Private(val) => {
                if val {
                    flags.push("prv");
                } else {
                    flags.push("pub");
                }
            }
            Attribute::Modifiable(val) => {
                if val {
                    flags.push("r/w");
                } else {
                    flags.push("r/o");
                }
            }
            Attribute::Local(val) => {
                if val {
                    flags.push("loc");
                } else {
                    flags.push("imp");
                }
            }
            Attribute::Sign(val) => {
                if val {
                    flags.push("sig");
                }
            }
            Attribute::Verify(val) => {
                if val {
                    flags.push("vfy");
                }
            }
            Attribute::Encrypt(val) => {
                if val {
                    flags.push("enc");
                }
            }
            Attribute::Decrypt(val) => {
                if val {
                    flags.push("dec");
                }
            }
            Attribute::Wrap(val) => {
                if val {
                    flags.push("wra");
                }
            }
            Attribute::Unwrap(val) => {
                if val {
                    flags.push("unw");
                }
            }
            Attribute::Derive(val) => {
                if val {
                    flags.push("der");
                }
            }
            Attribute::Sensitive(val) => {
                if val {
                    flags.push("sen");
                }
            }
            Attribute::AlwaysSensitive(val) => {
                if val {
                    flags.push("ase");
                }
            }
            Attribute::NeverExtractable(val) => {
                if val {
                    flags.push("nxt");
                }
            }
            Attribute::Extractable(val) => {
                if !val {
                    flags.push("XTR");
                }
            }
            Attribute::ModulusBits(bits) => {
                key_size = Some(usize::from(bits));
            }
            Attribute::ValueLen(len) => {
                if key_size.is_none() {
                    key_size = Some(usize::from(len) * 8); // Convert bytes to bits
                }
            }
            _ => {}
        }
    }

    // Format like p11ls: "prvk/rsa  label                             tok,prv,r/w,loc,sig,sen,ase,nxt,rsa(2048)"
    let type_label = if key_type_str.is_empty() {
        class_str.clone()
    } else {
        format!("{}/{}", class_str, key_type_str)
    };

    let flags_str = flags.join(",");

    let key_info = if let Some(size) = key_size {
        format!(",{}({})", key_type_str, size)
    } else {
        String::new()
    };

    Some(format!(
        "{:<10} {:<40} {}{}",
        type_label, label, flags_str, key_info
    ))
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
