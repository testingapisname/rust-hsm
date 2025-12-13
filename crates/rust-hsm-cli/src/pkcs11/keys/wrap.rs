use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::fs;
use tracing::{debug, info};

use super::utils::{find_token_slot, mechanism_name};

pub fn wrap_key(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    wrapping_key_label: &str,
    output_path: &str,
) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("PKCS#11 module loaded successfully");
    
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;
    debug!("PKCS#11 library initialized");

    debug!("Finding token slot for label: {}", label);
    let slot = find_token_slot(&pkcs11, label)?;
    info!("Wrapping key '{}' with wrapping key '{}' on token '{}'", key_label, wrapping_key_label, label);

    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_rw_session(slot)?;
    debug!("Session opened successfully");
    
    let pin = AuthPin::new(user_pin.to_string());
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;
    debug!("Logged in as User");

    // Find the key to wrap
    debug!("→ Finding key to wrap: {}", key_label);
    let key_to_wrap = find_key(&session, key_label)?;
    debug!("Found key to wrap with handle: {:?}", key_to_wrap);

    // Find the wrapping key (must be an AES key with CKA_WRAP = true)
    debug!("→ Finding wrapping key: {}", wrapping_key_label);
    let wrapping_key = find_wrapping_key(&session, wrapping_key_label)?;
    debug!("Found wrapping key with handle: {:?}", wrapping_key);

    // Wrap the key using AES Key Wrap (RFC 3394)
    let mechanism = Mechanism::AesKeyWrap;
    debug!("Using key wrapping mechanism: {}", mechanism_name(&mechanism));
    debug!("→ Calling C_WrapKey");
    let wrapped_key = session.wrap_key(&mechanism, wrapping_key, key_to_wrap)?;
    
    info!("Key wrapped successfully: {} bytes", wrapped_key.len());

    // Write wrapped key to file
    fs::write(output_path, &wrapped_key)?;
    println!("Key '{}' wrapped successfully", key_label);
    println!("  Wrapping key: {}", wrapping_key_label);
    println!("  Output: {} ({} bytes)", output_path, wrapped_key.len());

    debug!("→ Calling C_Logout");
    session.logout()?;
    debug!("Logged out");
    
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    debug!("PKCS#11 library finalized");

    Ok(())
}

pub fn unwrap_key(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    wrapping_key_label: &str,
    input_path: &str,
    key_type: &str,
) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("PKCS#11 module loaded successfully");
    
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;
    debug!("PKCS#11 library initialized");

    debug!("Finding token slot for label: {}", label);
    let slot = find_token_slot(&pkcs11, label)?;
    info!("Unwrapping key '{}' with wrapping key '{}' on token '{}'", key_label, wrapping_key_label, label);

    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_rw_session(slot)?;
    debug!("Session opened successfully");
    
    let pin = AuthPin::new(user_pin.to_string());
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;
    debug!("Logged in as User");

    // Find the wrapping key
    debug!("→ Finding wrapping key: {}", wrapping_key_label);
    let wrapping_key = find_wrapping_key(&session, wrapping_key_label)?;
    debug!("Found wrapping key with handle: {:?}", wrapping_key);

    // Read wrapped key data
    let wrapped_key = fs::read(input_path)?;
    info!("Read {} bytes of wrapped key data from {}", wrapped_key.len(), input_path);

    // Prepare template for the unwrapped key
    let key_template = match key_type.to_lowercase().as_str() {
        "aes" => {
            vec![
                Attribute::Token(true),
                Attribute::Label(key_label.as_bytes().to_vec()),
                Attribute::Id(key_label.as_bytes().to_vec()),
                Attribute::Class(cryptoki::object::ObjectClass::SECRET_KEY),
                Attribute::KeyType(cryptoki::object::KeyType::AES),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::Wrap(true),
                Attribute::Unwrap(true),
            ]
        }
        _ => anyhow::bail!("Unsupported key type for unwrap: {}. Currently only 'aes' is supported.", key_type),
    };

    // Unwrap the key using AES Key Wrap (RFC 3394)
    let mechanism = Mechanism::AesKeyWrap;
    debug!("Using key unwrapping mechanism: {}", mechanism_name(&mechanism));
    debug!("→ Calling C_UnwrapKey");
    let unwrapped_key = session.unwrap_key(&mechanism, wrapping_key, &wrapped_key, &key_template)?;
    
    println!("Key '{}' unwrapped successfully", key_label);
    println!("  Wrapping key: {}", wrapping_key_label);
    println!("  Key handle: {:?}", unwrapped_key);
    println!("  Key type: {}", key_type.to_uppercase());

    debug!("→ Calling C_Logout");
    session.logout()?;
    debug!("Logged out");
    
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    debug!("PKCS#11 library finalized");

    Ok(())
}

fn find_key(
    session: &cryptoki::session::Session,
    label: &str,
) -> anyhow::Result<ObjectHandle> {
    let template = vec![
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Class(cryptoki::object::ObjectClass::SECRET_KEY),
    ];

    let objects = session.find_objects(&template)?;
    
    if objects.is_empty() {
        anyhow::bail!("Key '{}' not found", label);
    }

    Ok(objects[0])
}

fn find_wrapping_key(
    session: &cryptoki::session::Session,
    label: &str,
) -> anyhow::Result<ObjectHandle> {
    // Find AES key with CKA_WRAP = true
    let template = vec![
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Class(cryptoki::object::ObjectClass::SECRET_KEY),
        Attribute::KeyType(cryptoki::object::KeyType::AES),
    ];

    let objects = session.find_objects(&template)?;
    
    if objects.is_empty() {
        anyhow::bail!("Wrapping key '{}' not found. Make sure it's an AES key with wrapping capability.", label);
    }

    Ok(objects[0])
}
