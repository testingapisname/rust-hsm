use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::fs;
use tracing::{debug, info, trace};

use super::utils::{find_token_slot, mechanism_name};

pub fn gen_symmetric_key(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    bits: u32,
    extractable: bool,
) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("PKCS#11 module loaded successfully");
    
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;
    debug!("PKCS#11 library initialized");

    debug!("Finding token slot for label: {}", label);
    let slot = find_token_slot(&pkcs11, label)?;
    info!("Generating AES-{} key on token '{}' in slot {}", bits, label, usize::from(slot));

    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_rw_session(slot)?;
    debug!("Session opened successfully");
    
    let pin = AuthPin::new(user_pin.to_string());
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;
    debug!("Logged in as User");

    // Validate key size
    if bits != 128 && bits != 192 && bits != 256 {
        anyhow::bail!("Invalid AES key size: {}. Must be 128, 192, or 256", bits);
    }

    // Generate AES key
    let mechanism = Mechanism::AesKeyGen;
    debug!("Using key generation mechanism: {}", mechanism_name(&mechanism));
    debug!("→ Calling C_GenerateKey");
    let key_template = vec![
        Attribute::Token(true),
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::Id(key_label.as_bytes().to_vec()),
        Attribute::Sensitive(true),
        Attribute::Extractable(extractable),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Wrap(true),
        Attribute::Unwrap(true),
        Attribute::ValueLen(((bits / 8) as u64).into()),
    ];

    let key = session.generate_key(&mechanism, &key_template)?;
    
    println!("AES-{} key '{}' generated successfully", bits, key_label);
    println!("  Key handle: {:?}", key);

    debug!("→ Calling C_Logout");
    session.logout()?;
    debug!("Logged out");
    
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    debug!("PKCS#11 library finalized");

    Ok(())
}

pub fn encrypt_symmetric(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    input_path: &str,
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
    info!("Encrypting data with AES key '{}' on token '{}'", key_label, label);

    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_ro_session(slot)?;
    debug!("Session opened successfully");
    
    let pin = AuthPin::new(user_pin.to_string());
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;
    debug!("Logged in as User");

    // Find the symmetric key
    debug!("→ Calling C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal");
    let template = vec![
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::Class(cryptoki::object::ObjectClass::SECRET_KEY),
    ];
    let objects = session.find_objects(&template)?;
    
    if objects.is_empty() {
        debug!("→ Calling C_Logout, C_Finalize");
        session.logout()?;
        pkcs11.finalize();
        anyhow::bail!("Symmetric key '{}' not found", key_label);
    }

    let key = objects[0];
    debug!("Found symmetric key object with handle: {:?}", key);

    // Read plaintext
    let plaintext = fs::read(input_path)?;
    info!("Read {} bytes from {}", plaintext.len(), input_path);

    // Generate random 96-bit (12-byte) IV for AES-GCM
    let mut iv: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
    trace!("Generated IV: {} bytes", iv.len());

    // Encrypt using AES-GCM
    let mechanism = Mechanism::AesGcm(cryptoki::mechanism::aead::GcmParams::new(&mut iv, &[], (128u64).into())?);
    debug!("Using encryption mechanism: {}", mechanism_name(&mechanism));
    debug!("→ Calling C_EncryptInit, C_Encrypt");
    let ciphertext = session.encrypt(&mechanism, key, &plaintext)?;
    
    info!("Encrypted {} bytes to {} bytes", plaintext.len(), ciphertext.len());

    // Write IV + ciphertext to file (IV is needed for decryption)
    let mut output = Vec::new();
    output.extend_from_slice(&iv);
    output.extend_from_slice(&ciphertext);
    fs::write(output_path, &output)?;
    
    println!("Data encrypted successfully with AES-GCM");
    println!("  Input: {} ({} bytes)", input_path, plaintext.len());
    println!("  Output: {} ({} bytes, includes 12-byte IV)", output_path, output.len());

    debug!("→ Calling C_Logout");
    session.logout()?;
    debug!("Logged out");
    
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    debug!("PKCS#11 library finalized");

    Ok(())
}

pub fn decrypt_symmetric(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    input_path: &str,
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
    info!("Decrypting data with AES key '{}' on token '{}'", key_label, label);

    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_ro_session(slot)?;
    debug!("Session opened successfully");
    
    let pin = AuthPin::new(user_pin.to_string());
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;
    debug!("Logged in as User");

    // Find the symmetric key
    debug!("→ Calling C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal");
    let template = vec![
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::Class(cryptoki::object::ObjectClass::SECRET_KEY),
    ];
    let objects = session.find_objects(&template)?;
    
    if objects.is_empty() {
        debug!("→ Calling C_Logout, C_Finalize");
        session.logout()?;
        pkcs11.finalize();
        anyhow::bail!("Symmetric key '{}' not found", key_label);
    }

    let key = objects[0];
    debug!("Found symmetric key object with handle: {:?}", key);

    // Read IV + ciphertext
    let data = fs::read(input_path)?;
    info!("Read {} bytes from {}", data.len(), input_path);

    if data.len() < 12 {
        anyhow::bail!("Invalid encrypted file: too short (expected at least 12 bytes for IV)");
    }

    // Extract IV (first 12 bytes) and ciphertext (remaining bytes)
    let mut iv = data[..12].to_vec();
    let ciphertext = &data[12..];
    trace!("Extracted IV: {} bytes, ciphertext: {} bytes", iv.len(), ciphertext.len());

    // Decrypt using AES-GCM
    let mechanism = Mechanism::AesGcm(cryptoki::mechanism::aead::GcmParams::new(&mut iv, &[], (128u64).into())?);
    debug!("Using decryption mechanism: {}", mechanism_name(&mechanism));
    debug!("→ Calling C_DecryptInit, C_Decrypt");
    let plaintext = session.decrypt(&mechanism, key, ciphertext)?;
    
    info!("Decrypted {} bytes to {} bytes", ciphertext.len(), plaintext.len());

    // Write plaintext to file
    fs::write(output_path, &plaintext)?;
    println!("Data decrypted successfully with AES-GCM");
    println!("  Input: {} ({} bytes)", input_path, data.len());
    println!("  Output: {} ({} bytes)", output_path, plaintext.len());

    debug!("→ Calling C_Logout");
    session.logout()?;
    debug!("Logged out");
    
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    debug!("PKCS#11 library finalized");

    Ok(())
}
