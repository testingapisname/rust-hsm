use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::fs;
use tracing::{debug, info, trace};

use super::utils::{find_token_slot, get_key_type, mechanism_name};

pub fn sign(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    input_path: &str,
    output_path: &str,
    json: bool,
) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module for signing operation");
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    debug!("Finding token slot for label: {}", label);
    let slot = find_token_slot(&pkcs11, label)?;
    info!("Signing data with key '{}' on token '{}'", key_label, label);
    debug!("Token found at slot: {}", usize::from(slot));

    debug!("Opening read-write session");
    let session = pkcs11.open_rw_session(slot)?;
    let pin = AuthPin::new(user_pin.to_string());
    debug!("Logging in as User");
    session.login(UserType::User, Some(&pin))?;
    debug!("User login successful");

    // Find private key by label
    debug!("Searching for private key with label: {}", key_label);
    debug!("→ Calling C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal");
    let key_handle = find_key_by_label(&session, key_label, true)?;
    debug!("Private key found with handle: {:?}", key_handle);

    // Detect key type
    let key_type = get_key_type(&session, key_handle)?;

    // Read input data
    debug!("Reading input data from: {}", input_path);
    let data = fs::read(input_path)?;
    info!("Read {} bytes from {}", data.len(), input_path);
    trace!(
        "Input data (first 32 bytes): {:02x?}",
        &data[..data.len().min(32)]
    );

    // Select appropriate signing mechanism
    let mechanism = match key_type {
        cryptoki::object::KeyType::RSA => Mechanism::Sha256RsaPkcs,
        cryptoki::object::KeyType::EC => Mechanism::Ecdsa,
        _ => anyhow::bail!("Unsupported key type for signing: {:?}", key_type),
    };
    debug!(
        "Using verification mechanism: {}",
        mechanism_name(&mechanism)
    );
    debug!("Using signing mechanism: {}", mechanism_name(&mechanism));

    let signature = if key_type == cryptoki::object::KeyType::EC {
        // For ECDSA, we hash the data first
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        session.sign(&mechanism, key_handle, &hash)?
    } else {
        // RSA mechanism does hashing internally
        session.sign(&mechanism, key_handle, &data)?
    };

    // Write signature
    fs::write(output_path, &signature)?;

    if json {
        let json_output = serde_json::json!({
            "status": "success",
            "operation": "sign",
            "key_label": key_label,
            "key_type": format!("{:?}", key_type),
            "input_file": input_path,
            "input_bytes": data.len(),
            "signature_file": output_path,
            "signature_bytes": signature.len()
        });
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    } else {
        println!("Signature created successfully");
        println!("  Input: {} ({} bytes)", input_path, data.len());
        println!("  Signature: {} ({} bytes)", output_path, signature.len());
    }

    session.logout()?;
    pkcs11.finalize();

    Ok(())
}

pub fn verify(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    input_path: &str,
    signature_path: &str,
    json: bool,
) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module for verification operation");
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    debug!("Finding token slot for label: {}", label);
    let slot = find_token_slot(&pkcs11, label)?;
    info!(
        "Verifying signature with key '{}' on token '{}'",
        key_label, label
    );
    debug!("Token found at slot: {}", usize::from(slot));

    debug!("Opening read-write session");
    let session = pkcs11.open_rw_session(slot)?;
    let pin = AuthPin::new(user_pin.to_string());
    debug!("Logging in as User");
    session.login(UserType::User, Some(&pin))?;
    debug!("User login successful");

    // Find public key by label
    debug!("Searching for public key with label: {}", key_label);
    debug!("→ Calling C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal");
    let key_handle = find_key_by_label(&session, key_label, false)?;
    debug!("Public key found with handle: {:?}", key_handle);

    // Read input data and signature
    debug!("Reading input data from: {}", input_path);
    let data = fs::read(input_path)?;
    debug!("Reading signature from: {}", signature_path);
    let signature = fs::read(signature_path)?;
    info!(
        "Read {} bytes of data and {} bytes of signature",
        data.len(),
        signature.len()
    );
    trace!(
        "Input data (first 32 bytes): {:02x?}",
        &data[..data.len().min(32)]
    );
    trace!(
        "Signature (first 32 bytes): {:02x?}",
        &signature[..signature.len().min(32)]
    );

    // Determine key type and select appropriate mechanism
    debug!("Querying key type from key handle");
    debug!("→ Calling C_GetAttributeValue");
    let key_type = get_key_type(&session, key_handle)?;
    debug!("Key type detected: {:?}", key_type);
    let mechanism = match key_type {
        cryptoki::object::KeyType::RSA => Mechanism::Sha256RsaPkcs,
        cryptoki::object::KeyType::EC => Mechanism::Ecdsa,
        _ => anyhow::bail!("Unsupported key type: {:?}", key_type),
    };

    // For ECDSA, we need to hash the data first
    let verify_result = if key_type == cryptoki::object::KeyType::EC {
        debug!("ECDSA detected: computing SHA-256 hash of input data");
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        debug!("SHA-256 hash computed: {} bytes", hash.len());
        trace!("Hash value: {:02x?}", &hash[..]);
        debug!("Calling PKCS#11 verify operation on hash");
        debug!("→ Calling C_VerifyInit");
        debug!("→ Calling C_Verify");
        session.verify(&mechanism, key_handle, &hash, &signature)
    } else {
        debug!("RSA detected: verifying data directly (mechanism includes hashing)");
        debug!("Calling PKCS#11 verify operation on raw data");
        debug!("→ Calling C_VerifyInit");
        debug!("→ Calling C_Verify");
        session.verify(&mechanism, key_handle, &data, &signature)
    };

    match verify_result {
        Ok(_) => {
            debug!("PKCS#11 verify operation succeeded");
            if json {
                let json_output = serde_json::json!({
                    "status": "success",
                    "operation": "verify",
                    "verification": "valid",
                    "key_label": key_label,
                    "key_type": format!("{:?}", key_type),
                    "input_file": input_path,
                    "input_bytes": data.len(),
                    "signature_file": signature_path,
                    "signature_bytes": signature.len()
                });
                println!("{}", serde_json::to_string_pretty(&json_output)?);
            } else {
                println!("✓ Signature verification successful");
                println!("  Input: {} ({} bytes)", input_path, data.len());
                println!(
                    "  Signature: {} ({} bytes)",
                    signature_path,
                    signature.len()
                );
                println!("  Key type: {:?}", key_type);
            }
        }
        Err(e) => {
            debug!("PKCS#11 verify operation failed: {:?}", e);
            if json {
                let json_output = serde_json::json!({
                    "status": "error",
                    "operation": "verify",
                    "verification": "invalid",
                    "error": format!("{}", e)
                });
                println!("{}", serde_json::to_string_pretty(&json_output)?);
            } else {
                println!("✗ Signature verification failed: {}", e);
            }
            anyhow::bail!("Verification failed");
        }
    }

    session.logout()?;
    pkcs11.finalize();

    Ok(())
}

pub fn encrypt(
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
    info!(
        "Encrypting data with key '{}' on token '{}'",
        key_label, label
    );

    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_ro_session(slot)?;
    debug!("Session opened successfully");

    let pin = AuthPin::new(user_pin.to_string());
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;
    debug!("Logged in as User");

    // Find the public key
    debug!("→ Calling C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal");
    let template = vec![
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::Class(cryptoki::object::ObjectClass::PUBLIC_KEY),
    ];
    let objects = session.find_objects(&template)?;

    if objects.is_empty() {
        debug!("→ Calling C_Logout, C_Finalize");
        session.logout()?;
        pkcs11.finalize();
        anyhow::bail!("Public key '{}' not found", key_label);
    }

    let public_key = objects[0];
    debug!("Found public key object with handle: {:?}", public_key);

    // Read input data
    let plaintext = fs::read(input_path)?;
    info!("Read {} bytes from {}", plaintext.len(), input_path);

    // RSA can only encrypt data up to key_size - padding_overhead
    // For PKCS#1 v1.5, overhead is 11 bytes
    // So max plaintext for 2048-bit key is 245 bytes, for 4096-bit is 501 bytes
    if plaintext.len() > 245 {
        anyhow::bail!("Input data too large for RSA encryption (max 245 bytes for 2048-bit key, {} bytes provided)", plaintext.len());
    }

    // Encrypt using RSA PKCS#1 v1.5
    let mechanism = Mechanism::RsaPkcs;
    debug!("Using encryption mechanism: {}", mechanism_name(&mechanism));
    debug!("→ Calling C_EncryptInit, C_Encrypt");
    let ciphertext = session.encrypt(&mechanism, public_key, &plaintext)?;

    info!(
        "Encrypted {} bytes to {} bytes",
        plaintext.len(),
        ciphertext.len()
    );

    // Write ciphertext to file
    fs::write(output_path, &ciphertext)?;
    println!("Data encrypted successfully");
    println!("  Input: {} ({} bytes)", input_path, plaintext.len());
    println!("  Output: {} ({} bytes)", output_path, ciphertext.len());

    debug!("→ Calling C_Logout");
    session.logout()?;
    debug!("Logged out");

    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    debug!("PKCS#11 library finalized");

    Ok(())
}

pub fn decrypt(
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
    info!(
        "Decrypting data with key '{}' on token '{}'",
        key_label, label
    );

    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_ro_session(slot)?;
    debug!("Session opened successfully");

    let pin = AuthPin::new(user_pin.to_string());
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;
    debug!("Logged in as User");

    // Find the private key
    debug!("→ Calling C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal");
    let template = vec![
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
    ];
    let objects = session.find_objects(&template)?;

    if objects.is_empty() {
        debug!("→ Calling C_Logout, C_Finalize");
        session.logout()?;
        pkcs11.finalize();
        anyhow::bail!("Private key '{}' not found", key_label);
    }

    let private_key = objects[0];
    debug!("Found private key object with handle: {:?}", private_key);

    // Read ciphertext
    let ciphertext = fs::read(input_path)?;
    info!("Read {} bytes from {}", ciphertext.len(), input_path);

    // Decrypt using RSA PKCS#1 v1.5
    let mechanism = Mechanism::RsaPkcs;
    debug!("Using decryption mechanism: {}", mechanism_name(&mechanism));
    debug!("→ Calling C_DecryptInit, C_Decrypt");
    let plaintext = session.decrypt(&mechanism, private_key, &ciphertext)?;

    info!(
        "Decrypted {} bytes to {} bytes",
        ciphertext.len(),
        plaintext.len()
    );

    // Write plaintext to file
    fs::write(output_path, &plaintext)?;
    println!("Data decrypted successfully");
    println!("  Input: {} ({} bytes)", input_path, ciphertext.len());
    println!("  Output: {} ({} bytes)", output_path, plaintext.len());

    debug!("→ Calling C_Logout");
    session.logout()?;
    debug!("Logged out");

    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    debug!("PKCS#11 library finalized");

    Ok(())
}

fn find_key_by_label(
    session: &cryptoki::session::Session,
    key_label: &str,
    is_private: bool,
) -> anyhow::Result<ObjectHandle> {
    let template = vec![
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::Class(if is_private {
            cryptoki::object::ObjectClass::PRIVATE_KEY
        } else {
            cryptoki::object::ObjectClass::PUBLIC_KEY
        }),
    ];

    let objects = session.find_objects(&template)?;

    if objects.is_empty() {
        anyhow::bail!("Key '{}' not found", key_label);
    }

    Ok(objects[0])
}
