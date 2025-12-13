use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::fs;
use tracing::{info, debug, trace};

pub fn gen_keypair(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    key_type: &str,
    bits: u32,
) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("PKCS#11 module loaded successfully");
    
    debug!("Initializing PKCS#11 library with OS threads");
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;
    debug!("PKCS#11 library initialized");

    debug!("Finding token slot for label: {}", label);
    let slot = find_token_slot(&pkcs11, label)?;
    info!("Generating {} keypair on token '{}' in slot {}", key_type, label, usize::from(slot));
    debug!("Token found at slot: {}", usize::from(slot));

    let session = pkcs11.open_rw_session(slot)?;
    let pin = AuthPin::new(user_pin.to_string());
    session.login(UserType::User, Some(&pin))?;

    match key_type.to_lowercase().as_str() {
        "rsa" => {
            debug!("Using RSA key generation mechanism");
            let mechanism = Mechanism::RsaPkcsKeyPairGen;
            debug!("Generating RSA-{} keypair", bits);
            
            let public_key_template = vec![
                Attribute::Token(true),
                Attribute::Label(key_label.as_bytes().to_vec()),
                Attribute::Id(key_label.as_bytes().to_vec()),
                Attribute::Encrypt(true),
                Attribute::Verify(true),
                Attribute::ModulusBits(cryptoki::types::Ulong::from(bits as u64)),
                Attribute::PublicExponent(vec![0x01, 0x00, 0x01]), // 65537
            ];

            let private_key_template = vec![
                Attribute::Token(true),
                Attribute::Label(key_label.as_bytes().to_vec()),
                Attribute::Id(key_label.as_bytes().to_vec()),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Decrypt(true),
                Attribute::Sign(true),
            ];

            let (public_key, private_key) = session.generate_key_pair(
                &mechanism,
                &public_key_template,
                &private_key_template,
            )?;

            println!("RSA-{} keypair '{}' generated successfully", bits, key_label);
            println!("  Public key handle: {:?}", public_key);
            println!("  Private key handle: {:?}", private_key);
        }
        "ecdsa" | "ec" | "p256" | "p384" => {
            debug!("Using ECDSA key generation mechanism");
            let mechanism = Mechanism::EccKeyPairGen;
            
            // EC parameters: ANSI X9.62 named curves
            let ec_params = match key_type.to_lowercase().as_str() {
                "p256" | "ec" | "ecdsa" => {
                    // secp256r1 / prime256v1 OID: 1.2.840.10045.3.1.7
                    vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
                }
                "p384" => {
                    // secp384r1 OID: 1.3.132.0.34
                    vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
                }
                _ => {
                    anyhow::bail!("Unsupported EC curve. Use 'p256' or 'p384'");
                }
            };
            
            let public_key_template = vec![
                Attribute::Token(true),
                Attribute::Label(key_label.as_bytes().to_vec()),
                Attribute::Id(key_label.as_bytes().to_vec()),
                Attribute::Verify(true),
                Attribute::EcParams(ec_params),
            ];

            let private_key_template = vec![
                Attribute::Token(true),
                Attribute::Label(key_label.as_bytes().to_vec()),
                Attribute::Id(key_label.as_bytes().to_vec()),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Sign(true),
            ];

            let (public_key, private_key) = session.generate_key_pair(
                &mechanism,
                &public_key_template,
                &private_key_template,
            )?;

            let curve_name = match key_type.to_lowercase().as_str() {
                "p384" => "P-384",
                _ => "P-256",
            };
            println!("ECDSA {} keypair '{}' generated successfully", curve_name, key_label);
            println!("  Public key handle: {:?}", public_key);
            println!("  Private key handle: {:?}", private_key);
        }
        _ => {
            anyhow::bail!("Unsupported key type: {}. Use 'rsa' or 'ecdsa'", key_type);
        }
    }

    session.logout()?;
    pkcs11.finalize();

    Ok(())
}

pub fn sign(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    input_path: &str,
    output_path: &str,
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
    trace!("Input data (first 32 bytes): {:02x?}", &data[..data.len().min(32)]);

    // Select appropriate signing mechanism
    let mechanism = match key_type.as_str() {
        "RSA" => Mechanism::Sha256RsaPkcs,
        "EC" => Mechanism::Ecdsa, // For ECDSA, we need to hash manually
        _ => anyhow::bail!("Unsupported key type for signing: {}", key_type),
    };

    let signature = if key_type == "EC" {
        // For ECDSA, we hash the data first
        use sha2::{Sha256, Digest};
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
    
    println!("Signature created successfully");
    println!("  Input: {} ({} bytes)", input_path, data.len());
    println!("  Signature: {} ({} bytes)", output_path, signature.len());

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
) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module for verification operation");
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    debug!("Finding token slot for label: {}", label);
    let slot = find_token_slot(&pkcs11, label)?;
    info!("Verifying signature with key '{}' on token '{}'", key_label, label);
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
    info!("Read {} bytes of data and {} bytes of signature", data.len(), signature.len());
    trace!("Input data (first 32 bytes): {:02x?}", &data[..data.len().min(32)]);
    trace!("Signature (first 32 bytes): {:02x?}", &signature[..signature.len().min(32)]);

    // Determine key type and select appropriate mechanism
    debug!("Querying key type from key handle");
    debug!("→ Calling C_GetAttributeValue");
    let key_type = get_key_type(&session, key_handle)?;
    debug!("Key type detected: {}", key_type);
    let mechanism = match key_type.as_str() {
        "RSA" => Mechanism::Sha256RsaPkcs,
        "EC" => Mechanism::Ecdsa,
        _ => anyhow::bail!("Unsupported key type: {}", key_type),
    };

    // For ECDSA, we need to hash the data first
    let verify_result = if key_type == "EC" {
        debug!("ECDSA detected: computing SHA-256 hash of input data");
        use sha2::{Sha256, Digest};
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
            println!("✓ Signature verification successful");
            println!("  Input: {} ({} bytes)", input_path, data.len());
            println!("  Signature: {} ({} bytes)", signature_path, signature.len());
            println!("  Key type: {}", key_type);
        }
        Err(e) => {
            debug!("PKCS#11 verify operation failed: {:?}", e);
            println!("✗ Signature verification failed: {}", e);
            anyhow::bail!("Verification failed");
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

fn get_key_type(
    session: &cryptoki::session::Session,
    key_handle: ObjectHandle,
) -> anyhow::Result<String> {
    use cryptoki::object::KeyType;
    
    debug!("Querying KeyType attribute from handle: {:?}", key_handle);
    debug!("→ Calling C_GetAttributeValue");
    let attrs = session.get_attributes(key_handle, &[AttributeType::KeyType])?;
    trace!("Received attributes: {:?}", attrs);
    
    if let Some(Attribute::KeyType(key_type)) = attrs.first() {
        match key_type {
            &KeyType::RSA => {
                debug!("Key type is RSA");
                Ok("RSA".to_string())
            }
            &KeyType::EC => {
                debug!("Key type is EC (Elliptic Curve)");
                Ok("EC".to_string())
            }
            _ => {
                debug!("Unsupported key type: {:?}", key_type);
                anyhow::bail!("Unsupported key type: {:?}", key_type)
            }
        }
    } else {
        debug!("KeyType attribute not found in response");
        anyhow::bail!("Could not determine key type")
    }
}
