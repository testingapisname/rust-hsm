use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::fs;
use tracing::{info, debug, trace};
use base64::Engine as _;

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

pub fn export_pubkey(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
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
    info!("Exporting public key '{}' from token '{}' in slot {}", key_label, label, usize::from(slot));

    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_ro_session(slot)?;
    debug!("Session opened successfully");
    
    let pin = AuthPin::new(user_pin.to_string());
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;
    debug!("Logged in as User");

    // Find the public key object
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

    // Determine key type
    debug!("→ Calling C_GetAttributeValue (KeyType)");
    let key_type = get_key_type(&session, public_key)?;
    debug!("Key type determined: {}", key_type);

    let pem_content = match key_type.as_str() {
        "RSA" => {
            info!("Exporting RSA public key");
            export_rsa_public_key(&session, public_key)?
        }
        "EC" => {
            info!("Exporting ECDSA public key");
            export_ec_public_key(&session, public_key)?
        }
        _ => {
            debug!("→ Calling C_Logout, C_Finalize");
            session.logout()?;
            pkcs11.finalize();
            anyhow::bail!("Unsupported key type for export: {}", key_type);
        }
    };

    // Write PEM to file
    fs::write(output_path, pem_content)?;
    println!("Public key exported to: {}", output_path);

    debug!("→ Calling C_Logout");
    session.logout()?;
    debug!("Logged out");
    
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    debug!("PKCS#11 library finalized");

    Ok(())
}

fn export_rsa_public_key(
    session: &cryptoki::session::Session,
    public_key: ObjectHandle,
) -> anyhow::Result<String> {
    debug!("→ Calling C_GetAttributeValue (Modulus, PublicExponent)");
    
    // Get modulus and public exponent
    let attrs = session.get_attributes(
        public_key,
        &[AttributeType::Modulus, AttributeType::PublicExponent],
    )?;

    let mut modulus = None;
    let mut public_exponent = None;

    for attr in attrs {
        match attr {
            Attribute::Modulus(m) => {
                trace!("Modulus bytes: {} bytes", m.len());
                modulus = Some(m);
            }
            Attribute::PublicExponent(e) => {
                trace!("Public exponent: {:?}", e);
                public_exponent = Some(e);
            }
            _ => {}
        }
    }

    let modulus = modulus.ok_or_else(|| anyhow::anyhow!("Modulus not found"))?;
    let public_exponent = public_exponent.ok_or_else(|| anyhow::anyhow!("Public exponent not found"))?;

    // Encode as PKCS#1 RSAPublicKey (sequence of modulus and exponent)
    let mut rsa_pub_key = Vec::new();
    
    // Sequence tag
    rsa_pub_key.push(0x30);
    
    // Calculate length of content
    let modulus_der = encode_integer(&modulus);
    let exponent_der = encode_integer(&public_exponent);
    let content_len = modulus_der.len() + exponent_der.len();
    
    // Encode length
    encode_length(&mut rsa_pub_key, content_len);
    
    // Add modulus and exponent
    rsa_pub_key.extend_from_slice(&modulus_der);
    rsa_pub_key.extend_from_slice(&exponent_der);

    // Build SubjectPublicKeyInfo structure
    // RSA algorithm OID: 1.2.840.113549.1.1.1
    let rsa_algorithm_id = build_rsa_algorithm_identifier();
    
    // BIT STRING wrapping the RSA public key
    let bit_string = encode_bit_string(&rsa_pub_key);
    
    // SEQUENCE { AlgorithmIdentifier, BIT STRING }
    let mut spki = Vec::new();
    spki.push(0x30); // SEQUENCE tag
    let content_len = rsa_algorithm_id.len() + bit_string.len();
    encode_length(&mut spki, content_len);
    spki.extend_from_slice(&rsa_algorithm_id);
    spki.extend_from_slice(&bit_string);
    
    Ok(encode_pem("PUBLIC KEY", &spki))
}

fn export_ec_public_key(
    session: &cryptoki::session::Session,
    public_key: ObjectHandle,
) -> anyhow::Result<String> {
    debug!("→ Calling C_GetAttributeValue (EcPoint, EcParams)");
    
    // Get EC point and parameters
    let attrs = session.get_attributes(
        public_key,
        &[AttributeType::EcPoint, AttributeType::EcParams],
    )?;

    let mut ec_point = None;
    let mut ec_params = None;

    for attr in attrs {
        match attr {
            Attribute::EcPoint(p) => {
                trace!("EC point bytes: {} bytes", p.len());
                ec_point = Some(p);
            }
            Attribute::EcParams(p) => {
                trace!("EC params bytes: {} bytes", p.len());
                ec_params = Some(p);
            }
            _ => {}
        }
    }

    let ec_point = ec_point.ok_or_else(|| anyhow::anyhow!("EC point not found"))?;
    let ec_params = ec_params.ok_or_else(|| anyhow::anyhow!("EC params not found"))?;

    // EC point is DER-encoded OCTET STRING, we need to extract the inner value
    let ec_point_bytes = if ec_point.len() > 2 && ec_point[0] == 0x04 {
        // Skip the OCTET STRING wrapper (tag 0x04 + length byte)
        &ec_point[2..]
    } else {
        &ec_point[..]
    };

    // Build EC algorithm identifier with curve parameters
    let ec_algorithm_id = build_ec_algorithm_identifier(&ec_params);
    
    // BIT STRING wrapping the EC point
    let bit_string = encode_bit_string(ec_point_bytes);
    
    // SEQUENCE { AlgorithmIdentifier, BIT STRING }
    let mut spki = Vec::new();
    spki.push(0x30); // SEQUENCE tag
    let content_len = ec_algorithm_id.len() + bit_string.len();
    encode_length(&mut spki, content_len);
    spki.extend_from_slice(&ec_algorithm_id);
    spki.extend_from_slice(&bit_string);
    
    Ok(encode_pem("PUBLIC KEY", &spki))
}

// Helper function to encode an integer in DER format
fn encode_integer(value: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(0x02); // INTEGER tag
    
    // Check if we need to add padding for negative interpretation
    let needs_padding = value[0] & 0x80 != 0;
    let len = if needs_padding { value.len() + 1 } else { value.len() };
    
    encode_length(&mut result, len);
    
    if needs_padding {
        result.push(0x00);
    }
    result.extend_from_slice(value);
    result
}

// Helper function to encode DER length
fn encode_length(buf: &mut Vec<u8>, length: usize) {
    if length < 128 {
        buf.push(length as u8);
    } else if length < 256 {
        buf.push(0x81);
        buf.push(length as u8);
    } else {
        buf.push(0x82);
        buf.push((length >> 8) as u8);
        buf.push(length as u8);
    }
}

// Helper function to encode a BIT STRING
fn encode_bit_string(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(0x03); // BIT STRING tag
    encode_length(&mut result, data.len() + 1);
    result.push(0x00); // No unused bits
    result.extend_from_slice(data);
    result
}

// Build RSA AlgorithmIdentifier: SEQUENCE { OID, NULL }
fn build_rsa_algorithm_identifier() -> Vec<u8> {
    let mut result = Vec::new();
    result.push(0x30); // SEQUENCE tag
    
    // RSA OID: 1.2.840.113549.1.1.1
    let oid = vec![0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    // NULL parameter
    let null = vec![0x05, 0x00];
    
    encode_length(&mut result, oid.len() + null.len());
    result.extend_from_slice(&oid);
    result.extend_from_slice(&null);
    result
}

// Build EC AlgorithmIdentifier: SEQUENCE { OID, curve_params }
fn build_ec_algorithm_identifier(curve_params: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(0x30); // SEQUENCE tag
    
    // EC public key OID: 1.2.840.10045.2.1
    let oid = vec![0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    
    encode_length(&mut result, oid.len() + curve_params.len());
    result.extend_from_slice(&oid);
    result.extend_from_slice(curve_params);
    result
}

// Encode DER bytes as PEM format
fn encode_pem(label: &str, data: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {}-----\n", label));
    
    // Split into 64-character lines
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

pub fn delete_key(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("PKCS#11 module loaded successfully");
    
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;
    debug!("PKCS#11 library initialized");

    debug!("Finding token slot for label: {}", label);
    let slot = find_token_slot(&pkcs11, label)?;
    info!("Deleting key '{}' from token '{}' in slot {}", key_label, label, usize::from(slot));

    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_rw_session(slot)?;
    debug!("Session opened successfully");
    
    let pin = AuthPin::new(user_pin.to_string());
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;
    debug!("Logged in as User");

    // Find all objects with this label (public and private key)
    debug!("→ Calling C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal");
    let template = vec![
        Attribute::Label(key_label.as_bytes().to_vec()),
    ];
    let objects = session.find_objects(&template)?;
    
    if objects.is_empty() {
        debug!("→ Calling C_Logout, C_Finalize");
        session.logout()?;
        pkcs11.finalize();
        anyhow::bail!("Key '{}' not found", key_label);
    }

    debug!("Found {} object(s) to delete", objects.len());
    
    // Delete each object (typically public and private key)
    for (i, obj) in objects.iter().enumerate() {
        debug!("→ Calling C_DestroyObject for object {}/{}", i + 1, objects.len());
        session.destroy_object(*obj)?;
        debug!("Destroyed object with handle: {:?}", obj);
    }

    println!("Key '{}' deleted successfully ({} object(s) removed)", key_label, objects.len());

    debug!("→ Calling C_Logout");
    session.logout()?;
    debug!("Logged out");
    
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    debug!("PKCS#11 library finalized");

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
    info!("Encrypting data with key '{}' on token '{}'", key_label, label);

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
    debug!("→ Calling C_EncryptInit, C_Encrypt");
    let mechanism = Mechanism::RsaPkcs;
    let ciphertext = session.encrypt(&mechanism, public_key, &plaintext)?;
    
    info!("Encrypted {} bytes to {} bytes", plaintext.len(), ciphertext.len());

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
    info!("Decrypting data with key '{}' on token '{}'", key_label, label);

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
    debug!("→ Calling C_DecryptInit, C_Decrypt");
    let mechanism = Mechanism::RsaPkcs;
    let plaintext = session.decrypt(&mechanism, private_key, &ciphertext)?;
    
    info!("Decrypted {} bytes to {} bytes", ciphertext.len(), plaintext.len());

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

pub fn gen_symmetric_key(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    bits: u32,
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
    debug!("→ Calling C_GenerateKey");
    let mechanism = Mechanism::AesKeyGen;
    let key_template = vec![
        Attribute::Token(true),
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::Id(key_label.as_bytes().to_vec()),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
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
    let iv: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
    trace!("Generated IV: {} bytes", iv.len());

    // Encrypt using AES-GCM
    debug!("→ Calling C_EncryptInit, C_Encrypt");
    let mechanism = Mechanism::AesGcm(cryptoki::mechanism::aead::GcmParams::new(&iv, &[], 128u64.into()));
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
    let iv = &data[..12];
    let ciphertext = &data[12..];
    trace!("Extracted IV: {} bytes, ciphertext: {} bytes", iv.len(), ciphertext.len());

    // Decrypt using AES-GCM
    debug!("→ Calling C_DecryptInit, C_Decrypt");
    let mechanism = Mechanism::AesGcm(cryptoki::mechanism::aead::GcmParams::new(iv, &[], 128u64.into()));
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
