use base64::Engine as _;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::fs;
use tracing::{debug, info, trace};

use super::utils::{find_token_slot, get_key_type};

pub fn export_pubkey(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    output_path: &str,
    json: bool,
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
        "Exporting public key '{}' from token '{}' in slot {}",
        key_label,
        label,
        usize::from(slot)
    );

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
    debug!("Key type determined: {:?}", key_type);

    let pem_content = match key_type {
        cryptoki::object::KeyType::RSA => {
            info!("Exporting RSA public key");
            export_rsa_public_key(&session, public_key)?
        }
        cryptoki::object::KeyType::EC => {
            info!("Exporting ECDSA public key");
            export_ec_public_key(&session, public_key)?
        }
        _ => {
            debug!("→ Calling C_Logout, C_Finalize");
            session.logout()?;
            pkcs11.finalize();
            anyhow::bail!("Unsupported key type for export: {:?}", key_type);
        }
    };

    // Write PEM to file
    fs::write(output_path, &pem_content)?;
    
    if json {
        let json_output = serde_json::json!({
            "status": "success",
            "operation": "export_pubkey",
            "key_label": key_label,
            "key_type": format!("{:?}", key_type),
            "output_file": output_path,
            "output_bytes": pem_content.len(),
            "format": "PEM"
        });
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    } else {
        println!("Public key exported to: {}", output_path);
    }

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
    let public_exponent =
        public_exponent.ok_or_else(|| anyhow::anyhow!("Public exponent not found"))?;

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
    let len = if needs_padding {
        value.len() + 1
    } else {
        value.len()
    };

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
    let oid = vec![
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
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
