use base64::Engine as _;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use sha2::{Digest, Sha256};
use simple_asn1::{to_der, ASN1Block, BigInt, BigUint, OID};
use std::fs;
use tracing::{debug, info};

use super::utils::{find_token_slot, get_key_type, mechanism_name};

/// Helper to create OID from integers
fn oid(components: &[u64]) -> OID {
    OID::new(components.iter().map(|&n| BigUint::from(n)).collect())
}

/// Generate a Certificate Signing Request (CSR) for a keypair in the HSM
pub fn generate_csr(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    subject_dn: &str,
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
        "Generating CSR for key '{}' on token '{}' in slot {}",
        key_label,
        label,
        usize::from(slot)
    );

    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_rw_session(slot)?;
    debug!("Session opened successfully");

    let pin = AuthPin::new(user_pin.to_string());
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;
    debug!("Logged in as User");

    // Find the keypair
    let (public_key_handle, private_key_handle, key_type) = find_keypair(&session, key_label)?;

    // Build the CSR
    let (tbs_der, signature_algorithm_oid) =
        build_tbs_certificate_request(&session, public_key_handle, &key_type, subject_dn)?;

    // Sign the TBS with the private key
    let signature = sign_tbs(&session, private_key_handle, &key_type, &tbs_der)?;

    // Build the complete CSR
    let csr_der = build_certificate_request(&tbs_der, &signature_algorithm_oid, &signature)?;

    // Convert to PEM
    let pem = format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
        base64::engine::general_purpose::STANDARD
            .encode(&csr_der)
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Write to file
    fs::write(output_path, pem.as_bytes())?;

    info!("CSR generated successfully");
    if json {
        let json_output = serde_json::json!({
            "status": "success",
            "operation": "generate_csr",
            "key_label": key_label,
            "subject": subject_dn,
            "key_type": format!("{:?}", key_type),
            "output_file": output_path,
            "output_bytes": pem.len(),
            "format": "PEM"
        });
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    } else {
        println!(
            "Certificate Signing Request generated for key '{}'",
            key_label
        );
        println!("  Subject: {}", subject_dn);
        println!("  Key type: {:?}", key_type);
        println!("  Output: {} ({} bytes)", output_path, pem.len());
    }

    debug!("→ Calling C_Logout");
    session.logout()?;
    debug!("→ Calling C_Finalize");
    pkcs11.finalize();

    Ok(())
}

/// Find both public and private key handles for a keypair
fn find_keypair(
    session: &cryptoki::session::Session,
    key_label: &str,
) -> anyhow::Result<(ObjectHandle, ObjectHandle, cryptoki::object::KeyType)> {
    // Find public key
    debug!("→ Calling C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal (public key)");
    let pub_template = vec![
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::Class(cryptoki::object::ObjectClass::PUBLIC_KEY),
    ];
    let pub_objects = session.find_objects(&pub_template)?;

    if pub_objects.is_empty() {
        anyhow::bail!("Public key '{}' not found", key_label);
    }
    let public_key_handle = pub_objects[0];

    // Find private key
    debug!("→ Calling C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal (private key)");
    let priv_template = vec![
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
    ];
    let priv_objects = session.find_objects(&priv_template)?;

    if priv_objects.is_empty() {
        anyhow::bail!("Private key '{}' not found", key_label);
    }
    let private_key_handle = priv_objects[0];

    // Get key type
    let key_type = get_key_type(session, public_key_handle)?;

    Ok((public_key_handle, private_key_handle, key_type))
}

/// Build the TBS (To Be Signed) part of the certificate request
fn build_tbs_certificate_request(
    session: &cryptoki::session::Session,
    public_key_handle: ObjectHandle,
    key_type: &cryptoki::object::KeyType,
    subject_dn: &str,
) -> anyhow::Result<(Vec<u8>, OID)> {
    use cryptoki::object::KeyType;

    // Parse subject DN
    let subject_name = parse_subject_dn(subject_dn)?;

    // Get public key info
    let (public_key_algorithm, _) = get_public_key_info(session, public_key_handle, key_type)?;

    // Determine signature algorithm OID
    let signature_algorithm_oid = match *key_type {
        KeyType::RSA => oid(&[1, 2, 840, 113549, 1, 1, 11]), // sha256WithRSAEncryption
        KeyType::EC => oid(&[1, 2, 840, 10045, 4, 3, 2]),    // ecdsa-with-SHA256
        _ => anyhow::bail!("Unsupported key type: {:?}", key_type),
    };

    // Build CertificationRequestInfo: SEQUENCE { version, subject, subjectPKInfo, attributes }
    // We need to manually construct this because simple_asn1 doesn't properly encode
    // context-specific implicit tags in to_der()

    // First encode the three main components
    let version = ASN1Block::Integer(0, BigInt::from(0));
    let version_der = to_der(&version)?;
    let subject_der = to_der(&subject_name)?;
    let spki_der = to_der(&public_key_algorithm)?;

    // Manually encode empty attributes with [0] IMPLICIT tag
    // [0] means context-specific, constructed, tag 0
    // Empty attributes = tag 0xA0, length 0x00
    let attributes_der = vec![0xA0, 0x00];

    // Calculate total length for the SEQUENCE
    let content_len = version_der.len() + subject_der.len() + spki_der.len() + attributes_der.len();

    // Build SEQUENCE manually
    let mut tbs_der = Vec::new();
    tbs_der.push(0x30); // SEQUENCE tag

    // Encode length (DER length encoding)
    if content_len < 128 {
        tbs_der.push(content_len as u8);
    } else if content_len < 256 {
        tbs_der.push(0x81); // long form, 1 byte
        tbs_der.push(content_len as u8);
    } else {
        tbs_der.push(0x82); // long form, 2 bytes
        tbs_der.push((content_len >> 8) as u8);
        tbs_der.push((content_len & 0xFF) as u8);
    }

    // Append all components
    tbs_der.extend_from_slice(&version_der);
    tbs_der.extend_from_slice(&subject_der);
    tbs_der.extend_from_slice(&spki_der);
    tbs_der.extend_from_slice(&attributes_der);

    Ok((tbs_der, signature_algorithm_oid))
}

/// Parse subject DN string into ASN.1 Name structure
fn parse_subject_dn(dn: &str) -> anyhow::Result<ASN1Block> {
    let mut rdns = Vec::new();

    for component in dn.split(',') {
        let component = component.trim();
        let parts: Vec<&str> = component.splitn(2, '=').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid DN component: {}", component);
        }

        let attr_type = parts[0].trim();
        let attr_value = parts[1].trim();

        let attribute_oid = match attr_type {
            "CN" => oid(&[2, 5, 4, 3]),
            "O" => oid(&[2, 5, 4, 10]),
            "OU" => oid(&[2, 5, 4, 11]),
            "C" => oid(&[2, 5, 4, 6]),
            "ST" => oid(&[2, 5, 4, 8]),
            "L" => oid(&[2, 5, 4, 7]),
            _ => anyhow::bail!("Unsupported DN attribute: {}", attr_type),
        };

        // Build AttributeTypeAndValue: SEQUENCE { type OID, value ANY }
        let atv = ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::ObjectIdentifier(0, attribute_oid),
                if attr_type == "C" {
                    ASN1Block::PrintableString(0, attr_value.to_string())
                } else {
                    ASN1Block::UTF8String(0, attr_value.to_string())
                },
            ],
        );

        // Wrap in SET
        rdns.push(ASN1Block::Set(0, vec![atv]));
    }

    Ok(ASN1Block::Sequence(0, rdns))
}

/// Get public key algorithm and bitstring
fn get_public_key_info(
    session: &cryptoki::session::Session,
    public_key_handle: ObjectHandle,
    key_type: &cryptoki::object::KeyType,
) -> anyhow::Result<(ASN1Block, ASN1Block)> {
    use cryptoki::object::KeyType;

    match *key_type {
        KeyType::RSA => {
            debug!("→ Calling C_GetAttributeValue (RSA modulus and exponent)");
            let attrs = session.get_attributes(
                public_key_handle,
                &[AttributeType::Modulus, AttributeType::PublicExponent],
            )?;

            let mut modulus = None;
            let mut exponent = None;

            for attr in attrs {
                match attr {
                    Attribute::Modulus(m) => modulus = Some(m),
                    Attribute::PublicExponent(e) => exponent = Some(e),
                    _ => {}
                }
            }

            let modulus = modulus.ok_or_else(|| anyhow::anyhow!("Failed to get modulus"))?;
            let exponent = exponent.ok_or_else(|| anyhow::anyhow!("Failed to get exponent"))?;

            // Build RSA public key: SEQUENCE { modulus INTEGER, exponent INTEGER }
            let rsa_key = ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::Integer(0, BigInt::from_bytes_be(num_bigint::Sign::Plus, &modulus)),
                    ASN1Block::Integer(0, BigInt::from_bytes_be(num_bigint::Sign::Plus, &exponent)),
                ],
            );

            let rsa_key_der = to_der(&rsa_key)?;

            // Build AlgorithmIdentifier: SEQUENCE { algorithm OID, parameters NULL }
            let algorithm = ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::ObjectIdentifier(0, oid(&[1, 2, 840, 113549, 1, 1, 1])), // rsaEncryption
                    ASN1Block::Null(0),
                ],
            );

            // Build SubjectPublicKeyInfo: SEQUENCE { algorithm, subjectPublicKey BIT STRING }
            let spki = ASN1Block::Sequence(
                0,
                vec![
                    algorithm,
                    ASN1Block::BitString(0, rsa_key_der.len() * 8, rsa_key_der),
                ],
            );

            Ok((spki, ASN1Block::BitString(0, 0, Vec::new())))
        }
        KeyType::EC => {
            debug!("→ Calling C_GetAttributeValue (EC params and point)");
            let attrs = session.get_attributes(
                public_key_handle,
                &[AttributeType::EcParams, AttributeType::EcPoint],
            )?;

            let mut ec_params = None;
            let mut ec_point = None;

            for attr in attrs {
                match attr {
                    Attribute::EcParams(p) => ec_params = Some(p),
                    Attribute::EcPoint(pt) => ec_point = Some(pt),
                    _ => {}
                }
            }

            let ec_params = ec_params.ok_or_else(|| anyhow::anyhow!("Failed to get EC params"))?;
            let ec_point = ec_point.ok_or_else(|| anyhow::anyhow!("Failed to get EC point"))?;

            // EC point is DER-encoded OCTET STRING, extract the actual point
            let point_bytes = if ec_point.starts_with(&[0x04]) && ec_point.len() > 2 {
                let len = ec_point[1] as usize;
                if ec_point.len() >= len + 2 {
                    &ec_point[2..2 + len]
                } else {
                    &ec_point[..]
                }
            } else {
                &ec_point[..]
            };

            // For EC params, just parse the existing DER
            use simple_asn1::from_der;
            let ec_params_block = from_der(&ec_params)?;
            let ec_params_asn = ec_params_block
                .first()
                .ok_or_else(|| anyhow::anyhow!("Failed to parse EC params"))?;

            // Build AlgorithmIdentifier: SEQUENCE { algorithm OID, parameters (EC params) }
            let algorithm = ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::ObjectIdentifier(0, oid(&[1, 2, 840, 10045, 2, 1])), // ecPublicKey
                    ec_params_asn.clone(),                                          // EC parameters
                ],
            );

            // Build SubjectPublicKeyInfo: SEQUENCE { algorithm, subjectPublicKey BIT STRING }
            let spki = ASN1Block::Sequence(
                0,
                vec![
                    algorithm,
                    ASN1Block::BitString(0, point_bytes.len() * 8, point_bytes.to_vec()),
                ],
            );

            Ok((spki, ASN1Block::BitString(0, 0, Vec::new())))
        }
        _ => anyhow::bail!("Unsupported key type: {:?}", key_type),
    }
}

/// Sign the TBS data with the private key
fn sign_tbs(
    session: &cryptoki::session::Session,
    private_key_handle: ObjectHandle,
    key_type: &cryptoki::object::KeyType,
    tbs_bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use cryptoki::object::KeyType;

    match *key_type {
        KeyType::RSA => {
            let mechanism = Mechanism::Sha256RsaPkcs;
            debug!(
                "Using CSR signing mechanism: {}",
                mechanism_name(&mechanism)
            );
            debug!("→ Calling C_Sign");
            let signature = session.sign(&mechanism, private_key_handle, tbs_bytes)?;
            Ok(signature)
        }
        KeyType::EC => {
            // For ECDSA, hash manually
            let mut hasher = Sha256::new();
            hasher.update(tbs_bytes);
            let hash = hasher.finalize();

            let mechanism = Mechanism::Ecdsa;
            debug!(
                "Using CSR signing mechanism: {}",
                mechanism_name(&mechanism)
            );
            debug!("→ Calling C_Sign");
            let raw_signature = session.sign(&mechanism, private_key_handle, &hash)?;

            // PKCS#11 returns ECDSA signature as raw r || s concatenation
            // X.509 CSR requires DER-encoded SEQUENCE { r INTEGER, s INTEGER }
            let signature = encode_ecdsa_signature(&raw_signature)?;
            Ok(signature)
        }
        _ => anyhow::bail!("Unsupported key type: {:?}", key_type),
    }
}

/// Convert raw ECDSA signature (r || s) to DER-encoded SEQUENCE { r INTEGER, s INTEGER }
#[allow(clippy::manual_is_multiple_of)] // is_multiple_of() not stable in Rust 1.83 (Docker)
fn encode_ecdsa_signature(raw_sig: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Split raw signature into r and s components (equal length)
    if raw_sig.len() % 2 != 0 {
        anyhow::bail!("Invalid ECDSA signature length: {}", raw_sig.len());
    }

    let component_len = raw_sig.len() / 2;
    let r_bytes = &raw_sig[..component_len];
    let s_bytes = &raw_sig[component_len..];

    // Convert to BigInt (note: PKCS#11 uses big-endian)
    let r = BigInt::from_bytes_be(num_bigint::Sign::Plus, r_bytes);
    let s = BigInt::from_bytes_be(num_bigint::Sign::Plus, s_bytes);

    // Build DER SEQUENCE { r INTEGER, s INTEGER }
    let sig_seq = ASN1Block::Sequence(0, vec![ASN1Block::Integer(0, r), ASN1Block::Integer(0, s)]);

    Ok(to_der(&sig_seq)?)
}

/// Build the complete CertificationRequest structure
fn build_certificate_request(
    tbs_der: &[u8],
    signature_algorithm_oid: &OID,
    signature: &[u8],
) -> anyhow::Result<Vec<u8>> {
    // Parse TBS back to ASN1Block for inclusion
    use simple_asn1::from_der;
    let tbs_block = from_der(tbs_der)?;
    let tbs_block = tbs_block
        .first()
        .ok_or_else(|| anyhow::anyhow!("Failed to parse TBS"))?;

    // Build AlgorithmIdentifier for signature
    let sig_algorithm = ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::ObjectIdentifier(0, signature_algorithm_oid.clone()),
            ASN1Block::Null(0),
        ],
    );

    // Build CertificationRequest: SEQUENCE { certificationRequestInfo, signatureAlgorithm, signature }
    let cert_req = ASN1Block::Sequence(
        0,
        vec![
            tbs_block.clone(),
            sig_algorithm,
            ASN1Block::BitString(0, signature.len() * 8, signature.to_vec()),
        ],
    );

    Ok(to_der(&cert_req)?)
}
