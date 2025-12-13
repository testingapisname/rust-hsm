use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use anyhow::{Context, Result};
use tracing::{debug, info};
use sha2::{Sha256, Digest};

use super::utils::find_token_slot;

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Display detailed attributes for a key
pub fn inspect_key(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
    key_label: &str,
    json_output: bool,
) -> Result<()> {
    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;
    
    pkcs11.initialize(CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11 module")?;

    let slot_id = find_token_slot(&pkcs11, token_label)?;

    info!("Inspecting key '{}' on token '{}'", key_label, token_label);

    let session = pkcs11.open_rw_session(slot_id)
        .context("Failed to open read-write session")?;
    
    let pin = AuthPin::new(user_pin.to_string());
    session.login(UserType::User, Some(&pin))
        .context("Failed to login with user PIN")?;

    // Search for all objects with this label
    let template = vec![
        Attribute::Label(key_label.as_bytes().to_vec()),
    ];

    let handles = session.find_objects(&template)
        .context("Failed to search for objects")?;

    if handles.is_empty() {
        anyhow::bail!("No objects found with label '{}'", key_label);
    }

    // Get all available attributes
    let attrs_to_query = vec![
        AttributeType::Class,
        AttributeType::KeyType,
        AttributeType::Label,
        AttributeType::Id,
        AttributeType::Token,
        AttributeType::Private,
        AttributeType::Modifiable,
        AttributeType::Sensitive,
        AttributeType::Extractable,
        AttributeType::Sign,
        AttributeType::Verify,
        AttributeType::Encrypt,
        AttributeType::Decrypt,
        AttributeType::Wrap,
        AttributeType::Unwrap,
        AttributeType::Derive,
        AttributeType::Local,
        AttributeType::AlwaysSensitive,
        AttributeType::NeverExtractable,
        AttributeType::ValueLen,
        AttributeType::Modulus,
        AttributeType::PublicExponent,
        AttributeType::EcParams,
        AttributeType::EcPoint,
    ];

    if json_output {
        output_json_inspect(key_label, &handles, &session, &attrs_to_query)?;
    } else {
        println!("\nKey: '{}' ({} object(s) found)", key_label, handles.len());
        println!("{}", "=".repeat(80));

        for (idx, handle) in handles.iter().enumerate() {
            if handles.len() > 1 {
                println!("\nObject {} (Handle: {:?}):", idx + 1, handle);
                println!("{}", "-".repeat(80));
            }

            // Calculate fingerprint for public keys
            let fingerprint = calculate_fingerprint(&session, *handle);
            if let Some(fp) = &fingerprint {
                println!("  FINGERPRINT (SHA-256):  {}", fp);
            }

            for attr_type in &attrs_to_query {
                match session.get_attributes(*handle, &[*attr_type]) {
                    Ok(attrs) => {
                        if let Some(attr) = attrs.first() {
                            print_attribute(attr, *attr_type);
                        }
                    }
                    Err(_) => {
                        // Attribute not available for this object type
                        debug!("Attribute {:?} not available", attr_type);
                    }
                }
            }
        }

        println!("\n{}", "=".repeat(80));
    }

    Ok(())
}

/// Calculate SHA-256 fingerprint of public key material
fn calculate_fingerprint(
    session: &cryptoki::session::Session,
    handle: cryptoki::object::ObjectHandle,
) -> Option<String> {
    // First check if this is a public key
    if let Ok(attrs) = session.get_attributes(handle, &[AttributeType::Class]) {
        if let Some(Attribute::Class(class)) = attrs.first() {
            if *class != ObjectClass::PUBLIC_KEY {
                return None;  // Only fingerprint public keys
            }
        }
    }

    // Get key type
    let key_type = if let Ok(attrs) = session.get_attributes(handle, &[AttributeType::KeyType]) {
        attrs.first().cloned()
    } else {
        return None;
    };

    let mut hasher = Sha256::new();
    let mut has_data = false;

    // Try RSA attributes first (modulus + public exponent)
    if let Ok(attrs) = session.get_attributes(handle, &[AttributeType::Modulus, AttributeType::PublicExponent]) {
        let mut found_modulus = false;
        let mut found_exponent = false;
        
        for attr in attrs {
            match attr {
                Attribute::Modulus(m) => {
                    hasher.update(&m);
                    found_modulus = true;
                }
                Attribute::PublicExponent(e) => {
                    hasher.update(&e);
                    found_exponent = true;
                }
                _ => {}
            }
        }
        
        if found_modulus && found_exponent {
            has_data = true;
        }
    }
    
    // If not RSA, try EC attributes (params + point)
    if !has_data {
        if let Ok(attrs) = session.get_attributes(handle, &[AttributeType::EcParams, AttributeType::EcPoint]) {
            for attr in attrs {
                match attr {
                    Attribute::EcParams(p) => {
                        hasher.update(&p);
                        has_data = true;
                    }
                    Attribute::EcPoint(pt) => {
                        hasher.update(&pt);
                        has_data = true;
                    }
                    _ => {}
                }
            }
        }
    }
    
    if !has_data {
        return None;  // No key material found
    }

    let result = hasher.finalize();
    
    // Format as colon-separated hex (like SSH fingerprints)
    let fingerprint = result.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":");
    
    Some(fingerprint)
}

fn print_attribute(attr: &Attribute, attr_type: AttributeType) {
    match attr {
        Attribute::Class(c) => {
            println!("  CKA_CLASS:              {:?}", c);
        }
        Attribute::KeyType(kt) => {
            println!("  CKA_KEY_TYPE:           {:?}", kt);
        }
        Attribute::Label(l) => {
            if let Ok(s) = String::from_utf8(l.clone()) {
                println!("  CKA_LABEL:              {}", s);
            }
        }
        Attribute::Id(id) => {
            if let Ok(s) = String::from_utf8(id.clone()) {
                println!("  CKA_ID:                 {}", s);
            } else {
                println!("  CKA_ID:                 {} bytes (binary)", id.len());
            }
        }
        Attribute::Token(b) => {
            println!("  CKA_TOKEN:              {}", b);
        }
        Attribute::Private(b) => {
            println!("  CKA_PRIVATE:            {}", b);
        }
        Attribute::Modifiable(b) => {
            println!("  CKA_MODIFIABLE:         {}", b);
        }
        Attribute::Sensitive(b) => {
            println!("  CKA_SENSITIVE:          {}", b);
        }
        Attribute::Extractable(b) => {
            println!("  CKA_EXTRACTABLE:        {}", b);
        }
        Attribute::Sign(b) => {
            println!("  CKA_SIGN:               {}", b);
        }
        Attribute::Verify(b) => {
            println!("  CKA_VERIFY:             {}", b);
        }
        Attribute::Encrypt(b) => {
            println!("  CKA_ENCRYPT:            {}", b);
        }
        Attribute::Decrypt(b) => {
            println!("  CKA_DECRYPT:            {}", b);
        }
        Attribute::Wrap(b) => {
            println!("  CKA_WRAP:               {}", b);
        }
        Attribute::Unwrap(b) => {
            println!("  CKA_UNWRAP:             {}", b);
        }
        Attribute::Derive(b) => {
            println!("  CKA_DERIVE:             {}", b);
        }
        Attribute::Local(b) => {
            println!("  CKA_LOCAL:              {}", b);
        }
        Attribute::AlwaysSensitive(b) => {
            println!("  CKA_ALWAYS_SENSITIVE:   {}", b);
        }
        Attribute::NeverExtractable(b) => {
            println!("  CKA_NEVER_EXTRACTABLE:  {}", b);
        }
        Attribute::ValueLen(len) => {
            println!("  CKA_VALUE_LEN:          {} bytes", u64::from(*len));
        }
        Attribute::Modulus(m) => {
            println!("  CKA_MODULUS:            {} bits ({} bytes)", m.len() * 8, m.len());
        }
        Attribute::PublicExponent(e) => {
            let exp_val = if e.len() <= 8 {
                let mut val: u64 = 0;
                for byte in e {
                    val = (val << 8) | (*byte as u64);
                }
                format!("{}", val)
            } else {
                format!("{} bytes", e.len())
            };
            println!("  CKA_PUBLIC_EXPONENT:    {}", exp_val);
        }
        Attribute::EcParams(p) => {
            let curve = match p.as_slice() {
                [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => "P-256 (secp256r1)",
                [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] => "P-384 (secp384r1)",
                _ => "Unknown curve",
            };
            println!("  CKA_EC_PARAMS:          {} ({} bytes)", curve, p.len());
        }
        Attribute::EcPoint(pt) => {
            println!("  CKA_EC_POINT:           {} bytes", pt.len());
        }
        _ => {
            debug!("Unhandled attribute type: {:?}", attr_type);
        }
    }
}

fn output_json_inspect(
    key_label: &str,
    handles: &[cryptoki::object::ObjectHandle],
    session: &cryptoki::session::Session,
    attrs_to_query: &[AttributeType],
) -> Result<()> {
    #[derive(Serialize)]
    struct KeyInspection {
        key_label: String,
        object_count: usize,
        objects: Vec<KeyObject>,
    }
    
    #[derive(Serialize)]
    struct KeyObject {
        handle: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        fingerprint: Option<String>,
        attributes: HashMap<String, serde_json::Value>,
    }
    
    let mut objects = Vec::new();
    
    for handle in handles {
        let mut attributes = HashMap::new();
        
        // Calculate fingerprint
        let fingerprint = calculate_fingerprint(session, *handle);
        
        for attr_type in attrs_to_query {
            if let Ok(attrs) = session.get_attributes(*handle, &[*attr_type]) {
                if let Some(attr) = attrs.first() {
                    let (key, value) = attribute_to_json(attr);
                    if let Some(v) = value {
                        attributes.insert(key, v);
                    }
                }
            }
        }
        
        objects.push(KeyObject {
            handle: format!("{:?}", handle),
            fingerprint,
            attributes,
        });
    }
    
    let inspection = KeyInspection {
        key_label: key_label.to_string(),
        object_count: handles.len(),
        objects,
    };
    
    println!("{}", serde_json::to_string_pretty(&inspection)?);
    Ok(())
}

fn attribute_to_json(attr: &Attribute) -> (String, Option<serde_json::Value>) {
    use serde_json::json;
    
    match attr {
        Attribute::Class(c) => ("CKA_CLASS".to_string(), Some(json!(format!("{:?}", c)))),
        Attribute::KeyType(kt) => ("CKA_KEY_TYPE".to_string(), Some(json!(format!("{:?}", kt)))),
        Attribute::Label(l) => {
            if let Ok(s) = String::from_utf8(l.clone()) {
                ("CKA_LABEL".to_string(), Some(json!(s)))
            } else {
                ("CKA_LABEL".to_string(), None)
            }
        }
        Attribute::Id(id) => {
            if let Ok(s) = String::from_utf8(id.clone()) {
                ("CKA_ID".to_string(), Some(json!(s)))
            } else {
                ("CKA_ID".to_string(), Some(json!({ "type": "binary", "length": id.len() })))
            }
        }
        Attribute::Token(b) => ("CKA_TOKEN".to_string(), Some(json!(b))),
        Attribute::Private(b) => ("CKA_PRIVATE".to_string(), Some(json!(b))),
        Attribute::Modifiable(b) => ("CKA_MODIFIABLE".to_string(), Some(json!(b))),
        Attribute::Sensitive(b) => ("CKA_SENSITIVE".to_string(), Some(json!(b))),
        Attribute::Extractable(b) => ("CKA_EXTRACTABLE".to_string(), Some(json!(b))),
        Attribute::Sign(b) => ("CKA_SIGN".to_string(), Some(json!(b))),
        Attribute::Verify(b) => ("CKA_VERIFY".to_string(), Some(json!(b))),
        Attribute::Encrypt(b) => ("CKA_ENCRYPT".to_string(), Some(json!(b))),
        Attribute::Decrypt(b) => ("CKA_DECRYPT".to_string(), Some(json!(b))),
        Attribute::Wrap(b) => ("CKA_WRAP".to_string(), Some(json!(b))),
        Attribute::Unwrap(b) => ("CKA_UNWRAP".to_string(), Some(json!(b))),
        Attribute::Derive(b) => ("CKA_DERIVE".to_string(), Some(json!(b))),
        Attribute::Local(b) => ("CKA_LOCAL".to_string(), Some(json!(b))),
        Attribute::AlwaysSensitive(b) => ("CKA_ALWAYS_SENSITIVE".to_string(), Some(json!(b))),
        Attribute::NeverExtractable(b) => ("CKA_NEVER_EXTRACTABLE".to_string(), Some(json!(b))),
        Attribute::ValueLen(len) => ("CKA_VALUE_LEN".to_string(), Some(json!(u64::from(*len)))),
        Attribute::Modulus(m) => ("CKA_MODULUS".to_string(), Some(json!({"bits": m.len() * 8, "bytes": m.len()}))),
        Attribute::PublicExponent(e) => {
            if e.len() <= 8 {
                let mut val: u64 = 0;
                for byte in e {
                    val = (val << 8) | (*byte as u64);
                }
                ("CKA_PUBLIC_EXPONENT".to_string(), Some(json!(val)))
            } else {
                ("CKA_PUBLIC_EXPONENT".to_string(), Some(json!({"bytes": e.len()})))
            }
        }
        Attribute::EcParams(p) => {
            let curve = match p.as_slice() {
                [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => "P-256 (secp256r1)",
                [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] => "P-384 (secp384r1)",
                _ => "Unknown curve",
            };
            ("CKA_EC_PARAMS".to_string(), Some(json!({"curve": curve, "bytes": p.len()})))
        }
        Attribute::EcPoint(pt) => ("CKA_EC_POINT".to_string(), Some(json!({"bytes": pt.len()}))),
        _ => ("UNKNOWN".to_string(), None),
    }
}
