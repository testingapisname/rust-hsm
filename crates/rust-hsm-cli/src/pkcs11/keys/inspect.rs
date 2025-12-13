use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use anyhow::{Context, Result};
use tracing::{debug, info};

use super::utils::find_token_slot;

/// Display detailed attributes for a key
pub fn inspect_key(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
    key_label: &str,
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

    println!("\nKey: '{}' ({} object(s) found)", key_label, handles.len());
    println!("{}", "=".repeat(80));

    for (idx, handle) in handles.iter().enumerate() {
        if handles.len() > 1 {
            println!("\nObject {} (Handle: {:?}):", idx + 1, handle);
            println!("{}", "-".repeat(80));
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

        for attr_type in attrs_to_query {
            match session.get_attributes(*handle, &[attr_type]) {
                Ok(attrs) => {
                    if let Some(attr) = attrs.first() {
                        print_attribute(attr, attr_type);
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

    Ok(())
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
