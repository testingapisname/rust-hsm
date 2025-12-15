use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use tracing::{debug, info};

/// Convert a Mechanism to its CKM_ name for logging
pub(super) fn mechanism_name(mechanism: &Mechanism) -> &'static str {
    match mechanism {
        Mechanism::RsaPkcsKeyPairGen => "CKM_RSA_PKCS_KEY_PAIR_GEN",
        Mechanism::EccKeyPairGen => "CKM_EC_KEY_PAIR_GEN",
        Mechanism::Sha256RsaPkcs => "CKM_SHA256_RSA_PKCS",
        Mechanism::Ecdsa => "CKM_ECDSA",
        Mechanism::RsaPkcs => "CKM_RSA_PKCS",
        Mechanism::AesKeyGen => "CKM_AES_KEY_GEN",
        Mechanism::AesGcm(_) => "CKM_AES_GCM",
        Mechanism::AesKeyWrap => "CKM_AES_KEY_WRAP",
        _ => "CKM_UNKNOWN",
    }
}

pub fn find_token_slot(pkcs11: &Pkcs11, label: &str) -> anyhow::Result<Slot> {
    debug!("→ Calling C_GetSlotList to find token");
    let slots = pkcs11.get_slots_with_token()?;

    for slot in slots {
        if let Ok(token_info) = pkcs11.get_token_info(slot) {
            let token_label = token_info.label().trim().to_string();
            if token_label == label {
                return Ok(slot);
            }
        }
    }
    anyhow::bail!("Token with label '{}' not found", label)
}

pub(super) fn get_key_type(
    session: &Session,
    key_handle: ObjectHandle,
) -> anyhow::Result<cryptoki::object::KeyType> {
    let attributes = session.get_attributes(key_handle, &[AttributeType::KeyType])?;

    for attr in attributes {
        if let Attribute::KeyType(key_type) = attr {
            return Ok(key_type);
        }
    }

    anyhow::bail!("Could not determine key type")
}

pub fn delete_key(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    json: bool,
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
    info!(
        "Deleting key '{}' from token '{}' in slot {}",
        key_label,
        label,
        usize::from(slot)
    );
    debug!("Token found at slot: {}", usize::from(slot));

    let session = pkcs11.open_rw_session(slot)?;
    let pin = AuthPin::new(user_pin.to_string());
    session.login(UserType::User, Some(&pin))?;

    // Find all objects with this label
    let template = vec![Attribute::Label(key_label.as_bytes().to_vec())];

    debug!("→ Calling C_FindObjects to locate key objects");
    let objects = session.find_objects(&template)?;

    if objects.is_empty() {
        anyhow::bail!("Key '{}' not found", key_label);
    }

    // Delete all objects with this label (typically public + private key)
    debug!(
        "Found {} object(s) with label '{}'",
        objects.len(),
        key_label
    );
    for obj in &objects {
        debug!("→ Calling C_DestroyObject for handle {:?}", obj);
        session.destroy_object(*obj)?;
    }

    session.logout()?;
    debug!("→ Calling C_Finalize");
    drop(session);
    pkcs11.finalize();

    if json {
        let json_output = serde_json::json!({
            "status": "success",
            "operation": "delete_key",
            "key_label": key_label,
            "objects_removed": objects.len()
        });
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    } else {
        println!(
            "Key '{}' deleted successfully ({} object(s) removed)",
            key_label,
            objects.len()
        );
    }
    Ok(())
}
