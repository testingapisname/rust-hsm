use crate::pkcs11::keys::find_token_slot;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use tracing::{debug, info};

/// Explain a PKCS#11 error code with context and troubleshooting steps
pub fn explain_error(error_code: &str, context: Option<&str>) -> anyhow::Result<()> {
    println!("\n=== PKCS#11 Error Explanation ===\n");

    let (code_name, hex_value, description, causes) = match error_code.to_uppercase().as_str() {
        "CKR_OK" | "0X00000000" | "0" => ("CKR_OK", "0x00000000", "Success - no error", vec![]),
        "CKR_CANCEL" | "0X00000001" | "1" => (
            "CKR_CANCEL",
            "0x00000001",
            "Operation was cancelled",
            vec![
                "User cancelled the operation",
                "Application requested cancellation",
            ],
        ),
        "CKR_HOST_MEMORY" | "0X00000002" | "2" => (
            "CKR_HOST_MEMORY",
            "0x00000002",
            "Insufficient host memory",
            vec![
                "System out of memory",
                "Memory allocation failed",
                "Too many concurrent operations",
            ],
        ),
        "CKR_SLOT_ID_INVALID" | "0X00000003" | "3" => (
            "CKR_SLOT_ID_INVALID",
            "0x00000003",
            "Invalid slot ID specified",
            vec![
                "Slot number doesn't exist",
                "Using slot number instead of finding by token label",
                "HSM not connected",
            ],
        ),
        "CKR_GENERAL_ERROR" | "0X00000005" | "5" => (
            "CKR_GENERAL_ERROR",
            "0x00000005",
            "General unspecified error",
            vec![
                "Hardware failure",
                "HSM internal error",
                "Check HSM logs for details",
            ],
        ),
        "CKR_FUNCTION_FAILED" | "0X00000006" | "6" => (
            "CKR_FUNCTION_FAILED",
            "0x00000006",
            "Function failed for unspecified reason",
            vec![
                "Operation failed on HSM",
                "Check mechanism support",
                "Verify key attributes match operation",
            ],
        ),
        "CKR_ARGUMENTS_BAD" | "0X00000007" | "7" => (
            "CKR_ARGUMENTS_BAD",
            "0x00000007",
            "Invalid arguments provided to function",
            vec![
                "NULL pointer passed",
                "Invalid parameter value",
                "Incorrect argument combination",
            ],
        ),
        "CKR_ATTRIBUTE_TYPE_INVALID" | "0X00000012" | "18" => (
            "CKR_ATTRIBUTE_TYPE_INVALID",
            "0x00000012",
            "Invalid or unsupported attribute type",
            vec![
                "Attribute not supported for this object",
                "Vendor-specific attribute not recognized",
            ],
        ),
        "CKR_ATTRIBUTE_VALUE_INVALID" | "0X00000013" | "19" => (
            "CKR_ATTRIBUTE_VALUE_INVALID",
            "0x00000013",
            "Invalid attribute value",
            vec![
                "Value out of range",
                "Conflicting attribute values",
                "Type mismatch",
            ],
        ),
        "CKR_DATA_INVALID" | "0X00000020" | "32" => (
            "CKR_DATA_INVALID",
            "0x00000020",
            "Data is invalid or corrupted",
            vec![
                "Input data malformed",
                "Data doesn't match expected format",
                "Encryption/padding error",
            ],
        ),
        "CKR_DATA_LEN_RANGE" | "0X00000021" | "33" => (
            "CKR_DATA_LEN_RANGE",
            "0x00000021",
            "Data length is out of valid range",
            vec![
                "Data too short",
                "Data too long",
                "Doesn't match block size requirements",
            ],
        ),
        "CKR_DEVICE_ERROR" | "0X00000030" | "48" => (
            "CKR_DEVICE_ERROR",
            "0x00000030",
            "Device error - hardware problem",
            vec![
                "HSM hardware failure",
                "Connection lost",
                "Device reset required",
            ],
        ),
        "CKR_DEVICE_MEMORY" | "0X00000031" | "49" => (
            "CKR_DEVICE_MEMORY",
            "0x00000031",
            "Device is out of memory",
            vec![
                "HSM storage full",
                "Too many objects on token",
                "Delete unused keys",
            ],
        ),
        "CKR_FUNCTION_NOT_SUPPORTED" | "0X00000054" | "84" => (
            "CKR_FUNCTION_NOT_SUPPORTED",
            "0x00000054",
            "Function is not supported by this token",
            vec![
                "Mechanism not available",
                "Feature not implemented",
                "Check supported mechanisms",
            ],
        ),
        "CKR_KEY_HANDLE_INVALID" | "0X00000060" | "96" => (
            "CKR_KEY_HANDLE_INVALID",
            "0x00000060",
            "The specified key handle is not valid",
            vec![
                "Key was deleted",
                "Session closed invalidating handle",
                "Wrong key type (public vs private)",
                "Key not accessible in current session",
            ],
        ),
        "CKR_KEY_SIZE_RANGE" | "0X00000062" | "98" => (
            "CKR_KEY_SIZE_RANGE",
            "0x00000062",
            "Key size is outside valid range",
            vec![
                "Key too small (insecure)",
                "Key too large (not supported)",
                "Use 2048 or 4096 for RSA",
            ],
        ),
        "CKR_KEY_TYPE_INCONSISTENT" | "0X00000063" | "99" => (
            "CKR_KEY_TYPE_INCONSISTENT",
            "0x00000063",
            "Key type inconsistent with operation",
            vec![
                "Using symmetric key for asymmetric operation",
                "Mechanism requires different key type",
            ],
        ),
        "CKR_KEY_FUNCTION_NOT_PERMITTED" | "0X00000068" | "104" => (
            "CKR_KEY_FUNCTION_NOT_PERMITTED",
            "0x00000068",
            "Key cannot be used for this operation",
            vec![
                "CKA_SIGN=false for signing",
                "CKA_DECRYPT=false for decryption",
                "Check key usage attributes",
            ],
        ),
        "CKR_MECHANISM_INVALID" | "0X00000070" | "112" => (
            "CKR_MECHANISM_INVALID",
            "0x00000070",
            "Invalid mechanism specified",
            vec![
                "Mechanism not supported",
                "Wrong mechanism for key type",
                "Check list-mechanisms output",
            ],
        ),
        "CKR_OBJECT_HANDLE_INVALID" | "0X00000082" | "130" => (
            "CKR_OBJECT_HANDLE_INVALID",
            "0x00000082",
            "Invalid object handle",
            vec![
                "Object was deleted",
                "Handle from different session",
                "Session closed",
            ],
        ),
        "CKR_PIN_INCORRECT" | "0X000000A0" | "160" => (
            "CKR_PIN_INCORRECT",
            "0x000000A0",
            "PIN is incorrect",
            vec![
                "Wrong PIN provided",
                "Check user PIN vs SO PIN",
                "PIN may be locked after multiple failures",
            ],
        ),
        "CKR_PIN_LOCKED" | "0X000000A4" | "164" => (
            "CKR_PIN_LOCKED",
            "0x000000A4",
            "PIN is locked due to too many failed attempts",
            vec![
                "Exceeded failed PIN attempts",
                "Unlock with SO PIN",
                "Wait for auto-unlock period",
            ],
        ),
        "CKR_SESSION_CLOSED" | "0X000000B0" | "176" => (
            "CKR_SESSION_CLOSED",
            "0x000000B0",
            "Session is closed",
            vec![
                "Session was closed before operation",
                "Timeout occurred",
                "Re-login required",
            ],
        ),
        "CKR_SESSION_HANDLE_INVALID" | "0X000000B3" | "179" => (
            "CKR_SESSION_HANDLE_INVALID",
            "0x000000B3",
            "Invalid session handle",
            vec![
                "Session doesn't exist",
                "Using closed session",
                "Session expired",
            ],
        ),
        "CKR_SESSION_READ_ONLY" | "0X000000B5" | "181" => (
            "CKR_SESSION_READ_ONLY",
            "0x000000B5",
            "Session is read-only, cannot modify objects",
            vec![
                "Opened RO session for write operation",
                "Need to open RW session",
                "Check session flags",
            ],
        ),
        "CKR_SIGNATURE_INVALID" | "0X000000C0" | "192" => (
            "CKR_SIGNATURE_INVALID",
            "0x000000C0",
            "Signature verification failed",
            vec![
                "Data was modified",
                "Wrong key used",
                "Signature corrupted",
                "Data and signature don't match",
            ],
        ),
        "CKR_TOKEN_NOT_PRESENT" | "0X000000E0" | "224" => (
            "CKR_TOKEN_NOT_PRESENT",
            "0x000000E0",
            "Token is not present in slot",
            vec![
                "HSM disconnected",
                "Token not initialized",
                "Check slot number",
                "Use list-slots to verify",
            ],
        ),
        "CKR_TOKEN_NOT_RECOGNIZED" | "0X000000E1" | "225" => (
            "CKR_TOKEN_NOT_RECOGNIZED",
            "0x000000E1",
            "Token is not recognized",
            vec![
                "Token format incompatible",
                "Wrong PKCS#11 module",
                "Token corrupted",
            ],
        ),
        "CKR_USER_ALREADY_LOGGED_IN" | "0X00000100" | "256" => (
            "CKR_USER_ALREADY_LOGGED_IN",
            "0x00000100",
            "User is already logged in",
            vec![
                "Attempted second login",
                "Session reuse issue",
                "Check application logic",
            ],
        ),
        "CKR_USER_NOT_LOGGED_IN" | "0X00000101" | "257" => (
            "CKR_USER_NOT_LOGGED_IN",
            "0x00000101",
            "User must log in first",
            vec![
                "No C_Login called",
                "Session expired",
                "PIN not provided",
                "Private key access requires login",
            ],
        ),
        "CKR_USER_PIN_NOT_INITIALIZED" | "0X00000102" | "258" => (
            "CKR_USER_PIN_NOT_INITIALIZED",
            "0x00000102",
            "User PIN has not been set",
            vec![
                "Token initialized but user PIN not set",
                "Run init-pin command",
                "Use SO PIN to set user PIN",
            ],
        ),
        "CKR_USER_TYPE_INVALID" | "0X00000103" | "259" => (
            "CKR_USER_TYPE_INVALID",
            "0x00000103",
            "Invalid user type",
            vec![
                "Wrong user type for operation",
                "Using CKU_USER when CKU_SO required",
                "Check login user type",
            ],
        ),
        "CKR_WRAPPED_KEY_INVALID" | "0X00000110" | "272" => (
            "CKR_WRAPPED_KEY_INVALID",
            "0x00000110",
            "Wrapped key is invalid or corrupted",
            vec![
                "Wrong unwrapping key",
                "Wrapped data corrupted",
                "Key wrap format mismatch",
            ],
        ),
        "CKR_KEY_UNEXTRACTABLE" | "0X00000117" | "279" => (
            "CKR_KEY_UNEXTRACTABLE",
            "0x00000117",
            "Key cannot be extracted (wrapped)",
            vec![
                "CKA_EXTRACTABLE=false",
                "Key marked non-extractable",
                "Cannot wrap sensitive keys",
                "Regenerate with --extractable if needed",
            ],
        ),
        "CKR_MECHANISM_PARAM_INVALID" | "0X00000071" | "113" => (
            "CKR_MECHANISM_PARAM_INVALID",
            "0x00000071",
            "Invalid mechanism parameters",
            vec![
                "Wrong IV length",
                "Invalid GCM parameters",
                "Parameter structure incorrect",
            ],
        ),
        "CKR_BUFFER_TOO_SMALL" | "0X00000150" | "336" => (
            "CKR_BUFFER_TOO_SMALL",
            "0x00000150",
            "Output buffer is too small",
            vec![
                "Provided buffer too small for result",
                "Query size first",
                "Increase buffer size",
            ],
        ),
        _ => (
            "UNKNOWN",
            error_code,
            "Unknown or unrecognized error code",
            vec![
                "Check PKCS#11 specification",
                "Vendor-specific error",
                "Consult HSM documentation",
            ],
        ),
    };

    println!("Error Code: {} ({})", code_name, hex_value);
    println!("\nMeaning: {}", description);

    if !causes.is_empty() {
        println!("\nCommon Causes:");
        for (i, cause) in causes.iter().enumerate() {
            println!("  {}. {}", i + 1, cause);
        }
    }

    // Context-specific troubleshooting
    if let Some(ctx) = context {
        println!("\nContext: {} operation", ctx);
        match ctx.to_lowercase().as_str() {
            "sign" => {
                println!("\nTroubleshooting Steps for Signing:");
                println!("  → Verify key exists: rust-hsm-cli list-objects --detailed");
                println!("  → Check key attributes: rust-hsm-cli inspect-key --key-label <name>");
                println!("  → Ensure CKA_SIGN=true on private key");
                println!(
                    "  → Test operation: rust-hsm-cli sign --key-label <name> --input test.txt"
                );
                println!("  → Check mechanism support: rust-hsm-cli list-mechanisms --detailed");
            }
            "verify" => {
                println!("\nTroubleshooting Steps for Verification:");
                println!("  → Verify public key exists and has CKA_VERIFY=true");
                println!("  → Ensure data hasn't been modified since signing");
                println!("  → Check signature file is correct and complete");
                println!("  → Verify same mechanism used for sign and verify");
            }
            "encrypt" => {
                println!("\nTroubleshooting Steps for Encryption:");
                println!("  → Check key has CKA_ENCRYPT=true");
                println!(
                    "  → Verify data size within key limits (RSA: max 245 bytes for 2048-bit)"
                );
                println!("  → Check mechanism is appropriate for key type");
                println!("  → For symmetric: ensure proper IV/parameters provided");
            }
            "decrypt" => {
                println!("\nTroubleshooting Steps for Decryption:");
                println!("  → Check private key has CKA_DECRYPT=true");
                println!("  → Verify encrypted data is not corrupted");
                println!("  → Ensure correct key is being used");
                println!("  → Check mechanism matches encryption mechanism");
            }
            "login" => {
                println!("\nTroubleshooting Steps for Login:");
                println!("  → Verify correct PIN (user vs SO PIN)");
                println!("  → Check if PIN is locked: rust-hsm-cli list-slots");
                println!("  → Ensure token is initialized: rust-hsm-cli list-slots");
                println!("  → If locked, unlock with SO PIN or wait for timeout");
            }
            "wrap" => {
                println!("\nTroubleshooting Steps for Key Wrapping:");
                println!("  → Ensure target key has CKA_EXTRACTABLE=true");
                println!("  → Verify wrapping key has CKA_WRAP=true");
                println!("  → Check mechanism support for key wrapping");
                println!("  → Regenerate target key with --extractable if needed");
            }
            _ => {
                println!("\nGeneral Troubleshooting:");
                println!("  → Check token status: rust-hsm-cli list-slots");
                println!("  → Verify connectivity: rust-hsm-cli info");
                println!("  → List available objects: rust-hsm-cli list-objects --detailed");
                println!("  → Check error logs for additional details");
            }
        }
    } else {
        println!("\nGeneral Troubleshooting:");
        println!("  → Check token status: rust-hsm-cli list-slots");
        println!("  → Verify connectivity: rust-hsm-cli info");
        println!("  → Review application logs for additional context");
        println!("  → Use --context flag for operation-specific guidance");
        println!("\nExample:");
        println!("  rust-hsm-cli explain-error {} --context sign", code_name);
    }

    println!();
    Ok(())
}

/// Find a key by label with fuzzy matching
pub fn find_key(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    show_similar: bool,
) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    let slot = find_token_slot(&pkcs11, label)?;
    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_ro_session(slot)?;

    let pin = AuthPin::new(user_pin.to_string());
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;

    info!("Searching for key: '{}'", key_label);
    println!("\n=== Key Search: '{}' ===\n", key_label);

    // Search for exact match
    let template = vec![Attribute::Label(key_label.as_bytes().to_vec())];

    let objects = session.find_objects(&template)?;

    if !objects.is_empty() {
        println!("✓ Exact match found!\n");
        for (idx, obj) in objects.iter().enumerate() {
            if let Ok(attrs) = session.get_attributes(
                *obj,
                &[
                    AttributeType::Class,
                    AttributeType::KeyType,
                    AttributeType::Sign,
                    AttributeType::Verify,
                    AttributeType::Encrypt,
                    AttributeType::Decrypt,
                    AttributeType::Local,
                    AttributeType::Sensitive,
                    AttributeType::Extractable,
                ],
            ) {
                let mut class_str = "Unknown".to_string();
                let mut key_type_str = "".to_string();
                let mut capabilities = Vec::new();
                let mut flags = Vec::new();

                for attr in attrs {
                    match attr {
                        Attribute::Class(ObjectClass::PUBLIC_KEY) => {
                            class_str = "Public Key".to_string()
                        }
                        Attribute::Class(ObjectClass::PRIVATE_KEY) => {
                            class_str = "Private Key".to_string()
                        }
                        Attribute::Class(ObjectClass::SECRET_KEY) => {
                            class_str = "Secret Key".to_string()
                        }
                        Attribute::KeyType(kt) => key_type_str = format!("{:?}", kt),
                        Attribute::Sign(true) => capabilities.push("sign"),
                        Attribute::Verify(true) => capabilities.push("verify"),
                        Attribute::Encrypt(true) => capabilities.push("encrypt"),
                        Attribute::Decrypt(true) => capabilities.push("decrypt"),
                        Attribute::Local(true) => flags.push("local"),
                        Attribute::Local(false) => flags.push("imported"),
                        Attribute::Sensitive(true) => flags.push("sensitive"),
                        Attribute::Extractable(false) => flags.push("non-extractable"),
                        _ => {}
                    }
                }

                println!("Match {}:", idx + 1);
                println!("  Type: {} ({})", class_str, key_type_str);
                println!("  Capabilities: {}", capabilities.join(", "));
                println!("  Flags: {}", flags.join(", "));
                println!();
            }
        }

        session.logout()?;
        pkcs11.finalize();
        return Ok(());
    }

    // No exact match - find similar keys if requested
    println!("✗ Exact match not found");

    if show_similar {
        println!("\nSearching for similar keys...\n");

        // Get all objects
        let all_objects = session.find_objects(&[])?;
        let mut similar_keys = Vec::new();

        for obj in &all_objects {
            if let Ok(attrs) = session.get_attributes(*obj, &[AttributeType::Label]) {
                for attr in attrs {
                    if let Attribute::Label(label_bytes) = attr {
                        if let Ok(obj_label) = String::from_utf8(label_bytes) {
                            // Calculate similarity
                            let distance = levenshtein_distance(
                                &key_label.to_lowercase(),
                                &obj_label.to_lowercase(),
                            );
                            if distance <= 3
                                || obj_label.to_lowercase().contains(&key_label.to_lowercase())
                                || key_label.to_lowercase().contains(&obj_label.to_lowercase())
                            {
                                similar_keys.push((obj_label, *obj, distance));
                            }
                        }
                    }
                }
            }
        }

        if similar_keys.is_empty() {
            println!("No similar keys found.");
        } else {
            println!("Similar keys found:");
            similar_keys.sort_by_key(|(_, _, dist)| *dist);

            for (i, (label, obj, distance)) in similar_keys.iter().take(5).enumerate() {
                println!("\n{}. '{}' (edit distance: {})", i + 1, label, distance);

                if let Ok(attrs) = session.get_attributes(
                    *obj,
                    &[
                        AttributeType::Class,
                        AttributeType::KeyType,
                        AttributeType::Sign,
                        AttributeType::Verify,
                        AttributeType::Encrypt,
                        AttributeType::Decrypt,
                        AttributeType::Local,
                    ],
                ) {
                    let mut class_str = "Unknown".to_string();
                    let mut key_type_str = "".to_string();
                    let mut capabilities = Vec::new();
                    let mut is_local = true;

                    for attr in attrs {
                        match attr {
                            Attribute::Class(ObjectClass::PUBLIC_KEY) => {
                                class_str = "Public Key".to_string()
                            }
                            Attribute::Class(ObjectClass::PRIVATE_KEY) => {
                                class_str = "Private Key".to_string()
                            }
                            Attribute::Class(ObjectClass::SECRET_KEY) => {
                                class_str = "Secret Key".to_string()
                            }
                            Attribute::KeyType(kt) => key_type_str = format!("{:?}", kt),
                            Attribute::Sign(true) => capabilities.push("sign"),
                            Attribute::Verify(true) => capabilities.push("verify"),
                            Attribute::Encrypt(true) => capabilities.push("encrypt"),
                            Attribute::Decrypt(true) => capabilities.push("decrypt"),
                            Attribute::Local(local) => is_local = local,
                            _ => {}
                        }
                    }

                    println!("   Type: {} ({})", class_str, key_type_str);
                    println!(
                        "   Capabilities: {}",
                        if capabilities.is_empty() {
                            "none".to_string()
                        } else {
                            capabilities.join(", ")
                        }
                    );
                    if !is_local {
                        println!("   ⚠ Imported key (CKA_LOCAL=false)");
                    }
                }
            }

            println!("\nSuggestion: Check for typos or different separators (-, _, space)");
        }
    } else {
        println!("\nUse --show-similar to search for similar key names");
    }

    session.logout()?;
    pkcs11.finalize();
    Ok(())
}

/// Calculate Levenshtein distance between two strings
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let len1 = s1.len();
    let len2 = s2.len();
    let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    for (i, c1) in s1.chars().enumerate() {
        for (j, c2) in s2.chars().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            matrix[i + 1][j + 1] = std::cmp::min(
                std::cmp::min(matrix[i][j + 1] + 1, matrix[i + 1][j] + 1),
                matrix[i][j] + cost,
            );
        }
    }

    matrix[len1][len2]
}

/// Compare two keys and show differences
pub fn diff_keys(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key1_label: &str,
    key2_label: &str,
) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("→ Calling C_Initialize");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    let slot = find_token_slot(&pkcs11, label)?;
    debug!("→ Calling C_OpenSession");
    let session = pkcs11.open_ro_session(slot)?;

    let pin = AuthPin::new(user_pin.to_string());
    debug!("→ Calling C_Login");
    session.login(UserType::User, Some(&pin))?;

    info!("Comparing keys: '{}' vs '{}'", key1_label, key2_label);
    println!("\n=== Key Comparison ===\n");
    println!("Key 1: {}", key1_label);
    println!("Key 2: {}", key2_label);
    println!();

    // Find both keys
    let key1 = session
        .find_objects(&[Attribute::Label(key1_label.as_bytes().to_vec())])?
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("Key '{}' not found", key1_label))?;

    let key2 = session
        .find_objects(&[Attribute::Label(key2_label.as_bytes().to_vec())])?
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("Key '{}' not found", key2_label))?;

    // Get attributes for both keys
    let attr_types = vec![
        AttributeType::Class,
        AttributeType::KeyType,
        AttributeType::Token,
        AttributeType::Private,
        AttributeType::Modifiable,
        AttributeType::Local,
        AttributeType::Sign,
        AttributeType::Verify,
        AttributeType::Encrypt,
        AttributeType::Decrypt,
        AttributeType::Wrap,
        AttributeType::Unwrap,
        AttributeType::Derive,
        AttributeType::Sensitive,
        AttributeType::AlwaysSensitive,
        AttributeType::NeverExtractable,
        AttributeType::Extractable,
    ];

    let attrs1 = session
        .get_attributes(key1, &attr_types)
        .unwrap_or_default();
    let attrs2 = session
        .get_attributes(key2, &attr_types)
        .unwrap_or_default();

    // Build comparison table
    println!(
        "{:<30} {:<20} {:<20} {}",
        "Attribute", "Key 1", "Key 2", "Status"
    );
    println!("{}", "─".repeat(80));

    let mut differences = Vec::new();

    // Compare attributes
    for attr_type in &attr_types {
        let val1 = format_attribute_value(&attrs1, attr_type);
        let val2 = format_attribute_value(&attrs2, attr_type);

        let status = if val1 == val2 { "✓" } else { "✗" };
        let attr_name = format!("{:?}", attr_type).replace("AttributeType::", "CKA_");

        println!("{:<30} {:<20} {:<20} {}", attr_name, val1, val2, status);

        if val1 != val2 {
            differences.push((attr_name, val1, val2));
        }
    }

    // Summary
    if differences.is_empty() {
        println!("\n✓ Keys are identical in all checked attributes");
    } else {
        println!("\n✗ Found {} difference(s):\n", differences.len());

        for (attr, val1, val2) in &differences {
            // Determine severity
            let (severity, explanation) = match attr.as_str() {
                "CKA_Sign" | "CKA_Verify" | "CKA_Encrypt" | "CKA_Decrypt" => (
                    "CRITICAL",
                    "This affects key functionality - operations may fail",
                ),
                "CKA_Sensitive"
                | "CKA_Extractable"
                | "CKA_AlwaysSensitive"
                | "CKA_NeverExtractable" => ("HIGH", "This affects key security posture"),
                "CKA_Local" => (
                    "MEDIUM",
                    "One key was imported, the other was generated on HSM",
                ),
                _ => ("LOW", "Minor difference in key properties"),
            };

            println!(
                "{} {}: {} vs {}",
                match severity {
                    "CRITICAL" => "✗",
                    "HIGH" => "⚠",
                    _ => "ℹ",
                },
                attr,
                val1,
                val2
            );
            println!("  → {}", explanation);
            println!();
        }
    }

    session.logout()?;
    pkcs11.finalize();
    Ok(())
}

fn format_attribute_value(attrs: &[Attribute], attr_type: &AttributeType) -> String {
    for attr in attrs {
        match (attr_type, attr) {
            (AttributeType::Class, Attribute::Class(c)) => return format!("{:?}", c),
            (AttributeType::KeyType, Attribute::KeyType(kt)) => return format!("{:?}", kt),
            (AttributeType::Token, Attribute::Token(b)) => return b.to_string(),
            (AttributeType::Private, Attribute::Private(b)) => return b.to_string(),
            (AttributeType::Modifiable, Attribute::Modifiable(b)) => return b.to_string(),
            (AttributeType::Local, Attribute::Local(b)) => return b.to_string(),
            (AttributeType::Sign, Attribute::Sign(b)) => return b.to_string(),
            (AttributeType::Verify, Attribute::Verify(b)) => return b.to_string(),
            (AttributeType::Encrypt, Attribute::Encrypt(b)) => return b.to_string(),
            (AttributeType::Decrypt, Attribute::Decrypt(b)) => return b.to_string(),
            (AttributeType::Wrap, Attribute::Wrap(b)) => return b.to_string(),
            (AttributeType::Unwrap, Attribute::Unwrap(b)) => return b.to_string(),
            (AttributeType::Derive, Attribute::Derive(b)) => return b.to_string(),
            (AttributeType::Sensitive, Attribute::Sensitive(b)) => return b.to_string(),
            (AttributeType::AlwaysSensitive, Attribute::AlwaysSensitive(b)) => {
                return b.to_string()
            }
            (AttributeType::NeverExtractable, Attribute::NeverExtractable(b)) => {
                return b.to_string()
            }
            (AttributeType::Extractable, Attribute::Extractable(b)) => return b.to_string(),
            _ => {}
        }
    }
    "N/A".to_string()
}
