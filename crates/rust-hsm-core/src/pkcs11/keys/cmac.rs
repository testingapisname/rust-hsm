use anyhow::{Context, Result};
use cryptoki::context::Pkcs11;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::fs;
use std::path::PathBuf;
use tracing::info;

use super::utils::find_token_slot;

/// Generate an AES key for CMAC operations
pub fn gen_cmac_key(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
    key_label: &str,
    bits: u32,
) -> Result<()> {
    // CMAC uses AES keys
    if bits != 128 && bits != 192 && bits != 256 {
        anyhow::bail!("Invalid AES key size: {}. Must be 128, 192, or 256", bits);
    }

    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;

    pkcs11
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11 module")?;

    let slot_id = find_token_slot(&pkcs11, token_label)?;

    info!(
        "Generating CMAC AES-{} key on token '{}' in slot {}",
        bits, token_label, slot_id
    );

    let session = pkcs11
        .open_rw_session(slot_id)
        .context("Failed to open read-write session")?;

    let pin = AuthPin::new(user_pin.to_string());
    session
        .login(UserType::User, Some(&pin))
        .context("Failed to login with user PIN")?;

    // AES key attributes for CMAC
    let key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Verify(true),
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::ValueLen(cryptoki::types::Ulong::from((bits / 8) as u64)),
    ];

    let mechanism = Mechanism::AesKeyGen;

    let key_handle = session
        .generate_key(&mechanism, &key_template)
        .context("Failed to generate CMAC AES key")?;

    println!(
        "CMAC AES-{} key '{}' generated successfully",
        bits, key_label
    );
    println!("  Key handle: {:?}", key_handle);

    Ok(())
}

/// Compute CMAC (sign) for data
pub fn cmac_sign(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
    key_label: &str,
    input_path: &PathBuf,
    output_path: &PathBuf,
    mac_len: Option<usize>,
) -> Result<()> {
    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;

    pkcs11
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11 module")?;

    let slot_id = find_token_slot(&pkcs11, token_label)?;

    info!(
        "Computing CMAC for key '{}' on token '{}'",
        key_label, token_label
    );

    let session = pkcs11
        .open_rw_session(slot_id)
        .context("Failed to open read-write session")?;

    let pin = AuthPin::new(user_pin.to_string());
    session
        .login(UserType::User, Some(&pin))
        .context("Failed to login with user PIN")?;

    // Find the CMAC key (AES key)
    let key_handles = session
        .find_objects(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Label(key_label.as_bytes().to_vec()),
        ])
        .context("Failed to search for key")?;

    let key_handle = key_handles
        .first()
        .ok_or_else(|| anyhow::anyhow!("CMAC key '{}' not found", key_label))?;

    // Read input data
    let data = fs::read(input_path)
        .with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    info!("Read {} bytes from {}", data.len(), input_path.display());

    // Use AES-CMAC mechanism
    let mechanism = Mechanism::AesCMac;

    // Compute CMAC
    let mut cmac = session
        .sign(&mechanism, *key_handle, &data)
        .context("Failed to compute CMAC")?;

    // Truncate if requested (CMAC full length is 16 bytes for AES)
    if let Some(len) = mac_len {
        if len > cmac.len() {
            anyhow::bail!(
                "Requested MAC length {} exceeds maximum {} bytes",
                len,
                cmac.len()
            );
        }
        cmac.truncate(len);
    }

    info!("Generated {}-byte CMAC", cmac.len());

    // Write CMAC to output file
    fs::write(output_path, &cmac)
        .with_context(|| format!("Failed to write CMAC to: {}", output_path.display()))?;

    println!("CMAC computed successfully");
    println!("  Input: {} ({} bytes)", input_path.display(), data.len());
    println!("  Output: {} ({} bytes)", output_path.display(), cmac.len());

    Ok(())
}

/// Verify CMAC for data
pub fn cmac_verify(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
    key_label: &str,
    input_path: &PathBuf,
    cmac_path: &PathBuf,
) -> Result<()> {
    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;

    pkcs11
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11 module")?;

    let slot_id = find_token_slot(&pkcs11, token_label)?;

    info!(
        "Verifying CMAC for key '{}' on token '{}'",
        key_label, token_label
    );

    let session = pkcs11
        .open_rw_session(slot_id)
        .context("Failed to open read-write session")?;

    let pin = AuthPin::new(user_pin.to_string());
    session
        .login(UserType::User, Some(&pin))
        .context("Failed to login with user PIN")?;

    // Find the CMAC key (AES key)
    let key_handles = session
        .find_objects(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Label(key_label.as_bytes().to_vec()),
        ])
        .context("Failed to search for key")?;

    let key_handle = key_handles
        .first()
        .ok_or_else(|| anyhow::anyhow!("CMAC key '{}' not found", key_label))?;

    // Read input data and CMAC
    let data = fs::read(input_path)
        .with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    let cmac = fs::read(cmac_path)
        .with_context(|| format!("Failed to read CMAC file: {}", cmac_path.display()))?;

    info!(
        "Read {} bytes data and {}-byte CMAC",
        data.len(),
        cmac.len()
    );

    // Use AES-CMAC mechanism
    let mechanism = Mechanism::AesCMac;

    // Verify CMAC
    session
        .verify(&mechanism, *key_handle, &data, &cmac)
        .context("CMAC verification failed")?;

    println!("✓ CMAC verification successful");
    println!("  Data: {} ({} bytes)", input_path.display(), data.len());
    println!("  CMAC: {} ({} bytes)", cmac_path.display(), cmac.len());

    Ok(())
}
