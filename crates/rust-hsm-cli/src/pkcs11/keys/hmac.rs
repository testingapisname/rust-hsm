use anyhow::{Context, Result};
use cryptoki::context::Pkcs11;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::{AuthPin, Ulong};
use std::fs;
use std::path::PathBuf;
use tracing::info;

use super::utils::find_token_slot;

/// Generate an HMAC key
pub fn gen_hmac_key(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
    key_label: &str,
    bits: u32,
) -> Result<()> {
    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;

    pkcs11
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11 module")?;

    let slot_id = find_token_slot(&pkcs11, token_label)?;

    info!(
        "Generating HMAC-{} key on token '{}' in slot {}",
        bits, token_label, slot_id
    );

    let session = pkcs11
        .open_rw_session(slot_id)
        .context("Failed to open read-write session")?;

    let pin = AuthPin::new(user_pin.to_string());
    session
        .login(UserType::User, Some(&pin))
        .context("Failed to login with user PIN")?;

    // Generic secret key attributes for HMAC
    let key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Verify(true),
        Attribute::Label(key_label.as_bytes().to_vec()),
        Attribute::ValueLen(Ulong::from((bits / 8) as u64)),
    ];

    let key_handle = session
        .generate_key(&Mechanism::GenericSecretKeyGen, &key_template)
        .context("Failed to generate HMAC key")?;

    println!("HMAC-{} key '{}' generated successfully", bits, key_label);
    println!("  Key handle: {:?}", key_handle);

    Ok(())
}

/// Compute HMAC (sign) for data
pub fn hmac_sign(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
    key_label: &str,
    algorithm: &str,
    input_path: &PathBuf,
    output_path: &PathBuf,
) -> Result<()> {
    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;

    pkcs11
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11 module")?;

    let slot_id = find_token_slot(&pkcs11, token_label)?;

    info!(
        "Computing HMAC with {} for key '{}' on token '{}'",
        algorithm, key_label, token_label
    );

    let session = pkcs11
        .open_rw_session(slot_id)
        .context("Failed to open read-write session")?;

    let pin = AuthPin::new(user_pin.to_string());
    session
        .login(UserType::User, Some(&pin))
        .context("Failed to login with user PIN")?;

    // Find the HMAC key
    let key_handles = session
        .find_objects(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Label(key_label.as_bytes().to_vec()),
        ])
        .context("Failed to search for key")?;

    let key_handle = key_handles
        .first()
        .ok_or_else(|| anyhow::anyhow!("HMAC key '{}' not found", key_label))?;

    // Read input data
    let data = fs::read(input_path)
        .with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    info!("Read {} bytes from {}", data.len(), input_path.display());

    // Select HMAC mechanism
    let mechanism = match algorithm.to_lowercase().as_str() {
        "sha1" | "sha-1" => Mechanism::Sha1Hmac,
        "sha256" | "sha-256" => Mechanism::Sha256Hmac,
        "sha384" | "sha-384" => Mechanism::Sha384Hmac,
        "sha512" | "sha-512" => Mechanism::Sha512Hmac,
        "sha224" | "sha-224" => Mechanism::Sha224Hmac,
        _ => anyhow::bail!(
            "Unsupported HMAC algorithm: {}. Supported: sha1, sha256, sha384, sha512, sha224",
            algorithm
        ),
    };

    // Compute HMAC
    let hmac = session
        .sign(&mechanism, *key_handle, &data)
        .context("Failed to compute HMAC")?;

    info!("Generated {}-byte HMAC", hmac.len());

    // Write HMAC to output file
    fs::write(output_path, &hmac)
        .with_context(|| format!("Failed to write HMAC to: {}", output_path.display()))?;

    println!(
        "HMAC computed successfully with {}",
        algorithm.to_uppercase()
    );
    println!("  Input: {} ({} bytes)", input_path.display(), data.len());
    println!("  Output: {} ({} bytes)", output_path.display(), hmac.len());

    Ok(())
}

/// Verify HMAC for data
pub fn hmac_verify(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
    key_label: &str,
    algorithm: &str,
    input_path: &PathBuf,
    hmac_path: &PathBuf,
) -> Result<()> {
    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;

    pkcs11
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11 module")?;

    let slot_id = find_token_slot(&pkcs11, token_label)?;

    info!(
        "Verifying HMAC with {} for key '{}' on token '{}'",
        algorithm, key_label, token_label
    );

    let session = pkcs11
        .open_rw_session(slot_id)
        .context("Failed to open read-write session")?;

    let pin = AuthPin::new(user_pin.to_string());
    session
        .login(UserType::User, Some(&pin))
        .context("Failed to login with user PIN")?;

    // Find the HMAC key
    let key_handles = session
        .find_objects(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Label(key_label.as_bytes().to_vec()),
        ])
        .context("Failed to search for key")?;

    let key_handle = key_handles
        .first()
        .ok_or_else(|| anyhow::anyhow!("HMAC key '{}' not found", key_label))?;

    // Read input data and HMAC
    let data = fs::read(input_path)
        .with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    let hmac = fs::read(hmac_path)
        .with_context(|| format!("Failed to read HMAC file: {}", hmac_path.display()))?;

    info!(
        "Read {} bytes data and {}-byte HMAC",
        data.len(),
        hmac.len()
    );

    // Select HMAC mechanism
    let mechanism = match algorithm.to_lowercase().as_str() {
        "sha1" | "sha-1" => Mechanism::Sha1Hmac,
        "sha256" | "sha-256" => Mechanism::Sha256Hmac,
        "sha384" | "sha-384" => Mechanism::Sha384Hmac,
        "sha512" | "sha-512" => Mechanism::Sha512Hmac,
        "sha224" | "sha-224" => Mechanism::Sha224Hmac,
        _ => anyhow::bail!(
            "Unsupported HMAC algorithm: {}. Supported: sha1, sha256, sha384, sha512, sha224",
            algorithm
        ),
    };

    // Verify HMAC
    match session.verify(&mechanism, *key_handle, &data, &hmac) {
        Ok(_) => {
            println!("✓ HMAC verification successful");
            println!("  Data: {} ({} bytes)", input_path.display(), data.len());
            println!("  HMAC: {} ({} bytes)", hmac_path.display(), hmac.len());
            Ok(())
        }
        Err(e) => {
            anyhow::bail!("HMAC verification failed: {:?}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_algorithms() {
        let algorithms = ["sha1", "sha256", "sha384", "sha512", "sha224"];
        for algo in algorithms {
            assert!(matches!(
                algo.to_lowercase().as_str(),
                "sha1"
                    | "sha-1"
                    | "sha256"
                    | "sha-256"
                    | "sha384"
                    | "sha-384"
                    | "sha512"
                    | "sha-512"
                    | "sha224"
                    | "sha-224"
            ));
        }
    }
}
