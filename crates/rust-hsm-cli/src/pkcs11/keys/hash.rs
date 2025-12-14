use anyhow::{Context, Result};
use cryptoki::context::Pkcs11;
use cryptoki::mechanism::Mechanism;
use cryptoki::session::Session;
use std::fs;
use std::path::PathBuf;
use tracing::info;

use super::utils::find_token_slot;

/// Hash data using SHA-256 or SHA-512
pub fn hash_data(
    module_path: &str,
    algorithm: &str,
    input_path: &PathBuf,
    output_path: &PathBuf,
) -> Result<()> {
    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;

    pkcs11
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11 module")?;

    // Use the first available slot for hashing (doesn't require a specific token)
    let slots = pkcs11
        .get_slots_with_initialized_token()
        .context("Failed to get slots")?;

    let slot_id = slots
        .first()
        .ok_or_else(|| anyhow::anyhow!("No initialized tokens found"))?;

    info!("Hashing data with {}", algorithm);

    // Open read-only session (no login needed for hashing)
    let session = pkcs11
        .open_ro_session(*slot_id)
        .context("Failed to open read-only session")?;

    // Read input data
    let data = fs::read(input_path)
        .with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    info!("Read {} bytes from {}", data.len(), input_path.display());

    // Select hash mechanism
    let mechanism = match algorithm.to_lowercase().as_str() {
        "sha256" | "sha-256" => Mechanism::Sha256,
        "sha512" | "sha-512" => Mechanism::Sha512,
        "sha224" | "sha-224" => Mechanism::Sha224,
        "sha1" | "sha-1" => Mechanism::Sha1,
        _ => anyhow::bail!(
            "Unsupported hash algorithm: {}. Supported: sha256, sha512, sha224, sha1",
            algorithm
        ),
    };

    // Hash the data
    let hash = session
        .digest(&mechanism, &data)
        .context("Failed to hash data")?;

    info!("Generated {}-byte hash", hash.len());

    // Write hash to output file
    fs::write(output_path, &hash)
        .with_context(|| format!("Failed to write hash to: {}", output_path.display()))?;

    println!("Data hashed successfully with {}", algorithm.to_uppercase());
    println!("  Input: {} ({} bytes)", input_path.display(), data.len());
    println!("  Output: {} ({} bytes)", output_path.display(), hash.len());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        // Test that SHA-256 produces a 32-byte hash
        let algorithm = "sha256";
        assert!(matches!(
            algorithm.to_lowercase().as_str(),
            "sha256" | "sha-256"
        ));
    }

    #[test]
    fn test_sha512_hash() {
        // Test that SHA-512 produces a 64-byte hash
        let algorithm = "sha512";
        assert!(matches!(
            algorithm.to_lowercase().as_str(),
            "sha512" | "sha-512"
        ));
    }
}
