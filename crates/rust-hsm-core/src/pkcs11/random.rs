use anyhow::{Context, Result};
use cryptoki::context::{CInitializeArgs, Pkcs11};
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info};

use super::slots::find_first_slot;

/// Generate random bytes using the HSM's random number generator
pub fn generate_random(
    module_path: &str,
    bytes: usize,
    output: Option<&PathBuf>,
    hex: bool,
    json: bool,
) -> Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;

    debug!("→ Calling C_Initialize");
    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11 module")?;

    // Find first available slot (RNG doesn't require token or login)
    let slot = find_first_slot(&pkcs11)?;

    info!(
        "Generating {} random bytes using HSM RNG in slot {}",
        bytes,
        usize::from(slot)
    );

    debug!("→ Calling C_OpenSession");
    let session = pkcs11
        .open_ro_session(slot)
        .context("Failed to open read-only session")?;

    debug!("→ Calling C_GenerateRandom");
    let mut random_bytes = vec![0u8; bytes];
    session
        .generate_random_slice(&mut random_bytes)
        .context("Failed to generate random bytes")?;

    info!("Generated {} random bytes", random_bytes.len());

    let hex_string = random_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    
    if let Some(output_path) = output {
        if hex {
            // Write as hex string
            fs::write(output_path, &hex_string).with_context(|| {
                format!("Failed to write hex output to: {}", output_path.display())
            })?;
            if json {
                let json_output = serde_json::json!({
                    "status": "success",
                    "operation": "generate_random",
                    "bytes": random_bytes.len(),
                    "format": "hex",
                    "output_file": output_path.display().to_string(),
                    "data": hex_string
                });
                println!("{}", serde_json::to_string_pretty(&json_output)?);
            } else {
                println!("Random bytes (hex) written to: {}", output_path.display());
                println!("  Length: {} bytes", random_bytes.len());
            }
        } else {
            // Write as binary
            fs::write(output_path, &random_bytes)
                .with_context(|| format!("Failed to write output to: {}", output_path.display()))?;
            if json {
                let json_output = serde_json::json!({
                    "status": "success",
                    "operation": "generate_random",
                    "bytes": random_bytes.len(),
                    "format": "binary",
                    "output_file": output_path.display().to_string(),
                    "data_hex": hex_string
                });
                println!("{}", serde_json::to_string_pretty(&json_output)?);
            } else {
                println!(
                    "Random bytes (binary) written to: {}",
                    output_path.display()
                );
                println!("  Length: {} bytes", random_bytes.len());
            }
        }
    } else {
        // Output to stdout
        if json {
            let json_output = serde_json::json!({
                "status": "success",
                "operation": "generate_random",
                "bytes": random_bytes.len(),
                "format": "hex",
                "data": hex_string
            });
            println!("{}", serde_json::to_string_pretty(&json_output)?);
        } else {
            println!("{}", hex_string);
        }
    }

    debug!("→ Calling C_Finalize");
    pkcs11.finalize();
    debug!("PKCS#11 library finalized");

    Ok(())
}
