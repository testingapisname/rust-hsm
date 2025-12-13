use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use tracing::{debug, info};

use super::utils::find_token_slot;

pub fn gen_keypair(
    module_path: &str,
    label: &str,
    user_pin: &str,
    key_label: &str,
    key_type: &str,
    bits: u32,
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
    info!("Generating {} keypair on token '{}' in slot {}", key_type, label, usize::from(slot));
    debug!("Token found at slot: {}", usize::from(slot));

    let session = pkcs11.open_rw_session(slot)?;
    let pin = AuthPin::new(user_pin.to_string());
    session.login(UserType::User, Some(&pin))?;

    match key_type.to_lowercase().as_str() {
        "rsa" => {
            debug!("Using RSA key generation mechanism");
            let mechanism = Mechanism::RsaPkcsKeyPairGen;
            debug!("Generating RSA-{} keypair", bits);
            
            let public_key_template = vec![
                Attribute::Token(true),
                Attribute::Label(key_label.as_bytes().to_vec()),
                Attribute::Id(key_label.as_bytes().to_vec()),
                Attribute::Encrypt(true),
                Attribute::Verify(true),
                Attribute::ModulusBits(cryptoki::types::Ulong::from(bits as u64)),
                Attribute::PublicExponent(vec![0x01, 0x00, 0x01]), // 65537
            ];

            let private_key_template = vec![
                Attribute::Token(true),
                Attribute::Label(key_label.as_bytes().to_vec()),
                Attribute::Id(key_label.as_bytes().to_vec()),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Decrypt(true),
                Attribute::Sign(true),
            ];

            let (public_key, private_key) = session.generate_key_pair(
                &mechanism,
                &public_key_template,
                &private_key_template,
            )?;

            println!("RSA-{} keypair '{}' generated successfully", bits, key_label);
            println!("  Public key handle: {:?}", public_key);
            println!("  Private key handle: {:?}", private_key);
        }
        "ecdsa" | "ec" | "p256" | "p384" => {
            debug!("Using ECDSA key generation mechanism");
            let mechanism = Mechanism::EccKeyPairGen;
            
            // EC parameters: ANSI X9.62 named curves
            let ec_params = match key_type.to_lowercase().as_str() {
                "p256" | "ec" | "ecdsa" => {
                    // secp256r1 / prime256v1 OID: 1.2.840.10045.3.1.7
                    vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
                }
                "p384" => {
                    // secp384r1 OID: 1.3.132.0.34
                    vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
                }
                _ => {
                    anyhow::bail!("Unsupported EC curve. Use 'p256' or 'p384'");
                }
            };
            
            let public_key_template = vec![
                Attribute::Token(true),
                Attribute::Label(key_label.as_bytes().to_vec()),
                Attribute::Id(key_label.as_bytes().to_vec()),
                Attribute::Verify(true),
                Attribute::EcParams(ec_params),
            ];

            let private_key_template = vec![
                Attribute::Token(true),
                Attribute::Label(key_label.as_bytes().to_vec()),
                Attribute::Id(key_label.as_bytes().to_vec()),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Sign(true),
            ];

            let (public_key, private_key) = session.generate_key_pair(
                &mechanism,
                &public_key_template,
                &private_key_template,
            )?;

            let curve_name = match key_type.to_lowercase().as_str() {
                "p384" => "P-384",
                _ => "P-256",
            };
            println!("ECDSA {} keypair '{}' generated successfully", curve_name, key_label);
            println!("  Public key handle: {:?}", public_key);
            println!("  Private key handle: {:?}", private_key);
        }
        _ => {
            anyhow::bail!("Unsupported key type: {}. Use 'rsa' or 'ecdsa'", key_type);
        }
    }

    session.logout()?;
    pkcs11.finalize();

    Ok(())
}
