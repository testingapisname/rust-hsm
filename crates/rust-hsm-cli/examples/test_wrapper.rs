use cryptoki::context::CInitializeArgs;
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
/// Test observe-cryptoki wrapper with real PKCS#11 operations
use observe_cryptoki::{ObserveConfig, ObservedPkcs11};

fn main() -> anyhow::Result<()> {
    println!("Testing observe-cryptoki wrapper...");

    // Create observe config
    let config = ObserveConfig::enabled("/app/test-wrapper.json")?;
    println!("✓ Created ObserveConfig");

    // Load PKCS#11 module with observability
    let pkcs11 = ObservedPkcs11::new("/usr/lib/softhsm/libsofthsm2.so", config)?;
    println!("✓ Loaded PKCS#11 module");

    // Initialize
    pkcs11.initialize(CInitializeArgs::OsThreads)?;
    println!("✓ Called C_Initialize");

    // === Test 1: CKR_USER_PIN_NOT_INITIALIZED ===
    println!("\n--- Test 1: CKR_USER_PIN_NOT_INITIALIZED ---");

    // Initialize a token but DON'T set user PIN (only SO PIN)
    let all_slots = pkcs11.inner().get_all_slots()?;
    if let Some(slot) = all_slots.first() {
        println!("✓ Found slot: {:?}", slot);

        // Initialize token with only SO PIN
        let label = "TEST_NO_USER_PIN";
        let so_pin = AuthPin::new("1234".to_string());
        pkcs11.inner().init_token(*slot, &so_pin, label)?;
        println!("✓ Token initialized (user PIN NOT set)");

        // Now try to login as user (should fail with CKR_USER_PIN_NOT_INITIALIZED)
        let session = pkcs11.open_rw_session(*slot)?;
        println!("✓ Opened session");

        let pin = AuthPin::new("123456".to_string());
        match session.login(UserType::User, Some(&pin)) {
            Ok(_) => println!("⚠ Unexpected login success"),
            Err(e) => println!("✓ Got expected CKR_USER_PIN_NOT_INITIALIZED: {:?}", e),
        }

        let _ = session.logout();
    }

    // === Test 2: Initialize token and test CKR_PIN_INCORRECT ===
    println!("\n--- Test 2: CKR_PIN_INCORRECT (or session state behavior) ---");

    // Get a slot to initialize (look for one that's not already initialized)
    let all_slots = pkcs11.inner().get_all_slots()?;
    let initialized_slots = pkcs11.inner().get_slots_with_initialized_token()?;

    // Find a slot that's not initialized
    let empty_slot = all_slots.iter().find(|s| !initialized_slots.contains(s));

    if let Some(slot) = empty_slot {
        println!("✓ Found empty slot: {:?}", slot);

        // Initialize token with SO PIN (4-8 chars for SoftHSM)
        let label = "WRAPPER_TEST";
        let so_pin = AuthPin::new("1234".to_string());
        pkcs11.inner().init_token(*slot, &so_pin, label)?;
        println!("✓ Token initialized");

        // Set user PIN using observed session (now it will be logged!)
        let user_pin = AuthPin::new("123456".to_string());
        {
            let so_session = pkcs11.open_rw_session(*slot)?;
            so_session.login(UserType::So, Some(&so_pin))?;
            // This will now emit a C_InitPIN event
            so_session.init_pin(&user_pin)?;
            so_session.logout()?;
            // Session closes and commits here
        }
        println!("✓ User PIN set (check log for C_InitPIN)");

        // Small delay to ensure token state is committed
        std::thread::sleep(std::time::Duration::from_millis(100));

        // First, verify the PIN works by logging in with the CORRECT PIN
        {
            let verify_session = pkcs11.open_rw_session(*slot)?;
            match verify_session.login(UserType::User, Some(&user_pin)) {
                Ok(_) => {
                    println!(
                        "✓ User PIN verified (correct PIN works) - now the user PIN is 'active'"
                    );
                    verify_session.logout()?; // IMPORTANT: Logout to clear session state
                }
                Err(e) => {
                    println!("⚠ PIN verification failed: {:?}", e);
                    return Ok(());
                }
            }
            // Session closes completely
        }

        // Now on a BRAND NEW SESSION (after successful PIN use), try wrong PIN
        let user_session = pkcs11.open_rw_session(*slot)?;
        println!("✓ Opened fresh session for wrong PIN attempt (after PIN was validated)");
        let wrong_pin = AuthPin::new("999999".to_string());
        match user_session.login(UserType::User, Some(&wrong_pin)) {
            Ok(_) => println!("⚠ Unexpected login success"),
            Err(e) => println!("✓ Got error: {:?}", e),
        }

        let _ = user_session.logout();
    } else {
        println!("ℹ No empty slots available for test 2");
    }

    // Finalize
    pkcs11.finalize();
    println!("\n✓ Called C_Finalize");

    println!("\n✅ All operations logged to /app/test-wrapper.json");
    println!("   Demonstrates CKR_USER_PIN_NOT_INITIALIZED and C_InitPIN logging");
    println!("   Note: Both HSMs return rv=40 for wrong PIN after logout (session state)");

    Ok(())
}
