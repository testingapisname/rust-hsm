use cryptoki::context::{CInitializeArgs, Pkcs11};

pub fn display_info(module_path: &str) -> anyhow::Result<()> {
    let pkcs11 = Pkcs11::new(module_path)?;
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    let info = pkcs11.get_library_info()?;
    
    println!("\n=== PKCS#11 Module Info ===");
    println!("Library Description: {}", info.library_description());
    println!("Library Version: {}.{}", info.library_version().major(), info.library_version().minor());
    println!("Manufacturer ID: {}", info.manufacturer_id());
    
    pkcs11.finalize();
    
    Ok(())
}
