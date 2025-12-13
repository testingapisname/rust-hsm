use cryptoki::context::{CInitializeArgs, Pkcs11};
use tracing::{debug, trace};

pub fn display_info(module_path: &str) -> anyhow::Result<()> {
    debug!("Loading PKCS#11 module from: {}", module_path);
    let pkcs11 = Pkcs11::new(module_path)?;
    debug!("Initializing PKCS#11 library");
    pkcs11.initialize(CInitializeArgs::OsThreads)?;

    debug!("Retrieving library information");
    let info = pkcs11.get_library_info()?;
    trace!("Library info: {:?}", info);
    
    println!("\n=== PKCS#11 Module Info ===");
    println!("Library Description: {}", info.library_description());
    println!("Library Version: {}.{}", info.library_version().major(), info.library_version().minor());
    println!("Manufacturer ID: {}", info.manufacturer_id());
    
    debug!("Finalizing PKCS#11 library");
    pkcs11.finalize();
    
    Ok(())
}
