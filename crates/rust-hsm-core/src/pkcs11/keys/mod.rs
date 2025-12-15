// Re-export all public functions from submodules
mod asymmetric;
mod cmac;
mod csr;
mod export;
mod hash;
mod hmac;
mod inspect;
mod keypair;
mod symmetric;
mod utils;
mod wrap;

pub use asymmetric::{decrypt, encrypt, sign, verify};
pub use cmac::{cmac_sign, cmac_verify, gen_cmac_key};
pub use csr::generate_csr;
pub use export::export_pubkey;
pub use hash::hash_data;
pub use hmac::{gen_hmac_key, hmac_sign, hmac_verify};
pub use inspect::inspect_key;
pub use keypair::gen_keypair;
pub use symmetric::{decrypt_symmetric, encrypt_symmetric, gen_symmetric_key};
pub use utils::{delete_key, find_token_slot};
pub use wrap::{unwrap_key, wrap_key};
