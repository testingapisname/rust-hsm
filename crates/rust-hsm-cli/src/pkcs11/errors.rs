use thiserror::Error;

#[derive(Error, Debug)]
pub enum Pkcs11Error {
    #[error("PKCS#11 error: {0}")]
    Cryptoki(#[from] cryptoki::error::Error),
    
    #[error("Token not found: {0}")]
    TokenNotFound(String),
    
    #[error("Slot not found")]
    SlotNotFound,
    
    #[error("Invalid PIN")]
    InvalidPin,
}

pub type Result<T> = std::result::Result<T, Pkcs11Error>;
