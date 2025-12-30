use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rust-hsm-cli")]
#[command(about = "Rust PKCS#11 CLI for SoftHSM2", long_about = None)]
pub struct Cli {
    /// Path to configuration file (optional)
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Display PKCS#11 module and token information
    Info {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// List all available slots and tokens
    ListSlots {
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// List supported mechanisms for a slot
    ListMechanisms {
        /// Slot ID (uses first slot if not specified)
        #[arg(long)]
        slot: Option<u64>,
        /// Show detailed mechanism capabilities (encrypt, decrypt, sign, verify, etc.)
        #[arg(long)]
        detailed: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Initialize a token
    InitToken {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        so_pin: Option<String>,
        /// Read SO PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Initialize user PIN on a token
    InitPin {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "so_pin_stdin")]
        so_pin: Option<String>,
        #[arg(long, conflicts_with = "user_pin_stdin")]
        user_pin: Option<String>,
        /// Read SO PIN from stdin (first line)
        #[arg(long = "so-pin-stdin")]
        so_pin_stdin: bool,
        /// Read user PIN from stdin (second line if so-pin-stdin, else first line)
        #[arg(long = "user-pin-stdin")]
        user_pin_stdin: bool,
    },

    /// Delete a token (reinitializes the slot, erasing all data)
    DeleteToken {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        so_pin: Option<String>,
        /// Read SO PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// List objects on a token
    ListObjects {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
        /// Show detailed object attributes (type, flags, key size)
        #[arg(long)]
        detailed: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Generate a keypair on the token
    GenKeypair {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long, default_value = "rsa")]
        key_type: String,
        #[arg(long, default_value = "2048")]
        bits: u32,
        /// Make private key extractable (INSECURE - for testing only)
        #[arg(long)]
        extractable: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Sign data with a private key
    Sign {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Verify a signature
    Verify {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        signature: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Export a public key in PEM format
    ExportPubkey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        output: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Delete a keypair from the token
    DeleteKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Inspect detailed key attributes (CKA_* values)
    InspectKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Encrypt data with an RSA public key
    Encrypt {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Decrypt data with an RSA private key
    Decrypt {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Generate a symmetric key (AES) on the token
    GenSymmetricKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// Key size in bits (128, 192, or 256)
        #[arg(long, default_value = "256")]
        bits: u32,
        /// Allow the key to be wrapped/exported (sets CKA_EXTRACTABLE=true)
        #[arg(long)]
        extractable: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Encrypt data with AES-GCM
    EncryptSymmetric {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Decrypt data with AES-GCM
    DecryptSymmetric {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Wrap (export) a key using AES Key Wrap
    WrapKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Label of the key to wrap (the key being exported)
        #[arg(long)]
        key_label: String,
        /// Label of the wrapping key (AES KEK - Key Encryption Key)
        #[arg(long)]
        wrapping_key_label: String,
        /// Output file for the wrapped key data
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Unwrap (import) a key using AES Key Wrap
    UnwrapKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Label for the imported key
        #[arg(long)]
        key_label: String,
        /// Label of the wrapping key (AES KEK - Key Encryption Key)
        #[arg(long)]
        wrapping_key_label: String,
        /// Input file containing the wrapped key data
        #[arg(long)]
        input: String,
        /// Key type: aes (for symmetric keys)
        #[arg(long, default_value = "aes")]
        key_type: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Generate a Certificate Signing Request (CSR) for a keypair
    GenCsr {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Label of the keypair to generate CSR for
        #[arg(long)]
        key_label: String,
        /// Subject Distinguished Name (e.g., "CN=example.com,O=MyOrg,C=US")
        #[arg(long)]
        subject: String,
        /// Output file for the CSR in PEM format
        #[arg(long)]
        output: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Hash data using SHA-256, SHA-512, or other hash algorithms
    Hash {
        /// Hash algorithm (sha256, sha512, sha224, sha1)
        #[arg(long, default_value = "sha256")]
        algorithm: String,
        /// Input file to hash
        #[arg(long)]
        input: String,
        /// Output file for the hash
        #[arg(long)]
        output: String,
    },

    /// Generate an HMAC key
    GenHmacKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// Key size in bits (typically 256)
        #[arg(long, default_value = "256")]
        bits: u32,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Compute HMAC for data (message authentication)
    HmacSign {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// HMAC algorithm (sha256, sha512, sha384, sha224, sha1)
        #[arg(long, default_value = "sha256")]
        algorithm: String,
        /// Input file to authenticate
        #[arg(long)]
        input: String,
        /// Output file for the HMAC
        #[arg(long)]
        output: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Verify HMAC for data
    HmacVerify {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// HMAC algorithm (sha256, sha512, sha384, sha224, sha1)
        #[arg(long, default_value = "sha256")]
        algorithm: String,
        /// Input file to verify
        #[arg(long)]
        input: String,
        /// HMAC file to verify against
        #[arg(long)]
        hmac: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Generate an AES-CMAC key
    GenCmacKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// AES key size in bits (128, 192, or 256)
        #[arg(long, default_value = "256")]
        bits: u32,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Compute CMAC for data (AES-based message authentication)
    CmacSign {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// Input file to authenticate
        #[arg(long)]
        input: String,
        /// Output file for the CMAC
        #[arg(long)]
        output: String,
        /// MAC length in bytes (default: 16 for full AES block)
        #[arg(long)]
        mac_len: Option<usize>,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Verify CMAC for data
    CmacVerify {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        #[arg(long)]
        key_label: String,
        /// Input file to verify
        #[arg(long)]
        input: String,
        /// CMAC file to verify against
        #[arg(long)]
        cmac: String,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Generate random bytes using HSM's RNG
    GenRandom {
        /// Number of bytes to generate
        #[arg(long, default_value = "32")]
        bytes: usize,
        /// Output file (if not specified, outputs hex to stdout)
        #[arg(long)]
        output: Option<PathBuf>,
        /// Output as hex string instead of binary (only applies to file output)
        #[arg(long)]
        hex: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Run comprehensive performance benchmarks
    Benchmark {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Specific key label to benchmark (optional - runs full suite if omitted)
        #[arg(long)]
        key_label: Option<String>,
        /// Number of iterations per test
        #[arg(long, default_value = "100")]
        iterations: usize,
        /// Output format (text, json, csv)
        #[arg(long, default_value = "text")]
        format: String,
        /// Number of warmup iterations to exclude from results
        #[arg(long, default_value = "0")]
        warmup: usize,
        /// Output file for JSON/CSV results (stdout if not specified)
        #[arg(long)]
        output: Option<String>,
        /// Compare with previous benchmark results (JSON file)
        #[arg(long)]
        compare: Option<String>,
        /// Test with multiple data sizes (1KB,10KB,100KB,1MB) for encryption/hash ops
        #[arg(long)]
        data_sizes: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Audit keys for security issues
    AuditKeys {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Explain PKCS#11 error codes with troubleshooting steps
    ExplainError {
        /// Error code (e.g., 0xa0, CKR_PIN_INCORRECT, 160)
        error_code: String,
        /// Operation context for targeted advice (sign, verify, encrypt, decrypt, login, wrap)
        #[arg(long)]
        context: Option<String>,
    },

    /// Find keys with fuzzy matching and show similar results
    FindKey {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// Key label pattern to search for
        #[arg(long)]
        key_label: String,
        /// Show similar keys when exact match not found
        #[arg(long)]
        show_similar: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Compare two keys and show attribute differences
    DiffKeys {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
        #[arg(long, conflicts_with = "pin_stdin")]
        user_pin: Option<String>,
        /// First key label
        #[arg(long)]
        key1_label: String,
        /// Second key label
        #[arg(long)]
        key2_label: String,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Read user PIN from stdin instead of command line
        #[arg(long = "pin-stdin")]
        pin_stdin: bool,
    },

    /// Analyze PKCS#11 observability logs and display statistics
    Analyze {
        /// Path to log file (JSON Lines format from observe-core or pkcs11-spy plaintext)
        #[arg(long)]
        log_file: String,
        /// Output format: text (analysis), json (analysis as JSON), events (raw JSON lines), pretty-events (formatted JSON array)
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Launch interactive terminal interface for guided HSM operations
    Interactive {
        /// Token label (uses config default if not specified)
        #[arg(long)]
        label: Option<String>,
    },
}
