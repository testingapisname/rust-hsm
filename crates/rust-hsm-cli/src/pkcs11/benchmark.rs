use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use std::fs::File;
use std::io::Write;
use tracing::info;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use indicatif::{ProgressBar, ProgressStyle};
use sysinfo::System;

use super::keys::find_token_slot;

#[derive(Debug, Serialize, Deserialize)]
struct BenchmarkResult {
    name: String,
    iterations: usize,
    #[serde(serialize_with = "serialize_duration_ms", deserialize_with = "deserialize_duration_ms")]
    total_duration: Duration,
    #[serde(serialize_with = "serialize_duration_ms", deserialize_with = "deserialize_duration_ms")]
    min: Duration,
    #[serde(serialize_with = "serialize_duration_ms", deserialize_with = "deserialize_duration_ms")]
    max: Duration,
    percentiles: Percentiles,
    #[serde(skip_serializing_if = "Option::is_none")]
    warmup_iterations: Option<usize>,
}

fn serialize_duration_ms<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_f64(duration.as_secs_f64() * 1000.0)
}

fn deserialize_duration_ms<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ms = f64::deserialize(deserializer)?;
    Ok(Duration::from_secs_f64(ms / 1000.0))
}

#[derive(Debug, Serialize, Deserialize)]
struct Percentiles {
    #[serde(serialize_with = "serialize_duration_ms", deserialize_with = "deserialize_duration_ms")]
    p50: Duration,
    #[serde(serialize_with = "serialize_duration_ms", deserialize_with = "deserialize_duration_ms")]
    p95: Duration,
    #[serde(serialize_with = "serialize_duration_ms", deserialize_with = "deserialize_duration_ms")]
    p99: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
struct BenchmarkReport {
    metadata: BenchmarkMetadata,
    results: Vec<BenchmarkResultWithMetrics>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BenchmarkMetadata {
    timestamp: DateTime<Utc>,
    token_label: String,
    iterations_per_test: usize,
    warmup_iterations: usize,
    system_info: SystemInfo,
}

#[derive(Debug, Serialize, Deserialize)]
struct SystemInfo {
    os: String,
    os_version: String,
    cpu_count: usize,
    total_memory_mb: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct BenchmarkResultWithMetrics {
    #[serde(flatten)]
    result: BenchmarkResult,
    ops_per_sec: f64,
    avg_latency_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

impl BenchmarkResult {
    fn ops_per_sec(&self) -> f64 {
        self.iterations as f64 / self.total_duration.as_secs_f64()
    }

    fn avg_latency_ms(&self) -> f64 {
        self.total_duration.as_secs_f64() * 1000.0 / self.iterations as f64
    }

    fn calculate_percentiles(mut durations: Vec<Duration>) -> Percentiles {
        durations.sort();
        let p50_idx = (durations.len() as f64 * 0.50) as usize;
        let p95_idx = (durations.len() as f64 * 0.95) as usize;
        let p99_idx = (durations.len() as f64 * 0.99) as usize;
        
        Percentiles {
            p50: durations[p50_idx.min(durations.len() - 1)],
            p95: durations[p95_idx.min(durations.len() - 1)],
            p99: durations[p99_idx.min(durations.len() - 1)],
        }
    }

    fn to_result_with_metrics(&self) -> BenchmarkResultWithMetrics {
        BenchmarkResultWithMetrics {
            ops_per_sec: self.ops_per_sec(),
            avg_latency_ms: self.avg_latency_ms(),
            p50_ms: self.percentiles.p50.as_secs_f64() * 1000.0,
            p95_ms: self.percentiles.p95.as_secs_f64() * 1000.0,
            p99_ms: self.percentiles.p99.as_secs_f64() * 1000.0,
            result: BenchmarkResult {
                name: self.name.clone(),
                iterations: self.iterations,
                total_duration: self.total_duration,
                min: self.min,
                max: self.max,
                percentiles: Percentiles {
                    p50: self.percentiles.p50,
                    p95: self.percentiles.p95,
                    p99: self.percentiles.p99,
                },
                warmup_iterations: self.warmup_iterations,
            },
        }
    }
}

fn get_system_info() -> SystemInfo {
    let mut sys = System::new_all();
    sys.refresh_all();

    SystemInfo {
        os: System::name().unwrap_or_else(|| "Unknown".to_string()),
        os_version: System::os_version().unwrap_or_else(|| "Unknown".to_string()),
        cpu_count: sys.cpus().len(),
        total_memory_mb: sys.total_memory() / 1024 / 1024,
    }
}

pub fn run_full_benchmark(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
    key_label: Option<&str>,
    iterations: usize,
    format: &str,
    warmup: usize,
    output_file: Option<&str>,
    compare_file: Option<&str>,
    data_sizes: bool,
) -> Result<()> {
    let show_progress = format == "text" && output_file.is_none();
    
    // Load comparison baseline if provided
    let baseline = if let Some(path) = compare_file {
        Some(load_baseline(path)?)
    } else {
        None
    };
    
    if show_progress {
        println!("\n{}", "=".repeat(80));
        println!("HSM Performance Benchmark Suite");
        println!("{}", "=".repeat(80));
        println!("Token: {}", token_label);
        if let Some(key) = key_label {
            println!("Key: {}", key);
        } else {
            println!("Mode: Full suite with temporary keys");
        }
        println!("Iterations per test: {}", iterations);
        if warmup > 0 {
            println!("Warmup iterations: {}", warmup);
        }
        if data_sizes {
            println!("Data sizes: 1KB, 10KB, 100KB, 1MB");
        }
        if baseline.is_some() {
            println!("Comparison mode: Enabled");
        }
        println!("Output format: {}", format);
        println!("{}\n", "=".repeat(80));
    }

    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;
    
    pkcs11.initialize(CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11 module")?;

    let slot = find_token_slot(&pkcs11, token_label)?;
    let session = pkcs11.open_rw_session(slot)?;
    let pin = AuthPin::new(user_pin.to_string());
    session.login(UserType::User, Some(&pin))?;

    let mut results = Vec::new();

    if let Some(key_label) = key_label {
        // Benchmark specific user key
        info!("Benchmarking specific key: {}", key_label);
        results.extend(benchmark_specific_key(&session, key_label, iterations, warmup, show_progress)?);
    } else {
        // Generate test keys and run full suite
        info!("Setting up test keys for benchmarking...");
        setup_benchmark_keys(&session)?;

        // Benchmark signing operations
        if show_progress {
            println!("\n📝 SIGNING OPERATIONS\n");
        }
        results.push(bench_rsa_sign(&session, "bench-rsa-2048", 2048, iterations, warmup, show_progress)?);
        results.push(bench_rsa_sign(&session, "bench-rsa-4096", 4096, iterations, warmup, show_progress)?);
        results.push(bench_ecdsa_sign(&session, "bench-p256", "P-256", iterations, warmup, show_progress)?);
        results.push(bench_ecdsa_sign(&session, "bench-p384", "P-384", iterations, warmup, show_progress)?);

        // Benchmark verification operations
        if show_progress {
            println!("\n✅ VERIFICATION OPERATIONS\n");
        }
        results.push(bench_rsa_verify(&session, "bench-rsa-2048", iterations, warmup, show_progress)?);
        results.push(bench_ecdsa_verify(&session, "bench-p256", iterations, warmup, show_progress)?);

        // Benchmark encryption operations
        if show_progress {
            println!("\n🔐 ENCRYPTION OPERATIONS\n");
        }
        results.push(bench_rsa_encrypt(&session, "bench-rsa-2048", iterations, warmup, show_progress)?);
        results.push(bench_aes_encrypt(&session, "bench-aes-256", iterations, warmup, show_progress)?);

        // Benchmark hash operations
        if show_progress {
            println!("\n#️⃣ HASH OPERATIONS\n");
        }
        results.push(bench_hash(&session, "SHA-256", Mechanism::Sha256, iterations, warmup, show_progress)?);
        results.push(bench_hash(&session, "SHA-384", Mechanism::Sha384, iterations, warmup, show_progress)?);
        results.push(bench_hash(&session, "SHA-512", Mechanism::Sha512, iterations, warmup, show_progress)?);

        // Benchmark MAC operations
        if show_progress {
            println!("\n🔏 MAC OPERATIONS\n");
        }
        results.push(bench_hmac(&session, "bench-hmac-key", iterations, warmup, show_progress)?);
        results.push(bench_cmac(&session, "bench-cmac-key", iterations, warmup, show_progress)?);

        // Benchmark random generation
        if show_progress {
            println!("\n🎲 RANDOM GENERATION\n");
        }
        results.push(bench_random(&session, iterations, warmup, show_progress)?);
        
        // Data size variation tests (if enabled)
        if data_sizes {
            if show_progress {
                println!("\n📊 DATA SIZE VARIATION\n");
            }
            let sizes = vec![(1024, "1KB"), (10240, "10KB"), (102400, "100KB"), (1048576, "1MB")];
            for (size, label) in sizes {
                results.push(bench_aes_encrypt_size(&session, "bench-aes-256", size, label, iterations, warmup, show_progress)?);
                results.push(bench_hash_size(&session, "SHA-256", Mechanism::Sha256, size, label, iterations, warmup, show_progress)?);
            }
        }
    }

    // Output results based on format
    match format {
        "json" => output_json(&results, token_label, iterations, warmup, output_file)?,
        "csv" => output_csv(&results, output_file)?,
        _ => {
            if let Some(ref baseline_data) = baseline {
                print_comparison_table(&results, baseline_data);
            } else {
                print_summary_table(&results);
            }
        }
    }

    Ok(())
}

fn setup_benchmark_keys(session: &cryptoki::session::Session) -> Result<()> {
    use cryptoki::object::Attribute;
    use cryptoki::mechanism::Mechanism;

    // Helper to check if key exists
    let key_exists = |label: &str| -> bool {
        session.find_objects(&[Attribute::Label(label.as_bytes().to_vec())])
            .ok()
            .and_then(|objs| objs.first().copied())
            .is_some()
    };

    // RSA-2048
    if !key_exists("bench-rsa-2048") {
        session.generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::Label(b"bench-rsa-2048".to_vec()),
                Attribute::Id(b"bench-rsa-2048".to_vec()),
                Attribute::Verify(true),
                Attribute::Encrypt(true),
                Attribute::ModulusBits(2048.into()),
                Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            ],
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Label(b"bench-rsa-2048".to_vec()),
                Attribute::Id(b"bench-rsa-2048".to_vec()),
                Attribute::Sign(true),
                Attribute::Decrypt(true),
            ],
        ).context("Failed to generate RSA-2048 keypair")?;
    }

    // RSA-4096
    if !key_exists("bench-rsa-4096") {
        session.generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::Label(b"bench-rsa-4096".to_vec()),
                Attribute::Id(b"bench-rsa-4096".to_vec()),
                Attribute::Verify(true),
                Attribute::Encrypt(true),
                Attribute::ModulusBits(4096.into()),
                Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            ],
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Label(b"bench-rsa-4096".to_vec()),
                Attribute::Id(b"bench-rsa-4096".to_vec()),
                Attribute::Sign(true),
                Attribute::Decrypt(true),
            ],
        ).context("Failed to generate RSA-4096 keypair")?;
    }

    // ECDSA P-256
    if !key_exists("bench-p256") {
        let p256_params: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        session.generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::Label(b"bench-p256".to_vec()),
                Attribute::Id(b"bench-p256".to_vec()),
                Attribute::Verify(true),
                Attribute::EcParams(p256_params.to_vec()),
            ],
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Label(b"bench-p256".to_vec()),
                Attribute::Id(b"bench-p256".to_vec()),
                Attribute::Sign(true),
            ],
        ).context("Failed to generate P-256 keypair")?;
    }

    // ECDSA P-384
    if !key_exists("bench-p384") {
        let p384_params: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
        session.generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::Label(b"bench-p384".to_vec()),
                Attribute::Id(b"bench-p384".to_vec()),
                Attribute::Verify(true),
                Attribute::EcParams(p384_params.to_vec()),
            ],
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Label(b"bench-p384".to_vec()),
                Attribute::Id(b"bench-p384".to_vec()),
                Attribute::Sign(true),
            ],
        ).context("Failed to generate P-384 keypair")?;
    }

    // AES-256
    if !key_exists("bench-aes-256") {
        session.generate_key(
            &Mechanism::AesKeyGen,
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Label(b"bench-aes-256".to_vec()),
                Attribute::Encrypt(true),
                Attribute::Decrypt(true),
                Attribute::ValueLen(32.into()),
            ],
        ).context("Failed to generate AES-256 key")?;
    }

    // HMAC key
    if !key_exists("bench-hmac-key") {
        session.generate_key(
            &Mechanism::GenericSecretKeyGen,
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Label(b"bench-hmac-key".to_vec()),
                Attribute::Sign(true),
                Attribute::Verify(true),
                Attribute::ValueLen(32.into()),
            ],
        ).context("Failed to generate HMAC key")?;
    }

    // CMAC key
    if !key_exists("bench-cmac-key") {
        session.generate_key(
            &Mechanism::AesKeyGen,
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Label(b"bench-cmac-key".to_vec()),
                Attribute::Sign(true),
                Attribute::Verify(true),
                Attribute::ValueLen(32.into()),
            ],
        ).context("Failed to generate CMAC key")?;
    }

    Ok(())
}

fn find_key(session: &cryptoki::session::Session, label: &str, class: ObjectClass) -> Result<cryptoki::object::ObjectHandle> {
    let objects = session.find_objects(&[
        Attribute::Class(class),
        Attribute::Label(label.as_bytes().to_vec()),
    ])?;
    objects.first().copied().ok_or_else(|| anyhow::anyhow!("Key not found: {}", label))
}

fn detect_key_type(session: &cryptoki::session::Session, label: &str) -> Result<String> {
    use cryptoki::object::KeyType;
    
    // Try to find as private key first
    if let Ok(key) = find_key(session, label, ObjectClass::PRIVATE_KEY) {
        let attrs = session.get_attributes(key, &[
            cryptoki::object::AttributeType::KeyType,
            cryptoki::object::AttributeType::ModulusBits,
        ])?;
        
        for attr in &attrs {
            if let Attribute::KeyType(key_type) = attr {
                match key_type {
                    &KeyType::RSA => {
                        // Get modulus bits
                        for attr in &attrs {
                            if let Attribute::ModulusBits(bits) = attr {
                                return Ok(format!("RSA-{}", bits.to_string()));
                            }
                        }
                        return Ok("RSA".to_string());
                    }
                    &KeyType::EC => {
                        // Try to determine curve
                        let ec_attrs = session.get_attributes(key, &[cryptoki::object::AttributeType::EcParams])?;
                        for attr in ec_attrs {
                            if let Attribute::EcParams(params) = attr {
                                // P-256: [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
                                // P-384: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
                                if params.len() == 10 && params[0..2] == [0x06, 0x08] {
                                    return Ok("ECDSA-P256".to_string());
                                } else if params.len() == 7 && params[0..2] == [0x06, 0x05] {
                                    return Ok("ECDSA-P384".to_string());
                                }
                                return Ok("ECDSA".to_string());
                            }
                        }
                        return Ok("ECDSA".to_string());
                    }
                    _ => return Ok(format!("{:?}", key_type)),
                }
            }
        }
    }
    
    // Try as secret key
    if let Ok(key) = find_key(session, label, ObjectClass::SECRET_KEY) {
        let attrs = session.get_attributes(key, &[cryptoki::object::AttributeType::KeyType])?;
        for attr in &attrs {
            if let Attribute::KeyType(key_type) = attr {
                match key_type {
                    &KeyType::AES => return Ok("AES".to_string()),
                    &KeyType::GENERIC_SECRET => return Ok("GENERIC_SECRET".to_string()),
                    _ => return Ok(format!("{:?}", key_type)),
                }
            }
        }
    }
    
    anyhow::bail!("Could not determine key type for '{}'", label)
}

fn benchmark_specific_key(
    session: &cryptoki::session::Session,
    key_label: &str,
    iterations: usize,
    warmup: usize,
    show_progress: bool,
) -> Result<Vec<BenchmarkResult>> {
    let key_type = detect_key_type(session, key_label)?;
    info!("Detected key type: {}", key_type);
    
    let mut results = Vec::new();
    
    if key_type.starts_with("RSA") {
        // Extract bit size
        let bits: usize = if key_type.contains("-") {
            key_type.split('-').nth(1).and_then(|s| s.parse().ok()).unwrap_or(2048)
        } else {
            2048
        };
        
        if show_progress {
            println!("\n📝 RSA OPERATIONS\n");
            println!("Testing RSA-{} key: {}\n", bits, key_label);
        }
        
        results.push(bench_rsa_sign(session, key_label, bits, iterations, warmup, show_progress)?);
        results.push(bench_rsa_verify(session, key_label, iterations, warmup, show_progress)?);
        results.push(bench_rsa_encrypt(session, key_label, iterations, warmup, show_progress)?);
        
    } else if key_type.starts_with("ECDSA") {
        let curve = if key_type.contains("P256") {
            "P-256"
        } else if key_type.contains("P384") {
            "P-384"
        } else {
            "P-256" // default
        };
        
        if show_progress {
            println!("\n📝 ECDSA OPERATIONS\n");
            println!("Testing {} key: {}\n", key_type, key_label);
        }
        
        results.push(bench_ecdsa_sign(session, key_label, curve, iterations, warmup, show_progress)?);
        results.push(bench_ecdsa_verify(session, key_label, iterations, warmup, show_progress)?);
        
    } else if key_type == "AES" || key_type == "GENERIC_SECRET" {
        if show_progress {
            println!("\n🔐 SYMMETRIC KEY OPERATIONS\n");
            println!("Testing {} key: {}\n", key_type, key_label);
        }
        
        if key_type == "AES" {
            // Check if it's CMAC-capable (CKA_SIGN attribute)
            if let Ok(key) = find_key(session, key_label, ObjectClass::SECRET_KEY) {
                let attrs = session.get_attributes(key, &[
                    cryptoki::object::AttributeType::Sign,
                    cryptoki::object::AttributeType::Encrypt,
                ])?;
                
                let can_sign = attrs.iter().any(|a| matches!(a, Attribute::Sign(true)));
                let can_encrypt = attrs.iter().any(|a| matches!(a, Attribute::Encrypt(true)));
                
                if can_encrypt {
                    results.push(bench_aes_encrypt(session, key_label, iterations, warmup, show_progress)?);
                }
                if can_sign {
                    results.push(bench_cmac(session, key_label, iterations, warmup, show_progress)?);
                }
            }
        } else {
            // GENERIC_SECRET - assume HMAC
            results.push(bench_hmac(session, key_label, iterations, warmup, show_progress)?);
        }
    } else {
        anyhow::bail!("Unsupported key type for benchmarking: {}", key_type);
    }
    
    Ok(results)
}

fn bench_rsa_sign(session: &cryptoki::session::Session, key_label: &str, bits: usize, iterations: usize, warmup: usize, show_progress: bool) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::PRIVATE_KEY)?;
    let data = b"Benchmark data for signing operation";
    let mechanism = Mechanism::Sha256RsaPkcs;
    
    run_benchmark_with_warmup(
        format!("RSA-{} Sign", bits),
        iterations,
        warmup,
        show_progress,
        || {
            let _ = session.sign(&mechanism, key, data)?;
            Ok(())
        },
    )
}

fn bench_rsa_verify(session: &cryptoki::session::Session, key_label: &str, iterations: usize, warmup: usize, show_progress: bool) -> Result<BenchmarkResult> {
    let priv_key = find_key(session, key_label, ObjectClass::PRIVATE_KEY)?;
    let pub_key = find_key(session, key_label, ObjectClass::PUBLIC_KEY)?;
    let data = b"Benchmark data for verification";
    let mechanism = Mechanism::Sha256RsaPkcs;
    
    let signature = session.sign(&mechanism, priv_key, data)?;
    
    run_benchmark_with_warmup(
        "RSA-2048 Verify".to_string(),
        iterations,
        warmup,
        show_progress,
        || {
            let _ = session.verify(&mechanism, pub_key, data, &signature);
            Ok(())
        },
    )
}

fn bench_ecdsa_sign(session: &cryptoki::session::Session, key_label: &str, curve: &str, iterations: usize, warmup: usize, show_progress: bool) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::PRIVATE_KEY)?;
    let data = b"Benchmark data for ECDSA signing";
    let mechanism = Mechanism::Ecdsa;
    
    // Hash data first (ECDSA requires pre-hashed data)
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    
    run_benchmark_with_warmup(
        format!("ECDSA-{} Sign", curve),
        iterations,
        warmup,
        show_progress,
        || {
            let _ = session.sign(&mechanism, key, &hash)?;
            Ok(())
        },
    )
}

fn bench_ecdsa_verify(session: &cryptoki::session::Session, key_label: &str, iterations: usize, warmup: usize, show_progress: bool) -> Result<BenchmarkResult> {
    let priv_key = find_key(session, key_label, ObjectClass::PRIVATE_KEY)?;
    let pub_key = find_key(session, key_label, ObjectClass::PUBLIC_KEY)?;
    let data = b"Benchmark data for ECDSA verification";
    let mechanism = Mechanism::Ecdsa;
    
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    
    let signature = session.sign(&mechanism, priv_key, &hash)?;
    
    run_benchmark_with_warmup(
        "ECDSA-P256 Verify".to_string(),
        iterations,
        warmup,
        show_progress,
        || {
            let _ = session.verify(&mechanism, pub_key, &hash, &signature);
            Ok(())
        },
    )
}

fn bench_rsa_encrypt(session: &cryptoki::session::Session, key_label: &str, iterations: usize, warmup: usize, show_progress: bool) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::PUBLIC_KEY)?;
    let data = b"Benchmark test data";
    let mechanism = Mechanism::RsaPkcs;
    
    run_benchmark_with_warmup(
        "RSA-2048 Encrypt".to_string(),
        iterations,
        warmup,
        show_progress,
        || {
            let _ = session.encrypt(&mechanism, key, data)?;
            Ok(())
        },
    )
}

fn bench_aes_encrypt(session: &cryptoki::session::Session, key_label: &str, iterations: usize, warmup: usize, show_progress: bool) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::SECRET_KEY)?;
    let data = vec![0u8; 1024]; // 1KB data
    
    run_benchmark_with_warmup(
        "AES-256-GCM Encrypt (1KB)".to_string(),
        iterations,
        warmup,
        show_progress,
        || {
            let mut iv = vec![0u8; 12];
            session.generate_random_slice(&mut iv)?;
            let mechanism = Mechanism::AesGcm(cryptoki::mechanism::aead::GcmParams::new(&mut iv, &[], 128.into())?);
            let _ = session.encrypt(&mechanism, key, &data)?;
            Ok(())
        },
    )
}

fn bench_hash(session: &cryptoki::session::Session, name: &str, mechanism: Mechanism, iterations: usize, warmup: usize, show_progress: bool) -> Result<BenchmarkResult> {
    let data = vec![0u8; 1024]; // 1KB data
    
    run_benchmark_with_warmup(
        format!("{} Hash (1KB)", name),
        iterations,
        warmup,
        show_progress,
        || {
            let _ = session.digest(&mechanism, &data)?;
            Ok(())
        },
    )
}

fn bench_hmac(session: &cryptoki::session::Session, key_label: &str, iterations: usize, warmup: usize, show_progress: bool) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::SECRET_KEY)?;
    let data = b"Benchmark HMAC data";
    let mechanism = Mechanism::Sha256Hmac;
    
    run_benchmark_with_warmup(
        "HMAC-SHA256".to_string(),
        iterations,
        warmup,
        show_progress,
        || {
            let _ = session.sign(&mechanism, key, data)?;
            Ok(())
        },
    )
}

fn bench_cmac(session: &cryptoki::session::Session, key_label: &str, iterations: usize, warmup: usize, show_progress: bool) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::SECRET_KEY)?;
    let data = b"Benchmark CMAC data";
    let mechanism = Mechanism::AesCMac;
    
    run_benchmark_with_warmup(
        "AES-CMAC".to_string(),
        iterations,
        warmup,
        show_progress,
        || {
            let _ = session.sign(&mechanism, key, data)?;
            Ok(())
        },
    )
}

fn bench_random(session: &cryptoki::session::Session, iterations: usize, warmup: usize, show_progress: bool) -> Result<BenchmarkResult> {
    let mut buffer = vec![0u8; 32];
    
    run_benchmark_with_warmup(
        "Random (32 bytes)".to_string(),
        iterations,
        warmup,
        show_progress,
        || {
            session.generate_random_slice(&mut buffer)?;
            Ok(())
        },
    )
}

fn create_progress_bar(name: &str, iterations: usize) -> ProgressBar {
    let pb = ProgressBar::new(iterations as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {pos}/{len} ({per_sec}, {elapsed}/{eta})")
            .unwrap()
            .progress_chars("=>-"),
    );
    pb.set_message(format!("{:<30}", name));
    pb
}

fn run_benchmark_with_warmup<F>(
    name: String,
    iterations: usize,
    warmup: usize,
    show_progress: bool,
    mut operation: F,
) -> Result<BenchmarkResult>
where
    F: FnMut() -> Result<()>,
{
    // Warmup phase
    for _ in 0..warmup {
        operation()?;
    }

    // Actual benchmark
    let pb = if show_progress {
        Some(create_progress_bar(&name, iterations))
    } else {
        None
    };

    let mut durations = Vec::with_capacity(iterations);
    let start = Instant::now();

    for _ in 0..iterations {
        let iter_start = Instant::now();
        operation()?;
        durations.push(iter_start.elapsed());
        if let Some(ref pb) = pb {
            pb.inc(1);
        }
    }

    let total = start.elapsed();

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    Ok(BenchmarkResult {
        name,
        iterations,
        total_duration: total,
        min: *durations.iter().min().unwrap(),
        max: *durations.iter().max().unwrap(),
        percentiles: BenchmarkResult::calculate_percentiles(durations),
        warmup_iterations: if warmup > 0 { Some(warmup) } else { None },
    })
}

fn output_json(
    results: &[BenchmarkResult],
    token_label: &str,
    iterations: usize,
    warmup: usize,
    output_file: Option<&str>,
) -> Result<()> {
    let report = BenchmarkReport {
        metadata: BenchmarkMetadata {
            timestamp: Utc::now(),
            token_label: token_label.to_string(),
            iterations_per_test: iterations,
            warmup_iterations: warmup,
            system_info: get_system_info(),
        },
        results: results.iter().map(|r| r.to_result_with_metrics()).collect(),
    };

    let json = serde_json::to_string_pretty(&report)?;

    if let Some(path) = output_file {
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        eprintln!("✓ Benchmark results written to {}", path);
    } else {
        println!("{}", json);
    }

    Ok(())
}

fn output_csv(results: &[BenchmarkResult], output_file: Option<&str>) -> Result<()> {
    if let Some(path) = output_file {
        let mut wtr = csv::Writer::from_path(path)?;
        write_csv_data(&mut wtr, results)?;
        wtr.flush()?;
        eprintln!("✓ Benchmark results written to {}", path);
    } else {
        let mut wtr = csv::Writer::from_writer(std::io::stdout());
        write_csv_data(&mut wtr, results)?;
        wtr.flush()?;
    }

    Ok(())
}

fn write_csv_data<W: std::io::Write>(wtr: &mut csv::Writer<W>, results: &[BenchmarkResult]) -> Result<()> {
    // Write header
    wtr.write_record(&[
        "operation",
        "iterations",
        "warmup_iterations",
        "ops_per_sec",
        "avg_latency_ms",
        "min_ms",
        "max_ms",
        "p50_ms",
        "p95_ms",
        "p99_ms",
    ])?;

    // Write data
    for result in results {
        wtr.write_record(&[
            result.name.clone(),
            result.iterations.to_string(),
            result.warmup_iterations.map(|w| w.to_string()).unwrap_or_else(|| "0".to_string()),
            format!("{:.1}", result.ops_per_sec()),
            format!("{:.2}", result.avg_latency_ms()),
            format!("{:.2}", result.min.as_secs_f64() * 1000.0),
            format!("{:.2}", result.max.as_secs_f64() * 1000.0),
            format!("{:.2}", result.percentiles.p50.as_secs_f64() * 1000.0),
            format!("{:.2}", result.percentiles.p95.as_secs_f64() * 1000.0),
            format!("{:.2}", result.percentiles.p99.as_secs_f64() * 1000.0),
        ])?;
    }

    Ok(())
}

fn print_summary_table(results: &[BenchmarkResult]) {
    println!("\n{}", "=".repeat(80));
    println!("BENCHMARK RESULTS SUMMARY");
    println!("{}", "=".repeat(80));
    println!("{:<30} {:>10} {:>10} {:>10} {:>10} {:>10}", 
        "Operation", "Ops/sec", "Avg (ms)", "P50 (ms)", "P95 (ms)", "P99 (ms)");
    println!("{}", "-".repeat(80));
    
    for result in results {
        println!("{:<30} {:>10.1} {:>10.2} {:>10.2} {:>10.2} {:>10.2}",
            result.name,
            result.ops_per_sec(),
            result.avg_latency_ms(),
            result.percentiles.p50.as_secs_f64() * 1000.0,
            result.percentiles.p95.as_secs_f64() * 1000.0,
            result.percentiles.p99.as_secs_f64() * 1000.0,
        );
    }
    
    println!("{}", "=".repeat(80));
}
fn load_baseline(path: &str) -> Result<BenchmarkReport> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open baseline file: {}", path))?;
    let report: BenchmarkReport = serde_json::from_reader(file)
        .with_context(|| format!("Failed to parse baseline JSON: {}", path))?;
    Ok(report)
}

fn print_comparison_table(results: &[BenchmarkResult], baseline: &BenchmarkReport) {
    println!("\n{}", "=".repeat(100));
    println!("BENCHMARK COMPARISON (Current vs Baseline)");
    println!("{}", "=".repeat(100));
    println!("Baseline: {} | {}", baseline.metadata.timestamp, baseline.metadata.token_label);
    println!("{}", "=".repeat(100));
    println!("{:<30} {:>10} {:>10} {:>10} {:>10} {:>10}", 
        "Operation", "Current", "Baseline", "Diff %", "P95 Cur", "P95 Base");
    println!("{}", "-".repeat(100));
    
    for result in results {
        // Find matching baseline result by name
        if let Some(baseline_result) = baseline.results.iter().find(|r| r.result.name == result.name) {
            let current_ops = result.ops_per_sec();
            let baseline_ops = baseline_result.ops_per_sec;
            let diff_pct = ((current_ops - baseline_ops) / baseline_ops) * 100.0;
            
            // Color code: green for improvements (>5%), red for regressions (<-5%)
            let diff_str = if diff_pct > 5.0 {
                format!("🟢 +{:.1}%", diff_pct)
            } else if diff_pct < -5.0 {
                format!("🔴 {:.1}%", diff_pct)
            } else {
                format!("  {:.1}%", diff_pct)
            };
            
            println!("{:<30} {:>10.1} {:>10.1} {:>10} {:>10.2} {:>10.2}",
                result.name,
                current_ops,
                baseline_ops,
                diff_str,
                result.percentiles.p95.as_secs_f64() * 1000.0,
                baseline_result.p95_ms,
            );
        } else {
            // New operation not in baseline
            println!("{:<30} {:>10.1} {:>10} {:>10} {:>10.2} {:>10}",
                result.name,
                result.ops_per_sec(),
                "-",
                "NEW",
                result.percentiles.p95.as_secs_f64() * 1000.0,
                "-",
            );
        }
    }
    
    println!("{}", "=".repeat(100));
    println!("🟢 = Improvement >5%  |  🔴 = Regression >5%");
    println!("{}", "=".repeat(100));
}

fn bench_aes_encrypt_size(
    session: &cryptoki::session::Session,
    key_label: &str,
    data_size: usize,
    size_label: &str,
    iterations: usize,
    warmup: usize,
    show_progress: bool,
) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::SECRET_KEY)?;
    let data = vec![0u8; data_size];
    
    run_benchmark_with_warmup(
        format!("AES-256-GCM Encrypt ({})", size_label),
        iterations,
        warmup,
        show_progress,
        || {
            let mut iv = vec![0u8; 12];
            session.generate_random_slice(&mut iv)?;
            let mechanism = Mechanism::AesGcm(cryptoki::mechanism::aead::GcmParams::new(&mut iv, &[], 128.into())?);
            let _ = session.encrypt(&mechanism, key, &data)?;
            Ok(())
        },
    )
}

fn bench_hash_size(
    session: &cryptoki::session::Session,
    name: &str,
    mechanism: Mechanism,
    data_size: usize,
    size_label: &str,
    iterations: usize,
    warmup: usize,
    show_progress: bool,
) -> Result<BenchmarkResult> {
    let data = vec![0u8; data_size];
    
    run_benchmark_with_warmup(
        format!("{} Hash ({})", name, size_label),
        iterations,
        warmup,
        show_progress,
        || {
            let _ = session.digest(&mechanism, &data)?;
            Ok(())
        },
    )
}