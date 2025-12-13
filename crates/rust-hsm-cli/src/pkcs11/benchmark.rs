use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use tracing::info;

use super::keys::find_token_slot;

#[derive(Debug)]
struct BenchmarkResult {
    name: String,
    iterations: usize,
    total_duration: Duration,
    min: Duration,
    max: Duration,
    percentiles: Percentiles,
}

#[derive(Debug)]
struct Percentiles {
    p50: Duration,
    p95: Duration,
    p99: Duration,
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
}

pub fn run_full_benchmark(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
    iterations: usize,
) -> Result<()> {
    println!("\n{}", "=".repeat(80));
    println!("HSM Performance Benchmark Suite");
    println!("{}", "=".repeat(80));
    println!("Token: {}", token_label);
    println!("Iterations per test: {}", iterations);
    println!("{}\n", "=".repeat(80));

    let pkcs11 = Pkcs11::new(module_path)
        .with_context(|| format!("Failed to load PKCS#11 module: {}", module_path))?;
    
    pkcs11.initialize(CInitializeArgs::OsThreads)
        .context("Failed to initialize PKCS#11 module")?;

    let slot = find_token_slot(&pkcs11, token_label)?;
    let session = pkcs11.open_rw_session(slot)?;
    let pin = AuthPin::new(user_pin.to_string());
    session.login(UserType::User, Some(&pin))?;

    let mut results = Vec::new();

    // Generate test keys
    info!("Setting up test keys for benchmarking...");
    setup_benchmark_keys(&session)?;

    // Benchmark signing operations
    println!("\n📝 SIGNING OPERATIONS\n");
    results.push(bench_rsa_sign(&session, "bench-rsa-2048", 2048, iterations)?);
    results.push(bench_rsa_sign(&session, "bench-rsa-4096", 4096, iterations)?);
    results.push(bench_ecdsa_sign(&session, "bench-p256", "P-256", iterations)?);
    results.push(bench_ecdsa_sign(&session, "bench-p384", "P-384", iterations)?);

    // Benchmark verification operations
    println!("\n✅ VERIFICATION OPERATIONS\n");
    results.push(bench_rsa_verify(&session, "bench-rsa-2048", iterations)?);
    results.push(bench_ecdsa_verify(&session, "bench-p256", iterations)?);

    // Benchmark encryption operations
    println!("\n🔐 ENCRYPTION OPERATIONS\n");
    results.push(bench_rsa_encrypt(&session, "bench-rsa-2048", iterations)?);
    results.push(bench_aes_encrypt(&session, "bench-aes-256", iterations)?);

    // Benchmark hash operations
    println!("\n#️⃣ HASH OPERATIONS\n");
    results.push(bench_hash(&session, "SHA-256", Mechanism::Sha256, iterations)?);
    results.push(bench_hash(&session, "SHA-384", Mechanism::Sha384, iterations)?);
    results.push(bench_hash(&session, "SHA-512", Mechanism::Sha512, iterations)?);

    // Benchmark MAC operations
    println!("\n🔏 MAC OPERATIONS\n");
    results.push(bench_hmac(&session, "bench-hmac-key", iterations)?);
    results.push(bench_cmac(&session, "bench-cmac-key", iterations)?);

    // Benchmark random generation
    println!("\n🎲 RANDOM GENERATION\n");
    results.push(bench_random(&session, iterations)?);

    // Print summary table
    print_summary_table(&results);

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

fn bench_rsa_sign(session: &cryptoki::session::Session, key_label: &str, bits: usize, iterations: usize) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::PRIVATE_KEY)?;
    let data = b"Benchmark data for signing operation";
    let mechanism = Mechanism::Sha256RsaPkcs;
    
    let mut durations = Vec::with_capacity(iterations);
    let start = Instant::now();
    
    for _ in 0..iterations {
        let iter_start = Instant::now();
        let _ = session.sign(&mechanism, key, data)?;
        durations.push(iter_start.elapsed());
    }
    
    let total = start.elapsed();
    
    Ok(BenchmarkResult {
        name: format!("RSA-{} Sign", bits),
        iterations,
        total_duration: total,
        min: *durations.iter().min().unwrap(),
        max: *durations.iter().max().unwrap(),
        percentiles: BenchmarkResult::calculate_percentiles(durations),
    })
}

fn bench_rsa_verify(session: &cryptoki::session::Session, key_label: &str, iterations: usize) -> Result<BenchmarkResult> {
    let priv_key = find_key(session, key_label, ObjectClass::PRIVATE_KEY)?;
    let pub_key = find_key(session, key_label, ObjectClass::PUBLIC_KEY)?;
    let data = b"Benchmark data for verification";
    let mechanism = Mechanism::Sha256RsaPkcs;
    
    let signature = session.sign(&mechanism, priv_key, data)?;
    
    let mut durations = Vec::with_capacity(iterations);
    let start = Instant::now();
    
    for _ in 0..iterations {
        let iter_start = Instant::now();
        let _ = session.verify(&mechanism, pub_key, data, &signature);
        durations.push(iter_start.elapsed());
    }
    
    let total = start.elapsed();
    
    Ok(BenchmarkResult {
        name: format!("RSA-2048 Verify"),
        iterations,
        total_duration: total,
        min: *durations.iter().min().unwrap(),
        max: *durations.iter().max().unwrap(),
        percentiles: BenchmarkResult::calculate_percentiles(durations),
    })
}

fn bench_ecdsa_sign(session: &cryptoki::session::Session, key_label: &str, curve: &str, iterations: usize) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::PRIVATE_KEY)?;
    let data = b"Benchmark data for ECDSA signing";
    let mechanism = Mechanism::Ecdsa;
    
    // Hash data first (ECDSA requires pre-hashed data)
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    
    let mut durations = Vec::with_capacity(iterations);
    let start = Instant::now();
    
    for _ in 0..iterations {
        let iter_start = Instant::now();
        let _ = session.sign(&mechanism, key, &hash)?;
        durations.push(iter_start.elapsed());
    }
    
    let total = start.elapsed();
    
    Ok(BenchmarkResult {
        name: format!("ECDSA-{} Sign", curve),
        iterations,
        total_duration: total,
        min: *durations.iter().min().unwrap(),
        max: *durations.iter().max().unwrap(),
        percentiles: BenchmarkResult::calculate_percentiles(durations),
    })
}

fn bench_ecdsa_verify(session: &cryptoki::session::Session, key_label: &str, iterations: usize) -> Result<BenchmarkResult> {
    let priv_key = find_key(session, key_label, ObjectClass::PRIVATE_KEY)?;
    let pub_key = find_key(session, key_label, ObjectClass::PUBLIC_KEY)?;
    let data = b"Benchmark data for ECDSA verification";
    let mechanism = Mechanism::Ecdsa;
    
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    
    let signature = session.sign(&mechanism, priv_key, &hash)?;
    
    let mut durations = Vec::with_capacity(iterations);
    let start = Instant::now();
    
    for _ in 0..iterations {
        let iter_start = Instant::now();
        let _ = session.verify(&mechanism, pub_key, &hash, &signature);
        durations.push(iter_start.elapsed());
    }
    
    let total = start.elapsed();
    
    Ok(BenchmarkResult {
        name: format!("ECDSA-P256 Verify"),
        iterations,
        total_duration: total,
        min: *durations.iter().min().unwrap(),
        max: *durations.iter().max().unwrap(),
        percentiles: BenchmarkResult::calculate_percentiles(durations),
    })
}

fn bench_rsa_encrypt(session: &cryptoki::session::Session, key_label: &str, iterations: usize) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::PUBLIC_KEY)?;
    let data = b"Benchmark test data";
    let mechanism = Mechanism::RsaPkcs;
    
    let mut durations = Vec::with_capacity(iterations);
    let start = Instant::now();
    
    for _ in 0..iterations {
        let iter_start = Instant::now();
        let _ = session.encrypt(&mechanism, key, data)?;
        durations.push(iter_start.elapsed());
    }
    
    let total = start.elapsed();
    
    Ok(BenchmarkResult {
        name: "RSA-2048 Encrypt".to_string(),
        iterations,
        total_duration: total,
        min: *durations.iter().min().unwrap(),
        max: *durations.iter().max().unwrap(),
        percentiles: BenchmarkResult::calculate_percentiles(durations),
    })
}

fn bench_aes_encrypt(session: &cryptoki::session::Session, key_label: &str, iterations: usize) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::SECRET_KEY)?;
    let data = vec![0u8; 1024]; // 1KB data
    
    let mut durations = Vec::with_capacity(iterations);
    let start = Instant::now();
    
    for _ in 0..iterations {
        let mut iv = vec![0u8; 12];
        session.generate_random_slice(&mut iv)?;
        let mechanism = Mechanism::AesGcm(cryptoki::mechanism::aead::GcmParams::new(&mut iv, &[], 128.into())?);
        
        let iter_start = Instant::now();
        let _ = session.encrypt(&mechanism, key, &data)?;
        durations.push(iter_start.elapsed());
    }
    
    let total = start.elapsed();
    
    Ok(BenchmarkResult {
        name: "AES-256-GCM Encrypt (1KB)".to_string(),
        iterations,
        total_duration: total,
        min: *durations.iter().min().unwrap(),
        max: *durations.iter().max().unwrap(),
        percentiles: BenchmarkResult::calculate_percentiles(durations),
    })
}

fn bench_hash(session: &cryptoki::session::Session, name: &str, mechanism: Mechanism, iterations: usize) -> Result<BenchmarkResult> {
    let data = vec![0u8; 1024]; // 1KB data
    
    let mut durations = Vec::with_capacity(iterations);
    let start = Instant::now();
    
    for _ in 0..iterations {
        let iter_start = Instant::now();
        let _ = session.digest(&mechanism, &data)?;
        durations.push(iter_start.elapsed());
    }
    
    let total = start.elapsed();
    
    Ok(BenchmarkResult {
        name: format!("{} Hash (1KB)", name),
        iterations,
        total_duration: total,
        min: *durations.iter().min().unwrap(),
        max: *durations.iter().max().unwrap(),
        percentiles: BenchmarkResult::calculate_percentiles(durations),
    })
}

fn bench_hmac(session: &cryptoki::session::Session, key_label: &str, iterations: usize) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::SECRET_KEY)?;
    let data = b"Benchmark HMAC data";
    let mechanism = Mechanism::Sha256Hmac;
    
    let mut durations = Vec::with_capacity(iterations);
    let start = Instant::now();
    
    for _ in 0..iterations {
        let iter_start = Instant::now();
        let _ = session.sign(&mechanism, key, data)?;
        durations.push(iter_start.elapsed());
    }
    
    let total = start.elapsed();
    
    Ok(BenchmarkResult {
        name: "HMAC-SHA256".to_string(),
        iterations,
        total_duration: total,
        min: *durations.iter().min().unwrap(),
        max: *durations.iter().max().unwrap(),
        percentiles: BenchmarkResult::calculate_percentiles(durations),
    })
}

fn bench_cmac(session: &cryptoki::session::Session, key_label: &str, iterations: usize) -> Result<BenchmarkResult> {
    let key = find_key(session, key_label, ObjectClass::SECRET_KEY)?;
    let data = b"Benchmark CMAC data";
    let mechanism = Mechanism::AesCMac;
    
    let mut durations = Vec::with_capacity(iterations);
    let start = Instant::now();
    
    for _ in 0..iterations {
        let iter_start = Instant::now();
        let _ = session.sign(&mechanism, key, data)?;
        durations.push(iter_start.elapsed());
    }
    
    let total = start.elapsed();
    
    Ok(BenchmarkResult {
        name: "AES-CMAC".to_string(),
        iterations,
        total_duration: total,
        min: *durations.iter().min().unwrap(),
        max: *durations.iter().max().unwrap(),
        percentiles: BenchmarkResult::calculate_percentiles(durations),
    })
}

fn bench_random(session: &cryptoki::session::Session, iterations: usize) -> Result<BenchmarkResult> {
    let mut buffer = vec![0u8; 32];
    
    let mut durations = Vec::with_capacity(iterations);
    let start = Instant::now();
    
    for _ in 0..iterations {
        let iter_start = Instant::now();
        session.generate_random_slice(&mut buffer)?;
        durations.push(iter_start.elapsed());
    }
    
    let total = start.elapsed();
    
    Ok(BenchmarkResult {
        name: "Random (32 bytes)".to_string(),
        iterations,
        total_duration: total,
        min: *durations.iter().min().unwrap(),
        max: *durations.iter().max().unwrap(),
        percentiles: BenchmarkResult::calculate_percentiles(durations),
    })
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
