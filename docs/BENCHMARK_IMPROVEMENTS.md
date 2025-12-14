# Benchmark Improvements Roadmap

Enhancements to make rust-hsm benchmarking more comprehensive and production-ready.

---

## Current State

**What Works Well:**
- ✅ 14 benchmark tests covering major operations
- ✅ Percentile calculations (P50, P95, P99)
- ✅ Auto-detection of key types
- ✅ Both full suite and custom key modes
- ✅ Clear summary table

**Limitations:**
- ❌ No concurrent/parallel testing
- ❌ No JSON/CSV export
- ❌ No result comparison or tracking
- ❌ Limited warmup/cooldown control
- ❌ No progress bars or live updates
- ❌ No data size variation testing
- ❌ No stress/endurance testing
- ❌ No visual charts

---

## Priority 1: Essential Improvements

### 1. **JSON/CSV Export** ⭐⭐⭐

**Why**: Machine-readable output for automation, analysis, CI/CD

**Implementation**:
```rust
#[derive(Serialize)]
struct BenchmarkReport {
    metadata: Metadata,
    results: Vec<BenchmarkResult>,
    system_info: SystemInfo,
}

#[derive(Serialize)]
struct Metadata {
    timestamp: DateTime<Utc>,
    token_label: String,
    hsm_module: String,
    iterations: usize,
    duration_secs: f64,
}

#[derive(Serialize)]
struct SystemInfo {
    os: String,
    cpu: String,
    memory_gb: f64,
    rust_version: String,
}
```

**Usage**:
```bash
# JSON output
rust-hsm-cli benchmark --label TOKEN --user-pin PIN --iterations 1000 \
  --json > results.json

# CSV output
rust-hsm-cli benchmark --label TOKEN --user-pin PIN --iterations 1000 \
  --csv > results.csv
```

**Benefits**:
- Import into spreadsheets
- Track performance over time
- Automate regression detection
- Generate custom reports

---

### 2. **Concurrent Operations Testing** ⭐⭐⭐

**Why**: Test real-world multi-threaded scenarios

**Implementation**:
```rust
pub fn run_concurrent_benchmark(
    module_path: &str,
    token_label: &str,
    user_pin: &str,
    key_label: &str,
    threads: usize,
    iterations_per_thread: usize,
) -> Result<()> {
    // Spawn N threads, each performing operations
    // Measure aggregate throughput and individual thread latencies
}
```

**Usage**:
```bash
# 4 threads, 250 iterations each = 1000 total
rust-hsm-cli benchmark --label TOKEN --user-pin PIN \
  --key-label my-key --threads 4 --iterations 250
```

**Output**:
```
Concurrent Benchmark: 4 threads
================================
Thread 1: 87.3 ops/sec, avg 11.45ms, p99 13.2ms
Thread 2: 88.1 ops/sec, avg 11.35ms, p99 13.1ms
Thread 3: 86.9 ops/sec, avg 11.51ms, p99 13.4ms
Thread 4: 87.7 ops/sec, avg 11.40ms, p99 13.3ms
--------------------------------
Aggregate: 350.0 ops/sec
Avg latency: 11.43ms
Thread contention: Low (3% variance)
```

---

### 3. **Comparison Mode** ⭐⭐

**Why**: Compare before/after optimization, different HSMs, key sizes

**Implementation**:
```rust
pub fn compare_benchmarks(
    baseline: &Path,
    current: &Path,
) -> Result<()> {
    // Load two JSON benchmark results
    // Calculate deltas, show improvements/regressions
}
```

**Usage**:
```bash
# Save baseline
rust-hsm-cli benchmark --label TOKEN --user-pin PIN --iterations 1000 \
  --json > baseline.json

# Make changes, run again
rust-hsm-cli benchmark --label TOKEN --user-pin PIN --iterations 1000 \
  --json > current.json

# Compare
rust-hsm-cli benchmark-compare baseline.json current.json
```

**Output**:
```
Benchmark Comparison
====================
Baseline: baseline.json (2025-12-13 10:23:45)
Current:  current.json (2025-12-14 15:42:11)

Operation               Baseline    Current     Delta      % Change
--------------------------------------------------------------------
RSA-2048 Signing        89.2        105.3      +16.1      +18.1% ⬆
RSA-4096 Signing        18.5         19.2       +0.7       +3.8% ⬆
ECDSA-P256 Signing     142.3        138.7       -3.6       -2.5% ⬇
AES-GCM Encrypt       1234.5       1456.2     +221.7      +18.0% ⬆

Summary: 3 improved, 1 regressed
Overall performance: +10.2% faster
```

---

### 4. **Data Size Variation** ⭐⭐

**Why**: Test with realistic payloads (1KB, 10KB, 1MB files)

**Implementation**:
```rust
pub fn bench_with_data_sizes(
    session: &Session,
    key_label: &str,
    sizes: &[usize],  // [1024, 10240, 102400, 1048576]
    iterations: usize,
) -> Result<Vec<BenchmarkResult>>
```

**Usage**:
```bash
rust-hsm-cli benchmark --label TOKEN --user-pin PIN \
  --key-label aes-key --data-sizes 1KB,10KB,100KB,1MB \
  --iterations 100
```

**Output**:
```
AES-GCM Encryption - Data Size Impact
======================================
Size       Ops/sec    Throughput (MB/s)    Latency (ms)
--------------------------------------------------------
1 KB       1234.5           1.2                0.81
10 KB       523.4           5.1                1.91
100 KB       78.9           7.7               12.67
1 MB         10.2          10.2               98.04

Observation: Throughput increases with size, latency scales linearly
```

---

### 5. **Progress Indicators** ⭐

**Why**: Long benchmarks (10k+ iterations) need feedback

**Implementation**:
```rust
use indicatif::{ProgressBar, ProgressStyle};

let pb = ProgressBar::new(iterations as u64);
pb.set_style(ProgressStyle::default_bar()
    .template("{msg} [{bar:40.cyan/blue}] {pos}/{len} [{elapsed_precise}]")
    .progress_chars("=>-"));

for i in 0..iterations {
    // ... perform operation ...
    pb.inc(1);
}
pb.finish_with_message("✓ Complete");
```

**Output**:
```
RSA-2048 Signing [=========>..............] 2341/10000 [00:00:23]
Est. remaining: 00:01:32, Current rate: 95.3 ops/sec
```

---

## Priority 2: Advanced Features

### 6. **Warmup & Cooldown** ⭐⭐

**Why**: First iterations often slower due to cold caches

**Usage**:
```bash
rust-hsm-cli benchmark --label TOKEN --user-pin PIN \
  --warmup 100 --iterations 1000 --cooldown 50
```

**Logic**:
```rust
// Warmup (excluded from results)
for _ in 0..warmup { /* ... */ }

// Actual benchmark
let mut results = vec![];
for _ in 0..iterations { /* ... collect results ... */ }

// Cooldown (detect thermal throttling)
for _ in 0..cooldown { /* ... check if perf degrades ... */ }
```

---

### 7. **Stress Testing** ⭐⭐

**Why**: Find HSM limits, test stability under load

**Usage**:
```bash
# Run until failure or time limit
rust-hsm-cli benchmark-stress --label TOKEN --user-pin PIN \
  --key-label my-key --duration 3600 --threads 8
```

**Output**:
```
Stress Test - 1 hour duration
==============================
Threads: 8
Target: my-key (RSA-2048)

Time     Ops/sec   Errors   CPU    Temp
-----------------------------------------
00:00    702.3        0    95%    58°C
00:05    698.1        0    96%    62°C
00:10    695.4        0    96%    64°C
...
00:55    687.2        0    97%    68°C
01:00    683.5        0    97%    69°C

Total ops: 2,465,340
Total errors: 0
Performance degradation: 2.7% (thermal throttling?)
```

---

### 8. **Latency Histograms** ⭐

**Why**: Visualize distribution, identify outliers

**Implementation**:
```rust
use textplots::{Chart, Plot, Shape};

fn print_histogram(durations: &[Duration]) {
    let data: Vec<(f32, f32)> = durations.iter().enumerate()
        .map(|(i, d)| (i as f32, d.as_secs_f32() * 1000.0))
        .collect();
    
    Chart::new(120, 30, 0.0, durations.len() as f32)
        .lineplot(&Shape::Lines(&data))
        .display();
}
```

**Output**:
```
Latency Distribution (RSA-2048 Signing)
========================================
   14ms ┤                                 ╭──╮
   13ms ┤                             ╭───╯  ╰──╮
   12ms ┤                         ╭───╯         ╰──╮
   11ms ┤                     ╭───╯                ╰──╮
   10ms ┤                 ╭───╯                       ╰──╮
    9ms ┤             ╭───╯                              ╰──╮
    8ms ┤         ╭───╯                                     ╰──╮
    7ms ┤     ╭───╯                                            ╰──╮
    6ms ┤ ╭───╯                                                   ╰─
        └──────────────────────────────────────────────────────────
        0    100   200   300   400   500   600   700   800   900  1000
                            Iteration Number
```

---

### 9. **Operation Mix Testing** ⭐

**Why**: Real apps do mixed operations (sign + verify + encrypt)

**Usage**:
```bash
rust-hsm-cli benchmark-mix --label TOKEN --user-pin PIN \
  --mix "sign:50%,verify:30%,encrypt:20%" --duration 60
```

**Output**:
```
Mixed Operation Benchmark
=========================
Duration: 60 seconds
Mix: 50% sign, 30% verify, 20% encrypt

Operation     Count    Ops/sec    % Time
-----------------------------------------
Sign          5,234       87.2    64.3%
Verify        3,141       52.4    21.8%
Encrypt       1,047       17.5    13.9%

Total throughput: 157.1 ops/sec
```

---

### 10. **Custom Test Suites** ⭐

**Why**: Define application-specific benchmark scenarios

**Configuration**:
```toml
# benchmark-suite.toml
[[tests]]
name = "Code Signing Workflow"
operations = [
  { type = "sign", key = "code-sign-key", data_size = "1MB", iterations = 100 },
  { type = "hash", algorithm = "SHA-256", data_size = "1MB", iterations = 1000 },
  { type = "verify", key = "code-sign-key", data_size = "1MB", iterations = 100 },
]

[[tests]]
name = "Document Encryption Workflow"
operations = [
  { type = "gen_random", size = "32B", iterations = 100 },
  { type = "encrypt_aes", key = "doc-encrypt-key", data_size = "10KB", iterations = 500 },
]
```

**Usage**:
```bash
rust-hsm-cli benchmark-suite --config benchmark-suite.toml \
  --label TOKEN --user-pin PIN
```

---

## Priority 3: Ecosystem Integration

### 11. **CI/CD Integration**

**GitHub Actions Example**:
```yaml
name: HSM Performance Test

on: [push, pull_request]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Benchmark
        run: |
          docker compose up -d
          docker exec rust-hsm-app /app/benchmark.sh
      
      - name: Compare with Baseline
        run: |
          docker exec rust-hsm-app rust-hsm-cli benchmark-compare \
            baseline.json current.json --threshold 10%
      
      - name: Fail on Regression
        if: failure()
        run: echo "Performance regressed by >10%!"
```

---

### 12. **Grafana/Prometheus Export**

**Prometheus Metrics**:
```rust
// Export metrics for monitoring
pub fn export_prometheus_metrics(results: &[BenchmarkResult]) -> String {
    let mut output = String::new();
    
    for result in results {
        output.push_str(&format!(
            "hsm_ops_per_sec{{operation=\"{}\"}} {}\n",
            result.name, result.ops_per_sec()
        ));
        output.push_str(&format!(
            "hsm_latency_p99_ms{{operation=\"{}\"}} {}\n",
            result.name, result.percentiles.p99.as_secs_f64() * 1000.0
        ));
    }
    
    output
}
```

**Usage**:
```bash
# Export to Prometheus pushgateway
rust-hsm-cli benchmark --label TOKEN --user-pin PIN \
  --prometheus | curl --data-binary @- \
  http://pushgateway:9091/metrics/job/hsm_benchmark
```

---

## Implementation Plan

### Phase 1 (Quick Wins) - 1-2 weeks
- [ ] JSON export
- [ ] CSV export
- [ ] Progress indicators
- [ ] Warmup/cooldown

### Phase 2 (Core Features) - 2-3 weeks
- [ ] Concurrent operations
- [ ] Comparison mode
- [ ] Data size variation
- [ ] Latency histograms

### Phase 3 (Advanced) - 3-4 weeks
- [ ] Stress testing
- [ ] Operation mix
- [ ] Custom test suites
- [ ] CI/CD integration

### Phase 4 (Polish) - 1-2 weeks
- [ ] Prometheus export
- [ ] Visual charts
- [ ] Regression detection
- [ ] Documentation updates

---

## Technical Considerations

### Dependencies to Add

```toml
[dependencies]
# For progress bars
indicatif = "0.17"

# For JSON serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# For CSV export
csv = "1.3"

# For date/time
chrono = { version = "0.4", features = ["serde"] }

# For system info
sysinfo = "0.30"

# For charts (optional)
textplots = "0.8"

# For concurrency
rayon = "1.8"
```

### API Changes

Maintain backward compatibility:
```rust
// Old API still works
pub fn run_full_benchmark(...) -> Result<()>

// New API with options
pub fn run_benchmark_with_options(
    config: BenchmarkConfig,
) -> Result<BenchmarkReport>

#[derive(Default)]
pub struct BenchmarkConfig {
    pub module_path: String,
    pub token_label: String,
    pub user_pin: String,
    pub iterations: usize,
    pub threads: Option<usize>,
    pub warmup: Option<usize>,
    pub data_sizes: Option<Vec<usize>>,
    pub export_json: bool,
    pub export_csv: bool,
}
```

---

## Next Steps

1. **Review priorities** - Which features matter most?
2. **Prototype JSON export** - Quick win, high value
3. **Design concurrent API** - Most complex feature
4. **Create test suite** - Validate improvements
5. **Update documentation** - Keep docs in sync

Would you like me to implement any of these improvements? I'd suggest starting with:
1. **JSON/CSV export** (easy, immediate value)
2. **Progress indicators** (easy, better UX)
3. **Comparison mode** (medium, high value)
