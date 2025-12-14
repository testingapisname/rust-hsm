# HSM Performance Benchmarking Guide

Comprehensive guide to benchmarking PKCS#11 HSM operations using rust-hsm-cli.

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Full Suite Benchmark](#full-suite-benchmark)
4. [Custom Key Benchmarking](#custom-key-benchmarking)
5. [Interpreting Results](#interpreting-results)
6. [Benchmarking Best Practices](#benchmarking-best-practices)
7. [Performance Tuning](#performance-tuning)
8. [Comparison Guidelines](#comparison-guidelines)
9. [Advanced Usage](#advanced-usage)

---

## Overview

The benchmark command measures HSM performance across multiple cryptographic operations:

### **Supported Operations**
- **Signing**: RSA (2048/4096), ECDSA (P-256/P-384)
- **Verification**: RSA, ECDSA
- **Encryption**: RSA, AES-GCM
- **Hashing**: SHA-256, SHA-384, SHA-512
- **MACs**: HMAC-SHA256, AES-CMAC
- **Random Generation**: 32-byte samples

### **Metrics Collected**
- **Operations/second** - Throughput measurement
- **Average latency** - Mean operation time
- **Percentiles** - P50 (median), P95, P99 for tail latency
- **Min/Max** - Best and worst case times

---

## Quick Start

### Basic Benchmark (Full Suite)

Run complete benchmark suite with temporary test keys:

```bash
docker exec rust-hsm-app rust-hsm-cli benchmark \
  --label DEV_TOKEN \
  --user-pin 123456 \
  --iterations 100
```

**Output Example:**
```
================================================================================
HSM Performance Benchmark Suite
================================================================================
Token: DEV_TOKEN
Mode: Full suite with temporary keys
Iterations per test: 100
================================================================================

📝 SIGNING OPERATIONS

RSA-2048 Signing: ████████████████████ 100/100 [00:00:01]
  Ops/sec: 89.2, Avg: 11.21ms, P50: 10.95ms, P95: 12.34ms, P99: 13.12ms

RSA-4096 Signing: ████████████████████ 100/100 [00:00:05]
  Ops/sec: 18.5, Avg: 54.03ms, P50: 53.21ms, P95: 58.76ms, P99: 61.23ms

...

================================================================================
BENCHMARK RESULTS SUMMARY
================================================================================
Operation                         Ops/sec    Avg (ms)    P50 (ms)    P95 (ms)    P99 (ms)
--------------------------------------------------------------------------------
RSA-2048 Signing                     89.2       11.21       10.95       12.34       13.12
RSA-4096 Signing                     18.5       54.03       53.21       58.76       61.23
ECDSA-P256 Signing                  142.3        7.03        6.87        7.89        8.45
ECDSA-P384 Signing                   98.7       10.13        9.98       11.02       11.67
RSA-2048 Verify                     234.5        4.27        4.12        4.89        5.23
ECDSA-P256 Verify                   189.2        5.29        5.18        5.78        6.12
RSA-2048 Encrypt                    156.8        6.38        6.21        7.01        7.45
AES-GCM Encrypt                    1234.5        0.81        0.79        0.91        0.98
SHA-256                            8765.4        0.11        0.11        0.13        0.14
SHA-384                            7234.2        0.14        0.13        0.15        0.16
SHA-512                            6543.1        0.15        0.15        0.17        0.18
HMAC-SHA256                        4321.5        0.23        0.22        0.26        0.28
AES-CMAC                           5678.9        0.18        0.17        0.20        0.21
Random (32 bytes)                 12345.6        0.08        0.08        0.09        0.10
================================================================================
```

---

## Full Suite Benchmark

### Standard Configuration

```bash
# 100 iterations (fast, 1-2 minutes)
rust-hsm-cli benchmark --label TOKEN --user-pin PIN --iterations 100

# 1000 iterations (accurate, 10-15 minutes)
rust-hsm-cli benchmark --label TOKEN --user-pin PIN --iterations 1000

# 10000 iterations (production baseline, 1-2 hours)
rust-hsm-cli benchmark --label TOKEN --user-pin PIN --iterations 10000
```

### What Gets Benchmarked

The full suite creates temporary keys and tests:

| Category | Operations | Key Sizes/Curves |
|----------|-----------|------------------|
| **Signing** | 4 tests | RSA-2048, RSA-4096, P-256, P-384 |
| **Verification** | 2 tests | RSA-2048, ECDSA-P256 |
| **Encryption** | 2 tests | RSA-2048, AES-256 |
| **Hashing** | 3 tests | SHA-256, SHA-384, SHA-512 |
| **MACs** | 2 tests | HMAC-SHA256, AES-CMAC |
| **Random** | 1 test | 32-byte generation |

**Total**: 14 benchmark tests

### Temporary Keys

Full suite automatically creates keys with prefix `bench-*`:
- `bench-rsa-2048`
- `bench-rsa-4096`
- `bench-p256`
- `bench-p384`
- `bench-aes-256`
- `bench-hmac-key`
- `bench-cmac-key`

**Note**: These keys persist on the token. Delete them after benchmarking:
```bash
rust-hsm-cli delete-key --label TOKEN --user-pin PIN --key-label bench-rsa-2048
# Repeat for other bench-* keys
```

---

## Custom Key Benchmarking

### Benchmark Specific Key

Test performance of your production keys:

```bash
rust-hsm-cli benchmark \
  --label PROD_TOKEN \
  --user-pin 123456 \
  --key-label my-production-key \
  --iterations 1000
```

### Auto-Detection

The benchmark automatically detects key type and runs appropriate tests:

**RSA Keys** → Tests signing, verification, encryption
**ECDSA Keys** → Tests signing, verification
**AES Keys** → Tests encryption
**HMAC/Generic Keys** → Tests MAC operations

**Example Output:**
```
================================================================================
HSM Performance Benchmark Suite
================================================================================
Token: PROD_TOKEN
Key: my-production-key
Iterations per test: 1000
================================================================================

Detected key type: RSA-2048

📝 SIGNING WITH: my-production-key

RSA-2048 Signing: ████████████████████ 1000/1000 [00:00:11]
  Ops/sec: 91.3, Avg: 10.95ms, P50: 10.78ms, P95: 12.01ms, P99: 12.89ms

✅ VERIFICATION WITH: my-production-key

RSA-2048 Verify: ████████████████████ 1000/1000 [00:00:04]
  Ops/sec: 241.8, Avg: 4.14ms, P50: 4.01ms, P95: 4.67ms, P99: 5.12ms

🔐 ENCRYPTION WITH: my-production-key

RSA-2048 Encrypt: ████████████████████ 1000/1000 [00:00:06]
  Ops/sec: 162.3, Avg: 6.16ms, P50: 6.02ms, P95: 6.78ms, P99: 7.23ms
```

---

## Interpreting Results

### Understanding Metrics

#### **Operations per Second (Ops/sec)**
- **High is better** - More operations completed per second
- **Typical values**:
  - RSA-2048 signing: 80-100 ops/sec (SoftHSM2)
  - ECDSA-P256 signing: 130-150 ops/sec (SoftHSM2)
  - AES-GCM: 1000-2000 ops/sec (SoftHSM2)
  - Hashing: 5000-10000 ops/sec (SoftHSM2)

#### **Average Latency (Avg ms)**
- **Low is better** - Faster operations
- Inverse of ops/sec: `latency = 1000 / ops_per_sec`

#### **Percentiles**
- **P50 (Median)**: Half of operations completed in this time or less
- **P95**: 95% of operations completed in this time or less
- **P99**: 99% of operations completed in this time or less

**Why percentiles matter**:
- Average can hide outliers
- P95/P99 show **tail latency** - critical for user experience
- Large P99 values indicate inconsistent performance

**Example Analysis**:
```
Operation: RSA-2048 Signing
Avg: 11.21ms, P50: 10.95ms, P95: 12.34ms, P99: 13.12ms

✅ Good: P99 only 17% higher than P50 (consistent performance)
```

```
Operation: RSA-2048 Signing
Avg: 11.21ms, P50: 10.95ms, P95: 25.67ms, P99: 45.23ms

⚠️ Concerning: P99 is 4x higher than P50 (inconsistent, investigate!)
```

### Performance Categories

| Operation | Excellent | Good | Acceptable | Poor |
|-----------|-----------|------|------------|------|
| **RSA-2048 Sign** | >100 ops/sec | 80-100 | 50-80 | <50 |
| **RSA-4096 Sign** | >20 ops/sec | 15-20 | 10-15 | <10 |
| **ECDSA-P256** | >150 ops/sec | 120-150 | 80-120 | <80 |
| **AES-GCM** | >1500 ops/sec | 1000-1500 | 500-1000 | <500 |
| **SHA-256** | >10000 ops/sec | 5000-10000 | 2000-5000 | <2000 |

**Note**: These are for SoftHSM2 (CPU-based). Hardware HSMs vary widely.

---

## Benchmarking Best Practices

### 1. **Minimize System Load**

```bash
# Close unnecessary applications
# Stop background services
# Disable CPU frequency scaling (Linux)
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

### 2. **Warm Up**

Run a short benchmark first to warm up caches:

```bash
# Warm-up run (ignored)
rust-hsm-cli benchmark --label TOKEN --user-pin PIN --iterations 10

# Real benchmark
rust-hsm-cli benchmark --label TOKEN --user-pin PIN --iterations 1000
```

### 3. **Multiple Runs**

Run 3-5 times and take the median:

```bash
for i in {1..5}; do
  echo "Run $i:"
  rust-hsm-cli benchmark --label TOKEN --user-pin PIN --iterations 1000 \
    | tee benchmark-run-$i.log
done
```

### 4. **Consistent Test Data**

Benchmark uses fixed test data for reproducibility:
- RSA/ECDSA: 32-byte payload
- AES: 1KB payload
- Hash: 1KB data
- MACs: 32-byte message

### 5. **Iteration Count Guidelines**

| Purpose | Iterations | Duration | Accuracy |
|---------|-----------|----------|----------|
| Quick check | 10-100 | 1-2 min | Low |
| Development | 100-500 | 5-10 min | Medium |
| Baseline | 1000-5000 | 15-60 min | High |
| Production | 10000+ | 1-2 hours | Very High |

**Formula**: More iterations = More accurate P95/P99 measurements

---

## Performance Tuning

### SoftHSM2 Configuration

Edit `/etc/softhsm2.conf` or `softhsm2.conf`:

```conf
# Increase object cache
objectstore.backend = file

# Token directory
directories.tokendir = /tokens

# Increase slot availability
slots.removable = false
```

### Docker Resource Limits

Allocate more CPU for better performance:

```yaml
# compose.yaml
services:
  app:
    cpus: '4.0'          # Allow 4 CPUs
    mem_limit: '4g'      # 4GB RAM
    mem_reservation: '2g'
```

### System Tuning (Linux)

```bash
# Disable CPU frequency scaling
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Increase file descriptors
ulimit -n 65536

# Disable swap for consistent timing
sudo swapoff -a
```

---

## Comparison Guidelines

### Before vs After Optimization

```bash
# Baseline
rust-hsm-cli benchmark --label TOKEN --user-pin PIN --iterations 1000 \
  | tee baseline.log

# Apply optimization
# ... make changes ...

# Compare
rust-hsm-cli benchmark --label TOKEN --user-pin PIN --iterations 1000 \
  | tee optimized.log

# Calculate improvement
# RSA-2048: 89.2 → 105.3 ops/sec = 18% improvement
```

### SoftHSM vs Hardware HSM

| Metric | SoftHSM2 | Luna SA | Thales nShield | YubiHSM2 |
|--------|----------|---------|----------------|----------|
| **RSA-2048 Sign** | 80-100 | 1000-2000 | 2000-5000 | 50-100 |
| **ECDSA-P256** | 130-150 | 3000-5000 | 5000-10000 | 200-300 |
| **AES-GCM** | 1000-2000 | 10000+ | 50000+ | 500-1000 |

**Key Differences**:
- **Hardware HSMs**: Dedicated crypto processor, much faster
- **SoftHSM**: CPU-bound, good for testing, not production
- **Network HSMs**: Add network latency (1-5ms)

---

## Advanced Usage

### Benchmark Specific Operations

Create custom keys and benchmark individual operations:

#### RSA Signing Only

```bash
# Create key
rust-hsm-cli gen-keypair --label TOKEN --user-pin PIN \
  --key-label perf-test-rsa --key-type rsa --bits 2048

# Benchmark it
rust-hsm-cli benchmark --label TOKEN --user-pin PIN \
  --key-label perf-test-rsa --iterations 5000
```

#### Compare Key Sizes

```bash
# RSA-2048
rust-hsm-cli gen-keypair --label TOKEN --user-pin PIN \
  --key-label rsa-2048-test --key-type rsa --bits 2048
rust-hsm-cli benchmark --label TOKEN --user-pin PIN \
  --key-label rsa-2048-test --iterations 1000

# RSA-4096
rust-hsm-cli gen-keypair --label TOKEN --user-pin PIN \
  --key-label rsa-4096-test --key-type rsa --bits 4096
rust-hsm-cli benchmark --label TOKEN --user-pin PIN \
  --key-label rsa-4096-test --iterations 1000

# Compare: RSA-4096 is ~4-5x slower than RSA-2048
```

#### ECDSA Curve Comparison

```bash
# P-256
rust-hsm-cli gen-keypair --label TOKEN --user-pin PIN \
  --key-label p256-test --key-type p256
rust-hsm-cli benchmark --label TOKEN --user-pin PIN \
  --key-label p256-test --iterations 1000

# P-384
rust-hsm-cli gen-keypair --label TOKEN --user-pin PIN \
  --key-label p384-test --key-type p384
rust-hsm-cli benchmark --label TOKEN --user-pin PIN \
  --key-label p384-test --iterations 1000

# P-384 is ~30-40% slower than P-256
```

### Concurrent Load Testing

Test HSM under concurrent load:

```bash
#!/bin/bash
# concurrent-bench.sh

for i in {1..10}; do
  docker exec rust-hsm-app rust-hsm-cli benchmark \
    --label TOKEN --user-pin PIN --iterations 100 &
done

wait
echo "All concurrent benchmarks complete"
```

### JSON Output for Analysis

```bash
# Future enhancement - export results as JSON
rust-hsm-cli benchmark --label TOKEN --user-pin PIN \
  --iterations 1000 --json > results.json

# Analyze with jq
cat results.json | jq '.results[] | select(.ops_per_sec < 50)'
```

---

## Troubleshooting

### Slow Performance

**Symptoms**: Operations much slower than expected

**Causes**:
1. System under load (CPU, memory, disk I/O)
2. Docker resource constraints
3. SoftHSM token storage on slow disk
4. Thermal throttling

**Solutions**:
```bash
# Check CPU usage
top
htop

# Check Docker stats
docker stats rust-hsm-app

# Move token storage to tmpfs (RAM disk)
docker run -v /dev/shm:/tokens ...

# Monitor temperature (Linux)
sensors
```

### Inconsistent Results (High P99)

**Symptoms**: P99 >> P50, large variance between runs

**Causes**:
1. Background processes interrupting
2. CPU frequency scaling
3. Thermal throttling
4. Swap activity
5. Container resource contention

**Solutions**:
```bash
# Disable CPU scaling
echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Pin Docker container to specific CPUs
docker run --cpuset-cpus="0-3" ...

# Increase iterations for statistical significance
--iterations 10000
```

### Out of Memory

**Symptoms**: Benchmark crashes or Docker container stops

**Cause**: Too many iterations or insufficient RAM

**Solution**:
```bash
# Reduce iterations
--iterations 100

# Increase Docker memory
docker run --memory="4g" ...
```

---

## Example Reports

### Development Environment

```
System: MacBook Pro M2, 16GB RAM, Docker Desktop
HSM: SoftHSM 2.6.1
Test: Full suite, 1000 iterations

RSA-2048 Signing:   92.3 ops/sec  (10.84ms avg, 11.23ms p99)
RSA-4096 Signing:   19.1 ops/sec  (52.36ms avg, 58.91ms p99)
ECDSA-P256 Sign:   145.2 ops/sec  ( 6.89ms avg,  7.45ms p99)
ECDSA-P384 Sign:   102.3 ops/sec  ( 9.77ms avg, 10.67ms p99)
AES-GCM Encrypt:  1234.5 ops/sec  ( 0.81ms avg,  0.94ms p99)
SHA-256 Hash:     9234.2 ops/sec  ( 0.11ms avg,  0.13ms p99)

Conclusion: Performance meets expectations for SoftHSM2 on Apple Silicon
```

### Production HSM

```
System: Dell R740, Xeon Gold 6248R, 128GB RAM
HSM: Thales Luna SA 7000, Network HSM
Test: Custom key benchmark, 10000 iterations
Network: 1Gbps, <1ms latency

RSA-2048 Signing:  1823.4 ops/sec  ( 0.55ms avg,  0.89ms p99)
ECDSA-P256 Sign:   4521.3 ops/sec  ( 0.22ms avg,  0.41ms p99)
AES-GCM Encrypt:  12345.6 ops/sec  ( 0.08ms avg,  0.12ms p99)

Conclusion: Hardware HSM delivers 20x performance vs SoftHSM
Network latency adds ~0.5-1ms to each operation
```

---

## Future Enhancements

Planned improvements to benchmarking:

1. **Concurrent Operations** - Test multi-threaded performance
2. **Throughput Testing** - Measure sustained ops/sec over time
3. **JSON Export** - Machine-readable results
4. **Comparison Mode** - Side-by-side result comparison
5. **Stress Testing** - Find breaking points
6. **Latency Histograms** - Visual distribution charts
7. **CSV Export** - Import into spreadsheets
8. **Regression Detection** - Alert on performance degradation
9. **CI/CD Integration** - Automated performance testing
10. **Custom Test Suites** - User-defined operation sequences

---

## See Also

- [Command Reference](commands/README.md)
- [Security Utilities](commands/security-utilities.md)
- [Troubleshooting Guide](TROUBLESHOOTING_EXAMPLE.md)

---

**Happy Benchmarking!** 📊
