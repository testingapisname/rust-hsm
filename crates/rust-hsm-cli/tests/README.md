# Benchmark Integration Tests

Comprehensive integration tests for the benchmark command and its features.

## Overview

These tests verify:
- ✅ JSON output format and structure
- ✅ CSV output format
- ✅ Warmup iterations
- ✅ Data size variation testing
- ✅ Comparison mode (baseline vs current)
- ✅ Combined features (data sizes + comparison)
- ✅ Error handling (invalid inputs)

## Running Tests

### Prerequisites

Tests require a running SoftHSM2 instance with a configured token. The easiest way is to use the Docker environment.

### Quick Test

```bash
# Start the container
docker compose up -d

# Run all benchmark tests (they're marked with #[ignore])
docker exec rust-hsm-app bash -c "cd /build/crates/rust-hsm-cli && cargo test --release -- --ignored benchmark"

# Run specific test
docker exec rust-hsm-app bash -c "cd /build/crates/rust-hsm-cli && cargo test --release -- --ignored test_benchmark_json_output"
```

### Local Development

```bash
# Setup SoftHSM2 token first
softhsm2-util --init-token --slot 0 --label TEST_TOKEN --so-pin 12345678 --pin 123456

# Run tests
cd crates/rust-hsm-cli
cargo test --release -- --ignored benchmark
```

## Test Descriptions

### Basic Functionality

**`test_benchmark_basic`**
- Runs basic benchmark with text output
- Verifies summary table and operation names appear
- Validates exit code success

**`test_benchmark_json_output`**
- Creates JSON file with `--format json --output`
- Validates complete JSON structure:
  - Metadata (timestamp, token, iterations, system info)
  - Results array with all metrics
  - Field types and presence

**`test_benchmark_csv_output`**
- Creates CSV file with `--format csv --output`
- Validates header row and data rows
- Checks column count and format

### Advanced Features

**`test_benchmark_warmup`**
- Tests `--warmup` flag
- Verifies warmup count recorded in JSON metadata
- Ensures warmup iterations excluded from measurements

**`test_benchmark_data_sizes`**
- Tests `--data-sizes` flag
- Validates output contains:
  - "DATA SIZE VARIATION" section
  - Tests for 1KB, 10KB, 100KB, 1MB
- Verifies additional operations beyond standard suite

**`test_benchmark_comparison`**
- Creates baseline JSON
- Runs comparison with `--compare baseline.json`
- Validates comparison output:
  - "BENCHMARK COMPARISON" header
  - Baseline timestamp
  - Current vs Baseline columns
  - Diff % column
  - Regression indicators (🟢/🔴)

**`test_benchmark_data_sizes_with_comparison`**
- Combines `--data-sizes` and `--compare` flags
- Creates baseline with data size variations
- Verifies comparison includes all size variations
- Validates result count (standard + size tests)

### Validation Tests

**`test_json_output_completeness`**
- Deep validation of JSON structure
- Checks all required fields present
- Validates data types and sanity values
- Ensures metadata completeness

**`test_invalid_baseline_file`**
- Tests error handling for missing baseline file
- Verifies appropriate error message

**`test_invalid_format`**
- Tests invalid `--format` value
- Verifies command fails with error

**`test_csv_requires_output_file`**
- Validates CSV format requires `--output`
- Tests error message

**`test_json_requires_output_file`**
- Validates JSON format requires `--output`
- Tests error message

## Test Coverage

| Feature | Coverage | Tests |
|---------|----------|-------|
| Text output | ✅ | test_benchmark_basic |
| JSON output | ✅ | test_benchmark_json_output, test_json_output_completeness |
| CSV output | ✅ | test_benchmark_csv_output |
| Warmup | ✅ | test_benchmark_warmup |
| Data sizes | ✅ | test_benchmark_data_sizes |
| Comparison | ✅ | test_benchmark_comparison |
| Combined features | ✅ | test_benchmark_data_sizes_with_comparison |
| Error handling | ✅ | test_invalid_* tests |

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Benchmark Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Start SoftHSM
        run: docker compose up -d
      
      - name: Run benchmark tests
        run: |
          docker exec rust-hsm-app bash -c \
            "cd /build/crates/rust-hsm-cli && \
             cargo test --release -- --ignored benchmark"
      
      - name: Stop SoftHSM
        run: docker compose down
```

## Adding New Tests

When adding new benchmark features, create corresponding tests:

1. **Add test function** with descriptive name
2. **Mark with `#[ignore]`** (requires HSM setup)
3. **Use predicates** for output validation
4. **Test both success and failure cases**
5. **Update this README** with test description

Example template:

```rust
#[test]
#[ignore] // Requires HSM setup
fn test_new_feature() {
    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label", TEST_TOKEN,
            "--user-pin", TEST_PIN,
            "--new-flag",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Expected output"));
}
```

## Debugging Failed Tests

### View test output
```bash
docker exec rust-hsm-app bash -c \
  "cd /build/crates/rust-hsm-cli && \
   cargo test --release -- --ignored --nocapture test_name"
```

### Check HSM state
```bash
# List tokens
docker exec rust-hsm-app softhsm2-util --show-slots

# Verify token exists
docker exec rust-hsm-app rust-hsm-cli list-tokens
```

### Manual test run
```bash
# Run benchmark manually to debug
docker exec rust-hsm-app rust-hsm-cli benchmark \
  --label TEST_TOKEN \
  --user-pin 123456 \
  --iterations 5 \
  --format json \
  --output /tmp/test.json

# Check output
docker exec rust-hsm-app cat /tmp/test.json
```

## Performance

Tests use low iteration counts (5-10) for speed:
- Full test suite: ~2-3 minutes
- Individual test: ~10-30 seconds

For accuracy testing, increase iterations in specific tests.

## See Also

- [Benchmark Documentation](../../docs/BENCHMARKING.md)
- [Command Reference](../../docs/commands/security-utilities.md#benchmark)
- [Cargo Test Documentation](https://doc.rust-lang.org/cargo/commands/cargo-test.html)
