# GitHub Actions CI/CD Documentation

This document provides comprehensive documentation for the GitHub Actions workflows used in the rust-hsm project.

## Table of Contents

- [Overview](#overview)
- [Workflows](#workflows)
  - [CI Workflow](#ci-workflow)
  - [Security Workflow](#security-workflow)
  - [Benchmark Workflow](#benchmark-workflow)
- [Testing Strategy](#testing-strategy)
- [Monitoring and Troubleshooting](#monitoring-and-troubleshooting)
- [Platform Considerations](#platform-considerations)

---

## Overview

The rust-hsm project uses GitHub Actions for continuous integration, security scanning, and performance benchmarking. All workflows run on `ubuntu-latest` runners and use a Dockerized environment to ensure consistent behavior across development and CI.

### Key Principles

1. **Docker-first approach**: All HSM-dependent operations run inside Docker containers with SoftHSM2
2. **Layered testing**: Quick checks → Unit tests → Integration tests
3. **Security focus**: Multiple scanning tools (cargo audit, Trivy, CodeQL, dependency review)
4. **Performance tracking**: Automated benchmarking with regression detection

---

## Workflows

### CI Workflow

**File**: `.github/workflows/ci.yml`

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main` branch

**Jobs**:

#### 1. Check Job
**Purpose**: Fast feedback for code quality issues

**Steps**:
- ✅ Format checking (`cargo fmt --check`)
- ✅ Linting (`cargo clippy` with warnings as errors)
- ✅ Basic compilation check (`cargo check`)

**Runtime**: ~2-3 minutes

**Cache Strategy**:
- Cargo registry
- Cargo index
- Target directory

**Failure reasons**:
- Code not formatted with `cargo fmt`
- Clippy warnings present
- Compilation errors

#### 2. Test Job
**Purpose**: Run unit tests without HSM dependencies

**Depends on**: `check` job

**Steps**:
- Run unit tests (`cargo test --bins`)
- Run documentation tests (`cargo test --doc`)

**Runtime**: ~1-2 minutes

**Notes**:
- Tests marked with `#[ignore]` are skipped (HSM-dependent tests)
- Only tests that can run without SoftHSM are executed

#### 3. Integration Job
**Purpose**: Full integration testing with SoftHSM2

**Depends on**: `test` job

**Steps**:
1. Set up Docker Buildx
2. Build Docker image from `compose.yaml`
3. Start container (`docker compose up -d`)
4. Wait 5 seconds for initialization
5. **Run full test suite** (`docker exec rust-hsm-app bash /app/test.sh`)
6. Show logs on failure
7. Stop container (always runs)

**Test Suite Coverage** (43 tests):
- HSM info and slot listing
- Token initialization and PIN management
- RSA-2048 keypair generation
- ECDSA P-256 and P-384 keypairs
- Sign/verify operations (RSA, ECDSA)
- RSA encryption/decryption
- AES-GCM symmetric encryption
- AES key sizes (128, 192, 256 bits)
- Key wrapping/unwrapping (AES Key Wrap)
- Public key export (PEM format)
- CSR generation
- Key deletion and management
- SHA-256 and SHA-512 hashing
- HMAC-SHA256 operations
- AES-CMAC operations
- Key attribute inspection
- Key fingerprinting
- Random number generation
- Error code explanation
- Key finding and comparison

**Runtime**: ~5-7 minutes

**Docker Configuration**:
```yaml
Container: rust-hsm-app
Base Image: rust:1.83-bookworm
HSM: SoftHSM2
Config: /app/.rust-hsm.toml
PKCS#11 Module: /usr/lib/softhsm/libsofthsm2.so
```

#### 4. Security Job
**Purpose**: Dependency vulnerability scanning

**Runs**: In parallel with other jobs

**Steps**:
- Install `cargo-audit`
- Run security audit on dependencies

**Runtime**: ~2-3 minutes

**Notes**:
- Configured with reduced strictness (unmaintained crates allowed)
- Fails on: unsound dependencies, yanked crates

#### 5. Coverage Job
**Purpose**: Track code coverage metrics

**Depends on**: `test` job

**Steps**:
1. Install `cargo-tarpaulin`
2. Generate coverage report (unit tests only)
3. Upload to Codecov

**Runtime**: ~2-3 minutes

**Current Coverage**: ~1.40%

**Notes**:
- `fail_ci_if_error: false` - doesn't block CI on upload failures
- Measures unit test coverage only (18 tests: config, mechanisms, hash, hmac)
- Integration tests (43 tests) are verified separately in the Integration job
- Simple and reliable - no HSM setup complexity

---

### Security Workflow

**File**: `.github/workflows/security.yml`

**Triggers**:
- Push to `main` branch
- Pull requests to `main` branch
- Daily schedule (3am UTC)

**Jobs**:

#### 1. Cargo Audit
**Purpose**: Check for known security vulnerabilities in dependencies

**Steps**:
- Run `cargo audit --deny unsound --deny yanked`

**Flags**:
- `--deny unsound`: Fails on unsound code patterns
- `--deny yanked`: Fails on yanked crates

#### 2. Dependency Review
**Purpose**: Review dependency changes in pull requests

**Runs**: Only on pull requests

**Configuration**:
- Fails on: Moderate or higher severity issues
- Reviews: New dependencies, version changes, license changes

#### 3. Trivy Container Scan
**Purpose**: Scan Docker image for vulnerabilities

**Permissions**: `security-events: write`

**Steps**:
1. Build Docker image
2. Scan with Trivy
3. Generate SARIF report
4. Upload to GitHub Security tab

**Scan Coverage**:
- OS packages
- Application dependencies
- Known CVEs

#### 4. CodeQL Analysis
**Purpose**: Static analysis for security issues and code quality

**Permissions**: `security-events: write`

**Language**: Rust

**Steps**:
1. Initialize CodeQL
2. Build release binary
3. Perform analysis
4. Upload results to Security tab

**Detection Coverage**:
- Security vulnerabilities
- Code quality issues
- Suspicious patterns

**Fixed Issues**:
- ✅ Corrected language from 'cpp' to 'rust'

---

### Benchmark Workflow

**File**: `.github/workflows/benchmark.yml`

**Triggers**:
- Push to `main` (when benchmark files change)
- Weekly schedule (Sunday 2am UTC)
- Manual workflow dispatch

**Purpose**: Track performance regressions

**Steps**:
1. Build Docker environment
2. Initialize benchmark token
3. Run benchmarks (1000 iterations, 50 warmup)
4. Store results as JSON
5. Compare against historical data
6. Alert on >10% regression

**Metrics Tracked**:
- Operations per second
- Average latency (ms)
- P95 latency (ms)

**Operations Benchmarked**:
- RSA-2048 key generation
- ECDSA P-256 key generation
- RSA sign/verify
- ECDSA sign/verify
- AES-GCM encrypt/decrypt
- HMAC operations

**Alert Configuration**:
- Threshold: 110% (alerts on 10%+ regression)
- Notification: Comment mentions `@testingapisname`
- Auto-push: Results stored in gh-pages

---

## Testing Strategy

### Test Layers

```
┌─────────────────────────────────────────┐
│   Integration Tests (43 tests)         │
│   Docker + SoftHSM2 + test.sh          │
│   Runtime: ~1 minute                    │
└─────────────────────────────────────────┘
              ↑
┌─────────────────────────────────────────┐
│   Unit Tests                            │
│   cargo test --bins                     │
│   Runtime: ~30 seconds                  │
└─────────────────────────────────────────┘
              ↑
┌─────────────────────────────────────────┐
│   Static Analysis                       │
│   fmt + clippy + check                  │
│   Runtime: ~1 minute                    │
└─────────────────────────────────────────┘
```

### Test Separation

**Unit Tests** (No HSM required):
- Run with `cargo test --bins`
- HSM-dependent tests marked with `#[ignore]`
- Example: `benchmark_tests.rs` (all 12 tests ignored)

**Integration Tests** (HSM required):
- Run via `test.sh` in Docker
- Full end-to-end testing
- 43 comprehensive tests covering all functionality

### Why Tests Don't Need SoftHSM in Unit Tests

The `test` job runs `cargo test --bins` which executes:
1. **Unit tests** from `src/` files (18 tests)
2. **Binary tests** that don't require HSM hardware

Tests requiring HSM are marked with `#[ignore]` attribute:

```rust
#[test]
#[ignore] // Requires SoftHSM
fn test_rsa_keygen() {
    // HSM-dependent test
}
```

These ignored tests are **not executed** during `cargo test --bins`, avoiding HSM dependency.

**Coverage Philosophy**: We measure unit test coverage (~1.4%) but validate actual functionality through 43 integration tests in the `integration` job. For a CLI tool interfacing with hardware, integration testing is more valuable than unit test coverage metrics.

### Full Integration Testing

The `integration` job executes `test.sh` which:
1. Initializes temporary test tokens
2. Sets up user PINs
3. Runs all 43 cryptographic operations
4. Verifies outputs and error handling
5. Cleans up test artifacts

---

## Monitoring and Troubleshooting

### Viewing CI Results

#### Via GitHub Web UI
1. Navigate to repository
2. Click **Actions** tab
3. Select workflow run
4. Click on individual jobs to see logs

#### Via GitHub CLI

**List recent runs**:
```powershell
gh run list --workflow=ci.yml --limit 5
```

**View run summary**:
```powershell
gh run view <run-id>
```

**View full logs**:
```powershell
gh run view <run-id> --log
```

**Search logs**:
```powershell
gh run view <run-id> --log | Select-String "Integration Tests" -Context 10
```

**Download logs**:
```powershell
gh run download <run-id>
```

### Common Failures and Solutions

#### Format Check Failed
**Error**: `cargo fmt --check` fails
**Cause**: Code not formatted
**Solution**:
```bash
cd crates/rust-hsm-cli
cargo fmt
git add .
git commit -m "fix: Format code"
```

#### Clippy Warnings
**Error**: `cargo clippy` reports warnings
**Cause**: Code quality issues
**Solution**:
```bash
cd crates/rust-hsm-cli
cargo clippy --fix --allow-dirty
git add .
git commit -m "fix: Address clippy warnings"
```

#### Integration Tests Failed
**Error**: `test.sh` exits with errors
**Troubleshooting**:
1. Check "Show logs on failure" step
2. Look for specific test failure messages
3. Reproduce locally:
   ```bash
   docker compose up -d
   docker exec rust-hsm-app bash /app/test.sh
   ```

#### Docker Build Failed
**Error**: Docker image build fails
**Common causes**:
- Dockerfile syntax errors
- Missing dependencies in Dockerfile
- Network issues downloading dependencies

**Solution**:
```bash
# Test build locally
docker compose build --no-cache
```

#### Security Scan Failed
**Error**: Trivy or cargo audit reports vulnerabilities
**Solution**:
1. Review security advisories
2. Update dependencies: `cargo update`
3. If no fix available, consider alternatives or accept risk

### Debugging Integration Tests

**Run specific test locally**:
```bash
# Start container
docker compose up -d

# Execute specific commands
docker exec rust-hsm-app rust-hsm-cli info
docker exec rust-hsm-app rust-hsm-cli list-slots

# Run full suite
docker exec rust-hsm-app bash /app/test.sh

# View logs
docker compose logs

# Clean up
docker compose down
```

**Access container shell**:
```bash
docker exec -it rust-hsm-app bash
```

**Check SoftHSM status**:
```bash
docker exec rust-hsm-app softhsm2-util --show-slots
```

---

## Platform Considerations

### Type Compatibility: u32 vs u64

**Issue**: `cryptoki::types::Ulong` has different implementations on different platforms:
- **Linux/64-bit**: Requires `From<u64>`
- **Windows**: Requires `From<u32>`

**Solution**: All bit-size calculations cast to `u64`:

```rust
// Correct (Linux-compatible)
let key_length = cryptoki::types::Ulong::from((bits / 8) as u64);

// Wrong (fails on Linux)
let key_length = cryptoki::types::Ulong::from(bits / 8);
```

**Affected Files**:
- `src/pkcs11/keys/cmac.rs`
- `src/pkcs11/keys/hmac.rs`
- `src/pkcs11/keys/symmetric.rs`
- `src/pkcs11/keys/keypair.rs`

### Docker Runtime vs Local Development

**Development Environment**:
- Windows PowerShell (not the runtime)
- Docker Desktop with WSL2 backend
- Container: `rust:1.83-bookworm` (Debian Linux)

**CI Environment**:
- GitHub Actions: `ubuntu-latest` runners
- Docker container: Same `rust:1.83-bookworm`
- Consistent behavior due to containerization

**Key Point**: Always develop and test inside the Docker container to match CI behavior exactly.

---

## Workflow Optimization

### Caching Strategy

All workflows cache:
- `~/.cargo/registry` - Downloaded crate files
- `~/.cargo/git` - Git dependencies
- `target/` - Compiled artifacts

**Cache key**: `${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}`

**Benefits**:
- Faster builds (~50% time reduction)
- Reduced network usage
- More consistent runtimes

### Job Dependencies

```
check ─────┬─→ test ─────┬─→ integration
           │             │
           │             └─→ coverage
           │
           └─→ security (parallel)
```

- `check` runs first (fast feedback)
- `test` waits for `check` to pass
- `integration` waits for `test` to pass
- `coverage` runs parallel to `integration`
- `security` runs independently

### Parallel Execution

Jobs run in parallel when possible:
- `security` doesn't wait for tests
- `coverage` and `integration` run simultaneously
- Multiple security scans run in parallel (separate workflow)

**Total CI time**: ~7-10 minutes (vs ~15-20 minutes sequential)

---

## Best Practices

### Before Pushing

1. **Format code**:
   ```bash
   cargo fmt
   ```

2. **Check locally**:
   ```bash
   cargo clippy --all-features -- -D warnings
   cargo check
   ```

3. **Run tests locally**:
   ```bash
   docker compose up -d
   docker exec rust-hsm-app bash /app/test.sh
   docker compose down
   ```

### Pull Request Workflow

1. Create feature branch
2. Make changes
3. Test locally in Docker
4. Push and create PR
5. Monitor CI results
6. Address any failures
7. Wait for security scans
8. Merge when all checks pass

### Monitoring

- **Enable email notifications**: Settings → Notifications → Actions
- **Watch CI status**: Check badges in README
- **Review security alerts**: Security tab → Dependabot alerts
- **Track coverage**: View Codecov reports

---

## Configuration Files

### compose.yaml
Defines Docker environment:
- Service: `rust-hsm-app`
- Build context: `./docker`
- Volume mounts: Code and SoftHSM config
- Working directory: `/app`

### docker/Dockerfile
Container setup:
- Base: `rust:1.83-bookworm`
- Installs: SoftHSM2, build tools, OpenSSL
- Copies: Source code and config
- Builds: Rust binary

### docker/softhsm2.conf
SoftHSM configuration:
- Token directory: `/var/lib/softhsm/tokens`
- Object store backend: File-based
- Logging: Configured for CI visibility

### .rust-hsm.toml
Application config:
- PKCS#11 module path: `/usr/lib/softhsm/libsofthsm2.so`
- Default slot: `0`
- Token label: Specified per test

---

## Future Improvements

### Planned Enhancements

1. **Test Reporting**:
   - Generate JUnit XML from test.sh
   - Add test result annotations to PR
   - Track test execution time trends

2. **Coverage Improvements**:
   - Include integration test coverage
   - Set minimum coverage thresholds
   - Add coverage badges to README

3. **Performance Tracking**:
   - Store benchmark history
   - Generate trend charts
   - Alert on latency increases

4. **Security Enhancements**:
   - Add SBOM generation
   - Implement supply chain verification
   - Add signed releases

5. **CI Optimization**:
   - Parallel test execution
   - Incremental compilation
   - Docker layer caching

---

## Troubleshooting Reference

### Quick Diagnostic Commands

```powershell
# Check current CI status
gh run list --workflow=ci.yml --limit 1

# View latest failure
gh run view --log | Select-String "Error|Failed|error:"

# Re-run failed jobs
gh run rerun <run-id> --failed

# View specific job
gh run view <run-id> --job <job-id> --log
```

### Common Error Patterns

| Error Pattern | Likely Cause | Solution |
|--------------|--------------|----------|
| `format check failed` | Not formatted | Run `cargo fmt` |
| `clippy::` warning | Code quality | Run `cargo clippy --fix` |
| `error[E0308]` | Type mismatch | Check u32/u64 casts |
| `Broken pipe (os error 32)` | Benign stdout issue | Ignore (test continues) |
| `RUSTSEC-` advisory | Vulnerable dependency | Run `cargo update` |
| `Container ... exited` | Docker startup issue | Check Docker logs |

### Log Interpretation

**Success indicators**:
```
✓ Signature verified
✓ AES-256 key generated
=== All tests passed! ===
```

**Warning indicators** (non-blocking):
```
thread 'main' panicked at ... Broken pipe
note: run with `RUST_BACKTRACE=1`
```

**Failure indicators**:
```
✗ Test failed
Error: ...
FAILED
```

---

## Support and Resources

### Documentation
- [TROUBLESHOOTING_EXAMPLE.md](./TROUBLESHOOTING_EXAMPLE.md) - Real debugging example
- [IMPLEMENTING_AES_CMAC.md](./IMPLEMENTING_AES_CMAC.md) - Feature implementation guide
- [BENCHMARKING.md](./BENCHMARKING.md) - Performance testing guide
- [commands/](./commands/) - CLI command documentation

### External Resources
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
- [Trivy](https://github.com/aquasecurity/trivy)
- [CodeQL](https://codeql.github.com/)
- [SoftHSM2](https://github.com/opendnssec/SoftHSMv2)

### Getting Help

1. **Check existing issues**: Search GitHub Issues
2. **Review logs**: Use `gh run view --log`
3. **Reproduce locally**: Test in Docker container
4. **Ask for help**: Create GitHub Issue with logs

---

## Summary

The rust-hsm project uses a comprehensive CI/CD pipeline that:

- ✅ **Validates code quality** with formatting and linting
- ✅ **Tests thoroughly** with unit and integration tests
- ✅ **Scans security** with multiple tools
- ✅ **Tracks performance** with automated benchmarks
- ✅ **Ensures consistency** with Docker containers
- ✅ **Provides visibility** with detailed logging

All workflows are de5-7 minutes per push
**Test coverage**: 43 integration tests + 18 unit tests = 61 total tests
**Security scans**: 4 independent tools
**Benchmark tracking**: Weekly + on-demand

### Coverage Philosophy

The project uses a **pragmatic testing approach**:

- **Unit tests** (18 tests): Config parsing, mechanism lookups, utility functions
- **Integration tests** (43 tests): Full cryptographic operations with SoftHSM2
- **Coverage metric**: ~1.4% (unit tests only)

For a CLI tool that interfaces with hardware (HSM), **integration testing provides more value** than high unit test coverage. The 43 integration tests validate:
- All cryptographic operations (RSA, ECDSA, AES)
- Token management and PIN operations
- Key lifecycle (generate, use, export, delete)
- Error handling and edge cases

This is intentional - measuring coverage of integration tests adds complexity without proportional value.unit tests
**Security scans**: 4 independent tools
**Benchmark tracking**: Weekly + on-demand

---

*Last updated: December 15, 2025*
*CI Status: All workflows passing ✓*
