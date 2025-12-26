# Observability Commands

Commands for analyzing PKCS#11 operation logs collected by the observe-core and observe-cryptoki infrastructure.

## analyze

Analyze PKCS#11 observability logs and display comprehensive statistics about HSM operations, performance, and errors.

### Syntax

```bash
rust-hsm-cli analyze --log-file <PATH> [--format <FORMAT>]
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `--log-file` | Yes | Path to observability log file (JSON Lines format) |
| `--format` | No | Output format: `text` (default) or `json` |

### Examples

#### Basic Analysis (Text Format)
```bash
$ rust-hsm-cli analyze --log-file /app/rust-hsm-observe.json

=== PKCS#11 Session Analysis ===

Total Operations: 35
Success Rate: 100.00%
Error Count: 0

--- Overall Timing ---
Total Duration: 43.91ms
Average: 1.25ms
Min: 0.00ms
Max: 13.46ms
P50: 0.77ms
P95: 1.88ms
P99: 13.46ms

--- Per-Function Statistics ---

C_Initialize
  Calls: 5
  Success: 5 (100.0%)
  Errors: 0 (0.0%)
  Avg Duration: 4.11ms

C_Login
  Calls: 5
  Success: 5 (100.0%)
  Errors: 0 (0.0%)
  Avg Duration: 0.85ms

C_Sign
  Calls: 5
  Success: 5 (100.0%)
  Errors: 0 (0.0%)
  Avg Duration: 0.84ms
```

#### JSON Output
```bash
$ rust-hsm-cli analyze --log-file /app/rust-hsm-observe.json --format json

{
  "total_ops": 35,
  "success_count": 35,
  "error_count": 0,
  "success_rate": 100.0,
  "duration_stats": {
    "total_ms": 43.91,
    "avg_ms": 1.25,
    "min_ms": 0.00,
    "max_ms": 13.46,
    "p50_ms": 0.77,
    "p95_ms": 1.88,
    "p99_ms": 1.88
  },
  "by_function": {
    "C_Initialize": {
      "count": 5,
      "success_count": 5,
      "error_count": 0,
      "avg_duration_ms": 4.11
    },
    "C_Sign": {
      "count": 5,
      "success_count": 5,
      "error_count": 0,
      "avg_duration_ms": 0.84
    }
  },
  "errors": []
}
```

#### With Error Analysis
```bash
# Example output when errors are present:
=== PKCS#11 Session Analysis ===

Total Operations: 42
Success Rate: 95.24%
Error Count: 2

--- Overall Timing ---
Total Duration: 52.30ms
Average: 1.24ms
Min: 0.00ms
Max: 15.20ms
P50: 0.80ms
P95: 2.10ms
P99: 15.20ms

--- Errors ---

C_Sign → CKR_KEY_HANDLE_INVALID (0x00000060)
  Count: 2
  First seen: 2025-12-26T04:33:18.781138641Z
```

---

## Enabling Observability

To generate logs for analysis, enable observability in your configuration file:

### Configuration File (.rust-hsm.toml)

```toml
default_token_label = "DEV_TOKEN"
pkcs11_module = "/usr/lib/softhsm/libsofthsm2.so"

# Enable observability
observe_enabled = true
observe_log_file = "/app/rust-hsm-observe.json"
```

**Configuration Locations** (checked in order):
1. `.rust-hsm.toml` (current directory)
2. `rust-hsm.toml` (current directory)
3. `~/.config/rust-hsm/config.toml`
4. `~/.rust-hsm.toml`
5. `/app/.rust-hsm.toml` (container)
6. `/app/rust-hsm.toml` (container)

### What Gets Logged

The observability system records:

**For every PKCS#11 operation:**
- Timestamp (RFC3339 with nanoseconds)
- Process ID and Thread ID
- Function name (e.g., `C_Sign`, `C_Initialize`)
- Return value (numeric + name, e.g., `0` / `CKR_OK`)
- Duration in milliseconds
- Slot ID (when applicable)
- Session handle (when applicable)
- Mechanism (when applicable)

**Example log entry:**
```json
{
  "ts": "2025-12-26T04:33:18.781138641Z",
  "pid": 241,
  "tid": 241,
  "func": "C_Sign",
  "rv": 0,
  "rv_name": "CKR_OK",
  "dur_ms": 0.8665809999999999,
  "slot_id": 0,
  "session": 1,
  "mech": "CKM_SHA256_RSA_PKCS"
}
```

### Log File Format

Logs are stored in **JSON Lines** format:
- One JSON object per line
- Each line is a complete, valid JSON document
- Easy to append (no array wrapper)
- Efficient for streaming/tailing
- Compatible with standard tools (jq, grep, awk)

---

## Analysis Metrics

### Overall Statistics

| Metric | Description |
|--------|-------------|
| **Total Operations** | Count of all PKCS#11 function calls |
| **Success Rate** | Percentage of operations returning CKR_OK |
| **Error Count** | Number of failed operations (non-zero return code) |

### Duration Statistics

| Metric | Description |
|--------|-------------|
| **Total Duration** | Sum of all operation durations |
| **Average** | Mean duration across all operations |
| **Min** | Fastest operation |
| **Max** | Slowest operation |
| **P50 (Median)** | 50th percentile - half of operations are faster |
| **P95** | 95th percentile - 95% of operations are faster |
| **P99** | 99th percentile - 99% of operations are faster |

### Per-Function Statistics

For each PKCS#11 function:
- **Calls**: Total number of times the function was called
- **Success**: Count and percentage of successful calls
- **Errors**: Count and percentage of failed calls
- **Avg Duration**: Average execution time in milliseconds

### Error Summary

When errors occur:
- **Function**: Which PKCS#11 function failed
- **Return Code**: Numeric error code and symbolic name
- **Count**: How many times this error occurred
- **First Seen**: Timestamp of first occurrence

---

## Use Cases

### 1. Performance Benchmarking

**Goal**: Measure HSM operation performance over time.

```bash
# Generate baseline metrics
rust-hsm-cli sign --label DEV_TOKEN --user-pin 123456 \
  --key-label perf-test --input /app/test.txt --output /app/test.sig

# Analyze performance
rust-hsm-cli analyze --log-file /app/rust-hsm-observe.json

# Check for slow operations (P95 > threshold)
rust-hsm-cli analyze --log-file /app/rust-hsm-observe.json --format json \
  | jq '.duration_stats.p95_ms'
```

**What to look for:**
- P95/P99 latencies (detect tail latency)
- Max duration spikes (identify outliers)
- Per-function averages (find bottlenecks)

### 2. Debugging Application Issues

**Goal**: Understand why an application fails to interact with the HSM.

```bash
# Enable observability
export OBSERVE_ENABLED=true
export OBSERVE_LOG_FILE=/tmp/hsm-debug.json

# Run failing operation
./your-app --use-hsm

# Analyze what happened
rust-hsm-cli analyze --log-file /tmp/hsm-debug.json

# Look for errors
rust-hsm-cli analyze --log-file /tmp/hsm-debug.json --format json \
  | jq '.errors'
```

**What to look for:**
- Error patterns (which functions fail?)
- Session lifecycle issues (missing login/logout?)
- Timing anomalies (operations taking too long?)

### 3. Security Audit

**Goal**: Verify HSM is being used correctly and securely.

```bash
# Collect logs from production
rust-hsm-cli analyze --log-file /var/log/hsm/prod.json

# Check for security concerns:
# - Excessive failed login attempts
# - Operations without proper authentication
# - Unusual operation patterns
```

**What to look for:**
- High error rates (potential attack or misconfiguration)
- Missing C_Login before sensitive operations
- Unusual function call sequences

### 4. Capacity Planning

**Goal**: Determine if HSM can handle increased load.

```bash
# Run load test
for i in {1..1000}; do
  rust-hsm-cli sign --label LOAD_TEST --user-pin 123456 \
    --key-label test-key --input /app/data-$i.txt --output /app/sig-$i.bin
done

# Analyze throughput
rust-hsm-cli analyze --log-file /app/rust-hsm-observe.json --format json

# Calculate operations per second
# ops_per_sec = total_ops / (total_duration_ms / 1000)
```

**What to look for:**
- Average duration trends (degradation under load?)
- P95/P99 increases (queue buildup?)
- Error rates (capacity limits reached?)

### 5. Comparing HSM Providers

**Goal**: Evaluate SoftHSM2 vs Kryoptic performance.

```bash
# Test with SoftHSM2
export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
rust-hsm-cli benchmark --label TEST_TOKEN --user-pin 123456 --iterations 100
rust-hsm-cli analyze --log-file /app/rust-hsm-observe.json > softhsm-stats.txt

# Test with Kryoptic
rm /app/rust-hsm-observe.json
export PKCS11_MODULE=/usr/lib/kryoptic/libkryoptic_pkcs11.so
rust-hsm-cli benchmark --label TEST_TOKEN --user-pin 123456 --iterations 100
rust-hsm-cli analyze --log-file /app/rust-hsm-observe.json > kryoptic-stats.txt

# Compare results
diff -u softhsm-stats.txt kryoptic-stats.txt
```

**What to look for:**
- Initialization overhead differences
- Sign/verify performance comparisons
- Memory usage patterns (via process monitoring)

---

## Advanced Usage

### Filtering by Time Range

Use standard tools to filter logs before analysis:

```bash
# Extract logs from last hour
jq 'select(.ts > "2025-12-26T03:00:00Z")' /app/rust-hsm-observe.json \
  > /tmp/recent.json

rust-hsm-cli analyze --log-file /tmp/recent.json
```

### Analyzing Specific Operations

```bash
# Extract only C_Sign operations
grep '"func":"C_Sign"' /app/rust-hsm-observe.json > /tmp/sign-only.json

rust-hsm-cli analyze --log-file /tmp/sign-only.json
```

### Monitoring in Real-Time

```bash
# Tail log file and analyze periodically
watch -n 5 "rust-hsm-cli analyze --log-file /app/rust-hsm-observe.json"
```

### Exporting for Visualization

```bash
# Export to JSON for external tools
rust-hsm-cli analyze --log-file /app/rust-hsm-observe.json --format json \
  > analysis.json

# Use jq to extract specific metrics
jq '.by_function | to_entries | map({name: .key, avg_ms: .value.avg_duration_ms})' \
  analysis.json
```

### Combining with Other Logs

```bash
# Correlate HSM operations with application logs
rust-hsm-cli analyze --log-file /app/rust-hsm-observe.json --format json \
  | jq -r '.errors[] | "\(.timestamp) \(.func) \(.rv_name)"' \
  | while read ts func error; do
      echo "HSM Error at $ts: $func -> $error"
      grep "$ts" /var/log/myapp.log
    done
```

---

## Performance Considerations

### Log File Size

Observability logs grow over time:
- ~160 bytes per operation (JSON Lines format)
- 10,000 operations ≈ 1.6 MB
- 1,000,000 operations ≈ 160 MB

**Recommendations:**
- Rotate logs daily or weekly
- Compress old logs (gzip achieves 70-80% reduction)
- Archive to long-term storage after analysis

### Analysis Performance

| Log Size | Operations | Analysis Time |
|----------|------------|---------------|
| 1 KB | 7 | < 1ms |
| 100 KB | ~600 | < 10ms |
| 1 MB | ~6,000 | < 100ms |
| 10 MB | ~60,000 | < 1s |
| 100 MB | ~600,000 | < 10s |

**Optimization tips:**
- Use JSON output for programmatic processing (avoids text formatting overhead)
- Filter logs before analysis (grep/jq for specific time ranges)
- Run analysis on separate host if log files are very large

### Observability Overhead

Enabling observability adds minimal overhead:
- Logging: ~10-50μs per operation
- JSON serialization: ~5-20μs per event
- File I/O: ~1-10μs (buffered writes)

**Total overhead: < 100μs per operation** (typically < 5% of operation time)

---

## Troubleshooting

### "Failed to open log file"

**Cause**: Log file doesn't exist or isn't readable.

**Solutions:**
1. Check observability is enabled:
   ```bash
   grep observe_enabled .rust-hsm.toml
   ```
2. Verify log file path:
   ```bash
   ls -lh /app/rust-hsm-observe.json
   ```
3. Run an operation to generate logs:
   ```bash
   rust-hsm-cli info  # Simple operation to trigger logging
   ```

### "Failed to parse JSON"

**Cause**: Corrupted log file or invalid JSON Lines format.

**Solutions:**
1. Check file format:
   ```bash
   head -5 /app/rust-hsm-observe.json
   ```
2. Validate each line:
   ```bash
   jq empty /app/rust-hsm-observe.json
   ```
3. Remove corrupted lines:
   ```bash
   jq -c . /app/rust-hsm-observe.json > /tmp/clean.json
   mv /tmp/clean.json /app/rust-hsm-observe.json
   ```

### "No events found in log file"

**Cause**: Log file is empty or only contains whitespace.

**Solutions:**
1. Check file size:
   ```bash
   wc -l /app/rust-hsm-observe.json
   ```
2. Verify observability is actually enabled (check config loading):
   ```bash
   RUST_LOG=debug rust-hsm-cli info 2>&1 | grep observe
   ```
3. Check file permissions:
   ```bash
   ls -l /app/rust-hsm-observe.json
   chmod 644 /app/rust-hsm-observe.json
   ```

### Unexpected Statistics

**Cause**: Log file contains data from multiple sessions/contexts.

**Solutions:**
1. Start fresh:
   ```bash
   rm /app/rust-hsm-observe.json
   ```
2. Filter by PID/TID:
   ```bash
   jq 'select(.pid == 1234)' /app/rust-hsm-observe.json > /tmp/single-process.json
   ```
3. Filter by time range (see Advanced Usage)

---

## Related Commands

- [info](information.md#info) - Display PKCS#11 module information
- [list-slots](information.md#list-slots) - List available slots
- [benchmark](security-utilities.md#benchmark) - Run performance benchmarks
- [explain-error](troubleshooting.md#explain-error) - Decode PKCS#11 error codes

---

## Future Enhancements

Planned features for observability:

- **TUI Dashboard**: Real-time terminal UI with live charts (using ratatui)
- **Comparison Mode**: Diff two log files to detect regressions
- **pkcs11-spy Integration**: Parse logs from the standard pkcs11-spy module
- **Export Formats**: CSV, Markdown, HTML reports
- **Alerting**: Configurable thresholds for slow operations or errors
- **Web API**: HTTP endpoints for querying analysis results
- **Time-Series Storage**: PostgreSQL/TimescaleDB integration
- **Fleet Monitoring**: Aggregate statistics across multiple HSMs

---

## Security Considerations

**What is logged:**
- Function names
- Return codes
- Timing information
- Slot/session handles
- Mechanism names

**What is NOT logged:**
- PINs (never logged)
- Key material (never logged)
- Plaintext data being encrypted/signed
- Ciphertext data being decrypted
- Attribute values (only attribute names)

**Redaction built-in:**
- Template summaries only include attribute names, not values
- CKA_LABEL and CKA_ID are hashed (SHA-256), not logged in plaintext
- All sensitive attributes (CKA_VALUE, private key components) are excluded

**Safe for production** when:
- Log files have proper access controls (chmod 600)
- Logs are stored on encrypted filesystems
- Rotation/archival policies are in place
- Log aggregation uses secure transport (TLS)

