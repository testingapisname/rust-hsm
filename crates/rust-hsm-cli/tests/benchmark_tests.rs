use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use tempfile::NamedTempFile;

const TEST_PIN: &str = "123456";
const TEST_TOKEN: &str = "TEST_TOKEN";

/// Helper to run benchmark command
fn benchmark_cmd() -> Command {
    Command::cargo_bin("rust-hsm-cli").unwrap()
}

/// Test basic benchmark execution (text format)
#[test]
#[ignore] // Requires HSM setup
fn test_benchmark_basic() {
    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--iterations",
            "5",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BENCHMARK RESULTS SUMMARY"))
        .stdout(predicate::str::contains("RSA-2048 Sign"))
        .stdout(predicate::str::contains("Ops/sec"));
}

/// Test JSON output format
#[test]
#[ignore] // Requires HSM setup
fn test_benchmark_json_output() {
    let temp_file = NamedTempFile::new().unwrap();
    let output_path = temp_file.path().to_str().unwrap();

    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--iterations",
            "5",
            "--format",
            "json",
            "--output",
            output_path,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Benchmark results written to"));

    // Verify JSON structure
    let json_content = fs::read_to_string(output_path).expect("Failed to read JSON output");
    let json: Value = serde_json::from_str(&json_content).expect("Invalid JSON");

    // Check metadata
    assert!(json["metadata"].is_object());
    assert!(json["metadata"]["timestamp"].is_string());
    assert_eq!(json["metadata"]["token_label"], TEST_TOKEN);
    assert_eq!(json["metadata"]["iterations_per_test"], 5);

    // Check system info
    assert!(json["metadata"]["system_info"].is_object());
    assert!(json["metadata"]["system_info"]["os"].is_string());
    assert!(json["metadata"]["system_info"]["cpu_count"].is_number());

    // Check results array
    assert!(json["results"].is_array());
    let results = json["results"].as_array().unwrap();
    assert!(!results.is_empty());

    // Check first result structure
    let first_result = &results[0];
    assert!(first_result["name"].is_string());
    assert!(first_result["ops_per_sec"].is_number());
    assert!(first_result["avg_latency_ms"].is_number());
    assert!(first_result["p50_ms"].is_number());
    assert!(first_result["p95_ms"].is_number());
    assert!(first_result["p99_ms"].is_number());
}

/// Test CSV output format
#[test]
#[ignore] // Requires HSM setup
fn test_benchmark_csv_output() {
    let temp_file = NamedTempFile::new().unwrap();
    let output_path = temp_file.path().to_str().unwrap();

    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--iterations",
            "5",
            "--format",
            "csv",
            "--output",
            output_path,
        ])
        .assert()
        .success();

    // Verify CSV structure
    let csv_content = fs::read_to_string(output_path).expect("Failed to read CSV output");

    // Check header
    assert!(csv_content.contains("operation,iterations,ops_per_sec"));

    // Check at least one data row
    let lines: Vec<&str> = csv_content.lines().collect();
    assert!(lines.len() > 1, "CSV should have header + data rows");

    // Verify data format
    let data_line = lines[1];
    let fields: Vec<&str> = data_line.split(',').collect();
    assert!(fields.len() >= 8, "CSV should have at least 8 columns");
}

/// Test warmup iterations
#[test]
#[ignore] // Requires HSM setup
fn test_benchmark_warmup() {
    let temp_file = NamedTempFile::new().unwrap();
    let output_path = temp_file.path().to_str().unwrap();

    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--iterations",
            "10",
            "--warmup",
            "5",
            "--format",
            "json",
            "--output",
            output_path,
        ])
        .assert()
        .success();

    // Verify warmup is recorded in metadata
    let json_content = fs::read_to_string(output_path).expect("Failed to read JSON output");
    let json: Value = serde_json::from_str(&json_content).expect("Invalid JSON");

    assert_eq!(json["metadata"]["warmup_iterations"], 5);
}

/// Test data size variation
#[test]
#[ignore] // Requires HSM setup
fn test_benchmark_data_sizes() {
    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--iterations",
            "5",
            "--data-sizes",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("DATA SIZE VARIATION"))
        .stdout(predicate::str::contains("1KB"))
        .stdout(predicate::str::contains("10KB"))
        .stdout(predicate::str::contains("100KB"))
        .stdout(predicate::str::contains("1MB"));
}

/// Test comparison mode
#[test]
#[ignore] // Requires HSM setup
fn test_benchmark_comparison() {
    // First create baseline
    let baseline_file = NamedTempFile::new().unwrap();
    let baseline_path = baseline_file.path().to_str().unwrap();

    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--iterations",
            "10",
            "--format",
            "json",
            "--output",
            baseline_path,
        ])
        .assert()
        .success();

    // Run comparison
    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--iterations",
            "10",
            "--compare",
            baseline_path,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BENCHMARK COMPARISON"))
        .stdout(predicate::str::contains("Baseline:"))
        .stdout(predicate::str::contains("Current"))
        .stdout(predicate::str::contains("Diff %"));
}

/// Test data sizes with comparison
#[test]
#[ignore] // Requires HSM setup
fn test_benchmark_data_sizes_with_comparison() {
    // Create baseline with data sizes
    let baseline_file = NamedTempFile::new().unwrap();
    let baseline_path = baseline_file.path().to_str().unwrap();

    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--iterations",
            "5",
            "--data-sizes",
            "--format",
            "json",
            "--output",
            baseline_path,
        ])
        .assert()
        .success();

    // Verify baseline includes data size tests
    let json_content = fs::read_to_string(baseline_path).expect("Failed to read baseline");
    let json: Value = serde_json::from_str(&json_content).expect("Invalid JSON");
    let results = json["results"].as_array().unwrap();

    // Should have standard tests + data size variations
    assert!(results.len() > 14, "Should have standard + data size tests");

    // Check for data size test names
    let result_names: Vec<&str> = results
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();

    assert!(result_names.iter().any(|&name| name.contains("(1KB)")));
    assert!(result_names.iter().any(|&name| name.contains("(10KB)")));
    assert!(result_names.iter().any(|&name| name.contains("(100KB)")));
    assert!(result_names.iter().any(|&name| name.contains("(1MB)")));

    // Run comparison with data sizes
    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--iterations",
            "5",
            "--data-sizes",
            "--compare",
            baseline_path,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("BENCHMARK COMPARISON"))
        .stdout(predicate::str::contains("(1KB)"))
        .stdout(predicate::str::contains("(1MB)"));
}

/// Test JSON structure completeness
#[test]
#[ignore] // Requires HSM setup
fn test_json_output_completeness() {
    let temp_file = NamedTempFile::new().unwrap();
    let output_path = temp_file.path().to_str().unwrap();

    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--iterations",
            "10",
            "--warmup",
            "3",
            "--format",
            "json",
            "--output",
            output_path,
        ])
        .assert()
        .success();

    let json_content = fs::read_to_string(output_path).expect("Failed to read JSON");
    let json: Value = serde_json::from_str(&json_content).expect("Invalid JSON");

    // Validate all required fields
    let metadata = &json["metadata"];
    assert!(metadata["timestamp"].as_str().unwrap().len() > 0);
    assert_eq!(metadata["token_label"].as_str().unwrap(), TEST_TOKEN);
    assert_eq!(metadata["iterations_per_test"].as_u64().unwrap(), 10);
    assert_eq!(metadata["warmup_iterations"].as_u64().unwrap(), 3);

    // Validate system info
    let sys_info = &metadata["system_info"];
    assert!(sys_info["os"].as_str().unwrap().len() > 0);
    assert!(sys_info["os_version"].as_str().unwrap().len() > 0);
    assert!(sys_info["cpu_count"].as_u64().unwrap() > 0);
    assert!(sys_info["total_memory_mb"].as_u64().unwrap() > 0);

    // Validate results
    let results = json["results"].as_array().unwrap();
    for result in results {
        assert!(result["name"].is_string());
        assert!(result["iterations"].is_number());
        assert!(result["ops_per_sec"].is_number());
        assert!(result["avg_latency_ms"].is_number());
        assert!(result["p50_ms"].is_number());
        assert!(result["p95_ms"].is_number());
        assert!(result["p99_ms"].is_number());

        // Sanity checks
        let ops_per_sec = result["ops_per_sec"].as_f64().unwrap();
        assert!(ops_per_sec > 0.0, "ops_per_sec should be positive");

        let avg_latency = result["avg_latency_ms"].as_f64().unwrap();
        assert!(avg_latency > 0.0, "avg_latency_ms should be positive");
    }
}

/// Test invalid baseline file handling
#[test]
#[ignore] // Requires HSM setup
fn test_invalid_baseline_file() {
    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--iterations",
            "5",
            "--compare",
            "/nonexistent/baseline.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to open baseline file"));
}

/// Test invalid format option
#[test]
fn test_invalid_format() {
    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--format",
            "invalid",
        ])
        .assert()
        .failure();
}

/// Test CSV output requires output file
#[test]
fn test_csv_requires_output_file() {
    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--format",
            "csv",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("CSV format requires --output"));
}

/// Test JSON output requires output file
#[test]
fn test_json_requires_output_file() {
    benchmark_cmd()
        .args(&[
            "benchmark",
            "--label",
            TEST_TOKEN,
            "--user-pin",
            TEST_PIN,
            "--format",
            "json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("JSON format requires --output"));
}
