//! Log analysis command

use anyhow::Result;

pub fn handle_analyze(log_file: String, format: String) -> Result<()> {
    use rust_hsm_analyze::{parse_log, Analyzer};

    // Parse the log file (auto-detects format: observe JSON or pkcs11-spy)
    let events = parse_log(&log_file)?;

    if events.is_empty() {
        println!("No events found in log file");
        return Ok(());
    }

    // Handle raw events output formats first (before moving events into analyzer)
    if format == "events" {
        // Output raw events as JSON Lines (one JSON object per line)
        for event in &events {
            println!("{}", serde_json::to_string(event)?);
        }
        return Ok(());
    } else if format == "pretty-events" {
        // Output raw events as pretty-printed JSON array
        println!("{}", serde_json::to_string_pretty(&events)?);
        return Ok(());
    }

    // Analyze the events (this consumes events)
    let analyzer = Analyzer::new(events);
    let analysis = analyzer.analyze();

    // Output analysis results
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&analysis)?);
    } else {
        println!("\n=== PKCS#11 Session Analysis ===\n");
        println!("Total Operations: {}", analysis.total_ops);
        println!("Success Rate: {:.2}%", analysis.success_rate);
        println!("Error Count: {}", analysis.error_count);

        println!("\n--- Overall Timing ---");
        println!("Total Duration: {:.2}ms", analysis.duration_stats.total_ms);
        println!("Average: {:.2}ms", analysis.duration_stats.avg_ms);
        println!("Min: {:.2}ms", analysis.duration_stats.min_ms);
        println!("Max: {:.2}ms", analysis.duration_stats.max_ms);
        println!("P50: {:.2}ms", analysis.duration_stats.p50_ms);
        println!("P95: {:.2}ms", analysis.duration_stats.p95_ms);
        println!("P99: {:.2}ms", analysis.duration_stats.p99_ms);

        if !analysis.by_function.is_empty() {
            println!("\n--- Per-Function Statistics ---");
            for (func, stats) in &analysis.by_function {
                println!("\n{}", func);
                println!("  Calls: {}", stats.count);
                let success_rate = if stats.count > 0 {
                    (stats.success_count as f64 / stats.count as f64) * 100.0
                } else {
                    0.0
                };
                let error_rate = if stats.count > 0 {
                    (stats.error_count as f64 / stats.count as f64) * 100.0
                } else {
                    0.0
                };
                println!("  Success: {} ({:.1}%)", stats.success_count, success_rate);
                println!("  Errors: {} ({:.1}%)", stats.error_count, error_rate);
                println!("  Avg Duration: {:.2}ms", stats.avg_duration_ms);
            }
        }

        if !analysis.errors.is_empty() {
            println!("\n--- Errors ---");
            for error in &analysis.errors {
                println!("\n{} → {} ({})", error.func, error.rv_name, error.rv);
                println!("  Count: {}", error.count);
                println!("  First seen: {}", error.timestamp);
            }
        }
    }

    Ok(())
}
