//! Log file parsers for different PKCS#11 logging formats

use anyhow::{Context, Result};
use observe_core::Pkcs11Event;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Supported log formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// observe-core JSON Lines format (one JSON object per line)
    ObserveJson,
    /// pkcs11-spy plaintext format (future)
    Pkcs11Spy,
}

/// Parse observe-core JSON Lines format
///
/// Each line should be a valid JSON object representing a Pkcs11Event.
///
/// # Example
/// ```no_run
/// use rust_hsm_analyze::parser::parse_observe_json;
///
/// let events = parse_observe_json("observe.json")?;
/// println!("Parsed {} events", events.len());
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn parse_observe_json(path: impl AsRef<Path>) -> Result<Vec<Pkcs11Event>> {
    let path = path.as_ref();
    let file =
        File::open(path).with_context(|| format!("Failed to open log file: {}", path.display()))?;

    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("Failed to read line {}", line_num + 1))?;

        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        // Parse JSON line
        let event: Pkcs11Event = serde_json::from_str(&line)
            .with_context(|| format!("Failed to parse JSON at line {}: {}", line_num + 1, line))?;

        events.push(event);
    }

    Ok(events)
}

/// Auto-detect log format and parse
///
/// Currently only supports ObserveJson format.
/// Will auto-detect pkcs11-spy format in the future.
pub fn parse_log(path: impl AsRef<Path>) -> Result<Vec<Pkcs11Event>> {
    // For now, assume observe JSON format
    // Future: detect format by reading first few lines
    parse_observe_json(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_observe_json() {
        // Create temp file with sample JSON Lines
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, r#"{{"ts":"2025-12-26T04:12:53.089921826Z","pid":57,"tid":57,"func":"Pkcs11::new","rv":0,"rv_name":"CKR_OK","dur_ms":2.6453729999999998}}"#).unwrap();
        writeln!(temp_file, r#"{{"ts":"2025-12-26T04:12:53.093008760Z","pid":57,"tid":57,"func":"C_Initialize","rv":0,"rv_name":"CKR_OK","dur_ms":2.6549009999999997}}"#).unwrap();
        temp_file.flush().unwrap();

        let events = parse_observe_json(temp_file.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].func, "Pkcs11::new");
        assert_eq!(events[1].func, "C_Initialize");
    }

    #[test]
    fn test_parse_empty_lines() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, r#"{{"ts":"2025-12-26T04:12:53.089921826Z","pid":57,"tid":57,"func":"C_Login","rv":0,"rv_name":"CKR_OK","dur_ms":1.0}}"#).unwrap();
        writeln!(temp_file, "").unwrap(); // Empty line
        writeln!(temp_file, r#"{{"ts":"2025-12-26T04:12:53.089921826Z","pid":57,"tid":57,"func":"C_Logout","rv":0,"rv_name":"CKR_OK","dur_ms":0.5}}"#).unwrap();
        temp_file.flush().unwrap();

        let events = parse_observe_json(temp_file.path()).unwrap();
        assert_eq!(events.len(), 2);
    }
}
