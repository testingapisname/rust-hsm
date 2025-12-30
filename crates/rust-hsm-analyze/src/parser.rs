//! Log file parsers for different PKCS#11 logging formats

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use observe_core::Pkcs11Event;
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::SystemTime;

/// Supported log formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// observe-core JSON Lines format (one JSON object per line)
    ObserveJson,
    /// pkcs11-spy plaintext format
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

/// Parse pkcs11-spy plaintext format
///
/// Converts pkcs11-spy logs to structured JSON events for unified analysis.
/// This enables "Wireshark for PKCS#11" functionality - capture with pkcs11-spy,
/// analyze with our structured tools.
///
/// Example pkcs11-spy format:
/// ```text
/// 0: C_Initialize
/// 1: Calling C_Initialize  
/// 2: [in] pInitArgs = 0x7ffd12345678
/// 3: [out] *pInitArgs = CK_C_INITIALIZE_ARGS...
/// 4: Returned: 0 CKR_OK
/// ```
pub fn parse_pkcs11_spy(path: impl AsRef<Path>) -> Result<Vec<Pkcs11Event>> {
    let path = path.as_ref();
    let file = File::open(path)
        .with_context(|| format!("Failed to open pkcs11-spy log: {}", path.display()))?;

    let reader = BufReader::new(file);
    let mut events = Vec::new();
    let mut current_call: Option<Pkcs11SpyCall> = None;
    let mut operation_counter = 0;

    // Generate base timestamp (pkcs11-spy doesn't include timestamps)
    let base_time = SystemTime::now();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("Failed to read line {}", line_num + 1))?;
        let original_line = line.clone(); // Preserve original for indentation detection
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        // Parse pkcs11-spy line format - pass original line to preserve indentation
        if let Some(captures) = parse_spy_line(&original_line) {
            match captures.line_type {
                SpyLineType::FunctionHeader => {
                    // Start of new function call
                    if let Some(call) = current_call.take() {
                        // Convert previous call to event
                        if let Some(event) = spy_call_to_event(call, base_time, operation_counter) {
                            events.push(event);
                            operation_counter += 1;
                        }
                    }
                    current_call = Some(Pkcs11SpyCall {
                        function: captures.function.unwrap_or_else(|| "Unknown".to_string()),
                        timestamp: None,
                        inputs: Vec::new(),
                        outputs: Vec::new(),
                        structured_outputs: Vec::new(),
                        return_code: None,
                        return_name: None,
                    });
                }
                SpyLineType::Timestamp => {
                    // Update timestamp for current call
                    if let Some(ref mut call) = current_call {
                        call.timestamp = captures.timestamp;
                    }
                }
                SpyLineType::Calling => {
                    // "Calling C_Function" - we already have the function name
                }
                SpyLineType::Input => {
                    if let Some(ref mut call) = current_call {
                        call.inputs.push(captures.parameter.unwrap_or_default());
                    }
                }
                SpyLineType::Output => {
                    if let Some(ref mut call) = current_call {
                        call.outputs.push(captures.parameter.unwrap_or_default());
                    }
                }
                SpyLineType::StructuredOutput => {
                    if let Some(ref mut call) = current_call {
                        call.structured_outputs
                            .push(captures.parameter.unwrap_or_default());
                    }
                }
                SpyLineType::Returned => {
                    if let Some(ref mut call) = current_call {
                        call.return_code = captures.return_code;
                        call.return_name = captures.return_name;
                    }
                }
                SpyLineType::Other => {
                    // Skip header lines and other non-functional content
                }
            }
        }
    }

    // Handle last call
    if let Some(call) = current_call {
        if let Some(event) = spy_call_to_event(call, base_time, operation_counter) {
            events.push(event);
        }
    }

    Ok(events)
}

/// Represents a complete pkcs11-spy function call
#[derive(Debug)]
struct Pkcs11SpyCall {
    function: String,
    timestamp: Option<String>, // Raw timestamp from spy log
    inputs: Vec<String>,
    outputs: Vec<String>,
    structured_outputs: Vec<String>, // Multi-line structured output like pInfo
    return_code: Option<u32>,
    return_name: Option<String>,
}

/// Types of lines in pkcs11-spy output
#[derive(Debug)]
enum SpyLineType {
    FunctionHeader,   // "0: C_Initialize"
    Timestamp,        // "2025-12-30 02:34:57.994"
    Calling,          // "1: Calling C_Initialize"
    Input,            // "2: [in] param = value"
    Output,           // "3: [out] param = value"
    StructuredOutput, // "      label: 'value'" (indented multi-line output)
    Returned,         // "4: Returned: 0 CKR_OK"
    Other,            // Other lines like headers, separators
}

/// Parsed line information
#[derive(Debug)]
struct SpyLineParse {
    line_type: SpyLineType,
    function: Option<String>,
    timestamp: Option<String>,
    parameter: Option<String>,
    return_code: Option<u32>,
    return_name: Option<String>,
}

/// Parse a single pkcs11-spy line
fn parse_spy_line(line: &str) -> Option<SpyLineParse> {
    // DON'T TRIM HERE - we need to preserve indentation for detection

    let trimmed_line = line.trim();

    // Skip empty lines and spy headers
    if trimmed_line.is_empty()
        || trimmed_line.starts_with("***")
        || trimmed_line.starts_with("Loaded:")
    {
        return Some(SpyLineParse {
            line_type: SpyLineType::Other,
            function: None,
            timestamp: None,
            parameter: None,
            return_code: None,
            return_name: None,
        });
    }

    // Timestamp line: "2025-12-30 02:34:57.994"
    if parse_timestamp_line(trimmed_line).is_some() {
        return Some(SpyLineParse {
            line_type: SpyLineType::Timestamp,
            function: None,
            timestamp: Some(trimmed_line.to_string()),
            parameter: None,
            return_code: None,
            return_name: None,
        });
    }

    // Structured output detection - catch any indented line with structured data
    let content_trimmed = line.trim_start();
    if content_trimmed != line && !content_trimmed.is_empty() {
        // This is an indented line - check if it looks like structured data
        if content_trimmed.contains(':')
            || content_trimmed.contains('=')
            || content_trimmed.starts_with("CKA_")
            || (content_trimmed
                .chars()
                .next()
                .unwrap_or(' ')
                .is_alphabetic()
                && content_trimmed.contains(' '))
        {
            return Some(SpyLineParse {
                line_type: SpyLineType::StructuredOutput,
                function: None,
                timestamp: None,
                parameter: Some(content_trimmed.to_string()), // Use trimmed content
                return_code: None,
                return_name: None,
            });
        }
    }

    // Special case: Return line "Returned:  0 CKR_OK" (double space after colon)
    if let Some(return_part) = trimmed_line.strip_prefix("Returned:") {
        let parts: Vec<&str> = return_part.split_whitespace().collect();

        let return_code = if let Some(code_str) = parts.first() {
            code_str.parse::<u32>().ok()
        } else {
            None
        };

        let return_name = if parts.len() > 1 {
            Some(parts[1..].join(" "))
        } else {
            None
        };

        return Some(SpyLineParse {
            line_type: SpyLineType::Returned,
            function: None,
            timestamp: None,
            parameter: None,
            return_code,
            return_name,
        });
    }

    // Format: "N: content"
    let parts: Vec<&str> = trimmed_line.splitn(2, ": ").collect();
    if parts.len() != 2 {
        // Could be continuation of structured output
        if trimmed_line.contains(":") || trimmed_line.contains("=") {
            return Some(SpyLineParse {
                line_type: SpyLineType::StructuredOutput,
                function: None,
                timestamp: None,
                parameter: Some(trimmed_line.to_string()),
                return_code: None,
                return_name: None,
            });
        }
        return None;
    }

    let content = parts[1];

    // Function header: "C_Initialize", "C_GetSlotList", etc.
    if content.starts_with("C_") && !content.starts_with("Calling") {
        return Some(SpyLineParse {
            line_type: SpyLineType::FunctionHeader,
            function: Some(content.to_string()),
            timestamp: None,
            parameter: None,
            return_code: None,
            return_name: None,
        });
    }

    // Calling: "Calling C_Initialize"
    if content.starts_with("Calling ") {
        return Some(SpyLineParse {
            line_type: SpyLineType::Calling,
            function: None,
            timestamp: None,
            parameter: None,
            return_code: None,
            return_name: None,
        });
    }

    // Input parameter: "[in] pInitArgs = 0x7ffd12345678"
    if content.starts_with("[in]") {
        return Some(SpyLineParse {
            line_type: SpyLineType::Input,
            function: None,
            timestamp: None,
            parameter: Some(content.to_string()),
            return_code: None,
            return_name: None,
        });
    }

    // Output parameter: "[out] *pInitArgs = CK_C_INITIALIZE_ARGS..."
    if content.starts_with("[out]") || content.starts_with("[in,out]") {
        return Some(SpyLineParse {
            line_type: SpyLineType::Output,
            function: None,
            timestamp: None,
            parameter: Some(content.to_string()),
            return_code: None,
            return_name: None,
        });
    }

    None
}

/// Parse timestamp line like "2025-12-30 02:34:57.994"
fn parse_timestamp_line(line: &str) -> Option<&str> {
    // Simple check for timestamp pattern: YYYY-MM-DD HH:MM:SS.mmm
    if line.len() >= 19
        && line.chars().nth(4) == Some('-')
        && line.chars().nth(7) == Some('-')
        && line.chars().nth(10) == Some(' ')
        && line.chars().nth(13) == Some(':')
        && line.chars().nth(16) == Some(':')
    {
        Some(line)
    } else {
        None
    }
}

/// Convert pkcs11-spy call to Pkcs11Event
fn spy_call_to_event(
    call: Pkcs11SpyCall,
    base_time: SystemTime,
    offset_ms: u64,
) -> Option<Pkcs11Event> {
    // Use actual timestamp from spy log if available, otherwise use base time + offset
    let timestamp = if let Some(ts_str) = &call.timestamp {
        // Try to parse the timestamp string
        if let Ok(parsed) =
            DateTime::parse_from_str(&format!("{} +00:00", ts_str), "%Y-%m-%d %H:%M:%S%.3f %z")
        {
            parsed.with_timezone(&Utc)
        } else {
            // Fallback to offset-based timestamp
            let timestamp = base_time + std::time::Duration::from_millis(offset_ms);
            timestamp.into()
        }
    } else {
        // Fallback to offset-based timestamp
        let timestamp = base_time + std::time::Duration::from_millis(offset_ms);
        timestamp.into()
    };

    // Build template summary from inputs, outputs, and structured data
    let mut template_map = HashMap::new();

    // Add input parameters
    if !call.inputs.is_empty() {
        template_map.insert(
            "inputs".to_string(),
            Value::Array(
                call.inputs
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
    }

    // Add output parameters
    if !call.outputs.is_empty() {
        template_map.insert(
            "outputs".to_string(),
            Value::Array(
                call.outputs
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
    }

    // Add structured outputs (like token info details)
    if !call.structured_outputs.is_empty() {
        template_map.insert(
            "structured_info".to_string(),
            Value::Array(
                call.structured_outputs
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
    }

    let template_summary = if template_map.is_empty() {
        None
    } else {
        Some(template_map)
    };

    // Extract session handle from inputs if present (common parameter)
    let session_handle = extract_session_handle(&call.inputs);

    // Extract slot ID from inputs if present
    let slot_id = extract_slot_id(&call.inputs);

    // Extract mechanism from inputs if present
    let mechanism = extract_mechanism(&call.inputs);

    // Generate operation ID for correlation
    let op_id = Some(format!("spy-{}", offset_ms / 100)); // Use offset as operation counter

    // Generate hint before moving call values
    let hint = generate_hint(&call);

    Some(Pkcs11Event {
        ts: timestamp,
        pid: 0, // pkcs11-spy doesn't provide PID
        tid: 0, // pkcs11-spy doesn't provide TID
        func: call.function,
        rv: call.return_code.unwrap_or(0) as u64,
        rv_name: call
            .return_name
            .clone()
            .unwrap_or_else(|| "CKR_UNKNOWN".to_string()),
        dur_ms: 1.0, // pkcs11-spy doesn't provide timing - use placeholder
        slot_id,
        session: session_handle,
        mech: mechanism,
        template_summary,
        op_id,
        hint,
    })
}

/// Extract session handle from input parameters
fn extract_session_handle(inputs: &[String]) -> Option<u64> {
    for input in inputs {
        if input.contains("hSession") || input.contains("session") {
            // Look for hex value like "0x1"
            if let Some(hex_start) = input.find("0x") {
                let hex_part = &input[hex_start + 2..];
                if let Some(space_pos) = hex_part.find(' ') {
                    if let Ok(handle) = u64::from_str_radix(&hex_part[..space_pos], 16) {
                        return Some(handle);
                    }
                } else if let Ok(handle) = u64::from_str_radix(hex_part, 16) {
                    return Some(handle);
                }
            }
        }
    }
    None
}

/// Extract slot ID from input parameters
fn extract_slot_id(inputs: &[String]) -> Option<u64> {
    for input in inputs {
        if input.contains("slotID") || input.contains("slot") {
            // Look for hex value like "0x0"
            if let Some(hex_start) = input.find("0x") {
                let hex_part = &input[hex_start + 2..];
                if let Some(space_pos) = hex_part.find(' ') {
                    if let Ok(slot) = u64::from_str_radix(&hex_part[..space_pos], 16) {
                        return Some(slot);
                    }
                } else if let Ok(slot) = u64::from_str_radix(hex_part, 16) {
                    return Some(slot);
                }
            }
        }
    }
    None
}

/// Extract mechanism from input parameters
fn extract_mechanism(inputs: &[String]) -> Option<String> {
    for input in inputs {
        if input.contains("pMechanism") || input.contains("mechanism") {
            // Look for CKM_ mechanism name
            if let Some(ckm_start) = input.find("CKM_") {
                let rest = &input[ckm_start..];
                if let Some(end_pos) = rest.find(' ') {
                    return Some(rest[..end_pos].to_string());
                } else {
                    return Some(rest.to_string());
                }
            }
        }
    }
    None
}

/// Generate contextual hints based on function call
fn generate_hint(call: &Pkcs11SpyCall) -> Option<String> {
    let base_hint = match call.function.as_str() {
        "C_Initialize" => Some("PKCS#11 library initialization".to_string()),
        "C_Finalize" => Some("PKCS#11 library cleanup".to_string()),
        "C_GetSlotList" => Some("Token discovery".to_string()),
        "C_GetSlotInfo" => Some("Slot hardware information".to_string()),
        "C_GetTokenInfo" => Some("Token details and capabilities".to_string()),
        "C_OpenSession" => Some("Session establishment".to_string()),
        "C_CloseSession" => Some("Session termination".to_string()),
        "C_Login" => Some("User authentication".to_string()),
        "C_Logout" => Some("Session logout".to_string()),
        "C_CreateObject" => Some("Object creation (key import)".to_string()),
        "C_DestroyObject" => Some("Object deletion".to_string()),
        "C_GetAttributeValue" => Some("Object attribute inspection".to_string()),
        "C_FindObjectsInit" => Some("Object search initialization".to_string()),
        "C_FindObjects" => Some("Object search execution".to_string()),
        "C_FindObjectsFinal" => Some("Object search cleanup".to_string()),
        "C_GenerateKey" => Some("Symmetric key generation".to_string()),
        "C_GenerateKeyPair" => Some("Asymmetric keypair generation".to_string()),
        "C_SignInit" => Some("Digital signature initialization".to_string()),
        "C_Sign" => Some("Digital signature generation".to_string()),
        "C_VerifyInit" => Some("Signature verification initialization".to_string()),
        "C_Verify" => Some("Signature verification".to_string()),
        "C_EncryptInit" => Some("Encryption initialization".to_string()),
        "C_Encrypt" => Some("Data encryption".to_string()),
        "C_DecryptInit" => Some("Decryption initialization".to_string()),
        "C_Decrypt" => Some("Data decryption".to_string()),
        "C_DigestInit" => Some("Hash initialization".to_string()),
        "C_Digest" => Some("Hash computation".to_string()),
        "C_WrapKey" => Some("Key wrapping (export)".to_string()),
        "C_UnwrapKey" => Some("Key unwrapping (import)".to_string()),
        "C_GetMechanismList" => Some("Cryptographic capability discovery".to_string()),
        "C_GetMechanismInfo" => Some("Mechanism capability details".to_string()),
        _ => {
            // Generate hint based on return code if available
            if let Some(rv_name) = &call.return_name {
                match rv_name.as_str() {
                    "CKR_OK" => Some("Operation completed successfully".to_string()),
                    "CKR_PIN_INCORRECT" => {
                        Some("Authentication failed - incorrect PIN".to_string())
                    }
                    "CKR_TOKEN_NOT_PRESENT" => Some("Hardware token not available".to_string()),
                    "CKR_USER_NOT_LOGGED_IN" => Some("Authentication required".to_string()),
                    "CKR_MECHANISM_INVALID" => {
                        Some("Unsupported cryptographic operation".to_string())
                    }
                    _ => None,
                }
            } else {
                None
            }
        }
    };

    // Add pkcs11-spy source indicator to all hints
    base_hint.map(|hint| format!("{} (via pkcs11-spy)", hint))
}
///
/// Detects format by examining file content:
/// - JSON Lines: Lines starting with '{'
/// - pkcs11-spy: Lines with format "N: C_Function" or "N: Calling"
pub fn parse_log(path: impl AsRef<Path>) -> Result<Vec<Pkcs11Event>> {
    let format = detect_format(&path)?;

    match format {
        LogFormat::ObserveJson => parse_observe_json(path),
        LogFormat::Pkcs11Spy => parse_pkcs11_spy(path),
    }
}

/// Detect log format by examining file content
fn detect_format(path: impl AsRef<Path>) -> Result<LogFormat> {
    let path = path.as_ref();
    let file = File::open(path).with_context(|| {
        format!(
            "Failed to open file for format detection: {}",
            path.display()
        )
    })?;

    let reader = BufReader::new(file);
    let mut json_lines = 0;
    let mut spy_lines = 0;
    let mut total_lines = 0;

    for line in reader.lines().take(20) {
        // Sample first 20 lines
        let line = line?;
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        total_lines += 1;

        // Check for JSON format
        if line.starts_with('{') && line.ends_with('}') {
            json_lines += 1;
        }

        // Check for pkcs11-spy format
        if let Some(colon_pos) = line.find(": ") {
            let prefix = &line[..colon_pos];
            let content = &line[colon_pos + 2..];

            // pkcs11-spy lines start with number: content
            if prefix.chars().all(|c| c.is_ascii_digit())
                && (content.starts_with("C_")
                    || content.starts_with("Calling")
                    || content.starts_with("[")
                    || content.starts_with("Returned:"))
            {
                spy_lines += 1;
            }
        }
    }

    // Determine format based on majority
    if total_lines == 0 {
        return Err(anyhow::anyhow!("Empty file or no readable lines"));
    }

    // Prioritize spy format if we detect any spy lines
    if spy_lines > 0 {
        Ok(LogFormat::Pkcs11Spy)
    } else if json_lines > 0 {
        Ok(LogFormat::ObserveJson)
    } else {
        // Default to JSON if unclear
        Ok(LogFormat::ObserveJson)
    }
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

    #[test]
    fn test_parse_pkcs11_spy() {
        // Create temp file with sample pkcs11-spy format
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "0: C_Initialize").unwrap();
        writeln!(temp_file, "1: Calling C_Initialize").unwrap();
        writeln!(temp_file, "2: [in] pInitArgs = 0x7ffd12345678").unwrap();
        writeln!(temp_file, "3: [out] *pInitArgs = CK_C_INITIALIZE_ARGS...").unwrap();
        writeln!(temp_file, "Returned: 0 CKR_OK").unwrap();
        writeln!(temp_file, "").unwrap();
        writeln!(temp_file, "0: C_GetSlotList").unwrap();
        writeln!(temp_file, "1: Calling C_GetSlotList").unwrap();
        writeln!(temp_file, "2: [in] tokenPresent = FALSE (0)").unwrap();
        writeln!(temp_file, "3: [in] pSlotList = NULL_PTR").unwrap();
        writeln!(temp_file, "4: [in,out] *pulCount = 2").unwrap();
        writeln!(temp_file, "Returned: 0 CKR_OK").unwrap();
        temp_file.flush().unwrap();

        let events = parse_pkcs11_spy(temp_file.path()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].func, "C_Initialize");
        assert_eq!(events[1].func, "C_GetSlotList");
        assert_eq!(events[0].rv, 0);
        assert_eq!(events[0].rv_name, "CKR_OK");
        assert_eq!(events[1].rv, 0);
        assert_eq!(events[1].rv_name, "CKR_OK");

        // Check that hint indicates pkcs11-spy conversion
        assert!(events[0].hint.as_ref().unwrap().contains("pkcs11-spy"));
    }

    #[test]
    fn test_format_detection() {
        // Test JSON format detection
        let mut json_file = NamedTempFile::new().unwrap();
        writeln!(json_file, r#"{{"func":"C_Initialize","rv":0}}"#).unwrap();
        writeln!(json_file, r#"{{"func":"C_GetSlotList","rv":0}}"#).unwrap();
        json_file.flush().unwrap();

        let format = detect_format(json_file.path()).unwrap();
        assert_eq!(format, LogFormat::ObserveJson);

        // Test pkcs11-spy format detection
        let mut spy_file = NamedTempFile::new().unwrap();
        writeln!(spy_file, "0: C_Initialize").unwrap();
        writeln!(spy_file, "1: Calling C_Initialize").unwrap();
        writeln!(spy_file, "Returned: 0 CKR_OK").unwrap();
        spy_file.flush().unwrap();

        let format = detect_format(spy_file.path()).unwrap();
        assert_eq!(format, LogFormat::Pkcs11Spy);
    }

    #[test]
    fn test_parse_log_auto_detect() {
        // Test auto-detection with JSON format
        let mut json_file = NamedTempFile::new().unwrap();
        writeln!(json_file, r#"{{"ts":"2025-12-26T04:12:53.089921826Z","pid":57,"tid":57,"func":"C_Initialize","rv":0,"rv_name":"CKR_OK","dur_ms":1.0}}"#).unwrap();
        json_file.flush().unwrap();

        let events = parse_log(json_file.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].func, "C_Initialize");

        // Test auto-detection with pkcs11-spy format
        let mut spy_file = NamedTempFile::new().unwrap();
        writeln!(spy_file, "0: C_GetSlotList").unwrap();
        writeln!(spy_file, "1: Calling C_GetSlotList").unwrap();
        writeln!(spy_file, "Returned: 0 CKR_OK").unwrap();
        spy_file.flush().unwrap();

        let events = parse_log(spy_file.path()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].func, "C_GetSlotList");
        assert!(events[0].hint.as_ref().unwrap().contains("pkcs11-spy"));
    }
}
