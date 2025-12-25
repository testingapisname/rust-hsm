//! Log sinks for writing PKCS#11 events
//!
//! Provides:
//! - FileSink: JSON Lines format to a file
//! - Future: StderrSink, OTelSink

use crate::event::Pkcs11Event;
use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Trait for event sinks
pub trait Sink: Send + Sync {
    /// Write an event to the sink
    fn write(&self, event: &Pkcs11Event) -> Result<()>;

    /// Flush any buffered data
    fn flush(&self) -> Result<()>;
}

/// File sink that writes JSON Lines format
pub struct FileSink {
    writer: Arc<Mutex<BufWriter<File>>>,
}

impl FileSink {
    /// Create a new file sink, appending to existing file
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .with_context(|| format!("Failed to open log file: {}", path.as_ref().display()))?;

        Ok(Self {
            writer: Arc::new(Mutex::new(BufWriter::new(file))),
        })
    }
}

impl Sink for FileSink {
    fn write(&self, event: &Pkcs11Event) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(event).context("Failed to serialize event to JSON")?;

        // Write as single line (JSON Lines format)
        writeln!(writer, "{}", json).context("Failed to write event to file")?;

        Ok(())
    }

    fn flush(&self) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        writer.flush().context("Failed to flush file sink")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Pkcs11Event;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn test_file_sink_creation() {
        let temp = NamedTempFile::new().unwrap();
        let sink = FileSink::new(temp.path()).unwrap();

        // Should be able to write
        let event = Pkcs11Event::new("C_Initialize", 0);
        sink.write(&event).unwrap();
        sink.flush().unwrap();
    }

    #[test]
    fn test_file_sink_json_lines() {
        let temp = NamedTempFile::new().unwrap();
        let sink = FileSink::new(temp.path()).unwrap();

        // Write two events
        let event1 = Pkcs11Event::new("C_Initialize", 0);
        let event2 = Pkcs11Event::new("C_Login", 0).with_session(42);

        sink.write(&event1).unwrap();
        sink.write(&event2).unwrap();
        sink.flush().unwrap();

        // Read back and verify JSON Lines format
        let mut file = File::open(temp.path()).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON
        let json1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let json2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();

        assert_eq!(json1["func"], "C_Initialize");
        assert_eq!(json2["func"], "C_Login");
        assert_eq!(json2["session"], 42);
    }

    #[test]
    fn test_file_sink_append() {
        let temp = NamedTempFile::new().unwrap();

        // Write first event
        {
            let sink = FileSink::new(temp.path()).unwrap();
            let event = Pkcs11Event::new("C_Initialize", 0);
            sink.write(&event).unwrap();
            sink.flush().unwrap();
        }

        // Write second event (should append)
        {
            let sink = FileSink::new(temp.path()).unwrap();
            let event = Pkcs11Event::new("C_Finalize", 0);
            sink.write(&event).unwrap();
            sink.flush().unwrap();
        }

        // Should have both events
        let mut file = File::open(temp.path()).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
    }
}
