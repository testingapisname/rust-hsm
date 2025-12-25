//! Configuration for observability

use observe_core::{FileSink, Sink};
use std::sync::Arc;

/// Configuration for PKCS#11 observability
#[derive(Clone)]
pub struct ObserveConfig {
    /// Whether observability is enabled
    pub enabled: bool,
    /// Sink for writing events (shared across threads)
    pub sink: Option<Arc<dyn Sink>>,
}

impl ObserveConfig {
    /// Create a disabled configuration (no logging)
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            sink: None,
        }
    }

    /// Create an enabled configuration with file sink
    pub fn enabled(log_file: impl Into<String>) -> anyhow::Result<Self> {
        let sink = FileSink::new(log_file.into())?;
        Ok(Self {
            enabled: true,
            sink: Some(Arc::new(sink)),
        })
    }

    /// Write an event if observability is enabled
    pub(crate) fn write(&self, event: &observe_core::Pkcs11Event) {
        if self.enabled {
            if let Some(ref sink) = self.sink {
                if let Err(e) = sink.write(event) {
                    tracing::warn!("Failed to write observe event: {}", e);
                }
            }
        }
    }

    /// Flush the sink if observability is enabled
    pub(crate) fn flush(&self) {
        if self.enabled {
            if let Some(ref sink) = self.sink {
                if let Err(e) = sink.flush() {
                    tracing::warn!("Failed to flush observe sink: {}", e);
                }
            }
        }
    }
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self::disabled()
    }
}
