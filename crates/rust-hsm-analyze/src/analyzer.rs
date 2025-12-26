//! Analysis engine for PKCS#11 operation logs

use observe_core::Pkcs11Event;
use std::collections::HashMap;

/// Main analyzer for PKCS#11 events
pub struct Analyzer {
    events: Vec<Pkcs11Event>,
}

/// Complete analysis of a PKCS#11 session
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionAnalysis {
    pub total_ops: usize,
    pub success_count: usize,
    pub error_count: usize,
    pub success_rate: f64,
    pub duration_stats: DurationStats,
    pub by_function: HashMap<String, FunctionStats>,
    pub errors: Vec<ErrorSummary>,
}

/// Duration statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DurationStats {
    pub total_ms: f64,
    pub avg_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

/// Per-function statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionStats {
    pub count: usize,
    pub success_count: usize,
    pub error_count: usize,
    pub total_duration_ms: f64,
    pub avg_duration_ms: f64,
    pub min_duration_ms: f64,
    pub max_duration_ms: f64,
}

/// Error summary
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ErrorSummary {
    pub func: String,
    pub rv: u64,
    pub rv_name: String,
    pub count: usize,
    pub timestamp: String,
}

impl Analyzer {
    /// Create a new analyzer for the given events
    pub fn new(events: Vec<Pkcs11Event>) -> Self {
        Self { events }
    }

    /// Analyze all events and return comprehensive statistics
    pub fn analyze(&self) -> SessionAnalysis {
        let total_ops = self.events.len();
        let success_count = self.events.iter().filter(|e| e.rv == 0).count();
        let error_count = total_ops - success_count;
        let success_rate = if total_ops > 0 {
            (success_count as f64 / total_ops as f64) * 100.0
        } else {
            0.0
        };

        let duration_stats = self.calculate_duration_stats();
        let by_function = self.calculate_per_function_stats();
        let errors = self.collect_errors();

        SessionAnalysis {
            total_ops,
            success_count,
            error_count,
            success_rate,
            duration_stats,
            by_function,
            errors,
        }
    }

    fn calculate_duration_stats(&self) -> DurationStats {
        let durations: Vec<f64> = self.events.iter().map(|e| e.dur_ms).collect();

        if durations.is_empty() {
            return DurationStats {
                total_ms: 0.0,
                avg_ms: 0.0,
                min_ms: 0.0,
                max_ms: 0.0,
                p50_ms: 0.0,
                p95_ms: 0.0,
                p99_ms: 0.0,
            };
        }

        let total_ms: f64 = durations.iter().sum();
        let avg_ms = total_ms / durations.len() as f64;
        let min_ms = durations.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_ms = durations.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        // Calculate percentiles
        let mut sorted_durations = durations.clone();
        sorted_durations.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p50_ms = percentile(&sorted_durations, 50.0);
        let p95_ms = percentile(&sorted_durations, 95.0);
        let p99_ms = percentile(&sorted_durations, 99.0);

        DurationStats {
            total_ms,
            avg_ms,
            min_ms,
            max_ms,
            p50_ms,
            p95_ms,
            p99_ms,
        }
    }

    fn calculate_per_function_stats(&self) -> HashMap<String, FunctionStats> {
        let mut stats: HashMap<String, Vec<&Pkcs11Event>> = HashMap::new();

        // Group events by function
        for event in &self.events {
            stats.entry(event.func.clone()).or_default().push(event);
        }

        // Calculate stats for each function
        stats
            .into_iter()
            .map(|(func, events)| {
                let count = events.len();
                let success_count = events.iter().filter(|e| e.rv == 0).count();
                let error_count = count - success_count;

                let durations: Vec<f64> = events.iter().map(|e| e.dur_ms).collect();

                let total_duration_ms: f64 = durations.iter().sum();
                let avg_duration_ms = if !durations.is_empty() {
                    total_duration_ms / durations.len() as f64
                } else {
                    0.0
                };
                let min_duration_ms = durations.iter().cloned().fold(f64::INFINITY, f64::min);
                let max_duration_ms = durations.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

                (
                    func,
                    FunctionStats {
                        count,
                        success_count,
                        error_count,
                        total_duration_ms,
                        avg_duration_ms,
                        min_duration_ms,
                        max_duration_ms,
                    },
                )
            })
            .collect()
    }

    fn collect_errors(&self) -> Vec<ErrorSummary> {
        let mut error_map: HashMap<(String, u64), Vec<&Pkcs11Event>> = HashMap::new();

        // Group errors by function and return value
        for event in &self.events {
            if event.rv != 0 {
                error_map
                    .entry((event.func.clone(), event.rv))
                    .or_default()
                    .push(event);
            }
        }

        // Create error summaries
        error_map
            .into_iter()
            .map(|((func, rv), events)| ErrorSummary {
                func: func.clone(),
                rv,
                rv_name: events[0].rv_name.clone(),
                count: events.len(),
                timestamp: events[0].ts.to_rfc3339(),
            })
            .collect()
    }

    /// Get all events
    pub fn events(&self) -> &[Pkcs11Event] {
        &self.events
    }

    /// Get events for a specific function
    pub fn events_for_function(&self, func: &str) -> Vec<&Pkcs11Event> {
        self.events.iter().filter(|e| e.func == func).collect()
    }

    /// Get all error events
    pub fn error_events(&self) -> Vec<&Pkcs11Event> {
        self.events.iter().filter(|e| e.rv != 0).collect()
    }
}

/// Calculate percentile from sorted data
fn percentile(sorted_data: &[f64], p: f64) -> f64 {
    if sorted_data.is_empty() {
        return 0.0;
    }
    let index = (p / 100.0 * (sorted_data.len() - 1) as f64).round() as usize;
    sorted_data[index.min(sorted_data.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_event(func: &str, rv: u64, dur_ms: f64) -> Pkcs11Event {
        use chrono::{DateTime, Utc};
        Pkcs11Event {
            ts: DateTime::parse_from_rfc3339("2025-12-26T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            pid: 123,
            tid: 123,
            func: func.to_string(),
            rv,
            rv_name: if rv == 0 {
                "CKR_OK".to_string()
            } else {
                "CKR_ERROR".to_string()
            },
            dur_ms,
            slot_id: None,
            session: None,
            mech: None,
            op_id: None,
            template_summary: None,
            hint: None,
        }
    }

    #[test]
    fn test_basic_analysis() {
        let events = vec![
            create_test_event("C_Initialize", 0, 2.0),
            create_test_event("C_Login", 0, 1.0),
            create_test_event("C_Sign", 0, 1.5),
        ];

        let analyzer = Analyzer::new(events);
        let analysis = analyzer.analyze();

        assert_eq!(analysis.total_ops, 3);
        assert_eq!(analysis.success_count, 3);
        assert_eq!(analysis.error_count, 0);
        assert_eq!(analysis.success_rate, 100.0);
        assert_eq!(analysis.duration_stats.total_ms, 4.5);
    }

    #[test]
    fn test_error_analysis() {
        let events = vec![
            create_test_event("C_Login", 0xA0, 1.0), // CKR_PIN_INCORRECT
            create_test_event("C_Login", 0, 1.0),
        ];

        let analyzer = Analyzer::new(events);
        let analysis = analyzer.analyze();

        assert_eq!(analysis.total_ops, 2);
        assert_eq!(analysis.success_count, 1);
        assert_eq!(analysis.error_count, 1);
        assert_eq!(analysis.success_rate, 50.0);
        assert_eq!(analysis.errors.len(), 1);
    }

    #[test]
    fn test_per_function_stats() {
        let events = vec![
            create_test_event("C_Sign", 0, 1.0),
            create_test_event("C_Sign", 0, 2.0),
            create_test_event("C_Verify", 0, 0.5),
        ];

        let analyzer = Analyzer::new(events);
        let analysis = analyzer.analyze();

        assert_eq!(analysis.by_function.len(), 2);

        let sign_stats = analysis.by_function.get("C_Sign").unwrap();
        assert_eq!(sign_stats.count, 2);
        assert_eq!(sign_stats.avg_duration_ms, 1.5);
    }
}
