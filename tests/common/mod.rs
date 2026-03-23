//! Shared test harness used across integration test files.
//!
//! Import with:
//! ```rust,ignore
//! #[path = "common/mod.rs"]
//! mod common;
//! use common::TestEmitter;
//! ```

use spiderfoot_rust::core::{EventEmitter, LogLevel, Target};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ── TestEmitter ───────────────────────────────────────────────────────────────

/// A simple in-memory [`EventEmitter`] for use in integration tests.
///
/// Events are stored as `(event_type, source_module, data, confidence)` tuples.
/// Log messages are stored as `(level, message)` tuples and also printed to
/// stdout so they appear in `cargo test -- --nocapture` output.
#[derive(Clone)]
pub struct TestEmitter {
    pub events: Arc<Mutex<Vec<(String, String, String, Option<f32>)>>>,
    pub logs: Arc<Mutex<Vec<(LogLevel, String)>>>,
}

impl TestEmitter {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            logs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns a snapshot of all emitted events.
    pub fn emitted(&self) -> Vec<(String, String, String, Option<f32>)> {
        self.events.lock().unwrap().clone()
    }

    /// Returns a map of `data → event_type` for quick membership assertions.
    pub fn by_data(&self) -> HashMap<String, String> {
        self.emitted()
            .into_iter()
            .map(|(etype, _, data, _)| (data, etype))
            .collect()
    }
}

impl Default for TestEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl EventEmitter for TestEmitter {
    fn emit(
        &mut self,
        event_type: &str,
        source_module: &str,
        _target: &Target,
        data: String,
        confidence: Option<f32>,
    ) {
        self.events.lock().unwrap().push((
            event_type.to_string(),
            source_module.to_string(),
            data,
            confidence,
        ));
    }

    fn log(&mut self, level: LogLevel, message: &str) {
        self.logs.lock().unwrap().push((level, message.to_string()));
        println!("[{level:?}] {message}");
    }
}
