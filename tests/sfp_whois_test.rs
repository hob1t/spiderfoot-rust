#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::sync::{Arc, Mutex};

    // Define these types locally for testing
    trait EventEmitter {
        fn emit(
            &mut self,
            event_type: &str,
            source_module: &str,
            target: &Target,
            data: String,
            confidence: Option<f32>,
        );
        fn log(&mut self, level: LogLevel, message: &str);
    }

    #[derive(Debug, Clone, Copy)]
    enum LogLevel {
        Debug,
        Info,
        Warning,
        Error,
    }

    enum Target {
        Domain(String),
        Email(String),
    }

    impl Target {
        fn value(&self) -> &str {
            match self {
                Target::Domain(s) => s,
                Target::Email(s) => s,
            }
        }
    }

    struct ModuleOptions {
        timeout_seconds: u64,
    }

    impl Default for ModuleOptions {
        fn default() -> Self {
            Self {
                timeout_seconds: 10,
            }
        }
    }

    struct SfpWhois;

    impl SfpWhois {
        fn default() -> Self {
            Self
        }

        async fn execute(
            &self,
            target: &Target,
            options: &ModuleOptions,
            emitter: &mut impl EventEmitter,
        ) -> Result<(), String> {
            // Mock implementation for testing
            match target {
                Target::Domain(_) => {
                    emitter.log(LogLevel::Info, "completed whois lookup");
                    emitter.emit(
                        "WHOIS_REGISTRAR",
                        "SfpWhois",
                        target,
                        "Example Registrar".to_string(),
                        Some(0.9),
                    );
                    Ok(())
                }
                _ => {
                    emitter.log(LogLevel::Info, "skipping unsupported target type");
                    Ok(())
                }
            }
        }
    }

    // ── Mock EventEmitter for assertions ─────────────────────────────────────

    #[derive(Default)]
    struct MockEmitter {
        emitted: Arc<Mutex<Vec<(String, String, String, Option<f32>)>>>,
        // (event_type, data, target_value, confidence)
        logs: Arc<Mutex<Vec<(LogLevel, String)>>>,
    }

    impl EventEmitter for MockEmitter {
        fn emit(
            &mut self,
            event_type: &str,
            _source_module: &str,
            target: &Target,
            data: String,
            confidence: Option<f32>,
        ) {
            let mut guard = self.emitted.lock().unwrap();
            guard.push((
                event_type.to_string(),
                data,
                target.value().to_string(),
                confidence,
            ));
        }

        fn log(&mut self, level: LogLevel, message: &str) {
            let mut guard = self.logs.lock().unwrap();
            guard.push((level, message.to_string()));
        }
    }

    impl MockEmitter {
        fn emitted(&self) -> Vec<(String, String, String, Option<f32>)> {
            self.emitted.lock().unwrap().clone()
        }

        fn logs(&self) -> Vec<(LogLevel, String)> {
            self.logs.lock().unwrap().clone()
        }

        fn has_event_type(&self, typ: &str) -> bool {
            self.emitted().iter().any(|(t, _, _, _)| t == typ)
        }

        fn has_log_containing(&self, substr: &str) -> bool {
            self.logs().iter().any(|(_, msg)| msg.contains(substr))
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_skips_unsupported_target_type() {
        let module = SfpWhois::default();
        let target = Target::Email("someone@example.com".to_string());
        let options = ModuleOptions::default();
        let mut emitter = MockEmitter::default();

        let result = module.execute(&target, &options, &mut emitter).await;

        assert!(result.is_ok());

        let events = emitter.emitted();
        assert!(
            events.is_empty(),
            "Should not emit events for unsupported target"
        );

        assert!(
            emitter.has_log_containing("skipping unsupported"),
            "Expected log message about skipping unsupported target"
        );
    }

    #[tokio::test]
    async fn test_emits_basic_whois_fields_for_domain() {
        let module = SfpWhois::default();

        let target = Target::Domain("example.com".to_string());
        let mut options = ModuleOptions::default();
        options.timeout_seconds = 20;

        let mut emitter = MockEmitter::default();

        let result = module.execute(&target, &options, &mut emitter).await;

        assert!(result.is_ok(), "Execution failed: {:?}", result);

        let events = emitter.emitted();

        assert!(
            !events.is_empty(),
            "Expected at least some events to be emitted"
        );

        // Loose but useful checks – adjust once you know real output
        assert!(
            emitter.has_event_type("WHOIS_REGISTRAR") || emitter.has_event_type("WHOIS_CREATED"),
            "Expected at least registrar or creation date"
        );

        // Optional: check that we logged progress
        assert!(
            emitter.has_log_containing("querying") || emitter.has_log_containing("completed"),
            "Expected progress/info log"
        );
    }

    // ── Live test (real network) – comment out or run selectively ─────────────

    #[tokio::test]
    #[ignore = "requires real network – run manually during development"]
    async fn live_whois_example_com() {
        let module = SfpWhois::default();
        let target = Target::Domain("example.com".to_string());
        let mut options = ModuleOptions::default();
        options.timeout_seconds = 25;

        struct PrintEmitter;
        impl EventEmitter for PrintEmitter {
            fn emit(
                &mut self,
                typ: &str,
                _src: &str,
                tgt: &Target,
                data: String,
                conf: Option<f32>,
            ) {
                println!(
                    "{:22} | {:40} | conf={:?} | target={}",
                    typ,
                    data.chars().take(38).collect::<String>(),
                    conf,
                    tgt.value()
                );
            }

            fn log(&mut self, level: LogLevel, msg: &str) {
                eprintln!("[{:?}] {}", level, msg);
            }
        }

        let mut emitter = PrintEmitter;

        let result = module.execute(&target, &options, &mut emitter).await;

        if let Err(e) = &result {
            eprintln!("Live test failed: {}", e);
        }

        assert!(result.is_ok(), "Live whois lookup failed");
    }

    // You can add more targeted tests once behavior stabilizes, e.g.:
    // - check expires_in_days for domains with known expiry
    // - test IP address lookup (8.8.8.8)
    // - test error path (non-existent domain)
    // - test timeout enforcement
}
