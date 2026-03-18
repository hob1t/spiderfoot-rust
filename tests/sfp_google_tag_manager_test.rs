use spiderfoot_rust::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_google_tag_manager::SfpGoogleTagManager;
use std::error::Error;
use std::sync::{Arc, Mutex};

struct TestEmitter {
    events: Arc<Mutex<Vec<(String, String, String, Option<f32>)>>>,
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
        let mut events = self.events.lock().unwrap();
        events.push((
            event_type.to_string(),
            source_module.to_string(),
            data,
            confidence,
        ));
    }

    fn log(&mut self, level: LogLevel, message: &str) {
        println!("[{:?}] {}", level, message);
    }
}

#[tokio::test]
async fn test_google_tag_manager_real() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpGoogleTagManager::default();
    let mut options = ModuleOptions::default();
    options.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36".to_string();
    options.timeout_seconds = 30;

    // Disable verification for this test to avoid network dependencies for DNS
    options
        .custom
        .insert("verify".to_string(), "false".to_string());

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    // A real GTM ID (e.g., GTM-P9FT69 is for google.com, but might change)
    // Let's use one that is likely to have results.
    let target = Target::Other(
        "WEB_ANALYTICS_ID".to_string(),
        "Google Tag Manager: GTM-P9FT69".to_string(),
    );

    module.execute(&target, &options, &mut emitter).await?;

    let events_lock = events.lock().unwrap();
    println!("Events for GTM-P9FT69: {:?}", *events_lock);

    // Check if we got some results
    assert!(
        !events_lock.is_empty(),
        "Should have found some results for GTM-P9FT69"
    );

    // Check if we got expected event types
    let has_internet_name = events_lock
        .iter()
        .any(|(t, _, _, _)| t == "INTERNET_NAME" || t == "AFFILIATE_INTERNET_NAME");
    assert!(
        has_internet_name,
        "Should have found at least one internet name"
    );

    Ok(())
}

#[tokio::test]
async fn test_google_tag_manager_invalid() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpGoogleTagManager::default();
    let mut options = ModuleOptions::default();
    options.timeout_seconds = 30;
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let target = Target::Other(
        "WEB_ANALYTICS_ID".to_string(),
        "Google Tag Manager: GTM-INVALID".to_string(),
    );
    module.execute(&target, &options, &mut emitter).await?;

    let events_lock = events.lock().unwrap();
    assert!(
        events_lock.is_empty(),
        "Should not have found any results for GTM-INVALID"
    );

    Ok(())
}
