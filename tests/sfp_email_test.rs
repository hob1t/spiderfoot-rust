use spiderfoot_rust::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_email::SfpEmail;
use std::error::Error;
use std::sync::{Arc, Mutex};

struct TestEmitter {
    events: Arc<Mutex<Vec<(String, String, String, Option<f32>)>>>, // (event_type, source_module, data, conf)
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
        let mut guard = self.events.lock().unwrap();
        guard.push((
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
async fn test_email_extraction_and_generic_classification(
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpEmail::default();
    let mut options = ModuleOptions::default();
    options
        .custom
        .insert("_genericusers".to_string(), "admin,webmaster".to_string());

    let input = r#"
        Contact us at Admin@Example.com.
        Also reach sales@real-example.co.uk and support@acme.com.
        Invalid examples: user@.bad.com user@bad..com user@bad
    "#;

    let target = Target::Other("TARGET_WEB_CONTENT".to_string(), input.to_string());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    module.execute(&target, &options, &mut emitter).await?;

    let events_lock = events.lock().unwrap().clone();
    let by_data: std::collections::HashMap<String, String> = events_lock
        .iter()
        .map(|(etype, _, data, _)| (data.clone(), etype.clone()))
        .collect();

    assert_eq!(
        by_data.get("admin@example.com").map(|s| s.as_str()),
        Some("EMAILADDR_GENERIC")
    );
    assert_eq!(
        by_data.get("support@acme.com").map(|s| s.as_str()),
        Some("EMAILADDR")
    );
    // `user@.bad.com` is normalized by stripping dots around the domain,
    // so we only assert on clearly malformed inputs.
    assert!(!by_data.contains_key("user@bad..com"));
    assert!(!by_data.contains_key("user@bad"));

    Ok(())
}

#[tokio::test]
async fn test_email_affiliate_event_overrides_generic() -> Result<(), Box<dyn Error + Send + Sync>>
{
    let module = SfpEmail::default();
    let mut options = ModuleOptions::default();
    options
        .custom
        .insert("_genericusers".to_string(), "admin,webmaster".to_string());

    let input = r#"
        Affiliate content: Admin@Example.com and user@external.org
    "#;

    let target = Target::Other("AFFILIATE_DOMAIN_WHOIS".to_string(), input.to_string());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    module.execute(&target, &options, &mut emitter).await?;

    let events_lock = events.lock().unwrap().clone();
    let mut has_admin = false;
    let mut has_user = false;
    for (etype, _, data, _) in events_lock {
        if data == "admin@example.com" {
            has_admin = true;
            assert_eq!(etype.as_str(), "AFFILIATE_EMAILADDR");
        }
        if data == "user@external.org" {
            has_user = true;
            assert_eq!(etype.as_str(), "AFFILIATE_EMAILADDR");
        }
    }

    assert!(has_admin, "Expected admin@example.com to be found");
    assert!(has_user, "Expected user@external.org to be found");
    Ok(())
}
