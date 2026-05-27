use spiderfoot_rust::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_cleanbrowsing::SfpCleanbrowsing;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

struct TestEmitter {
    events: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl EventEmitter for TestEmitter {
    fn emit(
        &mut self,
        event_type: &str,
        source_module: &str,
        _target: &Target,
        data: String,
        _confidence: Option<f32>,
    ) {
        let mut events = self.events.lock().unwrap();
        events.push((
            event_type.to_string(),
            source_module.to_string(),
            data.to_string(),
        ));
    }

    fn log(&mut self, level: LogLevel, message: &str) {
        println!("[{:?}] {}", level, message);
    }
}

#[tokio::test]
async fn test_cleanbrowsing_metadata() {
    let module = SfpCleanbrowsing::new();
    assert_eq!(module.name(), "CleanBrowsing.org");
    assert!(!module.description().is_empty());
    assert!(module.target_types().contains(&"INTERNET_NAME"));
    assert!(module
        .produced_event_types()
        .contains(&"BLACKLISTED_INTERNET_NAME"));
}

#[tokio::test]
async fn test_cleanbrowsing_no_block() {
    let module = SfpCleanbrowsing::new();
    let target = Target::Domain("example.com".to_string());
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let dummy_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
    let dns_override = vec![dummy_ip];

    let result = module
        .execute_inner(
            &target,
            &options,
            &mut emitter,
            Some(&dns_override),
            Some(&dns_override),
            Some(&dns_override),
        )
        .await;

    assert!(result.is_ok());
    let captured_events = events.lock().unwrap();
    assert_eq!(captured_events.len(), 0);
}

#[tokio::test]
async fn test_cleanbrowsing_security_block() {
    let module = SfpCleanbrowsing::new();
    let target = Target::Domain("malware.com".to_string());
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let dummy_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
    let dns_override = vec![dummy_ip];

    let result = module
        .execute_inner(
            &target,
            &options,
            &mut emitter,
            Some(&[]), // Security blocked
            Some(&dns_override),
            Some(&dns_override),
        )
        .await;

    assert!(result.is_ok());
    let captured_events = events.lock().unwrap();
    assert_eq!(captured_events.len(), 2); // Only security blocks
    assert_eq!(captured_events[0].0, "BLACKLISTED_INTERNET_NAME");
    assert!(captured_events[0].2.contains("Security"));
    assert_eq!(captured_events[1].0, "MALICIOUS_INTERNET_NAME");
    assert!(captured_events[1].2.contains("Security"));
}

#[tokio::test]
async fn test_cleanbrowsing_multiple_blocks() {
    let module = SfpCleanbrowsing::new();
    let target = Target::Domain("multi-block.com".to_string());
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let result = module
        .execute_inner(
            &target,
            &options,
            &mut emitter,
            Some(&[]), // Security blocked
            Some(&[]), // Adult blocked
            Some(&[]), // Family blocked
        )
        .await;

    assert!(result.is_ok());
    let captured_events = events.lock().unwrap();
    // 2 for security, 1 for adult, 1 for family = 4 total
    assert_eq!(captured_events.len(), 4);

    let types: Vec<String> = captured_events.iter().map(|e| e.2.clone()).collect();
    assert!(types.iter().any(|t| t.contains("Security")));
    assert!(types.iter().any(|t| t.contains("Adult")));
    assert!(types.iter().any(|t| t.contains("Family")));
}

#[tokio::test]
async fn test_cleanbrowsing_adult_block() {
    let module = SfpCleanbrowsing::new();
    let target = Target::Domain("adult.com".to_string());
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let dummy_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
    let dns_override = vec![dummy_ip];

    let result = module
        .execute_inner(
            &target,
            &options,
            &mut emitter,
            Some(&dns_override),
            Some(&[]), // Adult blocked
            Some(&dns_override),
        )
        .await;

    assert!(result.is_ok());
    let captured_events = events.lock().unwrap();
    assert_eq!(captured_events.len(), 1);
    assert_eq!(captured_events[0].0, "BLACKLISTED_INTERNET_NAME");
    assert!(captured_events[0].2.contains("Adult"));
}

#[tokio::test]
async fn test_cleanbrowsing_family_block() {
    let module = SfpCleanbrowsing::new();
    let target = Target::Domain("family-blocked.com".to_string());
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let dummy_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
    let dns_override = vec![dummy_ip];

    let result = module
        .execute_inner(
            &target,
            &options,
            &mut emitter,
            Some(&dns_override),
            Some(&dns_override),
            Some(&[]), // Family blocked
        )
        .await;

    assert!(result.is_ok());
    let captured_events = events.lock().unwrap();
    assert_eq!(captured_events.len(), 1);
    assert_eq!(captured_events[0].0, "BLACKLISTED_INTERNET_NAME");
    assert!(captured_events[0].2.contains("Family"));
}

#[tokio::test]
async fn test_cleanbrowsing_different_event_types() {
    let module = SfpCleanbrowsing::new();
    let dummy_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
    let dns_override = vec![dummy_ip];
    let options = ModuleOptions::default();

    // Affiliate
    {
        let target = Target::AffiliateDomainWhois("affiliate.com".to_string());
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut emitter = TestEmitter {
            events: events.clone(),
        };

        let _ = module
            .execute_inner(
                &target,
                &options,
                &mut emitter,
                Some(&[]), // Security blocked
                Some(&dns_override),
                Some(&dns_override),
            )
            .await;

        let captured_events = events.lock().unwrap();
        assert_eq!(captured_events[0].0, "BLACKLISTED_AFFILIATE_INTERNET_NAME");
    }

    // Co-hosted
    {
        let target = Target::CoHostedSiteDomainWhois("cohosted.com".to_string());
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut emitter = TestEmitter {
            events: events.clone(),
        };

        let _ = module
            .execute_inner(
                &target,
                &options,
                &mut emitter,
                Some(&[]), // Security blocked
                Some(&dns_override),
                Some(&dns_override),
            )
            .await;

        let captured_events = events.lock().unwrap();
        assert_eq!(captured_events[0].0, "BLACKLISTED_COHOST");
    }
}
