use spiderfoot_rust::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_quad9::SfpQuad9;
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
async fn test_quad9_metadata() {
    let module = SfpQuad9::new();
    assert_eq!(module.name(), "Quad9");
    assert!(!module.description().is_empty());
    assert!(module.target_types().contains(&"INTERNET_NAME"));
    assert!(module
        .produced_event_types()
        .contains(&"BLACKLISTED_INTERNET_NAME"));
}

#[tokio::test]
async fn test_quad9_no_block() {
    let module = SfpQuad9::new();
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
        )
        .await;

    assert!(result.is_ok());
    let captured_events = events.lock().unwrap();
    assert_eq!(captured_events.len(), 0);
}

#[tokio::test]
async fn test_quad9_block() {
    let module = SfpQuad9::new();
    let target = Target::Domain("malware.com".to_string());
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let dummy_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
    let dns_override = vec![dummy_ip];

    // empty override means blocked by Quad9, but dummy_ip means resolved by standard
    let result = module
        .execute_inner(
            &target,
            &options,
            &mut emitter,
            Some(&[]),
            Some(&dns_override),
        )
        .await;

    assert!(result.is_ok());
    let captured_events = events.lock().unwrap();
    assert_eq!(captured_events.len(), 2);
    assert_eq!(captured_events[0].0, "BLACKLISTED_INTERNET_NAME");
    assert_eq!(captured_events[1].0, "MALICIOUS_INTERNET_NAME");
    assert!(captured_events[0].2.contains("Quad9"));
    assert!(captured_events[0]
        .2
        .contains("https://quad9.net/result/?url=malware.com"));
}

#[tokio::test]
async fn test_quad9_different_event_types() {
    let module = SfpQuad9::new();
    let options = ModuleOptions::default();

    // Affiliate
    {
        let target = Target::AffiliateDomainWhois("affiliate.com".to_string());
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut emitter = TestEmitter {
            events: events.clone(),
        };

        let dummy_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
        let dns_override = vec![dummy_ip];

        let _ = module
            .execute_inner(
                &target,
                &options,
                &mut emitter,
                Some(&[]),
                Some(&dns_override),
            )
            .await;

        let captured_events = events.lock().unwrap();
        assert_eq!(captured_events[0].0, "BLACKLISTED_AFFILIATE_INTERNET_NAME");
    }

    // Co-hosted
    {
        let target = Target::Other("CO_HOSTED_SITE".to_string(), "cohosted.com".to_string());
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut emitter = TestEmitter {
            events: events.clone(),
        };

        let dummy_ip = "127.0.0.1".parse::<IpAddr>().unwrap();
        let dns_override = vec![dummy_ip];

        let _ = module
            .execute_inner(
                &target,
                &options,
                &mut emitter,
                Some(&[]),
                Some(&dns_override),
            )
            .await;

        let captured_events = events.lock().unwrap();
        assert_eq!(captured_events[0].0, "BLACKLISTED_COHOST");
    }
}
