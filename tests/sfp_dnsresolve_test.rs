use spiderfoot_rust::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_dnsresolve::SfpDnsResolve;
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
async fn test_dns_resolve_domain() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpDnsResolve::default();
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let target = Target::Domain("google.com".to_string());
    module.execute(&target, &options, &mut emitter).await?;

    let events_lock = events.lock().unwrap();
    println!("Events for google.com: {:?}", *events_lock);

    // Check if we got at least an IP_ADDRESS or IPV6_ADDRESS
    let has_ip = events_lock
        .iter()
        .any(|(t, _, _, _)| t == "IP_ADDRESS" || t == "IPV6_ADDRESS");
    assert!(
        has_ip,
        "Should have resolved at least one IP address for google.com"
    );

    // Check if we got DNS_RECORDs (like MX or NS)
    let has_dns_record = events_lock.iter().any(|(t, _, _, _)| t == "DNS_RECORD");
    assert!(
        has_dns_record,
        "Should have found some DNS records for google.com"
    );

    Ok(())
}

#[tokio::test]
async fn test_dns_resolve_reverse() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpDnsResolve::default();
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    // Google Public DNS
    let target = Target::IpAddr("8.8.8.8".to_string());
    module.execute(&target, &options, &mut emitter).await?;

    let events_lock = events.lock().unwrap();
    println!("Events for 8.8.8.8: {:?}", *events_lock);

    // Check if we got a DNS_NAME (PTR record)
    let has_dns_name = events_lock.iter().any(|(t, _, _, _)| t == "DNS_NAME");
    assert!(has_dns_name, "Should have resolved a DNS name for 8.8.8.8");

    Ok(())
}

#[tokio::test]
async fn test_dns_resolve_cisco() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpDnsResolve::default();
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let target = Target::Domain("cisco.com".to_string());
    module.execute(&target, &options, &mut emitter).await?;

    let events_lock = events.lock().unwrap();
    println!("Events for cisco.com: {:?}", *events_lock);

    // Check if we got at least an IP_ADDRESS or IPV6_ADDRESS
    let has_ip = events_lock
        .iter()
        .any(|(t, _, _, _)| t == "IP_ADDRESS" || t == "IPV6_ADDRESS");
    assert!(
        has_ip,
        "Should have resolved at least one IP address for cisco.com"
    );

    Ok(())
}
