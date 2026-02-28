use spiderfoot_rust::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_company::SfpCompany;
use spiderfoot_rust::modules::sfp_spider::SfpSpider;
use std::error::Error;
use std::sync::{Arc, Mutex};

struct TestEmitter {
    events: Arc<Mutex<Vec<(String, String, String, Option<Target>)>>>,
}

impl EventEmitter for TestEmitter {
    fn emit(
        &mut self,
        event_type: &str,
        source_module: &str,
        target: &Target,
        data: String,
        _confidence: Option<f32>,
    ) {
        let mut events = self.events.lock().unwrap();
        events.push((
            event_type.to_string(),
            source_module.to_string(),
            data.clone(),
            Some(target.clone()),
        ));
        println!("[EMIT] {} from {}: {}", event_type, source_module, data);
    }

    fn log(&mut self, level: LogLevel, message: &str) {
        println!("[{:?}] {}", level, message);
    }
}

#[tokio::test]
#[ignore = "Live network test"]
async fn test_real_scan_bbc() -> Result<(), Box<dyn Error + Send + Sync>> {
    let spider = SfpSpider::default();
    let company_module = SfpCompany::default();
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let domain = "truverack.com";
    let target = Target::Domain(domain.to_string());

    println!(
        "--- Phase 1: Spiderman fetching content from {} ---",
        domain
    );
    spider.execute(&target, &options, &mut emitter).await?;

    // Collect TARGET_WEB_CONTENT or TARGET_WEB_CONTENT_URL events
    let web_content_events: Vec<Target> = {
        let events_lock = events.lock().unwrap();
        events_lock
            .iter()
            .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT" || t == "TARGET_WEB_CONTENT_URL")
            .filter_map(|(_, _, _, target)| target.clone())
            .collect()
    };

    assert!(
        !web_content_events.is_empty(),
        "Failed to fetch any web content from {}",
        domain
    );

    println!(
        "--- Phase 2: Company module analyzing {} content chunks ---",
        web_content_events.len()
    );
    for content_target in web_content_events {
        company_module
            .execute(&content_target, &options, &mut emitter)
            .await?;
    }

    let final_events = events.lock().unwrap().clone();
    let companies: Vec<String> = final_events
        .iter()
        .filter(|(t, _, _, _)| t == "COMPANY_NAME")
        .map(|(_, _, data, _)| data.clone())
        .collect();

    println!("Found companies: {:?}", companies);

    // BBC often has "British Broadcasting Corporation" or similar in their footer.
    // Let's see if we caught it.
    // We expect at least one company name to be found.
    assert!(
        !companies.is_empty(),
        "Should have found at least one company name on {}",
        domain
    );

    Ok(())
}

#[tokio::test]
async fn test_scan_simulation_with_mock_content() -> Result<(), Box<dyn Error + Send + Sync>> {
    let company_module = SfpCompany::default();
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    // Simulate what SfpSpider would emit for bbc.com
    let mock_content = r#"
        <html>
            <body>
                <footer>
                    &copy; 2024 British Broadcasting Corporation. 
                    The BBC is not responsible for the content of external sites.
                    BBC World Service Inc.
                </footer>
            </body>
        </html>
    "#;

    // We don't run SfpSpider here to avoid network, just emit the event it would produce
    emitter.emit(
        "TARGET_WEB_CONTENT",
        "sfp_spider",
        &Target::Domain("bbc.com".to_string()),
        mock_content.to_string(),
        Some(1.0),
    );

    let web_content_events: Vec<String> = {
        let events_lock = events.lock().unwrap();
        events_lock
            .iter()
            .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
            .map(|(_, _, data, _)| data.clone())
            .collect()
    };

    for content in web_content_events {
        let content_target = Target::Other("TARGET_WEB_CONTENT".to_string(), content);
        company_module
            .execute(&content_target, &options, &mut emitter)
            .await?;
    }

    let companies: Vec<String> = events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _, _)| t == "COMPANY_NAME")
        .map(|(_, _, data, _)| data.clone())
        .collect();

    println!("Found companies in simulation: {:?}", companies);
    assert!(
        companies.contains(&"British Broadcasting Corporation".to_string())
            || companies.contains(&"BBC World Service Inc".to_string())
    );

    Ok(())
}

#[tokio::test]
async fn test_real_scan_truverack_reproduction() -> Result<(), Box<dyn Error + Send + Sync>> {
    let company_module = SfpCompany::default();
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let truverack_html = r#"
<!DOCTYPE html>
<html>
<head><title>TruVerAck - Acknowledging Truth</title></head>
<body>
    <h1>Welcome to TruVerAck</h1>
    <footer>© 2025 TruVerAck. All Rights Reserved</footer>
</body>
</html>
"#;

    let content_target =
        Target::Other("TARGET_WEB_CONTENT".to_string(), truverack_html.to_string());
    company_module
        .execute(&content_target, &options, &mut emitter)
        .await?;

    let final_events = events.lock().unwrap().clone();
    let companies: Vec<String> = final_events
        .iter()
        .filter(|(t, _, _, _)| t == "COMPANY_NAME")
        .map(|(_, _, data, _)| data.clone())
        .collect();

    println!("Found companies: {:?}", companies);
    assert!(
        !companies.is_empty(),
        "Should have found at least 'TruVerAck' as a company name"
    );

    Ok(())
}

#[tokio::test]
async fn test_affiliate_simulation() -> Result<(), Box<dyn Error + Send + Sync>> {
    let company_module = SfpCompany::default();
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    // 1. Simulate AFFILIATE_WEB_CONTENT
    let affiliate_html = r#"
        <html>
            <head><title>Partner Site - Affiliate Ltd.</title></head>
            <body>
                <h1>Welcome to Affiliate Corp</h1>
                <footer>Copyright 2024 Partner Inc.</footer>
            </body>
        </html>
    "#;

    let affiliate_content_target = Target::Other(
        "AFFILIATE_WEB_CONTENT".to_string(),
        affiliate_html.to_string(),
    );
    company_module
        .execute(&affiliate_content_target, &options, &mut emitter)
        .await?;

    // 2. Simulate AFFILIATE_DOMAIN_WHOIS
    let affiliate_whois = "Registrant Organization: Affiliate WHOIS LLC";
    let affiliate_whois_target = Target::Other(
        "AFFILIATE_DOMAIN_WHOIS".to_string(),
        affiliate_whois.to_string(),
    );
    company_module
        .execute(&affiliate_whois_target, &options, &mut emitter)
        .await?;

    let final_events = events.lock().unwrap().clone();
    let affiliate_companies: Vec<String> = final_events
        .iter()
        .filter(|(t, _, _, _)| t == "AFFILIATE_COMPANY_NAME")
        .map(|(_, _, data, _)| data.clone())
        .collect();

    println!("Found affiliate companies: {:?}", affiliate_companies);

    assert!(affiliate_companies.contains(&"Affiliate Ltd".to_string()));
    assert!(affiliate_companies.contains(&"Affiliate Corp".to_string()));
    assert!(affiliate_companies.contains(&"Partner Inc.".to_string()));
    assert!(affiliate_companies.contains(&"Affiliate WHOIS LLC".to_string()));

    // Ensure no regular COMPANY_NAME was emitted
    let regular_companies: Vec<String> = final_events
        .iter()
        .filter(|(t, _, _, _)| t == "COMPANY_NAME")
        .map(|(_, _, data, _)| data.clone())
        .collect();
    assert!(regular_companies.is_empty());

    Ok(())
}

#[tokio::test]
#[ignore = "Live network test with real URL"]
async fn test_real_scan() -> Result<(), Box<dyn Error + Send + Sync>> {
    let spider = SfpSpider::default();
    let company_module = SfpCompany::default();
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    // Use a real URL that is likely to have a company name and maybe some JS/CSS
    let domain = "google.com";
    let target = Target::Domain(domain.to_string());

    println!("--- Fetching {} ---", domain);
    spider.execute(&target, &options, &mut emitter).await?;

    // Collect TARGET_WEB_CONTENT_URL events (which use Target::WebContent)
    let web_content_events: Vec<Target> = {
        let events_lock = events.lock().unwrap();
        events_lock
            .iter()
            .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT_URL")
            .filter_map(|(_, _, _, target)| target.clone())
            .collect()
    };

    println!("Found {} WebContent targets", web_content_events.len());

    for content_target in web_content_events {
        company_module
            .execute(&content_target, &options, &mut emitter)
            .await?;
    }

    let final_events = events.lock().unwrap().clone();
    let companies: Vec<String> = final_events
        .iter()
        .filter(|(t, _, _, _)| t == "COMPANY_NAME")
        .map(|(_, _, data, _)| data.clone())
        .collect();

    println!("Found companies on {}: {:?}", domain, companies);

    // We expect Google to be found or at least some company name
    assert!(
        !companies.is_empty(),
        "Should have found some company names on {}",
        domain
    );

    Ok(())
}
