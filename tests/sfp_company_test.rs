use spiderfoot_rust::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_company::SfpCompany;
use std::error::Error;
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
        events.push((event_type.to_string(), source_module.to_string(), data));
    }

    fn log(&mut self, _level: LogLevel, _message: &str) {
        println!("[{:?}] {}", _level, _message);
    }
}

#[tokio::test]
async fn test_sfp_company_extraction() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpCompany::default();
    let content = "Welcome to Acme Corp. We are a subsidiary of Global Industries Ltd. and partner with Tech Solutions Inc. (Foundation).";
    let target = Target::Other("TARGET_WEB_CONTENT".to_string(), content.to_string());
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    module.execute(&target, &options, &mut emitter).await?;

    let emitted = events.lock().unwrap().clone();
    for (etype, module, data) in &emitted {
        println!("Emitted: {} from {} with data: {}", etype, module, data);
    }

    let companies: Vec<String> = emitted.iter().map(|(_, _, data)| data.clone()).collect();

    assert!(companies.contains(&"Acme Corp".to_string()));
    assert!(companies.contains(&"Global Industries Ltd".to_string()));
    assert!(companies.contains(&"Tech Solutions Inc".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_sfp_company_ssl_cert() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpCompany::default();
    let content = "CN=www.example.com, O=Example Enterprises LLC, L=New York, C=US";
    let target = Target::Other("SSL_CERTIFICATE_ISSUED".to_string(), content.to_string());
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    module.execute(&target, &options, &mut emitter).await?;

    let emitted = events.lock().unwrap().clone();
    let companies: Vec<String> = emitted.iter().map(|(_, _, data)| data.clone()).collect();

    assert!(companies.contains(&"Example Enterprises LLC".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_sfp_company_affiliate_extraction() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpCompany::default();
    let content = "Welcome to Affiliate Corp. We are a subsidiary of Partner Ltd.";
    // Test both AFFILIATE_WEB_CONTENT and AFFILIATE_DOMAIN_WHOIS
    let targets = vec![
        Target::Other("AFFILIATE_WEB_CONTENT".to_string(), content.to_string()),
        Target::Other(
            "AFFILIATE_DOMAIN_WHOIS".to_string(),
            "Registrant Organization: Affiliate WHOIS Inc.".to_string(),
        ),
    ];

    let options = ModuleOptions::default();

    for target in targets {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut emitter = TestEmitter {
            events: events.clone(),
        };

        module.execute(&target, &options, &mut emitter).await?;

        let emitted = events.lock().unwrap().clone();
        for (etype, _module, data) in &emitted {
            assert_eq!(etype, "AFFILIATE_COMPANY_NAME");
            println!("Emitted: {} with data: {}", etype, data);
        }
        assert!(!emitted.is_empty());
    }

    Ok(())
}

#[tokio::test]
async fn test_sfp_company_filter_js_css_logic() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpCompany::default();
    let content = r#"
        <html>
            <head>
                <script>
                    var x = "Scripting Solutions LLC";
                </script>
            </head>
            <body>
                <div>Real Company Inc.</div>
            </body>
        </html>
    "#;

    let target = Target::Other("TARGET_WEB_CONTENT".to_string(), content.to_string());
    let mut options = ModuleOptions::default();

    // Test with filter ON (default)
    let events_on = Arc::new(Mutex::new(Vec::new()));
    let mut emitter_on = TestEmitter {
        events: events_on.clone(),
    };
    module.execute(&target, &options, &mut emitter_on).await?;
    let companies_on: Vec<String> = events_on
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, d)| d.clone())
        .collect();

    assert!(companies_on.contains(&"Real Company Inc".to_string()));
    assert!(!companies_on.contains(&"Scripting Solutions LLC".to_string()));

    // Test with WebContent target and .js extension
    let js_target = Target::WebContent {
        url: "http://example.com/script.js".to_string(),
        content: content.to_string(),
    };
    let events_js = Arc::new(Mutex::new(Vec::new()));
    let mut emitter_js = TestEmitter {
        events: events_js.clone(),
    };
    module
        .execute(&js_target, &options, &mut emitter_js)
        .await?;
    let companies_js: Vec<String> = events_js
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, d)| d.clone())
        .collect();
    assert!(companies_js.is_empty(), "Should have skipped .js file");

    // Test with WebContent target and .html extension (should NOT skip)
    let html_target = Target::WebContent {
        url: "http://example.com/page.html".to_string(),
        content: content.to_string(),
    };
    let events_html = Arc::new(Mutex::new(Vec::new()));
    let mut emitter_html = TestEmitter {
        events: events_html.clone(),
    };
    module
        .execute(&html_target, &options, &mut emitter_html)
        .await?;
    let companies_html: Vec<String> = events_html
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, d)| d.clone())
        .collect();
    assert!(companies_html.contains(&"Real Company Inc".to_string()));

    // Test with filter OFF
    options
        .custom
        .insert("filterjscss".to_string(), "false".to_string());
    let events_off = Arc::new(Mutex::new(Vec::new()));
    let mut emitter_off = TestEmitter {
        events: events_off.clone(),
    };
    module.execute(&target, &options, &mut emitter_off).await?;
    let companies_off: Vec<String> = events_off
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, d)| d.clone())
        .collect();

    assert!(companies_off.contains(&"Real Company Inc".to_string()));
    assert!(companies_off.contains(&"Scripting Solutions LLC".to_string()));

    Ok(())
}
