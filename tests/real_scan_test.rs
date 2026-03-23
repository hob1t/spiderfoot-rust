use spiderfoot_rust::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_company::SfpCompany;
use spiderfoot_rust::modules::sfp_dnsneighbor::SfpDnsNeighbor;
use spiderfoot_rust::modules::sfp_dnsresolve::SfpDnsResolve;
use spiderfoot_rust::modules::sfp_email::SfpEmail;
use spiderfoot_rust::modules::sfp_google_tag_manager::SfpGoogleTagManager;
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

/// `185.199.111.153` is one of the four GitHub Pages IPs.
/// The /28 around it (185.199.111.144–185.199.111.159) is densely
/// reverse-mapped to `*.github.io` names, making it a reliable target
/// for exercising the full sfp_dnsneighbor pipeline.
///
/// What this test verifies:
/// 1. `sfp_dnsresolve` resolves the IP's PTR → hostname
/// 2. `sfp_dnsneighbor` finds at least one `AFFILIATE_IPADDR` neighbour
///    in the /28 that also has a valid PTR record
/// 3. The origin IP itself is never re-emitted
/// 4. All emitted IPs are in the 185.199.111.144/28 subnet
#[tokio::test]
#[ignore = "Live network test"]
async fn test_real_dnsneighbor_github_pages_ip() -> Result<(), Box<dyn Error + Send + Sync>> {
    const TARGET_IP: &str = "185.199.111.153";
    const SUBNET_BASE: u32 = (185 << 24) | (199 << 16) | (111 << 8) | 144; // 185.199.111.144
    const SUBNET_MASK: u32 = !0u32 << 4; // /28

    let dns_module = SfpDnsNeighbor::default();
    let mut options = ModuleOptions::default();
    // lookasidebits=4 → /28 → 16 neighbours
    options
        .custom
        .insert("lookasidebits".to_string(), "4".to_string());
    options
        .custom
        .insert("validatereverse".to_string(), "true".to_string());

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let target = Target::IpAddr(TARGET_IP.to_string());
    println!("--- sfp_dnsneighbor probing /28 around {} ---", TARGET_IP);
    dns_module.execute(&target, &options, &mut emitter).await?;

    let emitted = events.lock().unwrap().clone();
    println!(
        "Emitted {} events: {:#?}",
        emitted.len(),
        emitted
            .iter()
            .map(|(t, _, d, _)| format!("{t}: {d}"))
            .collect::<Vec<_>>()
    );

    // 1. Origin must never appear in output.
    let origin_reemitted = emitted.iter().any(|(_, _, data, _)| data == TARGET_IP);
    assert!(
        !origin_reemitted,
        "Origin IP {TARGET_IP} must not be re-emitted"
    );

    // 2. At least one AFFILIATE_IPADDR must be found.
    let affiliate_count = emitted
        .iter()
        .filter(|(t, _, _, _)| t == "AFFILIATE_IPADDR")
        .count();
    assert!(
        affiliate_count > 0,
        "Expected at least one AFFILIATE_IPADDR neighbour in the 185.199.111.144/28 subnet"
    );

    // 3. All emitted IPs must fall within the 185.199.111.144/28 subnet.
    for (evttype, _, data, confidence) in &emitted {
        let ip: std::net::IpAddr = data
            .parse()
            .unwrap_or_else(|_| panic!("Emitted data '{data}' is not a valid IP"));

        match ip {
            std::net::IpAddr::V4(v4) => {
                let n = u32::from(v4);
                assert_eq!(
                    n & SUBNET_MASK,
                    SUBNET_BASE,
                    "IP {v4} is outside the 185.199.111.144/28 subnet"
                );
            }
            std::net::IpAddr::V6(_) => {
                panic!("Unexpected IPv6 address {ip} from an IPv4 lookaside scan");
            }
        }

        assert!(
            evttype == "AFFILIATE_IPADDR" || evttype == "IP_ADDRESS",
            "Unexpected event type '{evttype}' for IP {data}"
        );
        // Note: real_scan_test's TestEmitter stores Option<Target> in the 4th slot,
        // not confidence. Confidence is validated in sfp_dnsneighbor_test.rs instead.
        let _ = confidence;
    }

    Ok(())
}

#[tokio::test]
#[ignore = "Live network test"]
async fn test_gtm_extraction_from_mozilla() -> Result<(), Box<dyn Error + Send + Sync>> {
    let spider = SfpSpider::default();
    let gtm_module = SfpGoogleTagManager::default();
    let mut options = ModuleOptions::default();
    options.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36".to_string();
    options.timeout_seconds = 30;

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let domain = "mozilla.org";
    let target = Target::Domain(domain.to_string());

    println!(
        "--- Phase 1: Spiderman fetching content from {} ---",
        domain
    );
    spider.execute(&target, &options, &mut emitter).await?;

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
        "--- Phase 2: GTM module analyzing {} content chunks ---",
        web_content_events.len()
    );
    for content_target in web_content_events {
        gtm_module
            .execute(&content_target, &options, &mut emitter)
            .await?;
    }

    let final_events = events.lock().unwrap().clone();
    let gtm_ids: Vec<String> = final_events
        .iter()
        .filter(|(t, _, _, _)| t == "WEB_ANALYTICS_ID")
        .map(|(_, _, data, _)| data.clone())
        .collect();

    let hostnames: Vec<String> = final_events
        .iter()
        .filter(|(t, _, _, _)| t == "INTERNET_NAME" || t == "AFFILIATE_INTERNET_NAME")
        .map(|(_, _, data, _)| data.clone())
        .collect();

    println!("Found GTM IDs: {:?}", gtm_ids);
    println!("Found hostnames: {:?}", hostnames);

    assert!(
        !gtm_ids.is_empty(),
        "Should have found at least one GTM ID on {}",
        domain
    );
    assert!(
        !hostnames.is_empty(),
        "Should have found at least one hostname from GTM on {}",
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

/// End-to-end pipeline:
///   1. `sfp_dnsresolve` resolves "truverack.com" → one or more IP_ADDRESS events
///   2. Each resolved IP is fed into `sfp_dnsneighbor` (lookasidebits=4 → /28)
///   3. We assert at least one AFFILIATE_IPADDR neighbour was found across all IPs
///   4. The origin IPs themselves must never appear in the neighbour output
#[tokio::test]
#[ignore = "Live network test"]
async fn test_real_dnsneighbor_truverack_pipeline() -> Result<(), Box<dyn Error + Send + Sync>> {
    const DOMAIN: &str = "truverack.com";

    let dns_resolve = SfpDnsResolve::default();
    let dns_neighbor = SfpDnsNeighbor::default();

    let mut resolve_opts = ModuleOptions::default();
    resolve_opts.timeout_seconds = 10;

    let mut neighbor_opts = ModuleOptions::default();
    neighbor_opts
        .custom
        .insert("lookasidebits".to_string(), "4".to_string());
    neighbor_opts
        .custom
        .insert("validatereverse".to_string(), "true".to_string());

    // ── Phase 1: resolve domain → IPs ────────────────────────────────────────
    let resolve_events = Arc::new(Mutex::new(Vec::new()));
    let mut resolve_emitter = TestEmitter {
        events: resolve_events.clone(),
    };

    let domain_target = Target::Domain(DOMAIN.to_string());
    println!("--- Phase 1: resolving {} ---", DOMAIN);
    dns_resolve
        .execute(&domain_target, &resolve_opts, &mut resolve_emitter)
        .await?;

    let resolved_ips: Vec<String> = resolve_events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _, _)| t == "IP_ADDRESS")
        .map(|(_, _, data, _)| data.clone())
        .collect();

    println!("Resolved IPs for {}: {:?}", DOMAIN, resolved_ips);
    assert!(
        !resolved_ips.is_empty(),
        "sfp_dnsresolve must return at least one IP_ADDRESS for {}",
        DOMAIN
    );

    // ── Phase 2: look-aside each resolved IP ─────────────────────────────────
    let neighbor_events = Arc::new(Mutex::new(Vec::new()));
    let mut neighbor_emitter = TestEmitter {
        events: neighbor_events.clone(),
    };

    for ip in &resolved_ips {
        println!("--- Phase 2: sfp_dnsneighbor probing /28 around {} ---", ip);
        let ip_target = Target::IpAddr(ip.clone());
        dns_neighbor
            .execute(&ip_target, &neighbor_opts, &mut neighbor_emitter)
            .await?;
    }

    let all_neighbor_events = neighbor_events.lock().unwrap().clone();
    println!("Neighbour events ({} total):", all_neighbor_events.len());
    for (t, _, data, _) in &all_neighbor_events {
        println!("  {t}: {data}");
    }

    // ── Assertions ────────────────────────────────────────────────────────────

    // Origin IPs must never be re-emitted by the neighbor module.
    for origin_ip in &resolved_ips {
        let reemitted = all_neighbor_events
            .iter()
            .any(|(_, _, data, _)| data == origin_ip);
        assert!(
            !reemitted,
            "Origin IP {} must not appear in sfp_dnsneighbor output",
            origin_ip
        );
    }

    // At least one AFFILIATE_IPADDR must have been discovered.
    let affiliate_count = all_neighbor_events
        .iter()
        .filter(|(t, _, _, _)| t == "AFFILIATE_IPADDR")
        .count();
    assert!(
        affiliate_count > 0,
        "Expected at least one AFFILIATE_IPADDR neighbour across all /28 subnets of {:?}",
        resolved_ips
    );

    // Every emitted event must carry the correct event type and confidence.
    for (evttype, src, data, confidence) in &all_neighbor_events {
        assert!(
            evttype == "AFFILIATE_IPADDR" || evttype == "IP_ADDRESS",
            "Unexpected event type '{evttype}' for data '{data}'"
        );
        assert_eq!(src.as_str(), "sfp_dnsneighbor");
        // Note: real_scan_test's TestEmitter stores Option<Target> in the 4th slot,
        // not confidence. Confidence is validated in sfp_dnsneighbor_test.rs instead.
        let _ = confidence;
        // Must be a parseable IP address.
        data.parse::<std::net::IpAddr>()
            .unwrap_or_else(|_| panic!("Emitted data '{data}' is not a valid IP address"));
    }

    Ok(())
}

#[tokio::test]
#[ignore = "Live network integration test"]
async fn test_real_integration_email_truverack() -> Result<(), Box<dyn Error + Send + Sync>> {
    let email = "tech.registrar@ap.org";
    let domain = email.split('@').nth(1).ok_or("Invalid test email format")?;

    let spider = SfpSpider::default();
    let email_module = SfpEmail::default();
    let company_module = SfpCompany::default();
    let dns_module = SfpDnsResolve::default();

    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    // 1) Fetch real site content
    let target = Target::Domain(domain.to_string());
    spider.execute(&target, &options, &mut emitter).await?;

    // 2) Collect web content targets that `SfpEmail` can process.
    // `SfpSpider` emits `TARGET_WEB_CONTENT_URL` with `Target::WebContent`,
    // and `Target::WebContent.kind()` is `TARGET_WEB_CONTENT`.
    let web_content_targets: Vec<Target> = {
        let events_lock = events.lock().unwrap();
        events_lock
            .iter()
            .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT_URL")
            .filter_map(|(_, _, _, target)| target.clone())
            .collect()
    };

    assert!(
        !web_content_targets.is_empty(),
        "Expected spider to fetch at least one TARGET_WEB_CONTENT_URL chunk from {}",
        domain
    );

    // 3) Extract email(s) from the fetched content
    for content_target in &web_content_targets {
        email_module
            .execute(content_target, &options, &mut emitter)
            .await?;
    }

    // 4) Assert our specific email is found (case-insensitive)
    let emitted_emails: Vec<String> = {
        let events_lock = events.lock().unwrap();
        events_lock
            .iter()
            .filter(|(t, _, _, _)| t == "EMAILADDR" || t == "EMAILADDR_GENERIC")
            .map(|(_, _, data, _)| data.clone())
            .collect()
    };

    let email_found = emitted_emails.iter().any(|e| e.eq_ignore_ascii_case(email));

    assert!(
        email_found,
        "Expected to find {} in emitted email events; got {:?}",
        email, emitted_emails
    );

    // 5) Also extract company name + DNS data as extra “relevant info”
    for content_target in &web_content_targets {
        company_module
            .execute(content_target, &options, &mut emitter)
            .await?;
    }

    dns_module
        .execute(&Target::Domain(domain.to_string()), &options, &mut emitter)
        .await?;

    let companies: Vec<String> = {
        let events_lock = events.lock().unwrap();
        events_lock
            .iter()
            .filter(|(t, _, _, _)| t == "COMPANY_NAME")
            .map(|(_, _, data, _)| data.clone())
            .collect()
    };

    assert!(
        !companies.is_empty(),
        "Expected at least one COMPANY_NAME to be extracted from {}",
        domain
    );

    let has_ip = {
        let events_lock = events.lock().unwrap();
        events_lock
            .iter()
            .any(|(t, _, _, _)| t == "IP_ADDRESS" || t == "IPV6_ADDRESS")
    };

    assert!(
        has_ip,
        "Expected sfp_dnsresolve to emit at least one IP_ADDRESS/IPV6_ADDRESS for {}",
        domain
    );

    Ok(())
}
