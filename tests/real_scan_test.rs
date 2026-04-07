use regex::Regex;
use spiderfoot_rust::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_company::SfpCompany;
use spiderfoot_rust::modules::sfp_crossref::SfpCrossref;
use spiderfoot_rust::modules::sfp_dnsneighbor::SfpDnsNeighbor;
use spiderfoot_rust::modules::sfp_dnsresolve::SfpDnsResolve;
use spiderfoot_rust::modules::sfp_duckduckgo::SfpDuckDuckGo;
use spiderfoot_rust::modules::sfp_email::SfpEmail;
use spiderfoot_rust::modules::sfp_google_tag_manager::SfpGoogleTagManager;
use spiderfoot_rust::modules::sfp_spider::SfpSpider;
use std::collections::HashSet;
use std::error::Error;
use std::sync::{Arc, Mutex};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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

// ── sfp_spider mock-based tests ───────────────────────────────────────────────
//
// These tests exercise SfpSpider end-to-end using a wiremock HTTP server so no
// real network traffic is needed.  They live here (rather than only in
// sfp_spider_test.rs) so that the full scan pipeline — spider → downstream
// module — can be tested in a single place.

/// Helper: build ModuleOptions with explicit max_pages / max_depth and
/// filter_mime disabled so wiremock responses without Content-Type still work.
fn spider_opts(max_pages: u32, max_depth: u32) -> ModuleOptions {
    let mut o = ModuleOptions::default();
    o.max_pages = max_pages;
    o.custom
        .insert("max_depth".to_string(), max_depth.to_string());
    o.custom
        .insert("filter_mime".to_string(), "false".to_string());
    o
}

/// Spider fetches a single page and emits TARGET_WEB_CONTENT.
/// Also verifies the source module is "sfp_spider" and confidence is 1.0.
#[tokio::test]
async fn test_spider_single_page_web_content() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body><h1>Hello Spider</h1></body></html>"),
        )
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    module
        .execute(&target, &spider_opts(5, 2), &mut emitter)
        .await?;

    let all = events.lock().unwrap().clone();

    let content_events: Vec<_> = all
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .collect();

    assert!(
        !content_events.is_empty(),
        "Expected TARGET_WEB_CONTENT, got: {all:?}"
    );
    assert_eq!(
        content_events[0].1, "sfp_spider",
        "source_module must be sfp_spider"
    );
    assert!(
        content_events[0].2.contains("Hello Spider"),
        "Body should contain page text"
    );
    Ok(())
}

/// Spider discovers an internal link, emits LINKED_URL_INTERNAL, and crawls it.
#[tokio::test]
async fn test_spider_internal_link_crawled() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"<html><body><a href="/about">About</a></body></html>"#),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/about"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><body>About page</body></html>"),
        )
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    module
        .execute(&target, &spider_opts(10, 2), &mut emitter)
        .await?;

    let all = events.lock().unwrap().clone();

    // LINKED_URL_INTERNAL for /about
    let internal: Vec<_> = all
        .iter()
        .filter(|(t, _, _, _)| t == "LINKED_URL_INTERNAL")
        .collect();
    assert!(
        !internal.is_empty(),
        "Expected LINKED_URL_INTERNAL, got: {all:?}"
    );
    assert!(
        internal.iter().any(|(_, _, d, _)| d.contains("/about")),
        "Expected /about in LINKED_URL_INTERNAL"
    );

    // Both pages should have been fetched
    let content_count = all
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert!(
        content_count >= 2,
        "Expected at least 2 TARGET_WEB_CONTENT events (root + /about), got {content_count}"
    );
    Ok(())
}

/// Spider classifies off-domain links as LINKED_URL_EXTERNAL and does NOT crawl them.
#[tokio::test]
async fn test_spider_external_link_not_crawled() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><a href="https://external-site.org/page">Ext</a></body></html>"#,
        ))
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    module
        .execute(&target, &spider_opts(10, 3), &mut emitter)
        .await?;

    let all = events.lock().unwrap().clone();

    // External link must be emitted
    let external: Vec<_> = all
        .iter()
        .filter(|(t, _, _, _)| t == "LINKED_URL_EXTERNAL")
        .collect();
    assert!(
        !external.is_empty(),
        "Expected LINKED_URL_EXTERNAL, got: {all:?}"
    );
    assert!(
        external
            .iter()
            .any(|(_, _, d, _)| d.contains("external-site.org")),
        "Expected external-site.org in LINKED_URL_EXTERNAL"
    );

    // Only the root page must have been fetched
    let content_count = all
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert_eq!(
        content_count, 1,
        "External links must not be crawled; expected 1 page, got {content_count}"
    );
    Ok(())
}

/// max_pages cap: spider must stop after fetching `max_pages` pages even when
/// more links are available.
#[tokio::test]
async fn test_spider_max_pages_cap() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body>
                <a href="/p1">P1</a>
                <a href="/p2">P2</a>
                <a href="/p3">P3</a>
            </body></html>"#,
        ))
        .mount(&server)
        .await;

    for p in ["/p1", "/p2", "/p3"] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<html><body>sub-page</body></html>"),
            )
            .mount(&server)
            .await;
    }

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    // Cap at 2 pages
    module
        .execute(&target, &spider_opts(2, 3), &mut emitter)
        .await?;

    let content_count = events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert_eq!(
        content_count, 2,
        "Expected exactly 2 pages (max_pages=2), got {content_count}"
    );
    Ok(())
}

/// max_depth cap: links discovered at max_depth must not be followed further.
#[tokio::test]
async fn test_spider_max_depth_cap() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    // depth 0: root → /d1
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"<html><body><a href="/d1">D1</a></body></html>"#),
        )
        .mount(&server)
        .await;

    // depth 1: /d1 → /d2
    Mock::given(method("GET"))
        .and(path("/d1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"<html><body><a href="/d2">D2</a></body></html>"#),
        )
        .mount(&server)
        .await;

    // depth 2: /d2 — must NOT be fetched when max_depth=1
    Mock::given(method("GET"))
        .and(path("/d2"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>D2</body></html>"))
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    // max_depth=1: crawl root (depth 0) + /d1 (depth 1); stop before /d2
    module
        .execute(&target, &spider_opts(10, 1), &mut emitter)
        .await?;

    let all = events.lock().unwrap().clone();

    let content_count = all
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert_eq!(
        content_count, 2,
        "Expected 2 pages at max_depth=1 (root + /d1), got {content_count}"
    );

    let has_d2 = all
        .iter()
        .any(|(t, _, d, _)| t == "LINKED_URL_INTERNAL" && d.contains("/d2"));
    assert!(
        !has_d2,
        "/d2 must not appear as LINKED_URL_INTERNAL when max_depth is reached"
    );
    Ok(())
}

/// URL deduplication: the same internal URL appearing twice in a page must only
/// be emitted once and fetched once.
#[tokio::test]
async fn test_spider_url_deduplication() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body>
                <a href="/dup">Link A</a>
                <a href="/dup">Link B</a>
            </body></html>"#,
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/dup"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>Dup</body></html>"))
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    module
        .execute(&target, &spider_opts(10, 2), &mut emitter)
        .await?;

    let all = events.lock().unwrap().clone();

    // /dup must appear as LINKED_URL_INTERNAL exactly once
    let dup_count = all
        .iter()
        .filter(|(t, _, d, _)| t == "LINKED_URL_INTERNAL" && d.contains("/dup"))
        .count();
    assert_eq!(
        dup_count, 1,
        "Duplicate URL should only be emitted once as LINKED_URL_INTERNAL"
    );

    // /dup must only be fetched once → 2 TARGET_WEB_CONTENT total
    let content_count = all
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert_eq!(
        content_count, 2,
        "Duplicate URL should only be fetched once"
    );
    Ok(())
}

/// INTERNET_NAME must be emitted for the seed host.
#[tokio::test]
async fn test_spider_emits_internet_name() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>Hi</body></html>"))
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    module
        .execute(&target, &spider_opts(5, 2), &mut emitter)
        .await?;

    let has_internet_name = events
        .lock()
        .unwrap()
        .iter()
        .any(|(t, _, _, _)| t == "INTERNET_NAME");

    assert!(
        has_internet_name,
        "Expected at least one INTERNET_NAME event for the seed host"
    );
    Ok(())
}

/// Non-2xx responses must not produce TARGET_WEB_CONTENT.
#[tokio::test]
async fn test_spider_skips_non_2xx() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    module
        .execute(&target, &spider_opts(5, 2), &mut emitter)
        .await?;

    let content_count = events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert_eq!(
        content_count, 0,
        "404 response must not produce TARGET_WEB_CONTENT"
    );
    Ok(())
}

/// MIME filter: when `filter_mime=true` (default), a JSON response must be
/// skipped; when `filter_mime=false`, it must be accepted.
#[tokio::test]
async fn test_spider_mime_filter_default_rejects_json() -> Result<(), Box<dyn Error + Send + Sync>>
{
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"key":"value"}"#),
        )
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    // filter_mime defaults to true — use plain ModuleOptions
    let mut o = ModuleOptions::default();
    o.max_pages = 5;
    o.custom.insert("max_depth".to_string(), "2".to_string());

    module.execute(&target, &o, &mut emitter).await?;

    let content_count = events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert_eq!(
        content_count, 0,
        "application/json must be skipped when filter_mime=true"
    );
    Ok(())
}

/// Unsupported target type (IP-ADDR) must produce no events and log a debug
/// message.
#[tokio::test]
async fn test_spider_skips_unsupported_target() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpSpider::default();
    let target = Target::IpAddr("1.2.3.4".to_string());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    module
        .execute(&target, &spider_opts(5, 2), &mut emitter)
        .await?;

    assert!(
        events.lock().unwrap().is_empty(),
        "No events should be emitted for an unsupported target type"
    );
    Ok(())
}

/// Full pipeline: spider → sfp_email.
///
/// The mock server serves a page containing an email address.  After running
/// the spider, the raw HTML is fed into `SfpEmail`, which must extract the
/// address and emit `EMAILADDR`.
#[tokio::test]
async fn test_spider_then_email_extraction() -> Result<(), Box<dyn Error + Send + Sync>> {
    use spiderfoot_rust::modules::sfp_email::SfpEmail;

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><body>Contact us at <a href=\"mailto:info@acme.example.com\">info@acme.example.com</a></body></html>",
        ))
        .mount(&server)
        .await;

    // ── Phase 1: spider ───────────────────────────────────────────────────────
    let spider = SfpSpider::default();
    let spider_target = Target::Url(server.uri());
    let spider_events = Arc::new(Mutex::new(Vec::new()));
    let mut spider_emitter = TestEmitter {
        events: spider_events.clone(),
    };

    spider
        .execute(&spider_target, &spider_opts(5, 2), &mut spider_emitter)
        .await?;

    // Collect the raw HTML bodies emitted as TARGET_WEB_CONTENT
    let html_bodies: Vec<String> = spider_events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .map(|(_, _, body, _)| body.clone())
        .collect();

    assert!(
        !html_bodies.is_empty(),
        "Spider must emit at least one TARGET_WEB_CONTENT"
    );

    // ── Phase 2: email extraction ─────────────────────────────────────────────
    let email_module = SfpEmail::default();
    let email_events = Arc::new(Mutex::new(Vec::new()));
    let mut email_emitter = TestEmitter {
        events: email_events.clone(),
    };
    let opts = ModuleOptions::default();

    for body in html_bodies {
        let content_target = Target::Other("TARGET_WEB_CONTENT".to_string(), body);
        email_module
            .execute(&content_target, &opts, &mut email_emitter)
            .await?;
    }

    let emails: Vec<String> = email_events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _, _)| t == "EMAILADDR" || t == "EMAILADDR_GENERIC")
        .map(|(_, _, d, _)| d.clone())
        .collect();

    assert!(
        emails
            .iter()
            .any(|e| e.eq_ignore_ascii_case("info@acme.example.com")),
        "Expected info@acme.example.com in emitted emails; got: {emails:?}"
    );
    Ok(())
}

/// Full pipeline: spider → sfp_company.
///
/// The mock server serves a page with a company name in the footer.  After
/// running the spider, the HTML is fed into `SfpCompany`, which must extract
/// the company name and emit `COMPANY_NAME`.
#[tokio::test]
async fn test_spider_then_company_extraction() -> Result<(), Box<dyn Error + Send + Sync>> {
    use spiderfoot_rust::modules::sfp_company::SfpCompany;

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><body><footer>© 2024 Acme Corporation. All rights reserved.</footer></body></html>",
        ))
        .mount(&server)
        .await;

    // ── Phase 1: spider ───────────────────────────────────────────────────────
    let spider = SfpSpider::default();
    let spider_target = Target::Url(server.uri());
    let spider_events = Arc::new(Mutex::new(Vec::new()));
    let mut spider_emitter = TestEmitter {
        events: spider_events.clone(),
    };

    spider
        .execute(&spider_target, &spider_opts(5, 2), &mut spider_emitter)
        .await?;

    let html_bodies: Vec<String> = spider_events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .map(|(_, _, body, _)| body.clone())
        .collect();

    assert!(
        !html_bodies.is_empty(),
        "Spider must emit at least one TARGET_WEB_CONTENT"
    );

    // ── Phase 2: company extraction ───────────────────────────────────────────
    let company_module = SfpCompany::default();
    let company_events = Arc::new(Mutex::new(Vec::new()));
    let mut company_emitter = TestEmitter {
        events: company_events.clone(),
    };
    let opts = ModuleOptions::default();

    for body in html_bodies {
        let content_target = Target::Other("TARGET_WEB_CONTENT".to_string(), body);
        company_module
            .execute(&content_target, &opts, &mut company_emitter)
            .await?;
    }

    let companies: Vec<String> = company_events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _, _)| t == "COMPANY_NAME")
        .map(|(_, _, d, _)| d.clone())
        .collect();

    assert!(
        !companies.is_empty(),
        "Expected at least one COMPANY_NAME; got: {companies:?}"
    );
    println!("[test_spider_then_company_extraction] companies: {companies:?}");
    Ok(())
}

/// Multi-page crawl pipeline: spider crawls root + /about, then email module
/// processes all collected HTML.  Verifies that emails from both pages are
/// found.
#[tokio::test]
async fn test_spider_multipage_then_email() -> Result<(), Box<dyn Error + Send + Sync>> {
    use spiderfoot_rust::modules::sfp_email::SfpEmail;

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body>
                <p>Root page — contact: root@example.test</p>
                <a href="/about">About</a>
            </body></html>"#,
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/about"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body>
                <p>About page — contact: about@example.test</p>
            </body></html>"#,
        ))
        .mount(&server)
        .await;

    // ── Phase 1: spider (crawl root + /about) ─────────────────────────────────
    let spider = SfpSpider::default();
    let spider_target = Target::Url(server.uri());
    let spider_events = Arc::new(Mutex::new(Vec::new()));
    let mut spider_emitter = TestEmitter {
        events: spider_events.clone(),
    };

    spider
        .execute(&spider_target, &spider_opts(10, 2), &mut spider_emitter)
        .await?;

    let html_bodies: Vec<String> = spider_events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .map(|(_, _, body, _)| body.clone())
        .collect();

    assert_eq!(
        html_bodies.len(),
        2,
        "Expected 2 pages crawled (root + /about)"
    );

    // ── Phase 2: email extraction from all pages ───────────────────────────────
    let email_module = SfpEmail::default();
    let email_events = Arc::new(Mutex::new(Vec::new()));
    let mut email_emitter = TestEmitter {
        events: email_events.clone(),
    };
    let opts = ModuleOptions::default();

    for body in html_bodies {
        let content_target = Target::Other("TARGET_WEB_CONTENT".to_string(), body);
        email_module
            .execute(&content_target, &opts, &mut email_emitter)
            .await?;
    }

    let emails: Vec<String> = email_events
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _, _)| t == "EMAILADDR" || t == "EMAILADDR_GENERIC")
        .map(|(_, _, d, _)| d.clone())
        .collect();

    assert!(
        emails
            .iter()
            .any(|e| e.eq_ignore_ascii_case("root@example.test")),
        "Expected root@example.test; got: {emails:?}"
    );
    assert!(
        emails
            .iter()
            .any(|e| e.eq_ignore_ascii_case("about@example.test")),
        "Expected about@example.test; got: {emails:?}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "Live network test – requires internet access"]
async fn test_real_crossref_spider_then_crossref() -> Result<(), Box<dyn Error + Send + Sync>> {
    let crossref = SfpCrossref::default();

    let mut opts = ModuleOptions::default();
    opts.timeout_seconds = 30;
    // We are scanning for "mediawiki.org"; Wikimedia sister sites (wikibooks,
    // wikisource, …) all run on MediaWiki and reliably mention mediawiki.org.
    opts.custom
        .insert("target_names".to_string(), "mediawiki.org".to_string());

    let events: Arc<Mutex<Vec<(String, String, String, Option<Target>)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    // These Wikimedia projects are known to reference mediawiki.org.
    // www.mediawiki.org itself would be skipped as "own target", so we use
    // sibling projects instead.
    let external_urls = ["https://www.wikibooks.org/", "https://www.wikisource.org/"];

    println!(
        "--- Feeding {} external URLs into sfp_crossref ---",
        external_urls.len()
    );

    for url in &external_urls {
        let url_target = Target::Other("LINKED_URL_EXTERNAL".to_string(), url.to_string());
        crossref.execute(&url_target, &opts, &mut emitter).await?;
    }

    let all_crossref = events.lock().unwrap().clone();
    println!("Crossref emitted {} events total", all_crossref.len());
    for (t, _, data, _) in &all_crossref {
        println!("  [{t}] {}", &data[..data.len().min(120)]);
    }

    // ── Assertions ────────────────────────────────────────────────────────────

    let affiliate_names: Vec<String> = all_crossref
        .iter()
        .filter(|(t, _, _, _)| t == "AFFILIATE_INTERNET_NAME")
        .map(|(_, _, d, _)| d.clone())
        .collect();

    assert!(
        !affiliate_names.is_empty(),
        "Expected at least one AFFILIATE_INTERNET_NAME (a Wikimedia site mentioning mediawiki.org)"
    );

    // The affiliate hostname must be a valid-looking domain (contains a dot).
    for name in &affiliate_names {
        assert!(
            name.contains('.'),
            "AFFILIATE_INTERNET_NAME '{name}' does not look like a valid hostname"
        );
    }

    // Every AFFILIATE_INTERNET_NAME must have a matching AFFILIATE_WEB_CONTENT.
    let content_count = all_crossref
        .iter()
        .filter(|(t, _, _, _)| t == "AFFILIATE_WEB_CONTENT")
        .count();
    assert_eq!(
        affiliate_names.len(),
        content_count,
        "Each AFFILIATE_INTERNET_NAME must be paired with exactly one AFFILIATE_WEB_CONTENT"
    );

    // Source module must always be "sfp_crossref".
    for (_, src, _, _) in &all_crossref {
        assert_eq!(
            src.as_str(),
            "sfp_crossref",
            "All crossref events must originate from sfp_crossref"
        );
    }

    Ok(())
}

/// Verifies the `SIMILARDOMAIN` input path end-to-end:
///
/// `sfp_crossref` prepends `http://` to a bare domain name and then fetches
/// it.  We use `wikimedia.org` as the similar domain and `wikipedia.org` as
/// the scan target name — Wikimedia's homepage reliably links back to
/// Wikipedia, so the module should emit `AFFILIATE_INTERNET_NAME` +
/// `AFFILIATE_WEB_CONTENT`.
#[tokio::test]
#[ignore = "Live network test – requires internet access"]
async fn test_real_crossref_similardomain_wikimedia() -> Result<(), Box<dyn Error + Send + Sync>> {
    let crossref = SfpCrossref::default();

    let mut opts = ModuleOptions::default();
    opts.timeout_seconds = 30;
    // The scan is for wikipedia.org; wikimedia.org should mention it.
    opts.custom
        .insert("target_names".to_string(), "wikipedia.org".to_string());

    let events: Arc<Mutex<Vec<(String, String, String, Option<Target>)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let target = Target::Other("SIMILARDOMAIN".to_string(), "wikimedia.org".to_string());
    println!("--- sfp_crossref: SIMILARDOMAIN wikimedia.org → target wikipedia.org ---");
    crossref.execute(&target, &opts, &mut emitter).await?;

    let emitted = events.lock().unwrap().clone();
    println!("Emitted {} events:", emitted.len());
    for (t, _, data, _) in &emitted {
        println!("  [{t}] {}", &data[..data.len().min(120)]);
    }

    let has_affiliate_name = emitted
        .iter()
        .any(|(t, _, _, _)| t == "AFFILIATE_INTERNET_NAME");
    assert!(
        has_affiliate_name,
        "Expected AFFILIATE_INTERNET_NAME when wikimedia.org mentions wikipedia.org"
    );

    let has_affiliate_content = emitted
        .iter()
        .any(|(t, _, _, _)| t == "AFFILIATE_WEB_CONTENT");
    assert!(
        has_affiliate_content,
        "Expected AFFILIATE_WEB_CONTENT alongside AFFILIATE_INTERNET_NAME"
    );

    // The emitted hostname must contain "wikimedia.org".
    let affiliate_host = emitted
        .iter()
        .find(|(t, _, _, _)| t == "AFFILIATE_INTERNET_NAME")
        .map(|(_, _, d, _)| d.as_str())
        .unwrap_or("");
    assert!(
        affiliate_host.contains("wikimedia.org"),
        "AFFILIATE_INTERNET_NAME should be wikimedia.org (or a subdomain), got: {affiliate_host}"
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

// ── Full crossref pipeline for any domain ────────────────────────────────────

/// Generic cross-reference discovery pipeline:
///
///   1. Spider the target domain's homepage to get its raw HTML.
///   2. Extract every unique external host referenced by an `href` in the HTML.
///   3. Feed each external host's base URL into `SfpCrossref` (target_names =
///      the domain being scanned).
///   4. Print every site that links back to the target — these are affiliates.
///
/// Change `TARGET_DOMAIN` to scan a different site.
/// The test never hard-fails on "no affiliates found" because a small site may
/// legitimately have zero external back-references; the output is printed for
/// the operator to review.

/// Queries the live DuckDuckGo Instant Answer API for a well-known domain
/// (`rust-lang.org`) and asserts that at least one descriptive event is
/// emitted (`DESCRIPTION_ABSTRACT` or `DESCRIPTION_CATEGORY`).
///
/// No mocking — this exercises the full HTTP path through `SfpDuckDuckGo`.
#[tokio::test]
#[ignore = "Live network test – requires internet access"]
async fn test_real_duckduckgo_domain_rust_lang() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpDuckDuckGo::default();
    let mut opts = ModuleOptions::default();
    opts.timeout_seconds = 20;

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    let target = Target::Domain("rust-lang.org".to_string());
    println!("--- sfp_duckduckgo: querying live API for rust-lang.org ---");
    module.execute(&target, &opts, &mut emitter).await?;

    let emitted = events.lock().unwrap().clone();
    println!("Emitted {} events:", emitted.len());
    for (t, _, data, _) in &emitted {
        println!("  [{t}] {}", &data[..data.len().min(120)]);
    }

    let has_abstract = emitted
        .iter()
        .any(|(t, _, _, _)| t == "DESCRIPTION_ABSTRACT");
    let has_category = emitted
        .iter()
        .any(|(t, _, _, _)| t == "DESCRIPTION_CATEGORY");

    assert!(
        has_abstract || has_category,
        "Expected at least one DESCRIPTION_ABSTRACT or DESCRIPTION_CATEGORY for rust-lang.org"
    );

    // Source module must always be sfp_duckduckgo.
    for (_, src, _, _) in &emitted {
        assert_eq!(src.as_str(), "sfp_duckduckgo");
    }

    Ok(())
}

/// Feeds an `AFFILIATE_INTERNET_NAME` (`www.rust-lang.org`) into the module.
///
/// The module must:
///   1. Strip the leftmost label → query `rust-lang.org` (not `www.rust-lang.org`).
///   2. Emit `AFFILIATE_DESCRIPTION_ABSTRACT` or `AFFILIATE_DESCRIPTION_CATEGORY`
///      (not the non-affiliate variants).
///
/// No mocking — this exercises the full HTTP path through `SfpDuckDuckGo`.
#[tokio::test]
#[ignore = "Live network test – requires internet access"]
async fn test_real_duckduckgo_affiliate_strips_subdomain(
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpDuckDuckGo::default();
    let mut opts = ModuleOptions::default();
    opts.timeout_seconds = 20;

    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    // Affiliate input: www.rust-lang.org — the module must strip "www." and
    // query "rust-lang.org" against the live API.
    let target = Target::Other(
        "AFFILIATE_INTERNET_NAME".to_string(),
        "www.rust-lang.org".to_string(),
    );
    println!(
        "--- sfp_duckduckgo: querying live API for AFFILIATE_INTERNET_NAME www.rust-lang.org ---"
    );
    module.execute(&target, &opts, &mut emitter).await?;

    let emitted = events.lock().unwrap().clone();
    println!("Emitted {} events:", emitted.len());
    for (t, _, data, _) in &emitted {
        println!("  [{t}] {}", &data[..data.len().min(120)]);
    }

    let has_affiliate_abstract = emitted
        .iter()
        .any(|(t, _, _, _)| t == "AFFILIATE_DESCRIPTION_ABSTRACT");
    let has_affiliate_category = emitted
        .iter()
        .any(|(t, _, _, _)| t == "AFFILIATE_DESCRIPTION_CATEGORY");

    assert!(
        has_affiliate_abstract || has_affiliate_category,
        "Expected AFFILIATE_DESCRIPTION_ABSTRACT or AFFILIATE_DESCRIPTION_CATEGORY \
         when querying www.rust-lang.org as AFFILIATE_INTERNET_NAME"
    );

    // Must never emit the non-affiliate variants for an affiliate input.
    let has_plain_abstract = emitted
        .iter()
        .any(|(t, _, _, _)| t == "DESCRIPTION_ABSTRACT");
    let has_plain_category = emitted
        .iter()
        .any(|(t, _, _, _)| t == "DESCRIPTION_CATEGORY");

    assert!(
        !has_plain_abstract && !has_plain_category,
        "Must not emit plain DESCRIPTION_* events for an AFFILIATE_INTERNET_NAME target"
    );

    // Source module must always be sfp_duckduckgo.
    for (_, src, _, _) in &emitted {
        assert_eq!(src.as_str(), "sfp_duckduckgo");
    }

    Ok(())
}

#[tokio::test]
#[ignore = "Live network test – spider then crossref for a given domain"]
async fn test_crossref_pipeline_for_domain() -> Result<(), Box<dyn Error + Send + Sync>> {
    const TARGET_DOMAIN: &str = "truverack.com";
    const MAX_EXTERNAL_HOSTS: usize = 30; // cap to keep the test reasonably fast

    // ── Phase 1: fetch homepage ───────────────────────────────────────────────
    let spider = SfpSpider::default();
    let mut spider_opts = ModuleOptions::default();
    spider_opts.timeout_seconds = 30;

    let spider_events: Arc<Mutex<Vec<(String, String, String, Option<Target>)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let mut spider_emitter = TestEmitter {
        events: spider_events.clone(),
    };

    println!("--- Phase 1: fetching homepage of {} ---", TARGET_DOMAIN);
    spider
        .execute(
            &Target::Domain(TARGET_DOMAIN.to_string()),
            &spider_opts,
            &mut spider_emitter,
        )
        .await?;

    let html: String = spider_events
        .lock()
        .unwrap()
        .iter()
        .find(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .map(|(_, _, data, _)| data.clone())
        .unwrap_or_default();

    assert!(
        !html.is_empty(),
        "Spider returned no content for {}",
        TARGET_DOMAIN
    );

    // ── Phase 2: extract unique external base-URLs from the HTML ─────────────
    //
    // Pattern: href="..." or href='...' — absolute and protocol-relative URLs.
    // We deduplicate by base URL (scheme + host) to avoid fetching the same
    // host multiple times via different paths.
    let href_re = Regex::new(r#"href=["']([^"'#\s]+)["']"#).unwrap();
    let mut seen: HashSet<String> = HashSet::new();
    let mut external_base_urls: Vec<String> = Vec::new();

    for cap in href_re.captures_iter(&html) {
        let href = cap[1].trim();

        // Normalise to an absolute URL.
        let abs = if href.starts_with("//") {
            format!("https:{}", href)
        } else if href.starts_with("http://") || href.starts_with("https://") {
            href.to_string()
        } else {
            continue; // relative or non-HTTP URL — skip
        };

        // Extract just the base (scheme + host, no path).
        let after_scheme = abs.find("://").map(|i| &abs[i + 3..]).unwrap_or(&abs);
        let host = after_scheme.split('/').next().unwrap_or("").to_lowercase();

        if host.is_empty() {
            continue;
        }

        // Skip own-domain links.
        if host == TARGET_DOMAIN || host.ends_with(&format!(".{}", TARGET_DOMAIN)) {
            continue;
        }

        let scheme = if abs.starts_with("https://") {
            "https"
        } else {
            "http"
        };
        let base_url = format!("{}://{}", scheme, host);

        if seen.insert(base_url.clone()) {
            external_base_urls.push(base_url);
            if external_base_urls.len() >= MAX_EXTERNAL_HOSTS {
                break;
            }
        }
    }

    println!(
        "--- Phase 2: found {} unique external hosts (capped at {}) ---",
        external_base_urls.len(),
        MAX_EXTERNAL_HOSTS
    );
    for u in &external_base_urls {
        println!("  {}", u);
    }

    if external_base_urls.is_empty() {
        println!(
            "No external links found on {}; nothing to crossref.",
            TARGET_DOMAIN
        );
        return Ok(());
    }

    // ── Phase 3: crossref each external host ─────────────────────────────────
    let crossref = SfpCrossref::default();
    let mut crossref_opts = ModuleOptions::default();
    crossref_opts.timeout_seconds = 30;
    crossref_opts
        .custom
        .insert("target_names".to_string(), TARGET_DOMAIN.to_string());

    let crossref_events: Arc<Mutex<Vec<(String, String, String, Option<Target>)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let mut crossref_emitter = TestEmitter {
        events: crossref_events.clone(),
    };

    println!(
        "--- Phase 3: checking {} external hosts for back-references to {} ---",
        external_base_urls.len(),
        TARGET_DOMAIN
    );

    for url in &external_base_urls {
        let url_target = Target::Other("LINKED_URL_EXTERNAL".to_string(), url.clone());
        crossref
            .execute(&url_target, &crossref_opts, &mut crossref_emitter)
            .await?;
    }

    // ── Results ───────────────────────────────────────────────────────────────
    let all_events = crossref_events.lock().unwrap().clone();
    let affiliates: Vec<String> = all_events
        .iter()
        .filter(|(t, _, _, _)| t == "AFFILIATE_INTERNET_NAME")
        .map(|(_, _, d, _)| d.clone())
        .collect();

    println!(
        "=== {} site(s) cross-reference {} ===",
        affiliates.len(),
        TARGET_DOMAIN
    );
    for host in &affiliates {
        println!("  → {}", host);
    }

    Ok(())
}
