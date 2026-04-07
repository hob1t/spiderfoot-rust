//! Integration tests for `sfp_spider`.
//!
//! All offline/mock tests use `wiremock` to serve controlled HTML pages so
//! no real network traffic is needed.  The live test at the bottom is
//! `#[ignore]` and must be run explicitly.

#[path = "common/mod.rs"]
mod common;
use common::TestEmitter;

use spiderfoot_rust::core::{ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_spider::SfpSpider;
use std::error::Error;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── helpers ───────────────────────────────────────────────────────────────────

fn opts(max_pages: u32, max_depth: u32) -> ModuleOptions {
    let mut o = ModuleOptions::default();
    o.max_pages = max_pages;
    o.custom
        .insert("max_depth".to_string(), max_depth.to_string());
    // Disable MIME filtering so wiremock responses without Content-Type still work.
    o.custom
        .insert("filter_mime".to_string(), "false".to_string());
    o
}

// ── module metadata ───────────────────────────────────────────────────────────

#[test]
fn test_module_name() {
    assert_eq!(SfpSpider::default().name(), "sfp_spider");
}

#[test]
fn test_target_types() {
    let m = SfpSpider::default();
    assert!(m.target_types().contains(&"DOMAIN"));
    assert!(m.target_types().contains(&"URL"));
}

#[test]
fn test_produced_event_types() {
    let m = SfpSpider::default();
    assert!(m.produced_event_types().contains(&"TARGET_WEB_CONTENT"));
    assert!(m.produced_event_types().contains(&"LINKED_URL_INTERNAL"));
    assert!(m.produced_event_types().contains(&"LINKED_URL_EXTERNAL"));
    assert!(m.produced_event_types().contains(&"INTERNET_NAME"));
}

#[test]
fn test_tags() {
    let m = SfpSpider::default();
    assert!(m.tags().contains(&"active"));
    assert!(m.tags().contains(&"crawling"));
}

// ── unsupported target type ───────────────────────────────────────────────────

#[tokio::test]
async fn test_skips_unsupported_target_type() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpSpider::default();
    let opts = ModuleOptions::default();
    let mut emitter = TestEmitter::new();

    // IP-ADDR is not in target_types()
    let target = Target::IpAddr("1.2.3.4".to_string());
    module.execute(&target, &opts, &mut emitter).await?;

    assert!(
        emitter.emitted().is_empty(),
        "Should emit nothing for unsupported target type"
    );

    let logged = emitter
        .logs
        .lock()
        .unwrap()
        .iter()
        .any(|(_, msg)| msg.contains("skipping unsupported target type"));
    assert!(logged, "Expected a debug log about skipping");
    Ok(())
}

// ── single page, no links ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_single_page_emits_web_content() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><body>Hello world</body></html>"),
        )
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let mut emitter = TestEmitter::new();

    module.execute(&target, &opts(5, 2), &mut emitter).await?;

    let events = emitter.emitted();
    let content_events: Vec<_> = events
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .collect();

    assert!(
        !content_events.is_empty(),
        "Expected at least one TARGET_WEB_CONTENT event"
    );
    assert!(
        content_events[0].2.contains("Hello world"),
        "Body should contain page text"
    );
    Ok(())
}

// ── internal link discovery ───────────────────────────────────────────────────

#[tokio::test]
async fn test_internal_links_emitted_and_crawled() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    // Root page links to /about
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"<html><body><a href="/about">About</a></body></html>"#),
        )
        .mount(&server)
        .await;

    // /about page
    Mock::given(method("GET"))
        .and(path("/about"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><body>About page</body></html>"),
        )
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let mut emitter = TestEmitter::new();

    module.execute(&target, &opts(5, 2), &mut emitter).await?;

    let events = emitter.emitted();

    // Should have emitted LINKED_URL_INTERNAL for /about
    let internal: Vec<_> = events
        .iter()
        .filter(|(t, _, _, _)| t == "LINKED_URL_INTERNAL")
        .collect();
    assert!(
        !internal.is_empty(),
        "Expected LINKED_URL_INTERNAL events, got: {events:?}"
    );
    assert!(
        internal
            .iter()
            .any(|(_, _, data, _)| data.contains("/about")),
        "Expected /about in LINKED_URL_INTERNAL"
    );

    // /about should also be crawled → two TARGET_WEB_CONTENT events
    let content_count = events
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert!(
        content_count >= 2,
        "Expected at least 2 TARGET_WEB_CONTENT events (root + /about), got {content_count}"
    );
    Ok(())
}

// ── external link classification ──────────────────────────────────────────────

#[tokio::test]
async fn test_external_links_emitted() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body>
                <a href="https://external.org/page">External</a>
            </body></html>"#,
        ))
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let mut emitter = TestEmitter::new();

    module.execute(&target, &opts(5, 2), &mut emitter).await?;

    let events = emitter.emitted();
    let external: Vec<_> = events
        .iter()
        .filter(|(t, _, _, _)| t == "LINKED_URL_EXTERNAL")
        .collect();

    assert!(!external.is_empty(), "Expected LINKED_URL_EXTERNAL events");
    assert!(
        external
            .iter()
            .any(|(_, _, data, _)| data.contains("external.org")),
        "Expected external.org in LINKED_URL_EXTERNAL"
    );
    Ok(())
}

// ── external links are NOT crawled ───────────────────────────────────────────

#[tokio::test]
async fn test_external_links_not_crawled() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body>
                <a href="https://external.org/page">External</a>
            </body></html>"#,
        ))
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let mut emitter = TestEmitter::new();

    module.execute(&target, &opts(10, 3), &mut emitter).await?;

    // Only the root page should have been fetched → exactly 1 TARGET_WEB_CONTENT
    let content_count = emitter
        .emitted()
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert_eq!(
        content_count, 1,
        "External links must not be crawled; expected 1 page fetched, got {content_count}"
    );
    Ok(())
}

// ── max_pages cap ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_max_pages_respected() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    // Root page links to three sub-pages
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
                ResponseTemplate::new(200).set_body_string("<html><body>page</body></html>"),
            )
            .mount(&server)
            .await;
    }

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let mut emitter = TestEmitter::new();

    // Cap at 2 pages
    module.execute(&target, &opts(2, 3), &mut emitter).await?;

    let content_count = emitter
        .emitted()
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert_eq!(
        content_count, 2,
        "Expected exactly 2 pages to be fetched (max_pages=2), got {content_count}"
    );
    Ok(())
}

// ── max_depth cap ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_max_depth_respected() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    // depth 0: root → links to /d1
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"<html><body><a href="/d1">D1</a></body></html>"#),
        )
        .mount(&server)
        .await;

    // depth 1: /d1 → links to /d2
    Mock::given(method("GET"))
        .and(path("/d1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"<html><body><a href="/d2">D2</a></body></html>"#),
        )
        .mount(&server)
        .await;

    // depth 2: /d2 (should NOT be fetched when max_depth=1)
    Mock::given(method("GET"))
        .and(path("/d2"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><body>D2 page</body></html>"),
        )
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let mut emitter = TestEmitter::new();

    // max_depth=1: crawl root (depth 0) and /d1 (depth 1), but do not follow
    // links on /d1 because depth 1 == max_depth.
    module.execute(&target, &opts(10, 1), &mut emitter).await?;

    let events = emitter.emitted();
    let content_count = events
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();

    // root + /d1 = 2 pages; /d2 must NOT be fetched
    assert_eq!(
        content_count, 2,
        "Expected 2 pages at max_depth=1, got {content_count}"
    );

    // /d2 must not appear in LINKED_URL_INTERNAL (link extraction is skipped at max depth)
    let has_d2_internal = events
        .iter()
        .any(|(t, _, data, _)| t == "LINKED_URL_INTERNAL" && data.contains("/d2"));
    assert!(
        !has_d2_internal,
        "/d2 should not appear as LINKED_URL_INTERNAL when max_depth is reached"
    );
    Ok(())
}

// ── URL deduplication ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_url_deduplication() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    // Root page has two anchors pointing to the same /dup URL
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body>
                <a href="/dup">Link 1</a>
                <a href="/dup">Link 2</a>
            </body></html>"#,
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/dup"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><body>Dup page</body></html>"),
        )
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let mut emitter = TestEmitter::new();

    module.execute(&target, &opts(10, 2), &mut emitter).await?;

    // /dup should appear as LINKED_URL_INTERNAL exactly once
    let dup_internal_count = emitter
        .emitted()
        .iter()
        .filter(|(t, _, data, _)| t == "LINKED_URL_INTERNAL" && data.contains("/dup"))
        .count();
    assert_eq!(
        dup_internal_count, 1,
        "Duplicate URL should only be emitted once as LINKED_URL_INTERNAL"
    );

    // /dup should only be fetched once → 2 TARGET_WEB_CONTENT events total
    let content_count = emitter
        .emitted()
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert_eq!(
        content_count, 2,
        "Duplicate URL should only be fetched once"
    );
    Ok(())
}

// ── external link deduplication ───────────────────────────────────────────────

#[tokio::test]
async fn test_external_link_deduplication() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    // Root page mentions the same external URL twice
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body>
                <a href="https://external.org/page">Ext 1</a>
                <a href="https://external.org/page">Ext 2</a>
            </body></html>"#,
        ))
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let mut emitter = TestEmitter::new();

    module.execute(&target, &opts(5, 2), &mut emitter).await?;

    let ext_count = emitter
        .emitted()
        .iter()
        .filter(|(t, _, data, _)| t == "LINKED_URL_EXTERNAL" && data.contains("external.org/page"))
        .count();
    assert_eq!(
        ext_count, 1,
        "Same external URL should only be emitted once as LINKED_URL_EXTERNAL"
    );
    Ok(())
}

// ── INTERNET_NAME emission ────────────────────────────────────────────────────

#[tokio::test]
async fn test_internet_name_emitted_for_subdomain() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    // Root page links to a sub-domain of the mock server's registered domain.
    // The mock server runs on 127.0.0.1 so we simulate by using a URL target
    // that includes a sub-path link pointing to the same host (same registered
    // domain → INTERNET_NAME should be emitted for the host).
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body>
                <a href="/internal">Internal</a>
            </body></html>"#,
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/internal"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><body>Internal</body></html>"),
        )
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let mut emitter = TestEmitter::new();

    module.execute(&target, &opts(5, 2), &mut emitter).await?;

    // At minimum the seed host itself should be emitted as INTERNET_NAME.
    let internet_names: Vec<_> = emitter
        .emitted()
        .into_iter()
        .filter(|(t, _, _, _)| t == "INTERNET_NAME")
        .collect();

    assert!(
        !internet_names.is_empty(),
        "Expected at least one INTERNET_NAME event"
    );
    Ok(())
}

// ── non-2xx response is skipped ───────────────────────────────────────────────

#[tokio::test]
async fn test_non_2xx_response_skipped() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .mount(&server)
        .await;

    let module = SfpSpider::default();
    let target = Target::Url(server.uri());
    let mut emitter = TestEmitter::new();

    module.execute(&target, &opts(5, 2), &mut emitter).await?;

    let content_count = emitter
        .emitted()
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert_eq!(
        content_count, 0,
        "404 response should not produce TARGET_WEB_CONTENT"
    );
    Ok(())
}

// ── MIME filter ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_mime_filter_skips_non_html() -> Result<(), Box<dyn Error + Send + Sync>> {
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
    let mut emitter = TestEmitter::new();

    // Use default opts (filter_mime=true)
    let mut o = ModuleOptions::default();
    o.max_pages = 5;
    o.custom.insert("max_depth".to_string(), "2".to_string());
    // filter_mime defaults to true

    module.execute(&target, &o, &mut emitter).await?;

    let content_count = emitter
        .emitted()
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert_eq!(
        content_count, 0,
        "application/json should be filtered out when filter_mime=true"
    );
    Ok(())
}

#[tokio::test]
async fn test_mime_filter_disabled_accepts_non_html() -> Result<(), Box<dyn Error + Send + Sync>> {
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
    let mut emitter = TestEmitter::new();

    // filter_mime=false → should accept any content type
    module.execute(&target, &opts(5, 2), &mut emitter).await?;

    let content_count = emitter
        .emitted()
        .iter()
        .filter(|(t, _, _, _)| t == "TARGET_WEB_CONTENT")
        .count();
    assert_eq!(
        content_count, 1,
        "With filter_mime=false, JSON body should still produce TARGET_WEB_CONTENT"
    );
    Ok(())
}

// ── DOMAIN target variant ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_domain_target_builds_https_seed() -> Result<(), Box<dyn Error + Send + Sync>> {
    // We can't easily mock HTTPS on a local server, so we verify the logic
    // indirectly: a DOMAIN target for a non-resolving host should log the
    // fetch error (no panic, no unwrap failure) and return Ok(()).
    let module = SfpSpider::default();
    let target = Target::Domain("this-domain-does-not-exist-xyzzy-99.invalid".to_string());
    let mut emitter = TestEmitter::new();

    let mut o = ModuleOptions::default();
    o.max_pages = 1;
    o.timeout_seconds = 3;

    let result = module.execute(&target, &o, &mut emitter).await;
    assert!(
        result.is_ok(),
        "execute() must not return Err for unreachable hosts"
    );
    Ok(())
}

// ── live network test (ignored in CI) ────────────────────────────────────────

/// End-to-end crawl of `example.com`.  Verifies that the spider fetches at
/// least one page and emits `TARGET_WEB_CONTENT`.
#[tokio::test]
#[ignore = "live network test – requires internet access, run with: cargo test -- --ignored"]
async fn live_spider_example_com() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpSpider::default();
    let target = Target::Domain("example.com".to_string());
    let mut emitter = TestEmitter::new();

    let mut o = ModuleOptions::default();
    o.max_pages = 3;
    o.timeout_seconds = 30;
    o.custom.insert("max_depth".to_string(), "2".to_string());

    module.execute(&target, &o, &mut emitter).await?;

    let events = emitter.emitted();
    println!("[live] emitted {} events", events.len());
    for (etype, _, data, _) in &events {
        println!("  [{etype}] {}", &data[..data.len().min(80)]);
    }

    let has_content = events.iter().any(|(t, _, _, _)| t == "TARGET_WEB_CONTENT");
    assert!(has_content, "Expected at least one TARGET_WEB_CONTENT");
    Ok(())
}
