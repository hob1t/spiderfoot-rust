// tests/sfp_urlscan_test.rs
//
// Integration tests for SfpUrlscan — all HTTP calls are intercepted by a
// wiremock server so no real network traffic is needed.

use spiderfoot_rust::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_urlscan::{
    domain_matches, is_domain, search_url, url_fqdn, SfpUrlscan,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Test double ───────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct RecordingEmitter {
    events: Vec<(String, String, String, Option<f32>)>, // (type, source, data, confidence)
    logs: Vec<(LogLevel, String)>,
}

impl EventEmitter for RecordingEmitter {
    fn emit(
        &mut self,
        event_type: &str,
        source_module: &str,
        _target: &Target,
        data: String,
        confidence: Option<f32>,
    ) {
        self.events.push((
            event_type.to_owned(),
            source_module.to_owned(),
            data,
            confidence,
        ));
    }

    fn log(&mut self, level: LogLevel, message: &str) {
        self.logs.push((level, message.to_owned()));
    }
}

impl RecordingEmitter {
    fn events_of_type(&self, kind: &str) -> Vec<&str> {
        self.events
            .iter()
            .filter(|(t, _, _, _)| t == kind)
            .map(|(_, _, d, _)| d.as_str())
            .collect()
    }

    fn has_log_containing(&self, needle: &str) -> bool {
        self.logs.iter().any(|(_, msg)| msg.contains(needle))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Run the module against a wiremock server, injecting `_test_base_url`.
async fn run(
    server: &MockServer,
    target: &Target,
    options: &ModuleOptions,
    emitter: &mut RecordingEmitter,
) {
    let mut opts = options.clone();
    opts.custom
        .insert("_test_base_url".to_owned(), server.uri());

    SfpUrlscan::new()
        .execute_for_test(target, &opts, emitter)
        .await
        .expect("execute_for_test failed");
}

/// Minimal JSON response with one result whose domain matches `domain`.
fn one_result_json(domain: &str, task_url: &str) -> String {
    format!(
        r#"{{"results":[{{"page":{{"domain":"{domain}","asn":"","city":"","country":"","server":""}},"task":{{"url":"{task_url}"}}}}]}}"#
    )
}

/// Full result JSON with all fields populated.
fn full_result_json(
    domain: &str,
    asn: &str,
    city: &str,
    country: &str,
    server: &str,
    task_url: &str,
) -> String {
    format!(
        r#"{{"results":[{{"page":{{"domain":"{domain}","asn":"{asn}","city":"{city}","country":"{country}","server":"{server}"}},"task":{{"url":"{task_url}"}}}}]}}"#
    )
}

// ═════════════════════════════════════════════════════════════════════════════
// ── 1. Pure unit tests: url_fqdn ─────────────────────────────────────────────
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn url_fqdn_valid_url() {
    assert_eq!(
        url_fqdn("https://www.example.com/path?q=1"),
        Some("www.example.com".to_owned())
    );
}

#[test]
fn url_fqdn_invalid_url() {
    assert_eq!(url_fqdn("not a url at all"), None);
}

#[test]
fn url_fqdn_no_host() {
    // data: URIs have no host component.
    assert_eq!(url_fqdn("data:text/plain,hello"), None);
}

// ═════════════════════════════════════════════════════════════════════════════
// ── 2. Pure unit tests: domain_matches ───────────────────────────────────────
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn domain_matches_exact() {
    assert!(domain_matches("example.com", "example.com"));
}

#[test]
fn domain_matches_subdomain() {
    assert!(domain_matches("sub.example.com", "example.com"));
}

#[test]
fn domain_matches_parent() {
    // target is a sub-domain of host → should still match (includeParents=true)
    assert!(domain_matches("example.com", "sub.example.com"));
}

#[test]
fn domain_matches_no_cross() {
    assert!(!domain_matches("evil.com", "example.com"));
}

#[test]
fn domain_matches_bare_tld() {
    // A bare TLD must never match every domain under it.
    assert!(!domain_matches("com", "example.com"));
}

// ═════════════════════════════════════════════════════════════════════════════
// ── 3. Pure unit tests: is_domain ────────────────────────────────────────────
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn is_domain_apex() {
    assert!(is_domain("example.com"));
}

#[test]
fn is_domain_subdomain() {
    // A subdomain is NOT a registrable domain.
    assert!(!is_domain("sub.example.com"));
}

#[test]
fn is_domain_invalid() {
    assert!(!is_domain("not_a_domain_at_all"));
}

// ═════════════════════════════════════════════════════════════════════════════
// ── 4. Pure unit tests: search_url ───────────────────────────────────────────
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn search_url_encodes_query() {
    let url = search_url("https://urlscan.io", "domain:foo.com");
    // The colon must be percent-encoded.
    assert!(
        url.contains("domain%3Afoo.com"),
        "expected percent-encoded colon; got: {url}"
    );
}

#[test]
fn search_url_trims_trailing_slash() {
    let with_slash = search_url("https://urlscan.io/", "domain:x.com");
    let without_slash = search_url("https://urlscan.io", "domain:x.com");
    assert_eq!(with_slash, without_slash);
}

// ═════════════════════════════════════════════════════════════════════════════
// ── 5. Module metadata ───────────────────────────────────────────────────────
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn module_name_is_sfp_urlscan() {
    assert_eq!(SfpUrlscan::new().name(), "sfp_urlscan");
}

#[test]
fn module_target_types_contains_internet_name() {
    assert!(SfpUrlscan::new().target_types().contains(&"INTERNET_NAME"));
}

#[test]
fn module_produced_event_types_are_complete() {
    let m = SfpUrlscan::new();
    for evt in &[
        "RAW_RIR_DATA",
        "LINKED_URL_INTERNAL",
        "GEOINFO",
        "INTERNET_NAME",
        "INTERNET_NAME_UNRESOLVED",
        "DOMAIN_NAME",
        "BGP_AS_MEMBER",
        "WEBSERVER_BANNER",
    ] {
        assert!(
            m.produced_event_types().contains(evt),
            "missing produced event type: {evt}"
        );
    }
}

#[test]
fn module_tags_include_passive() {
    assert!(SfpUrlscan::new().tags().contains(&"passive"));
}

// ═════════════════════════════════════════════════════════════════════════════
// ── 6. Async integration tests (mock HTTP via wiremock) ───────────────────────
// ═════════════════════════════════════════════════════════════════════════════

// ── 6.1 Target-type / value guards ───────────────────────────────────────────

#[tokio::test]
async fn unsupported_target_type_is_skipped() {
    let server = MockServer::start().await;
    // No mock registered — any HTTP call would panic.

    let target = Target::IpAddr("1.2.3.4".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    assert!(emitter.events.is_empty());
    assert!(
        emitter.has_log_containing("skipping unsupported target type"),
        "expected a 'skipping' debug log for IP target"
    );
}

#[tokio::test]
async fn empty_target_value_is_skipped() {
    let server = MockServer::start().await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "   ".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    assert!(emitter.events.is_empty());
}

// ── 6.2 Deduplication ────────────────────────────────────────────────────────

#[tokio::test]
async fn dedup_skips_second_call() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"results":[]}"#))
        .expect(1) // exactly one HTTP request
        .mount(&server)
        .await;

    let module = SfpUrlscan::new();
    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut opts = ModuleOptions::default();
    opts.custom
        .insert("_test_base_url".to_owned(), server.uri());

    let mut emitter = RecordingEmitter::default();

    module
        .execute_for_test(&target, &opts, &mut emitter)
        .await
        .unwrap();

    module
        .execute_for_test(&target, &opts, &mut emitter)
        .await
        .unwrap();

    assert!(
        emitter.has_log_containing("already checked"),
        "expected dedup log on second call"
    );
}

// ── 6.3 Empty results ────────────────────────────────────────────────────────

#[tokio::test]
async fn no_results_logs_info() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"results":[]}"#))
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    assert!(emitter.events.is_empty());
    assert!(
        emitter.has_log_containing("no results"),
        "expected an info log when results are empty"
    );
}

// ── 6.4 RAW_RIR_DATA ─────────────────────────────────────────────────────────

#[tokio::test]
async fn emits_raw_rir_data() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(one_result_json("example.com", "https://example.com/")),
        )
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    assert_eq!(
        emitter.events_of_type("RAW_RIR_DATA").len(),
        1,
        "RAW_RIR_DATA must be emitted exactly once"
    );
}

// ── 6.5 LINKED_URL_INTERNAL ──────────────────────────────────────────────────

#[tokio::test]
async fn emits_linked_url_internal() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(one_result_json("example.com", "https://example.com/page")),
        )
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    let urls = emitter.events_of_type("LINKED_URL_INTERNAL");
    assert!(
        urls.iter().any(|u| u.contains("example.com")),
        "expected LINKED_URL_INTERNAL containing example.com; got: {urls:?}"
    );
}

// ── 6.6 GEOINFO ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn emits_geoinfo() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(full_result_json(
            "example.com",
            "",
            "Amsterdam",
            "NL",
            "",
            "https://example.com/",
        )))
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    let geoinfo = emitter.events_of_type("GEOINFO");
    assert!(
        geoinfo
            .iter()
            .any(|g| g.contains("Amsterdam") && g.contains("NL")),
        "expected GEOINFO with city and country; got: {geoinfo:?}"
    );
}

// ── 6.7 BGP_AS_MEMBER (strips "AS" prefix) ───────────────────────────────────

#[tokio::test]
async fn emits_bgp_as_member_strips_as_prefix() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(full_result_json(
            "example.com",
            "AS12345",
            "",
            "",
            "",
            "https://example.com/",
        )))
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    let asns = emitter.events_of_type("BGP_AS_MEMBER");
    assert!(
        asns.contains(&"12345"),
        "expected BGP_AS_MEMBER '12345' (without 'AS' prefix); got: {asns:?}"
    );
    assert!(
        !asns.contains(&"AS12345"),
        "BGP_AS_MEMBER must not include the 'AS' prefix"
    );
}

// ── 6.8 WEBSERVER_BANNER ─────────────────────────────────────────────────────

#[tokio::test]
async fn emits_webserver_banner() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(full_result_json(
            "example.com",
            "",
            "",
            "",
            "nginx/1.24",
            "https://example.com/",
        )))
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    let banners = emitter.events_of_type("WEBSERVER_BANNER");
    assert!(
        banners.contains(&"nginx/1.24"),
        "expected WEBSERVER_BANNER 'nginx/1.24'; got: {banners:?}"
    );
}

// ── 6.9 INTERNET_NAME when verify=false ──────────────────────────────────────

#[tokio::test]
async fn emits_internet_name_when_verify_false() {
    let server = MockServer::start().await;

    // sub.example.com is a sub-domain → domain_matches passes → collected in `domains`.
    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(one_result_json(
            "sub.example.com",
            "https://sub.example.com/",
        )))
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut opts = ModuleOptions::default();
    opts.custom.insert("verify".to_owned(), "false".to_owned());

    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &opts, &mut emitter).await;

    let names = emitter.events_of_type("INTERNET_NAME");
    assert!(
        names.contains(&"sub.example.com"),
        "expected INTERNET_NAME for sub.example.com; got: {names:?}"
    );
}

// ── 6.10 DOMAIN_NAME for registrable domain ──────────────────────────────────

#[tokio::test]
async fn emits_domain_name_for_registrable() {
    let server = MockServer::start().await;

    // The page domain is a sub-domain that is itself a registrable domain
    // (e.g. "sub.example.com" is not, but "otherexample.com" would be).
    // We use a domain that is both a sub-domain of the target AND a registrable
    // domain to exercise the DOMAIN_NAME branch.
    // Use target = "sub.example.com" and page domain = "example.com" so that
    // domain_matches("example.com", "sub.example.com") is true (parent match)
    // and is_domain("example.com") is true.
    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(one_result_json("example.com", "https://example.com/")),
        )
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "sub.example.com".to_owned());
    let mut opts = ModuleOptions::default();
    opts.custom.insert("verify".to_owned(), "false".to_owned());

    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &opts, &mut emitter).await;

    let domains = emitter.events_of_type("DOMAIN_NAME");
    assert!(
        domains.contains(&"example.com"),
        "expected DOMAIN_NAME for example.com; got: {domains:?}"
    );
}

// ── 6.11 Rate-limit (HTTP 429) sets error state ──────────────────────────────

#[tokio::test]
async fn rate_limit_429_sets_error_state() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;

    let module = SfpUrlscan::new();
    let mut opts = ModuleOptions::default();
    opts.custom
        .insert("_test_base_url".to_owned(), server.uri());

    // First call — hits 429 and sets error_state.
    let target1 = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    module
        .execute_for_test(&target1, &opts, &mut emitter)
        .await
        .unwrap();

    assert!(
        emitter.has_log_containing("rate-limited"),
        "expected rate-limit log on 429"
    );

    // Second call — different domain but error_state is set → skipped immediately.
    let target2 = Target::Other("INTERNET_NAME".to_owned(), "other.com".to_owned());
    let mut emitter2 = RecordingEmitter::default();
    module
        .execute_for_test(&target2, &opts, &mut emitter2)
        .await
        .unwrap();

    assert!(
        emitter2.has_log_containing("error state"),
        "expected 'error state' log on subsequent call after 429"
    );
    assert!(emitter2.events.is_empty());
}

// ── 6.12 HTTP 500 error ───────────────────────────────────────────────────────

#[tokio::test]
async fn http_error_logs_and_returns_ok() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    assert!(emitter.events.is_empty());
    assert!(
        emitter.has_log_containing("HTTP 500"),
        "expected HTTP 500 error log"
    );
}

// ── 6.13 Malformed JSON ───────────────────────────────────────────────────────

#[tokio::test]
async fn malformed_json_logs_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    assert!(emitter.events.is_empty());
    assert!(
        emitter.has_log_containing("error processing JSON"),
        "expected JSON parse error log"
    );
}

// ── 6.14 Domain outside target is filtered ───────────────────────────────────

#[tokio::test]
async fn domain_outside_target_is_filtered() {
    let server = MockServer::start().await;

    // Page domain "evil.com" does not match target "example.com".
    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(one_result_json("evil.com", "https://evil.com/")),
        )
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    // RAW_RIR_DATA is emitted (results array is non-empty) but no domain-specific events.
    assert!(
        emitter.events_of_type("LINKED_URL_INTERNAL").is_empty(),
        "must not emit LINKED_URL_INTERNAL for external domain"
    );
    assert!(
        emitter.events_of_type("INTERNET_NAME").is_empty(),
        "must not emit INTERNET_NAME for external domain"
    );
    assert!(
        emitter.events_of_type("BGP_AS_MEMBER").is_empty(),
        "must not emit BGP_AS_MEMBER for external domain"
    );
}

// ── 6.15 All events have confidence = 1.0 ────────────────────────────────────

#[tokio::test]
async fn all_emitted_events_have_confidence_one() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(full_result_json(
            "example.com",
            "AS1234",
            "Berlin",
            "DE",
            "Apache",
            "https://example.com/",
        )))
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut opts = ModuleOptions::default();
    opts.custom.insert("verify".to_owned(), "false".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &opts, &mut emitter).await;

    assert!(!emitter.events.is_empty(), "expected at least one event");

    for (_, _, _, confidence) in &emitter.events {
        assert_eq!(
            *confidence,
            Some(1.0),
            "all events must have confidence 1.0"
        );
    }
}

// ── 6.16 All events have source_module = "sfp_urlscan" ───────────────────────

#[tokio::test]
async fn all_emitted_events_have_correct_source_module() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/search/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(full_result_json(
            "example.com",
            "AS999",
            "Paris",
            "FR",
            "nginx",
            "https://example.com/",
        )))
        .mount(&server)
        .await;

    let target = Target::Other("INTERNET_NAME".to_owned(), "example.com".to_owned());
    let mut opts = ModuleOptions::default();
    opts.custom.insert("verify".to_owned(), "false".to_owned());
    let mut emitter = RecordingEmitter::default();
    run(&server, &target, &opts, &mut emitter).await;

    assert!(!emitter.events.is_empty(), "expected at least one event");

    for (_, source, _, _) in &emitter.events {
        assert_eq!(
            source, "sfp_urlscan",
            "all events must have source 'sfp_urlscan'"
        );
    }
}
