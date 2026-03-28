use spiderfoot_rust::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_duckduckgo::{SfpDuckDuckGo, SfpDuckDuckGoOptions};
use wiremock::matchers::method;
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

fn make_module() -> SfpDuckDuckGo {
    SfpDuckDuckGo::with_options(SfpDuckDuckGoOptions::default())
}

async fn run_execute(
    mock_server: &MockServer,
    target: &Target,
    options: &ModuleOptions,
    emitter: &mut RecordingEmitter,
) {
    let mut opts = options.clone();
    opts.custom
        .insert("_test_base_url".to_owned(), mock_server.uri());

    let module = make_module();
    module
        .execute_for_test(target, &opts, emitter)
        .await
        .expect("execute_for_test failed");
}

// ── Pure unit tests (no I/O) ──────────────────────────────────────────────────

#[test]
fn host_domain_strips_single_subdomain() {
    assert_eq!(SfpDuckDuckGo::host_domain("www.example.com"), "example.com");
}

#[test]
fn host_domain_strips_only_leftmost_label() {
    assert_eq!(
        SfpDuckDuckGo::host_domain("sub.sub.example.co.uk"),
        "sub.example.co.uk"
    );
}

#[test]
fn host_domain_passthrough_apex() {
    assert_eq!(SfpDuckDuckGo::host_domain("example.com"), "example.com");
}

#[test]
fn host_domain_passthrough_single_label() {
    assert_eq!(SfpDuckDuckGo::host_domain("localhost"), "localhost");
}

#[test]
fn api_url_base_structure() {
    let url = SfpDuckDuckGo::api_url("example.com");
    assert!(url.starts_with("https://api.duckduckgo.com/"));
    assert!(url.contains("format=json"));
    assert!(url.contains("no_html=1"));
    assert!(url.contains("skip_disambig=1"));
}

#[test]
fn api_url_encodes_spaces() {
    let url = SfpDuckDuckGo::api_url("rust lang");
    assert!(url.contains("rust%20lang"), "expected %20 in: {url}");
}

#[test]
fn api_url_encodes_ampersand() {
    let url = SfpDuckDuckGo::api_url("foo&bar");
    assert!(url.contains("foo%26bar"), "expected %26 in: {url}");
}

#[test]
fn api_url_plain_domain_unmodified() {
    let url = SfpDuckDuckGo::api_url("example.com");
    assert!(url.contains("example.com"), "domain should appear verbatim");
}

#[test]
fn module_name() {
    assert_eq!(make_module().name(), "sfp_duckduckgo");
}

#[test]
fn module_target_types_contains_expected() {
    let m = make_module();
    for kind in &[
        "DOMAIN",
        "DOMAIN_NAME_PARENT",
        "INTERNET_NAME",
        "AFFILIATE_INTERNET_NAME",
    ] {
        assert!(
            m.target_types().contains(kind),
            "missing target type: {kind}"
        );
    }
}

#[test]
fn module_produced_event_types_contains_expected() {
    let m = make_module();
    for evt in &[
        "DESCRIPTION_ABSTRACT",
        "DESCRIPTION_CATEGORY",
        "AFFILIATE_DESCRIPTION_ABSTRACT",
        "AFFILIATE_DESCRIPTION_CATEGORY",
    ] {
        assert!(
            m.produced_event_types().contains(evt),
            "missing produced event type: {evt}"
        );
    }
}

#[test]
fn module_tags_include_passive() {
    assert!(make_module().tags().contains(&"passive"));
}

#[test]
fn options_affiliate_domains_default_true() {
    assert!(SfpDuckDuckGoOptions::default().affiliate_domains);
}

#[test]
fn options_with_options_respects_flag() {
    let m = SfpDuckDuckGo::with_options(SfpDuckDuckGoOptions {
        affiliate_domains: false,
    });
    assert!(!m.opts.affiliate_domains);
}

// ── Async integration tests (mock HTTP via wiremock) ──────────────────────────

#[tokio::test]
async fn no_events_when_heading_empty() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"Heading":"","AbstractText":"","RelatedTopics":[]}"#),
        )
        .mount(&server)
        .await;

    let target = Target::Domain("example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run_execute(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    assert!(
        emitter.events.is_empty(),
        "expected no events, got: {:?}",
        emitter.events
    );
    assert!(
        emitter.has_log_containing("no DuckDuckGo information"),
        "expected a 'no information' debug log"
    );
}

#[tokio::test]
async fn emits_description_abstract_for_domain() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"Heading":"Example Domain","AbstractText":"A domain used in examples.","RelatedTopics":[]}"#,
            ),
        )
        .mount(&server)
        .await;

    let target = Target::Domain("example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run_execute(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    let abstracts = emitter.events_of_type("DESCRIPTION_ABSTRACT");
    assert_eq!(abstracts, vec!["A domain used in examples."]);
}

#[tokio::test]
async fn emits_description_category_for_each_topic() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"Heading":"Example","AbstractText":"","RelatedTopics":[{"Text":"Topic A"},{"Text":"Topic B"}]}"#,
            ),
        )
        .mount(&server)
        .await;

    let target = Target::Domain("example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run_execute(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    let categories = emitter.events_of_type("DESCRIPTION_CATEGORY");
    assert_eq!(categories, vec!["Topic A", "Topic B"]);
}

#[tokio::test]
async fn empty_topic_text_logs_debug_not_event() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"Heading":"X","AbstractText":"","RelatedTopics":[{"Text":""}]}"#,
            ),
        )
        .mount(&server)
        .await;

    let target = Target::Domain("x.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run_execute(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    assert!(
        emitter.events_of_type("DESCRIPTION_CATEGORY").is_empty(),
        "empty topic text must not produce an event"
    );
    assert!(
        emitter.has_log_containing("no category text"),
        "expected debug log for empty topic text"
    );
}

#[tokio::test]
async fn affiliate_target_emits_affiliate_event_types() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"Heading":"Affiliate","AbstractText":"An affiliate abstract.","RelatedTopics":[{"Text":"Affiliate topic"}]}"#,
            ),
        )
        .mount(&server)
        .await;

    let target = Target::Other(
        "AFFILIATE_INTERNET_NAME".to_owned(),
        "sub.affiliate.com".to_owned(),
    );
    let mut emitter = RecordingEmitter::default();
    run_execute(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    assert!(
        !emitter
            .events_of_type("AFFILIATE_DESCRIPTION_ABSTRACT")
            .is_empty(),
        "expected AFFILIATE_DESCRIPTION_ABSTRACT"
    );
    assert!(
        !emitter
            .events_of_type("AFFILIATE_DESCRIPTION_CATEGORY")
            .is_empty(),
        "expected AFFILIATE_DESCRIPTION_CATEGORY"
    );
    assert!(
        emitter.events_of_type("DESCRIPTION_ABSTRACT").is_empty(),
        "must not emit non-affiliate DESCRIPTION_ABSTRACT for affiliate target"
    );
}

#[tokio::test]
async fn affiliate_with_affiliate_domains_queries_parent_domain() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"Heading":"Parent","AbstractText":"desc","RelatedTopics":[]}"#,
            ),
        )
        .mount(&server)
        .await;

    let target = Target::Other(
        "AFFILIATE_INTERNET_NAME".to_owned(),
        "www.affiliate.com".to_owned(),
    );
    let mut opts = ModuleOptions::default();
    opts.custom
        .insert("affiliate_domains".to_owned(), "true".to_owned());

    let mut emitter = RecordingEmitter::default();
    run_execute(&server, &target, &opts, &mut emitter).await;

    assert!(
        emitter.has_log_containing("affiliate.com"),
        "expected log to reference parent domain 'affiliate.com'"
    );
    assert!(
        !emitter.has_log_containing("www.affiliate.com"),
        "www prefix should have been stripped"
    );
}

#[tokio::test]
async fn dedup_skips_second_execute_for_same_query() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"Heading":"X","AbstractText":"desc","RelatedTopics":[]}"#),
        )
        .expect(1)
        .mount(&server)
        .await;

    let module = make_module();
    let target = Target::Domain("example.com".to_owned());
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

#[tokio::test]
async fn http_error_response_logs_and_returns_ok() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let target = Target::Domain("example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run_execute(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    assert!(emitter.events.is_empty());
    assert!(
        emitter.has_log_containing("error") || emitter.has_log_containing("no DuckDuckGo"),
        "expected an error or 'no information' log on HTTP 500"
    );
}

#[tokio::test]
async fn malformed_json_logs_error_and_returns_ok() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
        .mount(&server)
        .await;

    let target = Target::Domain("example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run_execute(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    assert!(emitter.events.is_empty());
    assert!(
        emitter.has_log_containing("error processing JSON"),
        "expected JSON parse error log"
    );
}

#[tokio::test]
async fn unsupported_target_type_is_skipped() {
    let server = MockServer::start().await;

    let target = Target::IpAddr("1.2.3.4".to_owned());
    let mut emitter = RecordingEmitter::default();
    run_execute(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    assert!(emitter.events.is_empty());
    assert!(
        emitter.has_log_containing("skipping unsupported target type"),
        "expected a 'skipping' debug log for IP-ADDR target"
    );
}

#[tokio::test]
async fn emitted_events_have_confidence_one() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"Heading":"H","AbstractText":"abstract","RelatedTopics":[{"Text":"cat"}]}"#,
        ))
        .mount(&server)
        .await;

    let target = Target::Domain("example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run_execute(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    for (_, _, _, confidence) in &emitter.events {
        assert_eq!(
            *confidence,
            Some(1.0),
            "all events should have confidence 1.0"
        );
    }
}

#[tokio::test]
async fn emitted_events_have_correct_source_module() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"Heading":"H","AbstractText":"abstract","RelatedTopics":[]}"#),
        )
        .mount(&server)
        .await;

    let target = Target::Domain("example.com".to_owned());
    let mut emitter = RecordingEmitter::default();
    run_execute(&server, &target, &ModuleOptions::default(), &mut emitter).await;

    for (_, source, _, _) in &emitter.events {
        assert_eq!(source, "sfp_duckduckgo");
    }
}
