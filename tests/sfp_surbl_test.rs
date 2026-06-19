// tests/sfp_surbl_test.rs
//
// Integration + unit tests for SfpSurbl.
// DNS calls are replaced by `dns_override` — no live DNS needed.

#[path = "common/mod.rs"]
mod common;

use common::TestEmitter;
use spiderfoot_rust::core::{ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_surbl::{
    build_lookup_name, ipv4_cidr_hosts, is_listed, is_rejected, prefix_len_from_cidr, reverse_ipv4,
    SfpSurbl,
};
use std::net::Ipv4Addr;

// ── helper ────────────────────────────────────────────────────────────────────

/// Run the module with an optional DNS override.
async fn run(
    module: &SfpSurbl,
    target: &Target,
    options: &ModuleOptions,
    dns_override: Option<Vec<String>>,
) -> TestEmitter {
    let mut emitter = TestEmitter::new();
    module
        .execute_for_test(target, options, &mut emitter, dns_override)
        .await
        .expect("execute_for_test failed");
    emitter
}

/// Shorthand: run with a fresh module and default options.
async fn run_default(target: &Target, dns_override: Option<Vec<String>>) -> TestEmitter {
    run(
        &SfpSurbl::new(),
        target,
        &ModuleOptions::default(),
        dns_override,
    )
    .await
}

fn listed_response() -> Option<Vec<String>> {
    Some(vec!["127.0.0.2".to_owned()])
}

fn rejected_response() -> Option<Vec<String>> {
    Some(vec!["127.0.0.1".to_owned()])
}

fn no_response() -> Option<Vec<String>> {
    Some(vec![])
}

fn events_of_type<'a>(
    emitted: &'a [(String, String, String, Option<f32>)],
    kind: &str,
) -> Vec<&'a str> {
    emitted
        .iter()
        .filter(|(t, _, _, _)| t == kind)
        .map(|(_, _, d, _)| d.as_str())
        .collect()
}

fn has_log_containing(emitter: &TestEmitter, needle: &str) -> bool {
    emitter
        .logs
        .lock()
        .unwrap()
        .iter()
        .any(|(_, msg)| msg.contains(needle))
}

// ═══════════════════════════════════════════════════════════════════════════════
// §7.1  Pure unit tests (no I/O) — helpers already tested inline; these are the
//       external-visibility versions required by the plan.
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn reverse_ipv4_standard() {
    assert_eq!(
        reverse_ipv4("1.2.3.4".parse::<Ipv4Addr>().unwrap()),
        "4.3.2.1"
    );
}

#[test]
fn reverse_ipv4_all_zeros() {
    assert_eq!(
        reverse_ipv4("0.0.0.0".parse::<Ipv4Addr>().unwrap()),
        "0.0.0.0"
    );
}

#[test]
fn reverse_ipv4_all_255() {
    assert_eq!(
        reverse_ipv4("255.255.255.255".parse::<Ipv4Addr>().unwrap()),
        "255.255.255.255"
    );
}

#[test]
fn build_lookup_name_ipv4() {
    assert_eq!(
        build_lookup_name("1.2.3.4"),
        Some("4.3.2.1.multi.surbl.org".to_owned())
    );
}

#[test]
fn build_lookup_name_domain() {
    assert_eq!(
        build_lookup_name("example.com"),
        Some("example.com.multi.surbl.org".to_owned())
    );
}

#[test]
fn build_lookup_name_invalid() {
    assert_eq!(build_lookup_name("notadomain"), None);
    assert_eq!(build_lookup_name(""), None);
}

#[test]
fn is_listed_127_0_0_2() {
    assert!(is_listed("127.0.0.2"));
}

#[test]
fn is_listed_127_0_0_255() {
    assert!(is_listed("127.0.0.255"));
}

#[test]
fn is_listed_127_0_0_1() {
    assert!(!is_listed("127.0.0.1"));
}

#[test]
fn is_listed_non_127() {
    assert!(!is_listed("1.2.3.4"));
}

#[test]
fn is_rejected_127_0_0_1() {
    assert!(is_rejected("127.0.0.1"));
}

#[test]
fn is_rejected_127_0_0_2() {
    assert!(!is_rejected("127.0.0.2"));
}

#[test]
fn ipv4_cidr_hosts_slash_30() {
    assert_eq!(ipv4_cidr_hosts("192.168.1.0/30").unwrap().len(), 4);
}

#[test]
fn ipv4_cidr_hosts_slash_32() {
    let hosts = ipv4_cidr_hosts("10.0.0.1/32").unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0], "10.0.0.1".parse::<Ipv4Addr>().unwrap());
}

#[test]
fn ipv4_cidr_hosts_slash_24() {
    assert_eq!(ipv4_cidr_hosts("10.0.0.0/24").unwrap().len(), 256);
}

#[test]
fn ipv4_cidr_hosts_invalid() {
    assert!(ipv4_cidr_hosts("notacidr").is_err());
}

#[test]
fn prefix_len_from_cidr_24() {
    assert_eq!(prefix_len_from_cidr("192.168.1.0/24"), Some(24));
}

#[test]
fn prefix_len_from_cidr_invalid() {
    assert_eq!(prefix_len_from_cidr("notacidr"), None);
}

// ═══════════════════════════════════════════════════════════════════════════════
// §7.2  Module metadata
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn module_name() {
    assert_eq!(SfpSurbl::new().name(), "sfp_surbl");
}

#[test]
fn module_target_types() {
    let m = SfpSurbl::new();
    for t in &[
        "IP_ADDRESS",
        "AFFILIATE_IPADDR",
        "NETBLOCK_OWNER",
        "NETBLOCK_MEMBER",
        "INTERNET_NAME",
        "AFFILIATE_INTERNET_NAME",
        "CO_HOSTED_SITE",
    ] {
        assert!(m.target_types().contains(t), "missing target type: {t}");
    }
}

#[test]
fn module_produced_event_types() {
    let m = SfpSurbl::new();
    for evt in &[
        "BLACKLISTED_IPADDR",
        "MALICIOUS_IPADDR",
        "BLACKLISTED_AFFILIATE_IPADDR",
        "MALICIOUS_AFFILIATE_IPADDR",
        "BLACKLISTED_NETBLOCK",
        "MALICIOUS_NETBLOCK",
        "BLACKLISTED_SUBNET",
        "MALICIOUS_SUBNET",
        "BLACKLISTED_INTERNET_NAME",
        "MALICIOUS_INTERNET_NAME",
        "BLACKLISTED_AFFILIATE_INTERNET_NAME",
        "MALICIOUS_AFFILIATE_INTERNET_NAME",
        "BLACKLISTED_COHOST",
        "MALICIOUS_COHOST",
    ] {
        assert!(
            m.produced_event_types().contains(evt),
            "missing produced event type: {evt}"
        );
    }
}

#[test]
fn module_tags_include_passive() {
    assert!(SfpSurbl::new().tags().contains(&"passive"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// §7.3  Async integration tests
// ═══════════════════════════════════════════════════════════════════════════════

// ── guards ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn unsupported_target_type_is_skipped() {
    let target = Target::Email("user@example.com".to_owned()); // kind = "EMAIL-ADDR"
    let emitter = run_default(&target, no_response()).await;
    assert!(emitter.emitted().is_empty());
    assert!(
        has_log_containing(&emitter, "skipping unsupported target type"),
        "expected 'skipping unsupported' debug log"
    );
}

#[tokio::test]
async fn empty_target_value_is_skipped() {
    let target = Target::Other("IP_ADDRESS".to_owned(), "   ".to_owned());
    let emitter = run_default(&target, no_response()).await;
    assert!(emitter.emitted().is_empty());
}

// ── dedup ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn dedup_skips_second_call() {
    let module = SfpSurbl::new();
    let target = Target::Other("IP_ADDRESS".to_owned(), "1.2.3.4".to_owned());
    let opts = ModuleOptions::default();

    // First call.
    let mut emitter = TestEmitter::new();
    module
        .execute_for_test(&target, &opts, &mut emitter, no_response())
        .await
        .unwrap();

    // Second call — same value → dedup.
    module
        .execute_for_test(&target, &opts, &mut emitter, no_response())
        .await
        .unwrap();

    assert!(
        has_log_containing(&emitter, "already checked"),
        "expected dedup log on second call"
    );
}

// ── IP_ADDRESS ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ip_address_listed_emits_both_events() {
    let target = Target::Other("IP_ADDRESS".to_owned(), "1.2.3.4".to_owned());
    let emitter = run_default(&target, listed_response()).await;
    let ev = emitter.emitted();
    assert!(
        !events_of_type(&ev, "BLACKLISTED_IPADDR").is_empty(),
        "expected BLACKLISTED_IPADDR"
    );
    assert!(
        !events_of_type(&ev, "MALICIOUS_IPADDR").is_empty(),
        "expected MALICIOUS_IPADDR"
    );
}

#[tokio::test]
async fn ip_address_not_listed_emits_nothing() {
    let target = Target::Other("IP_ADDRESS".to_owned(), "1.2.3.4".to_owned());
    let emitter = run_default(&target, no_response()).await;
    assert!(emitter.emitted().is_empty());
}

// ── AFFILIATE_IPADDR ──────────────────────────────────────────────────────────

#[tokio::test]
async fn affiliate_ip_listed_when_checkaffiliates_true() {
    let target = Target::Other("AFFILIATE_IPADDR".to_owned(), "1.2.3.4".to_owned());
    let emitter = run_default(&target, listed_response()).await;
    let ev = emitter.emitted();
    assert!(
        !events_of_type(&ev, "BLACKLISTED_AFFILIATE_IPADDR").is_empty(),
        "expected BLACKLISTED_AFFILIATE_IPADDR"
    );
}

#[tokio::test]
async fn affiliate_ip_skipped_when_checkaffiliates_false() {
    let target = Target::Other("AFFILIATE_IPADDR".to_owned(), "1.2.3.4".to_owned());
    let mut opts = ModuleOptions::default();
    opts.custom
        .insert("checkaffiliates".to_owned(), "false".to_owned());
    let emitter = run(&SfpSurbl::new(), &target, &opts, listed_response()).await;
    assert!(emitter.emitted().is_empty());
}

// ── INTERNET_NAME ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn internet_name_listed_emits_both_events() {
    let target = Target::Other("INTERNET_NAME".to_owned(), "evil.example.com".to_owned());
    let emitter = run_default(&target, listed_response()).await;
    let ev = emitter.emitted();
    assert!(
        !events_of_type(&ev, "BLACKLISTED_INTERNET_NAME").is_empty(),
        "expected BLACKLISTED_INTERNET_NAME"
    );
    assert!(
        !events_of_type(&ev, "MALICIOUS_INTERNET_NAME").is_empty(),
        "expected MALICIOUS_INTERNET_NAME"
    );
}

// ── AFFILIATE_INTERNET_NAME ───────────────────────────────────────────────────

#[tokio::test]
async fn affiliate_internet_name_listed() {
    let target = Target::Other(
        "AFFILIATE_INTERNET_NAME".to_owned(),
        "evil.example.com".to_owned(),
    );
    let emitter = run_default(&target, listed_response()).await;
    let ev = emitter.emitted();
    assert!(
        !events_of_type(&ev, "BLACKLISTED_AFFILIATE_INTERNET_NAME").is_empty(),
        "expected BLACKLISTED_AFFILIATE_INTERNET_NAME"
    );
}

#[tokio::test]
async fn affiliate_internet_name_skipped_when_flag_false() {
    let target = Target::Other(
        "AFFILIATE_INTERNET_NAME".to_owned(),
        "evil.example.com".to_owned(),
    );
    let mut opts = ModuleOptions::default();
    opts.custom
        .insert("checkaffiliates".to_owned(), "false".to_owned());
    let emitter = run(&SfpSurbl::new(), &target, &opts, listed_response()).await;
    assert!(emitter.emitted().is_empty());
}

// ── CO_HOSTED_SITE ────────────────────────────────────────────────────────────

#[tokio::test]
async fn cohost_listed_when_checkcohosts_true() {
    let target = Target::Other("CO_HOSTED_SITE".to_owned(), "cohost.example.com".to_owned());
    let emitter = run_default(&target, listed_response()).await;
    let ev = emitter.emitted();
    assert!(
        !events_of_type(&ev, "BLACKLISTED_COHOST").is_empty(),
        "expected BLACKLISTED_COHOST"
    );
    assert!(
        !events_of_type(&ev, "MALICIOUS_COHOST").is_empty(),
        "expected MALICIOUS_COHOST"
    );
}

#[tokio::test]
async fn cohost_skipped_when_checkcohosts_false() {
    let target = Target::Other("CO_HOSTED_SITE".to_owned(), "cohost.example.com".to_owned());
    let mut opts = ModuleOptions::default();
    opts.custom
        .insert("checkcohosts".to_owned(), "false".to_owned());
    let emitter = run(&SfpSurbl::new(), &target, &opts, listed_response()).await;
    assert!(emitter.emitted().is_empty());
}

// ── NETBLOCK_OWNER ────────────────────────────────────────────────────────────

#[tokio::test]
async fn netblock_owner_expanded_and_listed() {
    // /30 → 4 IPs; all return 127.0.0.2 → 4×2 = 8 events
    let target = Target::Other("NETBLOCK_OWNER".to_owned(), "192.168.1.0/30".to_owned());
    let emitter = run_default(&target, listed_response()).await;
    let ev = emitter.emitted();
    assert_eq!(
        events_of_type(&ev, "BLACKLISTED_NETBLOCK").len(),
        4,
        "expected 4 BLACKLISTED_NETBLOCK events (one per IP in /30)"
    );
    assert_eq!(
        events_of_type(&ev, "MALICIOUS_NETBLOCK").len(),
        4,
        "expected 4 MALICIOUS_NETBLOCK events"
    );
}

#[tokio::test]
async fn netblock_owner_skipped_when_flag_false() {
    let target = Target::Other("NETBLOCK_OWNER".to_owned(), "192.168.1.0/30".to_owned());
    let mut opts = ModuleOptions::default();
    opts.custom
        .insert("netblocklookup".to_owned(), "false".to_owned());
    let emitter = run(&SfpSurbl::new(), &target, &opts, listed_response()).await;
    assert!(emitter.emitted().is_empty());
}

#[tokio::test]
async fn netblock_owner_too_large_is_skipped() {
    // /16 prefix < maxnetblock(24) → skip
    let target = Target::Other("NETBLOCK_OWNER".to_owned(), "10.0.0.0/16".to_owned());
    let emitter = run_default(&target, listed_response()).await;
    assert!(emitter.emitted().is_empty());
    assert!(
        has_log_containing(&emitter, "larger than"),
        "expected 'larger than' debug log"
    );
}

// ── NETBLOCK_MEMBER ───────────────────────────────────────────────────────────

#[tokio::test]
async fn netblock_member_expanded_and_listed() {
    let target = Target::Other("NETBLOCK_MEMBER".to_owned(), "192.168.2.0/30".to_owned());
    let emitter = run_default(&target, listed_response()).await;
    let ev = emitter.emitted();
    assert_eq!(
        events_of_type(&ev, "BLACKLISTED_SUBNET").len(),
        4,
        "expected 4 BLACKLISTED_SUBNET events"
    );
}

#[tokio::test]
async fn netblock_member_skipped_when_flag_false() {
    let target = Target::Other("NETBLOCK_MEMBER".to_owned(), "192.168.2.0/30".to_owned());
    let mut opts = ModuleOptions::default();
    opts.custom
        .insert("subnetlookup".to_owned(), "false".to_owned());
    let emitter = run(&SfpSurbl::new(), &target, &opts, listed_response()).await;
    assert!(emitter.emitted().is_empty());
}

#[tokio::test]
async fn netblock_member_too_large_is_skipped() {
    let target = Target::Other("NETBLOCK_MEMBER".to_owned(), "10.0.0.0/16".to_owned());
    let emitter = run_default(&target, listed_response()).await;
    assert!(emitter.emitted().is_empty());
    assert!(
        has_log_containing(&emitter, "larger than"),
        "expected 'larger than' debug log"
    );
}

// ── error state ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn rejection_127_0_0_1_sets_error_state() {
    let module = SfpSurbl::new();
    let target = Target::Other("IP_ADDRESS".to_owned(), "1.2.3.4".to_owned());
    let opts = ModuleOptions::default();

    let mut emitter = TestEmitter::new();
    module
        .execute_for_test(&target, &opts, &mut emitter, rejected_response())
        .await
        .unwrap();

    assert!(
        has_log_containing(&emitter, "rate-limited"),
        "expected rate-limited error log"
    );
    // No BLACKLISTED/MALICIOUS events should be emitted for a rejection.
    assert!(emitter.emitted().is_empty());
}

#[tokio::test]
async fn error_state_skips_subsequent_calls() {
    let module = SfpSurbl::new();
    let opts = ModuleOptions::default();

    // First call: triggers rejection.
    let t1 = Target::Other("IP_ADDRESS".to_owned(), "1.2.3.4".to_owned());
    let mut e1 = TestEmitter::new();
    module
        .execute_for_test(&t1, &opts, &mut e1, rejected_response())
        .await
        .unwrap();

    // Second call: different value, but error_state is set.
    let t2 = Target::Other("IP_ADDRESS".to_owned(), "5.6.7.8".to_owned());
    let mut e2 = TestEmitter::new();
    module
        .execute_for_test(&t2, &opts, &mut e2, listed_response())
        .await
        .unwrap();

    assert!(
        has_log_containing(&e2, "error state"),
        "expected 'error state' log on second call"
    );
    assert!(e2.emitted().is_empty());
}

// ── DNS NXDOMAIN (empty response) ────────────────────────────────────────────

#[tokio::test]
async fn dns_nxdomain_emits_nothing() {
    let target = Target::Other("IP_ADDRESS".to_owned(), "1.2.3.4".to_owned());
    let emitter = run_default(&target, no_response()).await;
    assert!(emitter.emitted().is_empty());
}

// ── event quality ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn all_events_have_confidence_one() {
    let target = Target::Other("IP_ADDRESS".to_owned(), "1.2.3.4".to_owned());
    let emitter = run_default(&target, listed_response()).await;
    let ev = emitter.emitted();
    assert!(!ev.is_empty(), "expected at least one event");
    for (_, _, _, confidence) in &ev {
        assert_eq!(
            *confidence,
            Some(1.0),
            "all events must have confidence 1.0"
        );
    }
}

#[tokio::test]
async fn all_events_have_correct_source_module() {
    let target = Target::Other("IP_ADDRESS".to_owned(), "1.2.3.4".to_owned());
    let emitter = run_default(&target, listed_response()).await;
    let ev = emitter.emitted();
    assert!(!ev.is_empty(), "expected at least one event");
    for (_, source, _, _) in &ev {
        assert_eq!(
            source, "sfp_surbl",
            "all events must have source 'sfp_surbl'"
        );
    }
}

#[tokio::test]
async fn event_data_contains_surbl_label() {
    let target = Target::Other("IP_ADDRESS".to_owned(), "1.2.3.4".to_owned());
    let emitter = run_default(&target, listed_response()).await;
    let ev = emitter.emitted();
    assert!(!ev.is_empty(), "expected at least one event");
    for (_, _, data, _) in &ev {
        assert!(
            data.contains("SURBL ["),
            "event data must contain 'SURBL ['; got: {data}"
        );
    }
}
