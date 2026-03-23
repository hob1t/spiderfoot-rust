//! Integration tests for `sfp_dnsneighbor`.
//!
//! The unit tests for pure helper functions live in the module itself
//! (`src/modules/sfp_dnsneighbor.rs`).  These tests exercise the full
//! `execute()` path against real DNS and are gated behind `#[ignore]` so
//! they don't run in offline / CI environments by default.
//!
//! Run them explicitly with:
//!   cargo test --test sfp_dnsneighbor_test -- --include-ignored

#[path = "common/mod.rs"]
mod common;
use common::TestEmitter;

use spiderfoot_rust::core::{LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_dnsneighbor::SfpDnsNeighbor;
use std::error::Error;

// ── unsupported target type ───────────────────────────────────────────────────

#[tokio::test]
async fn test_skips_unsupported_target_type() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpDnsNeighbor::default();
    let options = ModuleOptions::default();
    let mut emitter = TestEmitter::new();

    // DOMAIN is not in target_types() → should be silently skipped
    let target = Target::Domain("example.com".to_string());
    module.execute(&target, &options, &mut emitter).await?;

    assert!(
        emitter.emitted().is_empty(),
        "No events should be emitted for unsupported target type"
    );
    Ok(())
}

// ── invalid IP ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_invalid_ip_logs_error_and_returns_ok() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpDnsNeighbor::default();
    let options = ModuleOptions::default();
    let mut emitter = TestEmitter::new();

    let target = Target::IpAddr("not-an-ip".to_string());
    module.execute(&target, &options, &mut emitter).await?;

    assert!(emitter.emitted().is_empty());
    let logs = emitter.logs.lock().unwrap();
    assert!(
        logs.iter()
            .any(|(lvl, msg)| *lvl == LogLevel::Error && msg.contains("invalid IP")),
        "Expected an error log for an invalid IP"
    );
    Ok(())
}

// ── option: validatereverse = false ──────────────────────────────────────────

#[tokio::test]
async fn test_options_no_validation_accepted() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpDnsNeighbor::default();
    let mut options = ModuleOptions::default();
    options
        .custom
        .insert("validatereverse".to_string(), "false".to_string());
    options
        .custom
        .insert("lookasidebits".to_string(), "1".to_string()); // 2 neighbours only → fast

    let mut emitter = TestEmitter::new();
    // Loopback address — PTR is unlikely to exist, so no events expected,
    // but the module must not panic or return Err.
    let target = Target::IpAddr("127.0.0.1".to_string());
    module.execute(&target, &options, &mut emitter).await?;

    // The origin IP must never appear in the output.
    assert!(
        !emitter.by_data().contains_key("127.0.0.1"),
        "Origin IP must not be re-emitted"
    );
    Ok(())
}

// ── live DNS tests (ignored by default) ──────────────────────────────────────

/// Probe the /28 around 8.8.8.8 (Google Public DNS).
/// Google's DNS servers are densely reverse-mapped, so we expect at least
/// one `AFFILIATE_IPADDR` to come back.
#[tokio::test]
#[ignore = "requires live DNS"]
async fn test_live_google_dns_neighbour() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpDnsNeighbor::default();
    let mut options = ModuleOptions::default();
    // lookasidebits=4 → /28 → 16 hosts around 8.8.8.8
    options
        .custom
        .insert("lookasidebits".to_string(), "4".to_string());
    options
        .custom
        .insert("validatereverse".to_string(), "true".to_string());

    let mut emitter = TestEmitter::new();
    let target = Target::IpAddr("8.8.8.8".to_string());
    module.execute(&target, &options, &mut emitter).await?;

    let events = emitter.emitted();
    println!("Events from 8.8.8.8 lookaside: {events:#?}");

    // The origin itself must never be re-emitted.
    assert!(
        !emitter.by_data().contains_key("8.8.8.8"),
        "Origin IP must not be re-emitted"
    );

    // We expect at least one affiliate neighbour.
    let affiliate_count = events
        .iter()
        .filter(|(t, _, _, _)| t == "AFFILIATE_IPADDR")
        .count();
    assert!(
        affiliate_count > 0,
        "Expected at least one AFFILIATE_IPADDR from 8.8.8.x /28"
    );

    // All emitted IPs must be valid IPv4 addresses and carry confidence=1.0.
    for (_, _, data, confidence) in &events {
        let ip: std::net::IpAddr = data.parse().expect("emitted data must be a valid IP");
        assert!(
            matches!(ip, std::net::IpAddr::V4(_)),
            "Expected IPv4, got {ip}"
        );
        assert_eq!(*confidence, Some(1.0));
    }

    Ok(())
}

/// Probe 1 bit around 1.1.1.1 (Cloudflare) with validation disabled.
/// Even without validation, the origin must not appear in the output.
#[tokio::test]
#[ignore = "requires live DNS"]
async fn test_live_cloudflare_no_validation() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpDnsNeighbor::default();
    let mut options = ModuleOptions::default();
    options
        .custom
        .insert("lookasidebits".to_string(), "1".to_string()); // 2 hosts only
    options
        .custom
        .insert("validatereverse".to_string(), "false".to_string());

    let mut emitter = TestEmitter::new();
    let target = Target::IpAddr("1.1.1.1".to_string());
    module.execute(&target, &options, &mut emitter).await?;

    println!(
        "Events from 1.1.1.1 lookaside (no validate): {:#?}",
        emitter.emitted()
    );

    assert!(
        !emitter.by_data().contains_key("1.1.1.1"),
        "Origin must not be re-emitted"
    );
    Ok(())
}

/// IPv6 smoke test: probe a /124 around a well-known IPv6 address.
#[tokio::test]
#[ignore = "requires live DNS"]
async fn test_live_ipv6_lookaside() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpDnsNeighbor::default();
    let mut options = ModuleOptions::default();
    options
        .custom
        .insert("lookasidebits".to_string(), "4".to_string()); // /124 → 16 hosts
    options
        .custom
        .insert("validatereverse".to_string(), "false".to_string());

    let mut emitter = TestEmitter::new();
    // Google's well-known IPv6 DNS resolver
    let target = Target::IpAddr("2001:4860:4860::8888".to_string());
    module.execute(&target, &options, &mut emitter).await?;

    println!(
        "Events from 2001:4860:4860::8888 lookaside: {:#?}",
        emitter.emitted()
    );

    assert!(
        !emitter.by_data().contains_key("2001:4860:4860::8888"),
        "Origin must not be re-emitted"
    );
    Ok(())
}
