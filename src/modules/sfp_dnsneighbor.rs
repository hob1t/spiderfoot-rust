//! # sfp_dnsneighbor — DNS Look-aside
//!
//! Ported from the Python SpiderFoot module `sfp_dnsneighbor`.
//!
//! ## What it does
//! Given an IP address, it computes a small subnet around it (controlled by
//! `lookasidebits`, default 4 → /28 for IPv4, /124 for IPv6), then
//! reverse-resolves every host in that subnet.  Each result that has a valid
//! PTR record (and optionally passes forward-validation) is emitted as
//! `AFFILIATE_IPADDR`.  The origin IP itself is never re-emitted.
//!
//! ## Options (via `ModuleOptions::custom`)
//! | key               | default | description |
//! |-------------------|---------|-------------|
//! | `lookasidebits`   | `"4"`   | CIDR bits to mask off from the host address (1–16 for both IPv4 and IPv6). Capped at 16 to prevent enumerating more than 65 536 hosts. |
//! | `validatereverse` | `"true"`| When `"true"`, a PTR result is only kept if it forward-resolves back to the same IP |
//!
//! ## Concurrency
//! All reverse-lookups (and optional forward-validations) are issued
//! concurrently via `tokio::task::JoinSet`.  A semaphore caps in-flight
//! requests at [`MAX_CONCURRENT_LOOKUPS`].
//!
//! ## Note on resolver lifetime
//! A new `TokioAsyncResolver` is constructed on every `execute()` call.
//! This is acceptable for the current single-module-per-scan usage pattern.
//! TODO: accept a shared resolver via `ModuleOptions` or a dedicated context
//! type to avoid redundant `/etc/resolv.conf` reads in multi-module pipelines.

use crate::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::collections::HashSet;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

// ── constants ─────────────────────────────────────────────────────────────────

/// Maximum number of concurrent DNS lookups per `execute()` call.
const MAX_CONCURRENT_LOOKUPS: usize = 50;

/// Hard cap on the number of hosts enumerated per subnet, regardless of
/// `lookasidebits`.  Prevents accidental OOM when a caller passes a very
/// large value (e.g. `lookasidebits = 32`).
const MAX_HOSTS: u32 = 65_536;

/// Maximum allowed value for `lookasidebits`.  Corresponds to `MAX_HOSTS`.
const MAX_LOOKASIDE_BITS: u8 = 16;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Expand an IPv4 address into every host in the /`prefix_len` subnet it
/// belongs to.  `prefix_len` must be in `[1, 32]`; host count is capped at
/// [`MAX_HOSTS`].
fn ipv4_lookaside_hosts(addr: Ipv4Addr, prefix_len: u8) -> Vec<IpAddr> {
    let prefix_len = prefix_len.clamp(1, 32);
    let mask: u32 = !0u32 << (32 - prefix_len);
    let base = u32::from(addr) & mask;
    let count = ((1u64 << (32 - prefix_len)) as u32).min(MAX_HOSTS);
    (0..count)
        .map(|i| IpAddr::V4(Ipv4Addr::from(base + i)))
        .collect()
}

/// Expand an IPv6 address into every host in the /`prefix_len` subnet.
/// `prefix_len` must be in `[1, 128]`; host count is capped at [`MAX_HOSTS`].
fn ipv6_lookaside_hosts(addr: Ipv6Addr, prefix_len: u8) -> Vec<IpAddr> {
    let prefix_len = prefix_len.clamp(1, 128);
    let mask: u128 = !0u128 << (128 - prefix_len);
    let base = u128::from(addr) & mask;
    let count = ((1u128 << (128 - prefix_len)) as u32).min(MAX_HOSTS);
    (0..count)
        .map(|i| IpAddr::V6(Ipv6Addr::from(base + i as u128)))
        .collect()
}

// ── module ────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct SfpDnsNeighbor;

impl SfpDnsNeighbor {
    /// Parse `lookasidebits` from options and return the effective CIDR prefix
    /// length (= `max_bits − lookasidebits`) for the given address family.
    ///
    /// `lookasidebits` is clamped to `[1, MAX_LOOKASIDE_BITS]` before use so
    /// that the resulting prefix length always leaves at least 1 host bit free
    /// and never exceeds `MAX_HOSTS` hosts.
    fn prefix_len(options: &ModuleOptions, max_bits: u8) -> u8 {
        let bits: u8 = options
            .custom
            .get("lookasidebits")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(4u8);
        let bits = bits.clamp(1, MAX_LOOKASIDE_BITS);
        max_bits - bits
    }

    fn validate_reverse(options: &ModuleOptions) -> bool {
        options
            .custom
            .get("validatereverse")
            .map(|v| v.trim().to_lowercase() != "false")
            .unwrap_or(true)
    }
}

#[async_trait]
impl SpiderfootModule for SfpDnsNeighbor {
    fn name(&self) -> &'static str {
        "sfp_dnsneighbor"
    }

    fn description(&self) -> &'static str {
        "Attempt to reverse-resolve the IP addresses next to your target to see if they are related."
    }

    /// Both IPv4 and IPv6 addresses are carried by `Target::IpAddr`; the
    /// actual address family is determined at parse time inside `execute()`.
    /// `"IPV6-ADDR"` is intentionally absent: `Target::IpAddr.kind()` always
    /// returns `"IP-ADDR"` regardless of address family.
    fn target_types(&self) -> &'static [&'static str] {
        &["IP-ADDR"]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &["AFFILIATE_IPADDR"]
    }

    fn tags(&self) -> &'static [&'static str] {
        &["passive", "recon", "dns"]
    }

    async fn execute(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let kind = target.kind();
        if !self.target_types().contains(&kind) {
            emitter.log(
                LogLevel::Debug,
                &format!(
                    "sfp_dnsneighbor skipping unsupported target: {} ({})",
                    target.value(),
                    kind
                ),
            );
            return Ok(());
        }

        let raw = target.value().trim();
        let origin: IpAddr = match raw.parse() {
            Ok(ip) => ip,
            Err(_) => {
                emitter.log(
                    LogLevel::Error,
                    &format!("sfp_dnsneighbor: invalid IP address: {raw}"),
                );
                return Ok(());
            }
        };

        // TODO: accept a shared resolver via context to avoid re-reading
        // /etc/resolv.conf on every execute() call in multi-module pipelines.
        let resolver = Arc::new(TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        ));

        let validate = Self::validate_reverse(options);

        // Build the list of neighbour IPs to probe (origin excluded later via `seen`).
        let neighbours: Vec<IpAddr> = match origin {
            IpAddr::V4(v4) => {
                let prefix = Self::prefix_len(options, 32);
                ipv4_lookaside_hosts(v4, prefix)
            }
            IpAddr::V6(v6) => {
                let prefix = Self::prefix_len(options, 128);
                ipv6_lookaside_hosts(v6, prefix)
            }
        };

        emitter.log(
            LogLevel::Debug,
            &format!(
                "sfp_dnsneighbor: probing {} neighbours of {}",
                neighbours.len(),
                origin
            ),
        );

        // Candidates to probe: exclude the origin so it is never re-emitted.
        let candidates: Vec<IpAddr> = neighbours.into_iter().filter(|&ip| ip != origin).collect();

        // ── concurrent DNS lookups ────────────────────────────────────────────
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_LOOKUPS));
        let mut join_set: JoinSet<Option<IpAddr>> = JoinSet::new();

        for neighbour in candidates {
            let resolver = Arc::clone(&resolver);
            let sem = Arc::clone(&semaphore);

            join_set.spawn(async move {
                let _permit = sem.acquire().await.ok()?;

                // Reverse-resolve: IP → PTR hostnames.
                let lookup = resolver.reverse_lookup(neighbour).await.ok()?;
                let hostnames: Vec<String> = lookup
                    .iter()
                    .map(|n| {
                        // Strip the trailing dot that hickory appends to FQDN names.
                        n.to_utf8().trim_end_matches('.').to_string()
                    })
                    .filter(|s| !s.is_empty())
                    .collect();

                if hostnames.is_empty() {
                    return None;
                }

                // Optional forward-validation: at least one hostname must
                // resolve back to this neighbour IP.
                if validate {
                    let mut confirmed = false;
                    'outer: for hostname in &hostnames {
                        if let Ok(fwd) = resolver.lookup_ip(hostname.as_str()).await {
                            for ip in fwd.iter() {
                                if ip == neighbour {
                                    confirmed = true;
                                    break 'outer;
                                }
                            }
                        }
                    }
                    if !confirmed {
                        return None;
                    }
                }

                Some(neighbour)
            });
        }

        // Collect results, deduplicate, and emit.
        let mut seen: HashSet<IpAddr> = HashSet::new();
        while let Some(result) = join_set.join_next().await {
            let neighbour = match result {
                Ok(Some(ip)) => ip,
                Ok(None) => continue, // no PTR or failed validation
                Err(e) => {
                    emitter.log(
                        LogLevel::Debug,
                        &format!("sfp_dnsneighbor: task error: {e}"),
                    );
                    continue;
                }
            };

            if !seen.insert(neighbour) {
                continue; // duplicate
            }

            // Every neighbour that reaches this point is, by construction,
            // different from the origin (filtered above), so it is always an
            // affiliate.
            emitter.emit(
                "AFFILIATE_IPADDR",
                self.name(),
                target,
                neighbour.to_string(),
                Some(1.0),
            );

            emitter.log(
                LogLevel::Debug,
                &format!("sfp_dnsneighbor: emitting AFFILIATE_IPADDR {neighbour}"),
            );
        }

        Ok(())
    }
}

// ── unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ipv4_lookaside_hosts ─────────────────────────────────────────────────

    #[test]
    fn test_ipv4_lookaside_default_bits() {
        // lookasidebits=4 → prefix_len=28 → 16 hosts
        let addr: Ipv4Addr = "192.0.2.5".parse().unwrap();
        let hosts = ipv4_lookaside_hosts(addr, 28);
        assert_eq!(hosts.len(), 16);
        // Network address of 192.0.2.5/28 is 192.0.2.0
        assert_eq!(hosts[0], IpAddr::V4("192.0.2.0".parse().unwrap()));
        assert_eq!(hosts[15], IpAddr::V4("192.0.2.15".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_lookaside_single_bit() {
        // lookasidebits=1 → prefix_len=31 → 2 hosts
        let addr: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let hosts = ipv4_lookaside_hosts(addr, 31);
        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains(&IpAddr::V4("10.0.0.0".parse().unwrap())));
        assert!(hosts.contains(&IpAddr::V4("10.0.0.1".parse().unwrap())));
    }

    #[test]
    fn test_ipv4_lookaside_clamps_to_max() {
        // prefix_len=32 → exactly 1 host (the address itself)
        let addr: Ipv4Addr = "1.2.3.4".parse().unwrap();
        let hosts = ipv4_lookaside_hosts(addr, 32);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], IpAddr::V4(addr));
    }

    #[test]
    fn test_ipv4_lookaside_origin_included() {
        let addr: Ipv4Addr = "203.0.113.10".parse().unwrap();
        let hosts = ipv4_lookaside_hosts(addr, 28);
        assert!(hosts.contains(&IpAddr::V4(addr)));
    }

    /// Ensure IPv4 lookaside never exceeds MAX_HOSTS regardless of prefix_len.
    #[test]
    fn test_ipv4_lookaside_cap_at_max_hosts() {
        // prefix_len=1 → 2^31 hosts without the cap; must be capped at MAX_HOSTS
        let addr: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let hosts = ipv4_lookaside_hosts(addr, 1);
        assert_eq!(hosts.len(), MAX_HOSTS as usize);
    }

    // ── ipv6_lookaside_hosts ─────────────────────────────────────────────────

    #[test]
    fn test_ipv6_lookaside_default_bits() {
        // lookasidebits=4 → prefix_len=124 → 16 hosts
        let addr: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let hosts = ipv6_lookaside_hosts(addr, 124);
        assert_eq!(hosts.len(), 16);
    }

    #[test]
    fn test_ipv6_lookaside_cap_at_max_hosts() {
        // prefix_len=112 → 2^16 = 65_536 hosts (cap)
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let hosts = ipv6_lookaside_hosts(addr, 112);
        assert_eq!(hosts.len(), MAX_HOSTS as usize);
    }

    #[test]
    fn test_ipv6_lookaside_origin_included() {
        let addr: Ipv6Addr = "2001:db8::a".parse().unwrap();
        let hosts = ipv6_lookaside_hosts(addr, 124);
        assert!(hosts.contains(&IpAddr::V6(addr)));
    }

    // ── option parsing ───────────────────────────────────────────────────────

    #[test]
    fn test_prefix_len_default() {
        let opts = ModuleOptions::default();
        // default lookasidebits=4, max_bits=32 → prefix_len=28
        assert_eq!(SfpDnsNeighbor::prefix_len(&opts, 32), 28);
    }

    #[test]
    fn test_prefix_len_custom() {
        let mut opts = ModuleOptions::default();
        opts.custom
            .insert("lookasidebits".to_string(), "8".to_string());
        // 32 - 8 = 24
        assert_eq!(SfpDnsNeighbor::prefix_len(&opts, 32), 24);
    }

    #[test]
    fn test_prefix_len_clamped_zero() {
        let mut opts = ModuleOptions::default();
        opts.custom
            .insert("lookasidebits".to_string(), "0".to_string());
        // 0 is clamped to 1 → prefix_len = 31
        assert_eq!(SfpDnsNeighbor::prefix_len(&opts, 32), 31);
    }

    #[test]
    fn test_prefix_len_clamped_over_max_lookaside_bits() {
        let mut opts = ModuleOptions::default();
        opts.custom
            .insert("lookasidebits".to_string(), "99".to_string());
        // 99 is clamped to MAX_LOOKASIDE_BITS (16) → prefix_len = 32 - 16 = 16
        assert_eq!(
            SfpDnsNeighbor::prefix_len(&opts, 32),
            32 - MAX_LOOKASIDE_BITS
        );
    }

    #[test]
    fn test_validate_reverse_default_true() {
        let opts = ModuleOptions::default();
        assert!(SfpDnsNeighbor::validate_reverse(&opts));
    }

    #[test]
    fn test_validate_reverse_explicit_false() {
        let mut opts = ModuleOptions::default();
        opts.custom
            .insert("validatereverse".to_string(), "false".to_string());
        assert!(!SfpDnsNeighbor::validate_reverse(&opts));
    }

    #[test]
    fn test_validate_reverse_explicit_true() {
        let mut opts = ModuleOptions::default();
        opts.custom
            .insert("validatereverse".to_string(), "true".to_string());
        assert!(SfpDnsNeighbor::validate_reverse(&opts));
    }

    // ── module metadata ──────────────────────────────────────────────────────

    #[test]
    fn test_module_metadata() {
        let m = SfpDnsNeighbor;
        assert_eq!(m.name(), "sfp_dnsneighbor");
        // Both IPv4 and IPv6 addresses arrive as Target::IpAddr whose kind() is "IP-ADDR".
        assert!(m.target_types().contains(&"IP-ADDR"));
        assert!(!m.target_types().contains(&"IPV6-ADDR"));
        assert!(m.produced_event_types().contains(&"AFFILIATE_IPADDR"));
        // IP_ADDRESS is no longer produced; every neighbour is an affiliate.
        assert!(!m.produced_event_types().contains(&"IP_ADDRESS"));
    }
}
