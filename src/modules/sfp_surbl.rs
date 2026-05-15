//! # `sfp_surbl` — SURBL DNS Blacklist lookup
//!
//! Port of the Python SpiderFoot module `sfp_surbl`.
//!
//! Original: <https://github.com/smicallef/spiderfoot/blob/master/modules/sfp_surbl.py>
//!
//! ## What it does
//! Checks IPs, domains, and netblocks against the SURBL DNS-based blacklist
//! (`multi.surbl.org`). Every lookup is a plain DNS A-record query — no HTTP.
//!
//! * IPv4 → octets reversed, appended with `.multi.surbl.org`
//!   (`1.2.3.4` → `4.3.2.1.multi.surbl.org`)
//! * Domain / hostname → prepended directly (`example.com.multi.surbl.org`)
//! * SURBL returns `127.0.0.x` when listed:
//!   - `127.0.0.1` → rate-limited / rejected → set `errorState = true`
//!   - Any other `127.0.0.x` → emit `BLACKLISTED_*` + `MALICIOUS_*` pair
//!
//! ## Target types consumed
//! `IP_ADDRESS`, `AFFILIATE_IPADDR`, `NETBLOCK_OWNER`, `NETBLOCK_MEMBER`,
//! `INTERNET_NAME`, `AFFILIATE_INTERNET_NAME`, `CO_HOSTED_SITE`
//!
//! ## Options (via `ModuleOptions::custom`)
//! | key                | default  | description                                    |
//! |--------------------|----------|------------------------------------------------|
//! | `checkaffiliates`  | `"true"` | Process `AFFILIATE_*` event types              |
//! | `checkcohosts`     | `"true"` | Process `CO_HOSTED_SITE`                       |
//! | `netblocklookup`   | `"true"` | Expand `NETBLOCK_OWNER` CIDRs                  |
//! | `maxnetblock`      | `"24"`   | Skip `NETBLOCK_OWNER` with prefix < this value |
//! | `subnetlookup`     | `"true"` | Expand `NETBLOCK_MEMBER` CIDRs                 |
//! | `maxsubnet`        | `"24"`   | Skip `NETBLOCK_MEMBER` with prefix < this value |

use crate::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use dashmap::DashSet;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::error::Error;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ── constants ─────────────────────────────────────────────────────────────────

const SURBL_SUFFIX: &str = "multi.surbl.org";

// ── pure helper functions ─────────────────────────────────────────────────────

/// Reverse the octets of an IPv4 address.
///
/// `1.2.3.4` → `"4.3.2.1"`
pub fn reverse_ipv4(addr: Ipv4Addr) -> String {
    let octets = addr.octets();
    format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0])
}

/// Build the SURBL DNSBL lookup name for an IPv4 address or domain name.
///
/// Returns `None` when `addr_or_domain` is neither a parseable IPv4 address
/// nor a non-empty string that could be a domain.
pub fn build_lookup_name(addr_or_domain: &str) -> Option<String> {
    let trimmed = addr_or_domain.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Try to parse as IPv4 first.
    if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
        return Some(format!("{}.{}", reverse_ipv4(ip), SURBL_SUFFIX));
    }

    // Treat as a domain / hostname — must contain at least one dot and no
    // spaces (basic sanity guard).
    if trimmed.contains('.') && !trimmed.contains(' ') {
        return Some(format!("{}.{}", trimmed.to_lowercase(), SURBL_SUFFIX));
    }

    None
}

/// Returns `true` when `response_ip` is a SURBL listing indicator.
///
/// SURBL returns `127.0.0.x` for listed entries, **except** `127.0.0.1` which
/// signals a rate-limit / rejection rather than a real listing.
pub fn is_listed(response_ip: &str) -> bool {
    if let Ok(ip) = response_ip.trim().parse::<Ipv4Addr>() {
        let octets = ip.octets();
        return octets[0] == 127 && octets[1] == 0 && octets[2] == 0 && octets[3] >= 2;
    }
    false
}

/// Returns `true` when `response_ip` is `127.0.0.1` (rate-limit / rejection).
pub fn is_rejected(response_ip: &str) -> bool {
    response_ip.trim() == "127.0.0.1"
}

/// Parse the prefix length from a CIDR string.
///
/// `"192.168.1.0/24"` → `Some(24)`
pub fn prefix_len_from_cidr(cidr: &str) -> Option<u8> {
    let slash = cidr.rfind('/')?;
    cidr[slash + 1..].parse::<u8>().ok()
}

/// Expand an IPv4 CIDR block into all host addresses (including network and
/// broadcast addresses, matching Python's `netaddr.IPNetwork` behaviour).
///
/// Returns `Err` when `cidr` cannot be parsed.
pub fn ipv4_cidr_hosts(cidr: &str) -> Result<Vec<Ipv4Addr>, String> {
    let slash = cidr
        .rfind('/')
        .ok_or_else(|| format!("invalid CIDR (no '/'): {cidr}"))?;

    let ip_str = &cidr[..slash];
    let prefix: u8 = cidr[slash + 1..]
        .parse()
        .map_err(|_| format!("invalid prefix length in CIDR: {cidr}"))?;

    if prefix > 32 {
        return Err(format!("prefix length > 32 in CIDR: {cidr}"));
    }

    let base: Ipv4Addr = ip_str
        .parse()
        .map_err(|_| format!("invalid IPv4 address in CIDR: {cidr}"))?;

    let base_u32 = u32::from(base);
    let mask: u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let network = base_u32 & mask;
    let count = 1u64 << (32 - prefix);

    let mut hosts = Vec::with_capacity(count as usize);
    for i in 0..count {
        hosts.push(Ipv4Addr::from(network + i as u32));
    }
    Ok(hosts)
}

// ── module struct ─────────────────────────────────────────────────────────────

/// SURBL DNS blacklist module.
pub struct SfpSurbl {
    resolver: TokioAsyncResolver,
    /// Tracks already-checked values within a scan run.
    seen: Arc<DashSet<String>>,
    /// Set to `true` after a `127.0.0.1` (rate-limit) response.
    error_state: Arc<AtomicBool>,
}

impl SfpSurbl {
    /// Create a new instance with a default DNS resolver.
    #[must_use]
    pub fn new() -> Self {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Self {
            resolver,
            seen: Arc::new(DashSet::new()),
            error_state: Arc::new(AtomicBool::new(false)),
        }
    }

    // ── option helpers ────────────────────────────────────────────────────────

    fn opt_bool(options: &ModuleOptions, key: &str, default: bool) -> bool {
        options
            .custom
            .get(key)
            .map(|v| {
                let s = v.trim().to_lowercase();
                s != "false" && s != "0"
            })
            .unwrap_or(default)
    }

    fn opt_u8(options: &ModuleOptions, key: &str, default: u8) -> u8 {
        options
            .custom
            .get(key)
            .and_then(|v| v.trim().parse::<u8>().ok())
            .unwrap_or(default)
    }

    // ── DNS lookup (real) ─────────────────────────────────────────────────────

    async fn dns_lookup(&self, fqdn: &str) -> Vec<String> {
        match self.resolver.lookup_ip(fqdn).await {
            Ok(resp) => resp
                .iter()
                .filter_map(|addr| {
                    if let std::net::IpAddr::V4(v4) = addr {
                        Some(v4.to_string())
                    } else {
                        None
                    }
                })
                .collect(),
            Err(_) => vec![],
        }
    }

    // ── core per-address check ────────────────────────────────────────────────

    /// Check a single address or domain against SURBL.
    ///
    /// `dns_override` replaces the real DNS call (used in tests).
    /// Returns `(rejected, listed_ips)`.
    async fn check_one(
        &self,
        addr_or_domain: &str,
        dns_override: Option<&[String]>,
    ) -> (bool, Vec<String>) {
        let fqdn = match build_lookup_name(addr_or_domain) {
            Some(f) => f,
            None => return (false, vec![]),
        };

        let answers: Vec<String> = match dns_override {
            Some(ips) => ips.to_vec(),
            None => self.dns_lookup(&fqdn).await,
        };

        let mut rejected = false;
        let mut listed = vec![];

        for ip in &answers {
            if is_rejected(ip) {
                rejected = true;
            } else if is_listed(ip) {
                listed.push(ip.clone());
            }
        }

        (rejected, listed)
    }

    // ── public test entry-point ───────────────────────────────────────────────

    /// Exposed for integration tests.
    ///
    /// `dns_override` replaces every real DNS call with a fixed set of IPs.
    pub async fn execute_for_test<E>(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut E,
        dns_override: Option<Vec<String>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        E: EventEmitter + Send,
    {
        self.execute_inner(target, options, emitter, dns_override.as_deref())
            .await
    }

    // ── core logic ────────────────────────────────────────────────────────────

    async fn execute_inner(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
        dns_override: Option<&[String]>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Bail out immediately if a previous call was rate-limited.
        if self.error_state.load(Ordering::Relaxed) {
            emitter.log(
                LogLevel::Debug,
                "sfp_surbl: module is in error state, skipping",
            );
            return Ok(());
        }

        let kind = target.kind();
        let event_data = target.value().trim().to_string();

        if event_data.is_empty() {
            return Ok(());
        }

        // Deduplication guard.
        if !self.seen.insert(event_data.clone()) {
            emitter.log(
                LogLevel::Debug,
                &format!("sfp_surbl: already checked '{event_data}', skipping"),
            );
            return Ok(());
        }

        // Read options.
        let check_affiliates = Self::opt_bool(options, "checkaffiliates", true);
        let check_cohosts = Self::opt_bool(options, "checkcohosts", true);
        let netblock_lookup = Self::opt_bool(options, "netblocklookup", true);
        let max_netblock = Self::opt_u8(options, "maxnetblock", 24);
        let subnet_lookup = Self::opt_bool(options, "subnetlookup", true);
        let max_subnet = Self::opt_u8(options, "maxsubnet", 24);

        match kind {
            "IP_ADDRESS" => {
                self.check_and_emit(
                    &event_data,
                    "BLACKLISTED_IPADDR",
                    "MALICIOUS_IPADDR",
                    target,
                    emitter,
                    dns_override,
                )
                .await?;
            }

            "AFFILIATE_IPADDR" => {
                if !check_affiliates {
                    emitter.log(
                        LogLevel::Debug,
                        "sfp_surbl: skipping AFFILIATE_IPADDR (checkaffiliates=false)",
                    );
                    return Ok(());
                }
                self.check_and_emit(
                    &event_data,
                    "BLACKLISTED_AFFILIATE_IPADDR",
                    "MALICIOUS_AFFILIATE_IPADDR",
                    target,
                    emitter,
                    dns_override,
                )
                .await?;
            }

            "NETBLOCK_OWNER" => {
                if !netblock_lookup {
                    emitter.log(
                        LogLevel::Debug,
                        "sfp_surbl: skipping NETBLOCK_OWNER (netblocklookup=false)",
                    );
                    return Ok(());
                }
                let prefix = match prefix_len_from_cidr(&event_data) {
                    Some(p) => p,
                    None => {
                        emitter.log(
                            LogLevel::Debug,
                            &format!("sfp_surbl: cannot parse CIDR '{event_data}', skipping"),
                        );
                        return Ok(());
                    }
                };
                if prefix < max_netblock {
                    emitter.log(
                        LogLevel::Debug,
                        &format!(
                            "sfp_surbl: NETBLOCK_OWNER /{prefix} is larger than /{max_netblock}, skipping"
                        ),
                    );
                    return Ok(());
                }
                let hosts = match ipv4_cidr_hosts(&event_data) {
                    Ok(h) => h,
                    Err(e) => {
                        emitter.log(
                            LogLevel::Debug,
                            &format!("sfp_surbl: CIDR expansion error: {e}"),
                        );
                        return Ok(());
                    }
                };
                for ip in hosts {
                    if self.error_state.load(Ordering::Relaxed) {
                        break;
                    }
                    self.check_and_emit(
                        &ip.to_string(),
                        "BLACKLISTED_NETBLOCK",
                        "MALICIOUS_NETBLOCK",
                        target,
                        emitter,
                        dns_override,
                    )
                    .await?;
                }
            }

            "NETBLOCK_MEMBER" => {
                if !subnet_lookup {
                    emitter.log(
                        LogLevel::Debug,
                        "sfp_surbl: skipping NETBLOCK_MEMBER (subnetlookup=false)",
                    );
                    return Ok(());
                }
                let prefix = match prefix_len_from_cidr(&event_data) {
                    Some(p) => p,
                    None => {
                        emitter.log(
                            LogLevel::Debug,
                            &format!("sfp_surbl: cannot parse CIDR '{event_data}', skipping"),
                        );
                        return Ok(());
                    }
                };
                if prefix < max_subnet {
                    emitter.log(
                        LogLevel::Debug,
                        &format!(
                            "sfp_surbl: NETBLOCK_MEMBER /{prefix} is larger than /{max_subnet}, skipping"
                        ),
                    );
                    return Ok(());
                }
                let hosts = match ipv4_cidr_hosts(&event_data) {
                    Ok(h) => h,
                    Err(e) => {
                        emitter.log(
                            LogLevel::Debug,
                            &format!("sfp_surbl: CIDR expansion error: {e}"),
                        );
                        return Ok(());
                    }
                };
                for ip in hosts {
                    if self.error_state.load(Ordering::Relaxed) {
                        break;
                    }
                    self.check_and_emit(
                        &ip.to_string(),
                        "BLACKLISTED_SUBNET",
                        "MALICIOUS_SUBNET",
                        target,
                        emitter,
                        dns_override,
                    )
                    .await?;
                }
            }

            "INTERNET_NAME" => {
                self.check_and_emit(
                    &event_data,
                    "BLACKLISTED_INTERNET_NAME",
                    "MALICIOUS_INTERNET_NAME",
                    target,
                    emitter,
                    dns_override,
                )
                .await?;
            }

            "AFFILIATE_INTERNET_NAME" => {
                if !check_affiliates {
                    emitter.log(
                        LogLevel::Debug,
                        "sfp_surbl: skipping AFFILIATE_INTERNET_NAME (checkaffiliates=false)",
                    );
                    return Ok(());
                }
                self.check_and_emit(
                    &event_data,
                    "BLACKLISTED_AFFILIATE_INTERNET_NAME",
                    "MALICIOUS_AFFILIATE_INTERNET_NAME",
                    target,
                    emitter,
                    dns_override,
                )
                .await?;
            }

            "CO_HOSTED_SITE" => {
                if !check_cohosts {
                    emitter.log(
                        LogLevel::Debug,
                        "sfp_surbl: skipping CO_HOSTED_SITE (checkcohosts=false)",
                    );
                    return Ok(());
                }
                self.check_and_emit(
                    &event_data,
                    "BLACKLISTED_COHOST",
                    "MALICIOUS_COHOST",
                    target,
                    emitter,
                    dns_override,
                )
                .await?;
            }

            other => {
                emitter.log(
                    LogLevel::Debug,
                    &format!(
                        "sfp_surbl: skipping unsupported target type '{other}' (value: {event_data})"
                    ),
                );
            }
        }

        Ok(())
    }

    /// Perform one SURBL check and emit the appropriate event pair.
    async fn check_and_emit(
        &self,
        addr_or_domain: &str,
        blacklisted_type: &str,
        malicious_type: &str,
        target: &Target,
        emitter: &mut (dyn EventEmitter + Send),
        dns_override: Option<&[String]>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (rejected, listed) = self.check_one(addr_or_domain, dns_override).await;

        if rejected {
            emitter.log(
                LogLevel::Error,
                &format!(
                    "sfp_surbl: received 127.0.0.1 for '{addr_or_domain}' — rate-limited by SURBL"
                ),
            );
            self.error_state.store(true, Ordering::Relaxed);
            return Ok(());
        }

        if !listed.is_empty() {
            let data = format!("SURBL [{addr_or_domain}] listed: {}", listed.join(", "));
            emitter.emit(
                blacklisted_type,
                self.name(),
                target,
                data.clone(),
                Some(1.0),
            );
            emitter.emit(malicious_type, self.name(), target, data, Some(1.0));
        }

        Ok(())
    }
}

impl Default for SfpSurbl {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SpiderfootModule for SfpSurbl {
    fn name(&self) -> &'static str {
        "sfp_surbl"
    }

    fn description(&self) -> &'static str {
        "Check IPs and domains against the SURBL DNS-based blacklist."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &[
            "IP_ADDRESS",
            "AFFILIATE_IPADDR",
            "NETBLOCK_OWNER",
            "NETBLOCK_MEMBER",
            "INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME",
            "CO_HOSTED_SITE",
        ]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &[
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
        ]
    }

    fn tags(&self) -> &'static [&'static str] {
        &["passive", "recon", "dnsbl", "free", "no-auth"]
    }

    async fn execute(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.execute_inner(target, options, emitter, None).await
    }
}
