//! # `sfp_stevenblack_hosts` — Steven Black Hosts
//!
//! Port of the Python SpiderFoot module `sfp_stevenblack_hosts`.
//!
//! Original: <https://github.com/smicallef/spiderfoot/blob/master/modules/sfp_stevenblack_hosts.py>
//!
//! ## What it does
//! Checks if a domain is malicious (malware or adware) according to Steven Black Hosts list.
//! The module fetches the hosts file from `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`
//! and caches it for 24 hours (configurable).
//!
//! ## Target types consumed
//! `INTERNET_NAME`, `AFFILIATE_INTERNET_NAME`, `CO_HOSTED_SITE`
//!
//! ## Events produced
//! `MALICIOUS_INTERNET_NAME`, `BLACKLISTED_INTERNET_NAME`,
//! `MALICIOUS_AFFILIATE_INTERNET_NAME`, `BLACKLISTED_AFFILIATE_INTERNET_NAME`,
//! `MALICIOUS_COHOST`, `BLACKLISTED_COHOST`

use crate::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use dashmap::DashSet;
use reqwest::Client;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;

// ── constants ─────────────────────────────────────────────────────────────────

const HOSTS_URL: &str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
const DEFAULT_CACHE_PERIOD_HOURS: u64 = 24;

// ── module struct ─────────────────────────────────────────────────────────────

struct CachedList {
    hosts: HashSet<String>,
    fetched_at: Instant,
}

use std::collections::HashSet;

pub struct SfpStevenblackHosts {
    client: Client,
    /// Tracks already-checked values within a scan run.
    seen: Arc<DashSet<String>>,
    /// Cached hosts list, shared across instances.
    cache: Arc<RwLock<Option<Arc<CachedList>>>>,
    /// Set to `true` if we fail to fetch/parse and want to stop trying.
    error_state: Arc<AtomicBool>,
}

impl SfpStevenblackHosts {
    /// Create a new instance.
    #[must_use]
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("spiderfoot-rust/0.1")
            .build()
            .expect("failed to build reqwest Client");

        Self {
            client,
            seen: Arc::new(DashSet::new()),
            cache: Arc::new(RwLock::new(None)),
            error_state: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn get_hosts(
        &self,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Option<Arc<CachedList>> {
        let cache_period =
            Duration::from_secs(options.get_u64("cacheperiod", DEFAULT_CACHE_PERIOD_HOURS) * 3600);

        {
            let cache = self.cache.read().await;
            if let Some(cached) = &*cache {
                if cached.fetched_at.elapsed() < cache_period {
                    return Some(Arc::clone(cached));
                }
            }
        }

        let mut cache = self.cache.write().await;
        // Re-check after acquiring write lock
        if let Some(cached) = &*cache {
            if cached.fetched_at.elapsed() < cache_period {
                return Some(Arc::clone(cached));
            }
        }

        let url = options
            .custom
            .get("_test_url")
            .map(|s| s.as_str())
            .unwrap_or(HOSTS_URL);
        emitter.log(
            LogLevel::Info,
            &format!("sfp_stevenblack_hosts: fetching hosts from {url}"),
        );

        let resp = match self.client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                emitter.log(
                    LogLevel::Error,
                    &format!("sfp_stevenblack_hosts: failed to fetch {url}: {e}"),
                );
                self.error_state.store(true, Ordering::Relaxed);
                return None;
            }
        };

        if !resp.status().is_success() {
            emitter.log(
                LogLevel::Error,
                &format!(
                    "sfp_stevenblack_hosts: unexpected HTTP status {} from {url}",
                    resp.status()
                ),
            );
            self.error_state.store(true, Ordering::Relaxed);
            return None;
        }

        let body = match resp.text().await {
            Ok(t) => t,
            Err(e) => {
                emitter.log(
                    LogLevel::Error,
                    &format!("sfp_stevenblack_hosts: failed to read response body: {e}"),
                );
                self.error_state.store(true, Ordering::Relaxed);
                return None;
            }
        };

        let hosts = self.parse_hosts(&body);
        let hosts_count = hosts.len();
        let list = Arc::new(CachedList {
            hosts,
            fetched_at: Instant::now(),
        });
        *cache = Some(Arc::clone(&list));

        emitter.log(
            LogLevel::Info,
            &format!("sfp_stevenblack_hosts: loaded {hosts_count} hosts"),
        );
        Some(list)
    }

    fn parse_hosts(&self, content: &str) -> HashSet<String> {
        let mut hosts = HashSet::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Lines are like "0.0.0.0 host.name"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                hosts.insert(parts[1].to_lowercase());
            }
        }
        hosts
    }

    async fn execute_inner(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.error_state.load(Ordering::Relaxed) {
            return Ok(());
        }

        let kind = target.kind();
        let event_data = target.value().trim().to_lowercase();

        if event_data.is_empty() {
            return Ok(());
        }

        if !self.seen.insert(event_data.clone()) {
            return Ok(());
        }

        let (malicious_type, blacklist_type) = match kind {
            "INTERNET_NAME" | "DOMAIN" => ("MALICIOUS_INTERNET_NAME", "BLACKLISTED_INTERNET_NAME"),
            "AFFILIATE_INTERNET_NAME" | "AFFILIATE_DOMAIN_WHOIS" => {
                if !options.get_bool("checkaffiliates", true) {
                    return Ok(());
                }
                (
                    "MALICIOUS_AFFILIATE_INTERNET_NAME",
                    "BLACKLISTED_AFFILIATE_INTERNET_NAME",
                )
            }
            "CO_HOSTED_SITE" | "CO_HOSTED_SITE_DOMAIN_WHOIS" => {
                if !options.get_bool("checkcohosts", true) {
                    return Ok(());
                }
                ("MALICIOUS_COHOST", "BLACKLISTED_COHOST")
            }
            _ => return Ok(()),
        };

        let blacklist = match self.get_hosts(options, emitter).await {
            Some(h) => h,
            None => return Ok(()),
        };

        if blacklist.hosts.contains(&event_data) {
            let text = format!("Steven Black Hosts Blocklist [{event_data}]\n{HOSTS_URL}");
            emitter.emit(malicious_type, self.name(), target, text.clone(), Some(1.0));
            emitter.emit(blacklist_type, self.name(), target, text, Some(1.0));
        }

        Ok(())
    }
}

impl Default for SfpStevenblackHosts {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SpiderfootModule for SfpStevenblackHosts {
    fn name(&self) -> &'static str {
        "sfp_stevenblack_hosts"
    }

    fn description(&self) -> &'static str {
        "Check if a domain is malicious (malware or adware) according to Steven Black Hosts list."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &["INTERNET_NAME", "AFFILIATE_INTERNET_NAME", "CO_HOSTED_SITE"]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &[
            "MALICIOUS_INTERNET_NAME",
            "BLACKLISTED_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST",
            "BLACKLISTED_COHOST",
        ]
    }

    fn tags(&self) -> &'static [&'static str] {
        &["passive", "reputation", "free"]
    }

    async fn execute(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.execute_inner(target, options, emitter).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hosts() {
        let module = SfpStevenblackHosts::new();
        let content = "
# Comment
0.0.0.0 example.com
0.0.0.0 another.one
  0.0.0.0   spaced.out  
";
        let hosts = module.parse_hosts(content);
        assert_eq!(hosts.len(), 3);
        assert!(hosts.contains("example.com"));
        assert!(hosts.contains("another.one"));
        assert!(hosts.contains("spaced.out"));
    }
}
