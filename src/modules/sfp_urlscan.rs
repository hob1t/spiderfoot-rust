//! # `sfp_urlscan` — URLScan.io cache search
//!
//! Port of the Python SpiderFoot module `sfp_urlscan`.
//!
//! Original: <https://github.com/smicallef/spiderfoot/blob/master/modules/sfp_urlscan.py>
//! API docs: <https://urlscan.io/about-api/>
//!
//! ## What it does
//! Queries the URLScan.io search API (`/api/v1/search/`) with `domain:<target>`
//! and extracts the following data from each result:
//!
//! * `LINKED_URL_INTERNAL` — every scanned URL whose FQDN matches the target
//!   domain (including parents).
//! * `GEOINFO` — `"<city>, <country>"` pairs found in page metadata.
//! * `INTERNET_NAME` — sub-/parent domains that resolve via DNS.
//! * `INTERNET_NAME_UNRESOLVED` — sub-/parent domains that **do not** resolve
//!   (only emitted when `verify = true`).
//! * `DOMAIN_NAME` — domains that are themselves registrable domain names
//!   (detected via PSL using the [`addr`] crate).
//! * `BGP_AS_MEMBER` — ASN numbers extracted from the `asn` page field
//!   (the `"AS"` prefix is stripped so only the numeric part is emitted).
//! * `WEBSERVER_BANNER` — `server` header values.
//! * `RAW_RIR_DATA` — the raw JSON `results` array (emitted once when at least
//!   one result is present).
//!
//! ## Target types consumed
//! `INTERNET_NAME`
//!
//! ## Options (via `ModuleOptions::custom`)
//! | key       | default   | description                                              |
//! |-----------|-----------|----------------------------------------------------------|
//! | `verify`  | `"true"`  | Resolve discovered hostnames; emit `INTERNET_NAME_UNRESOLVED` when DNS fails |

use crate::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use dashmap::DashSet;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

// ── URLScan API response types ────────────────────────────────────────────────

/// Top-level response from `GET /api/v1/search/`.
#[derive(Debug, Deserialize, serde::Serialize)]
struct UrlscanResponse {
    #[serde(default)]
    results: Vec<UrlscanResult>,
}

/// One entry inside `results`.
#[derive(Debug, Deserialize, serde::Serialize)]
struct UrlscanResult {
    #[serde(default)]
    page: UrlscanPage,
    #[serde(default)]
    task: UrlscanTask,
}

/// The `page` sub-object — metadata about the scanned page.
#[derive(Debug, Default, Deserialize, serde::Serialize)]
struct UrlscanPage {
    #[serde(default)]
    domain: String,
    #[serde(default)]
    asn: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    country: String,
    #[serde(default)]
    server: String,
}

/// The `task` sub-object — metadata about the scan task.
#[derive(Debug, Default, Deserialize, serde::Serialize)]
struct UrlscanTask {
    #[serde(default)]
    url: String,
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Extract the FQDN from a URL string.
///
/// Returns `None` when the URL cannot be parsed or has no host component.
pub fn url_fqdn(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    parsed
        .host_str()
        .map(|h| h.trim_end_matches('.').to_lowercase())
}

/// Returns `true` when `host` matches `target_domain`, including sub-domains
/// and parent domains (mirrors Python's `getTarget().matches(…, includeParents=True)`).
///
/// The parent-match arm requires `host` to contain at least one dot so that
/// bare TLDs (e.g. `"com"`) never match every `.com` domain.
pub fn domain_matches(host: &str, target_domain: &str) -> bool {
    let h = host.to_lowercase();
    let t = target_domain.to_lowercase();
    let host_has_dot = h.contains('.');

    h == t
        || h.ends_with(&format!(".{t}"))                        // sub-domain of target
        || (host_has_dot && t.ends_with(&format!(".{h}"))) // target is sub-domain of host
}

/// Returns `true` when `domain` is a registrable domain name according to the
/// Public Suffix List (mirrors Python's `sf.isDomain(…)`).
///
/// Uses the [`addr`] crate for PSL-aware parsing.  A domain is considered
/// registrable when the PSL parser finds it has no prefix (i.e. it IS the
/// root of a registrable domain).
pub fn is_domain(domain: &str) -> bool {
    match addr::parse_domain_name(domain) {
        Ok(name) => name.root().is_some() && name.prefix().is_none(),
        Err(_) => false,
    }
}

/// Build the URLScan.io search API URL for a given query string.
///
/// The query is URL-encoded before being appended.  The `base_url` parameter
/// allows tests to redirect calls to a mock server.
pub fn search_url(base_url: &str, query: &str) -> String {
    format!(
        "{}/api/v1/search/?q={}",
        base_url.trim_end_matches('/'),
        urlencoding::encode(query),
    )
}

// ── constants ─────────────────────────────────────────────────────────────────

const DEFAULT_TIMEOUT_SECS: u64 = 15;
const URLSCAN_BASE: &str = "https://urlscan.io";

// ── module ────────────────────────────────────────────────────────────────────

/// URLScan.io search module.
pub struct SfpUrlscan {
    client: Client,
    resolver: TokioAsyncResolver,
    /// Tracks already-queried values within a scan run to avoid duplicate API calls.
    seen: Arc<DashSet<String>>,
    /// Set to `true` after a rate-limit (HTTP 429) response so subsequent
    /// executions bail out immediately.
    error_state: Arc<std::sync::atomic::AtomicBool>,
}

impl SfpUrlscan {
    /// Create a new instance with a default HTTP client and DNS resolver.
    #[must_use]
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .user_agent("SpiderFoot")
            .build()
            .expect("failed to build reqwest client");

        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        Self {
            client,
            resolver,
            seen: Arc::new(DashSet::new()),
            error_state: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    // ── option helpers ────────────────────────────────────────────────────────

    /// Read the `verify` option (default: `true`).
    fn opt_verify(options: &ModuleOptions) -> bool {
        options
            .custom
            .get("verify")
            .map(|v| v.trim().to_lowercase() != "false" && v.trim() != "0")
            .unwrap_or(true)
    }

    // ── DNS resolution ────────────────────────────────────────────────────────

    /// Returns `true` when `host` resolves via DNS (A or AAAA record).
    async fn resolves(&self, host: &str) -> bool {
        self.resolver.lookup_ip(host).await.is_ok()
    }

    // ── public test entry-point ───────────────────────────────────────────────

    /// Redirect HTTP calls to `_test_base_url` from `options.custom`.
    /// Exposed so integration tests can use a mock server without boxing.
    pub async fn execute_for_test<E>(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut E,
    ) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        E: EventEmitter + Send,
    {
        self.execute_inner(target, options, emitter).await
    }

    // ── core logic ────────────────────────────────────────────────────────────

    async fn execute_inner(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Bail out immediately if a previous call hit a rate-limit.
        if self.error_state.load(std::sync::atomic::Ordering::Relaxed) {
            emitter.log(
                LogLevel::Error,
                "sfp_urlscan: module is in error state, skipping",
            );
            return Ok(());
        }

        let kind = target.kind();
        if !self.target_types().contains(&kind) {
            emitter.log(
                LogLevel::Debug,
                &format!(
                    "sfp_urlscan: skipping unsupported target type '{kind}' (value: {})",
                    target.value()
                ),
            );
            return Ok(());
        }

        let event_data = target.value().trim().to_string();
        if event_data.is_empty() {
            return Ok(());
        }

        // Deduplication guard.
        if !self.seen.insert(event_data.clone()) {
            emitter.log(
                LogLevel::Debug,
                &format!("sfp_urlscan: already checked '{event_data}', skipping"),
            );
            return Ok(());
        }

        let base_url = options
            .custom
            .get("_test_base_url")
            .map(String::as_str)
            .unwrap_or(URLSCAN_BASE);

        let query = format!("domain:{event_data}");
        let url = search_url(base_url, &query);

        emitter.log(LogLevel::Debug, &format!("sfp_urlscan: querying {url}"));

        let timeout_secs = if options.timeout_seconds > 0 {
            options.timeout_seconds
        } else {
            DEFAULT_TIMEOUT_SECS
        };

        let resp = match self
            .client
            .get(&url)
            .timeout(Duration::from_secs(timeout_secs))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                emitter.log(
                    LogLevel::Error,
                    &format!("sfp_urlscan: fetch error for {url}: {e}"),
                );
                return Ok(());
            }
        };

        // Rate-limit handling.
        if resp.status().as_u16() == 429 {
            emitter.log(
                LogLevel::Error,
                "sfp_urlscan: you are being rate-limited by URLScan.io",
            );
            self.error_state
                .store(true, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }

        if !resp.status().is_success() {
            emitter.log(
                LogLevel::Error,
                &format!("sfp_urlscan: HTTP {} from {url}", resp.status().as_u16()),
            );
            return Ok(());
        }

        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                emitter.log(
                    LogLevel::Error,
                    &format!("sfp_urlscan: body read error: {e}"),
                );
                return Ok(());
            }
        };

        let parsed: UrlscanResponse = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                emitter.log(
                    LogLevel::Debug,
                    &format!("sfp_urlscan: error processing JSON response: {e}"),
                );
                return Ok(());
            }
        };

        if parsed.results.is_empty() {
            emitter.log(
                LogLevel::Info,
                &format!("sfp_urlscan: no results info found for {event_data}"),
            );
            return Ok(());
        }

        // Emit the raw results array exactly once.
        emitter.emit(
            "RAW_RIR_DATA",
            self.name(),
            target,
            serde_json::to_string(&parsed.results).unwrap_or_else(|_| body.clone()),
            Some(1.0),
        );

        // Collect unique values across all results before emitting.
        let mut urls: HashSet<String> = HashSet::new();
        let mut asns: HashSet<String> = HashSet::new();
        let mut domains: HashSet<String> = HashSet::new();
        let mut locations: HashSet<String> = HashSet::new();
        let mut servers: HashSet<String> = HashSet::new();

        for result in &parsed.results {
            let page = &result.page;

            // Skip results with no domain.
            if page.domain.is_empty() {
                continue;
            }

            // Only process pages whose domain matches the scan target
            // (including parent domains).
            if !domain_matches(&page.domain, &event_data) {
                continue;
            }

            // Collect sub-/parent domains that differ from the event data.
            if !page.domain.eq_ignore_ascii_case(&event_data) {
                domains.insert(page.domain.to_lowercase());
            }

            // ASN — strip the leading "AS" prefix to get the numeric part.
            if !page.asn.is_empty() {
                asns.insert(page.asn.trim_start_matches("AS").to_string());
            }

            // Geo location — join non-empty city and country.
            let location: String = [page.city.as_str(), page.country.as_str()]
                .iter()
                .filter(|s| !s.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join(", ");
            if !location.is_empty() {
                locations.insert(location);
            }

            // Web server banner.
            if !page.server.is_empty() {
                servers.insert(page.server.clone());
            }

            // Scanned URL — include only when its FQDN matches the target.
            if !result.task.url.is_empty() {
                if let Some(fqdn) = url_fqdn(&result.task.url) {
                    if domain_matches(&fqdn, &event_data) {
                        urls.insert(result.task.url.clone());
                    }
                }
            }
        }

        // ── Emit LINKED_URL_INTERNAL ──────────────────────────────────────────
        for url in &urls {
            emitter.emit(
                "LINKED_URL_INTERNAL",
                self.name(),
                target,
                url.clone(),
                Some(1.0),
            );
        }

        // ── Emit GEOINFO ──────────────────────────────────────────────────────
        for location in &locations {
            emitter.emit("GEOINFO", self.name(), target, location.clone(), Some(1.0));
        }

        // ── Emit INTERNET_NAME / INTERNET_NAME_UNRESOLVED + DOMAIN_NAME ──────
        let verify = Self::opt_verify(options);
        if verify && !domains.is_empty() {
            emitter.log(
                LogLevel::Info,
                &format!("sfp_urlscan: resolving {} domains ...", domains.len()),
            );
        }

        for domain in &domains {
            if verify {
                if self.resolves(domain).await {
                    emitter.emit(
                        "INTERNET_NAME",
                        self.name(),
                        target,
                        domain.clone(),
                        Some(1.0),
                    );
                } else {
                    emitter.emit(
                        "INTERNET_NAME_UNRESOLVED",
                        self.name(),
                        target,
                        domain.clone(),
                        Some(1.0),
                    );
                }
            } else {
                // When verify is disabled always emit INTERNET_NAME.
                emitter.emit(
                    "INTERNET_NAME",
                    self.name(),
                    target,
                    domain.clone(),
                    Some(1.0),
                );
            }

            if is_domain(domain) {
                emitter.emit(
                    "DOMAIN_NAME",
                    self.name(),
                    target,
                    domain.clone(),
                    Some(1.0),
                );
            }
        }

        // ── Emit BGP_AS_MEMBER ────────────────────────────────────────────────
        for asn in &asns {
            emitter.emit("BGP_AS_MEMBER", self.name(), target, asn.clone(), Some(1.0));
        }

        // ── Emit WEBSERVER_BANNER ─────────────────────────────────────────────
        for server in &servers {
            emitter.emit(
                "WEBSERVER_BANNER",
                self.name(),
                target,
                server.clone(),
                Some(1.0),
            );
        }

        Ok(())
    }
}

impl Default for SfpUrlscan {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SpiderfootModule for SfpUrlscan {
    fn name(&self) -> &'static str {
        "sfp_urlscan"
    }

    fn description(&self) -> &'static str {
        "Search URLScan.io cache for domain information."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &["INTERNET_NAME"]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &[
            "GEOINFO",
            "LINKED_URL_INTERNAL",
            "RAW_RIR_DATA",
            "DOMAIN_NAME",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "BGP_AS_MEMBER",
            "WEBSERVER_BANNER",
        ]
    }

    fn tags(&self) -> &'static [&'static str] {
        &["passive", "recon", "search-engine", "free", "no-auth"]
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
