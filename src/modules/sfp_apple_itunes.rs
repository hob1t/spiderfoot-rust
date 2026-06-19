// src/modules/sfp_apple_itunes.rs
//
// Port of sfp_apple_itunes.py — queries the Apple iTunes Search API for mobile
// apps whose bundle ID matches the target domain.
//
// Original: https://github.com/smicallef/spiderfoot/blob/master/modules/sfp_apple_itunes.py
// API docs: https://developer.apple.com/library/archive/documentation/AudioVideo/Conceptual/iTuneSearchAPI/

//! # `sfp_apple_itunes` — Apple iTunes App Store search
//!
//! ## What it does
//! Queries the iTunes Search API with the *reversed* domain name
//! (e.g. `"com.example"` for `"example.com"`) to find apps whose
//! `bundleId` belongs to the target domain.
//!
//! For each matching app it emits:
//! * `APPSTORE_ENTRY` — `"<trackName> <version> (<bundleId>)\n<SFURL><trackViewUrl></SFURL>"`
//! * `LINKED_URL_INTERNAL` — the app's `sellerUrl` when it resolves to the
//!   target domain or a sub/parent domain.
//! * `INTERNET_NAME` — the seller URL host when it matches the target domain.
//! * `AFFILIATE_INTERNET_NAME` — the seller URL host when it does *not* match.
//! * `RAW_RIR_DATA` — the full JSON response from the API (emitted once when
//!   at least one `APPSTORE_ENTRY` was emitted).
//!
//! ## Events consumed
//! `DOMAIN_NAME`
//!
//! ## Options (via `ModuleOptions::custom`)
//! | key        | default | description                               |
//! |------------|---------|-------------------------------------------|
//! | `limit`    | `"100"` | Maximum number of results to request      |

use crate::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ── iTunes Search API response ────────────────────────────────────────────────

/// Top-level response from `https://itunes.apple.com/search`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ItunesResponse {
    #[serde(default)]
    results: Vec<ItunesResult>,
}

/// One app entry inside `results`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ItunesResult {
    #[serde(default)]
    bundle_id: String,
    #[serde(default)]
    track_name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    track_view_url: String,
    #[serde(default)]
    seller_url: String,
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Reverse the labels of a domain name.
///
/// `"example.com"` → `"com.example"` (matches typical bundle-ID prefix)
pub(crate) fn reverse_domain(domain: &str) -> String {
    domain
        .trim()
        .to_lowercase()
        .split('.')
        .rev()
        .collect::<Vec<_>>()
        .join(".")
}

/// Extract the FQDN from a URL (scheme stripped, path stripped).
///
/// Returns `None` when the URL cannot be parsed or has no host.
pub(crate) fn url_fqdn(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    parsed
        .host_str()
        .map(|h| h.trim_end_matches('.').to_lowercase())
}

/// Returns `true` when `host` matches `target_domain`, including sub-domains
/// and parent domains.
///
/// Mirrors Python's `self.getTarget().matches(host, includeChildren=True,
/// includeParents=True)`.
///
/// # Edge cases
/// The parent-match arm (`t.ends_with(&format!(".{h}"))`) requires `host` to
/// contain at least one dot so that bare TLDs (e.g. `"com"`) never match every
/// `.com` domain.
pub(crate) fn domain_matches(host: &str, target_domain: &str) -> bool {
    let h = host.to_lowercase();
    let t = target_domain.to_lowercase();

    // Guard: bare TLDs must not act as wildcards for parent matching.
    let host_has_dot = h.contains('.');

    h == t
        || h.ends_with(&format!(".{t}")) // sub-domain of target
        || (host_has_dot && t.ends_with(&format!(".{h}"))) // target is sub-domain of host
}

/// Filter `results` down to entries whose `bundleId` belongs to `domain_reversed`.
///
/// An entry matches when its lowercased bundle ID:
/// * equals `domain_reversed` exactly, or
/// * starts with `"<domain_reversed>."` (app under that namespace), or
/// * ends with `".<domain_reversed>"` (less common reverse style), or
/// * contains `".<domain_reversed>."` (embedded segment).
fn filter_results<'a>(
    results: &'a [ItunesResult],
    domain_reversed: &str,
    emitter: &mut (dyn EventEmitter + Send),
) -> Vec<&'a ItunesResult> {
    results
        .iter()
        .filter(|r| {
            if r.bundle_id.is_empty() || r.track_name.is_empty() || r.version.is_empty() {
                return false;
            }
            let bid = r.bundle_id.to_lowercase();
            let matches = bid == domain_reversed
                || bid.starts_with(&format!("{domain_reversed}."))
                || bid.ends_with(&format!(".{domain_reversed}"))
                || bid.contains(&format!(".{domain_reversed}."));
            if !matches {
                emitter.log(
                    LogLevel::Debug,
                    &format!(
                        "sfp_apple_itunes: app '{} {} ({})' does not match '{domain_reversed}', skipping",
                        r.track_name, r.version, r.bundle_id,
                    ),
                );
            }
            matches
        })
        .collect()
}

/// Emit seller-URL events (`LINKED_URL_INTERNAL`, `INTERNET_NAME`,
/// `AFFILIATE_INTERNET_NAME`) for the given set of unique seller URLs.
fn emit_seller_url_events(
    seller_urls: HashSet<String>,
    domain: &str,
    module_name: &'static str,
    target: &Target,
    emitter: &mut (dyn EventEmitter + Send),
) {
    // Collect unique hosts first so we emit each host event exactly once.
    let unique_hosts: HashSet<String> = seller_urls.iter().filter_map(|u| url_fqdn(u)).collect();

    for url in &seller_urls {
        let Some(host) = url_fqdn(url) else {
            continue;
        };
        if domain_matches(&host, domain) {
            emitter.emit(
                "LINKED_URL_INTERNAL",
                module_name,
                target,
                url.clone(),
                Some(1.0),
            );
        }
    }

    for host in &unique_hosts {
        if domain_matches(host, domain) {
            emitter.emit(
                "INTERNET_NAME",
                module_name,
                target,
                host.clone(),
                Some(1.0),
            );
        } else {
            emitter.emit(
                "AFFILIATE_INTERNET_NAME",
                module_name,
                target,
                host.clone(),
                Some(1.0),
            );
        }
    }
}

// ── module ────────────────────────────────────────────────────────────────────

/// Default result limit sent to the iTunes Search API.
const DEFAULT_LIMIT: u32 = 100;
/// Default HTTP timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 15;
/// Production iTunes Search API base URL.
const ITUNES_API_BASE: &str = "https://itunes.apple.com";

pub struct SfpAppleItunes {
    client: Client,
    /// Tracks already-queried domain values within a scan run.
    /// Uses `Mutex<HashSet>` — module execution is sequential in the scan
    /// engine; the `Mutex` is sufficient and avoids the `dashmap` dependency.
    seen: Arc<Mutex<HashSet<String>>>,
}

impl SfpAppleItunes {
    #[must_use]
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .user_agent("SpiderFoot")
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            seen: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Parse `limit` from `ModuleOptions::custom`, falling back to the default.
    fn limit(options: &ModuleOptions) -> u32 {
        options
            .custom
            .get("limit")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(DEFAULT_LIMIT)
    }

    /// Build the iTunes Search API query URL.
    #[must_use]
    pub fn search_url(base: &str, query: &str, limit: u32) -> String {
        format!(
            "{}/search?media=software&entity=software,iPadSoftware,softwareDeveloper&limit={limit}&term={}",
            base.trim_end_matches('/'),
            urlencoding::encode(query),
        )
    }

    /// Public test entry-point: honours `_test_base_url` in `options.custom`
    /// to redirect HTTP calls to a mock server.
    ///
    /// This is intentionally generic over `E: EventEmitter + Send` so callers
    /// can pass a concrete emitter type without boxing.
    pub async fn execute_for_test<E>(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut E,
    ) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        E: EventEmitter + Send,
    {
        // For tests that need a clean state (like different test cases in the same run),
        // we offer an option to clear the 'seen' set via a special custom option.
        if options.get_bool("_test_clear_seen", false) {
            let mut seen = self.seen.lock().expect("seen mutex poisoned");
            seen.clear();
        }

        let emitter_dyn: &mut (dyn EventEmitter + Send) = emitter;
        self.execute_inner(target, options, emitter_dyn).await
    }

    /// Core execution logic.
    ///
    /// `api_base` is read from `options.custom[\"_test_base_url\"]` when present
    /// (test injection point), otherwise falls back to `ITUNES_API_BASE`.
    async fn execute_inner(
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
                    "sfp_apple_itunes: skipping unsupported target type '{kind}' (value: {})",
                    target.value()
                ),
            );
            return Ok(());
        }

        let domain = target.value().trim().to_lowercase();
        if domain.is_empty() {
            return Ok(());
        }

        // Deduplication: skip if we've already processed this domain.
        {
            let mut seen = self.seen.lock().expect("seen mutex poisoned");
            if !seen.insert(domain.clone()) {
                emitter.log(
                    LogLevel::Debug,
                    &format!("sfp_apple_itunes: already checked '{domain}', skipping"),
                );
                return Ok(());
            }
        }

        // Resolve the API base URL — overridable via options for tests.
        let api_base = options
            .custom
            .get("_test_base_url")
            .map(String::as_str)
            .unwrap_or(ITUNES_API_BASE);

        let domain_reversed = reverse_domain(&domain);
        let limit = Self::limit(options);
        let url = Self::search_url(api_base, &domain_reversed, limit);

        emitter.log(
            LogLevel::Info,
            &format!("sfp_apple_itunes: querying iTunes for '{domain_reversed}'"),
        );

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
                    &format!("sfp_apple_itunes: fetch error for {url}: {e}"),
                );
                return Ok(());
            }
        };

        // Reject non-2xx responses before attempting to parse the body.
        if !resp.status().is_success() {
            emitter.log(
                LogLevel::Error,
                &format!(
                    "sfp_apple_itunes: HTTP {} from {url}",
                    resp.status().as_u16()
                ),
            );
            return Ok(());
        }

        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                emitter.log(
                    LogLevel::Error,
                    &format!("sfp_apple_itunes: body read error: {e}"),
                );
                return Ok(());
            }
        };

        let itunes: ItunesResponse = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                emitter.log(
                    LogLevel::Error,
                    &format!(
                        "sfp_apple_itunes: error processing JSON response from Apple iTunes: {e}"
                    ),
                );
                return Ok(());
            }
        };

        if itunes.results.is_empty() {
            emitter.log(
                LogLevel::Debug,
                &format!("sfp_apple_itunes: no results found for '{domain}'"),
            );
            return Ok(());
        }

        // ── Filter results to those matching the target domain ────────────────
        let matching = filter_results(&itunes.results, &domain_reversed, emitter);

        // ── Emit APPSTORE_ENTRY for each matching app ─────────────────────────
        //
        // `found` is set to `true` only when at least one APPSTORE_ENTRY is
        // emitted. Seller-URL events alone must NOT trigger RAW_RIR_DATA.
        let mut found = false;
        // Collect seller URLs only from matching apps.
        let mut seller_urls: HashSet<String> = HashSet::new();

        for result in matching {
            if result.track_view_url.is_empty() {
                continue;
            }

            let app_data = format!(
                "{} {} ({})\n<SFURL>{}</SFURL>",
                result.track_name, result.version, result.bundle_id, result.track_view_url,
            );

            emitter.emit("APPSTORE_ENTRY", self.name(), target, app_data, Some(1.0));
            found = true;

            if !result.seller_url.is_empty() {
                seller_urls.insert(result.seller_url.clone());
            }
        }

        // ── Emit seller-URL events ────────────────────────────────────────────
        if !seller_urls.is_empty() {
            emit_seller_url_events(seller_urls, &domain, self.name(), target, emitter);
        }

        // ── RAW_RIR_DATA — emitted only when at least one APPSTORE_ENTRY was
        //    produced; seller-URL-only matches do not qualify.
        if found {
            emitter.emit("RAW_RIR_DATA", self.name(), target, body, Some(1.0));
        }

        Ok(())
    }
}

impl Default for SfpAppleItunes {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SpiderfootModule for SfpAppleItunes {
    fn name(&self) -> &'static str {
        "sfp_apple_itunes"
    }

    fn description(&self) -> &'static str {
        "Search Apple iTunes for mobile apps associated with the target domain."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &["DOMAIN_NAME"]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &[
            "APPSTORE_ENTRY",
            "INTERNET_NAME",
            "LINKED_URL_INTERNAL",
            "AFFILIATE_INTERNET_NAME",
            "RAW_RIR_DATA",
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
