// src/modules/sfp_duckduckgo.rs
//
// Port of sfp_duckduckgo.py — queries DuckDuckGo's Instant Answer API for
// descriptive information about a domain / internet name target.
//
// Original: https://github.com/smicallef/spiderfoot/blob/master/modules/sfp_duckduckgo.py
// API docs: https://api.duckduckgo.com/api

use crate::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use dashmap::DashSet;
use reqwest::Client;
use serde::Deserialize;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

// ── DuckDuckGo Instant Answer API response ───────────────────────────────────

/// Minimal representation of the DDG Instant Answer JSON response.
/// Only the fields we actually consume are deserialized; everything else
/// is silently ignored by serde.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DdgResponse {
    /// Non-empty when DDG found a matching topic (e.g. "Rust (programming language)")
    #[serde(default)]
    heading: String,

    /// Short prose description of the topic.
    #[serde(default)]
    abstract_text: String,

    /// Related topic entries — each may contain a `Text` field.
    #[serde(default)]
    related_topics: Vec<DdgTopic>,
}

/// One entry inside `RelatedTopics`.
/// DDG sometimes nests sub-lists (the `Topics` key); we ignore those and only
/// look at flat entries that carry a `Text` value directly.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DdgTopic {
    #[serde(default)]
    text: String,
}

// ── Module implementation ────────────────────────────────────────────────────

/// Options recognised by this module (mirrors Python `opts`).
#[derive(Debug, Clone)]
pub struct SfpDuckDuckGoOptions {
    /// When the input is an `AFFILIATE_INTERNET_NAME`, strip the hostname and
    /// query only the parent domain.  This usually returns richer results.
    pub affiliate_domains: bool,
}

impl Default for SfpDuckDuckGoOptions {
    fn default() -> Self {
        Self {
            affiliate_domains: true,
        }
    }
}

pub struct SfpDuckDuckGo {
    client: Client,
    /// Tracks already-queried values so we never hit the API twice for the
    /// same string within a single scan.
    seen: Arc<DashSet<String>>,
    pub opts: SfpDuckDuckGoOptions,
}

impl SfpDuckDuckGo {
    /// Create a new instance with default options and a shared HTTP client.
    pub fn new() -> Self {
        Self::with_options(SfpDuckDuckGoOptions::default())
    }

    /// Create with custom options.
    pub fn with_options(opts: SfpDuckDuckGoOptions) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("SpiderFoot")
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            seen: Arc::new(DashSet::new()),
            opts,
        }
    }

    /// Strip the leftmost DNS label from a hostname, respecting the
    /// Public Suffix List (PSL) via the [`addr`] crate.
    ///
    /// Mirrors Python's `self.sf.hostDomain(eventData, tlds)`.
    ///
    /// # Behaviour
    /// * If the hostname cannot be parsed by the PSL (e.g. `"localhost"`,
    ///   bare single labels, or invalid names), falls back to the naive
    ///   string-split approach so the function never panics.
    /// * If the hostname is already at the registrable domain level
    ///   (i.e. `prefix()` is `None`), it is returned unchanged.
    /// * Otherwise the leftmost label is stripped from the prefix:
    ///   - `"www.example.com"`       → `"example.com"`
    ///   - `"sub.sub.example.co.uk"` → `"sub.example.co.uk"`
    ///   - `"example.co.uk"`         → `"example.co.uk"` (no prefix)
    pub fn host_domain(hostname: &str) -> &str {
        // Attempt PSL-aware parsing first.
        if let Ok(name) = addr::parse_domain_name(hostname) {
            if let Some(root) = name.root() {
                match name.prefix() {
                    // No prefix → already at the registrable domain level.
                    None => {
                        // Return the original slice that covers root.
                        // `root` is a sub-slice of `hostname`, so we can
                        // find its byte offset and return the matching slice.
                        let offset = root.as_ptr() as usize - hostname.as_ptr() as usize;
                        return &hostname[offset..offset + root.len()];
                    }
                    // Prefix has no dot → single subdomain label (e.g. "www").
                    // Stripping it leaves just the root.
                    Some(prefix) if !prefix.contains('.') => {
                        let offset = root.as_ptr() as usize - hostname.as_ptr() as usize;
                        return &hostname[offset..offset + root.len()];
                    }
                    // Prefix has multiple labels → strip only the leftmost one.
                    Some(prefix) => {
                        // e.g. prefix = "a.b", root = "example.co.uk"
                        // after_first_dot = "b" → result = "b.example.co.uk"
                        let after_first_dot = &prefix[prefix.find('.').unwrap() + 1..];
                        // `after_first_dot` is a sub-slice of `hostname`.
                        let offset = after_first_dot.as_ptr() as usize - hostname.as_ptr() as usize;
                        return &hostname[offset..];
                    }
                }
            }
        }

        // Fallback: naive label-count approach (handles localhost, IPs, etc.).
        match hostname.find('.') {
            Some(dot_pos) => {
                let remainder = &hostname[dot_pos + 1..];
                if remainder.contains('.') {
                    remainder
                } else {
                    hostname
                }
            }
            None => hostname,
        }
    }

    /// Build the DDG Instant Answer API URL for a query string.
    pub fn api_url(query: &str) -> String {
        format!(
            "https://api.duckduckgo.com/?q={}&format=json&no_html=1&skip_disambig=1",
            urlencoding::encode(query)
        )
    }

    /// Build the DDG Instant Answer API URL against a custom base URL.
    /// Used in tests to redirect requests to a mock server.
    pub fn api_url_with_base(base_url: &str, query: &str) -> String {
        format!(
            "{}/?q={}&format=json&no_html=1&skip_disambig=1",
            base_url.trim_end_matches('/'),
            urlencoding::encode(query)
        )
    }

    /// Core execution logic, accepting an explicit base URL so tests can
    /// redirect HTTP calls to a mock server.
    async fn execute_inner(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
        base_url: Option<&str>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let kind = target.kind();

        if !self.target_types().contains(&kind) {
            emitter.log(
                LogLevel::Debug,
                &format!(
                    "sfp_duckduckgo: skipping unsupported target type '{}' (value: {})",
                    kind,
                    target.value()
                ),
            );
            return Ok(());
        }

        let is_affiliate = kind.contains("AFFILIATE");

        let affiliate_domains = options
            .custom
            .get("affiliate_domains")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(self.opts.affiliate_domains);

        let raw_value = target.value();
        let query: &str = if is_affiliate && affiliate_domains {
            Self::host_domain(raw_value)
        } else {
            raw_value
        };

        if query.is_empty() {
            emitter.log(
                LogLevel::Debug,
                "sfp_duckduckgo: empty query string after host_domain resolution, skipping",
            );
            return Ok(());
        }

        if !self.seen.insert(query.to_owned()) {
            emitter.log(
                LogLevel::Debug,
                &format!("sfp_duckduckgo: already checked '{query}', skipping"),
            );
            return Ok(());
        }

        let url = base_url.unwrap_or("https://api.duckduckgo.com/");

        emitter.log(
            LogLevel::Info,
            &format!("sfp_duckduckgo: querying {url} with query='{query}'"),
        );

        let timeout_secs = if options.timeout_seconds > 0 {
            options.timeout_seconds
        } else {
            15
        };

        let response = self
            .client
            .get(url)
            .query(&[
                ("q", query),
                ("format", "json"),
                ("no_html", "1"),
                ("skip_disambig", "1"),
            ])
            .timeout(Duration::from_secs(timeout_secs))
            .send()
            .await;

        let resp = match response {
            Ok(resp) => resp,
            Err(e) => {
                emitter.log(
                    LogLevel::Error,
                    &format!("sfp_duckduckgo: unable to fetch {url}: {e}"),
                );
                return Ok(());
            }
        };

        let ddg: DdgResponse = match resp.json::<DdgResponse>().await {
            Ok(v) => v,
            Err(e) => {
                emitter.log(
                    LogLevel::Error,
                    &format!("sfp_duckduckgo: error processing JSON response from DuckDuckGo: {e}"),
                );
                return Ok(());
            }
        };

        if ddg.heading.is_empty() {
            emitter.log(
                LogLevel::Debug,
                &format!("sfp_duckduckgo: no DuckDuckGo information for '{query}'"),
            );
            return Ok(());
        }

        if !ddg.abstract_text.is_empty() {
            let event_type = if is_affiliate {
                "AFFILIATE_DESCRIPTION_ABSTRACT"
            } else {
                "DESCRIPTION_ABSTRACT"
            };

            emitter.emit(
                event_type,
                self.name(),
                target,
                ddg.abstract_text,
                Some(1.0),
            );
        }

        if !ddg.related_topics.is_empty() {
            let event_type = if is_affiliate {
                "AFFILIATE_DESCRIPTION_CATEGORY"
            } else {
                "DESCRIPTION_CATEGORY"
            };

            for topic in ddg.related_topics {
                if topic.text.is_empty() {
                    emitter.log(
                        LogLevel::Debug,
                        "sfp_duckduckgo: no category text found from DuckDuckGo",
                    );
                    continue;
                }

                emitter.emit(event_type, self.name(), target, topic.text, Some(1.0));
            }
        }

        Ok(())
    }

    /// Test entry point: reads `_test_base_url` from `ModuleOptions::custom`
    /// and redirects HTTP calls to that address.
    pub async fn execute_for_test<E>(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut E,
    ) -> Result<(), Box<dyn Error + Send + Sync>>
    where
        E: EventEmitter + Send,
    {
        let base = options.custom.get("_test_base_url").cloned();
        self.execute_inner(target, options, emitter, base.as_deref())
            .await
    }
}

impl Default for SfpDuckDuckGo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SpiderfootModule for SfpDuckDuckGo {
    fn name(&self) -> &'static str {
        "sfp_duckduckgo"
    }

    fn description(&self) -> &'static str {
        "Query DuckDuckGo's Instant Answer API for descriptive information about the target."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &[
            "DOMAIN",
            "DOMAIN_NAME_PARENT",
            "INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME",
        ]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &[
            "DESCRIPTION_ABSTRACT",
            "DESCRIPTION_CATEGORY",
            "AFFILIATE_DESCRIPTION_ABSTRACT",
            "AFFILIATE_DESCRIPTION_CATEGORY",
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
        self.execute_inner(target, options, emitter, None).await
    }
}
