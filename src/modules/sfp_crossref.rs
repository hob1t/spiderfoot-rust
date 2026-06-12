//! # sfp_crossref — Cross-Referencer
//!
//! Ported from the Python SpiderFoot module `sfp_crossref`.
//!
//! ## What it does
//! For every external URL or domain that the scan discovers (via
//! `LINKED_URL_EXTERNAL`, `SIMILARDOMAIN`, `CO_HOSTED_SITE`, or
//! `DARKNET_MENTION_URL` events), this module fetches the remote page and
//! checks whether its content contains a reference back to any of the scan
//! target's known names (domains / hostnames).
//!
//! If a back-reference is found the external hostname is emitted as
//! `AFFILIATE_INTERNET_NAME` and the fetched page body as
//! `AFFILIATE_WEB_CONTENT`.
//!
//! When no back-reference is found on the exact URL **and** the input was a
//! `LINKED_URL_EXTERNAL` event **and** `checkbase` is `true`, the module
//! retries with the base URL (scheme + host only) before giving up.
//!
//! ## Options (via `ModuleOptions::custom`)
//! | key          | default  | description |
//! |--------------|----------|-------------|
//! | `checkbase`  | `"true"` | When `"true"`, fall back to the base URL of a `LINKED_URL_EXTERNAL` if the exact URL shows no cross-reference |
//!
//! ## Target types consumed
//! `LINKED_URL_EXTERNAL`, `SIMILARDOMAIN`, `CO_HOSTED_SITE`,
//! `DARKNET_MENTION_URL`
//!
//! ## Events produced
//! `AFFILIATE_INTERNET_NAME`, `AFFILIATE_WEB_CONTENT`

use crate::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use reqwest::{Client, Url};
use std::collections::HashSet;
use std::error::Error;
use std::time::Duration;

// ── constants ─────────────────────────────────────────────────────────────────

/// Maximum response body size accepted (10 MB — matches the Python original).
const MAX_BODY_BYTES: u64 = 10_000_000;

/// HTTP request timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 15;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Extract the FQDN from a URL string.
/// Returns `None` if the URL cannot be parsed or has no host.
fn url_fqdn(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    parsed
        .host_str()
        .map(|h: &str| h.trim_end_matches('.').to_lowercase())
}

/// Return the base URL (scheme + host, no path/query/fragment).
/// e.g. `"https://example.com/foo?bar"` → `"https://example.com"`.
fn url_base(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let mut base = format!("{}://{}", parsed.scheme(), parsed.host_str()?);
    if let Some(port) = parsed.port() {
        base = format!("{}:{}", base, port);
    }
    Some(base)
}

/// Core delimiter-aware search over already-lowercased strings.
/// Mirrors the Python regex:
/// ```python
/// r"([\.\'\/\"\ ]" + re.escape(name) + r"[\.\'\/\"\ ])"
/// ```
fn content_mentions_lowered(lower_content: &str, lower_name: &str) -> bool {
    if lower_name.is_empty() {
        return false;
    }
    let delimiters = ['.', '\'', '/', '"', ' '];
    let mut search_start = 0;
    while let Some(pos) = lower_content[search_start..].find(lower_name) {
        let abs_pos = search_start + pos;
        let before = abs_pos
            .checked_sub(1)
            .and_then(|i| lower_content.as_bytes().get(i).copied())
            .map(|b| b as char);
        let after = lower_content
            .as_bytes()
            .get(abs_pos + lower_name.len())
            .copied()
            .map(|b| b as char);
        let before_ok = before.map_or(true, |c| {
            delimiters.contains(&c) || c.is_whitespace() || c == '>'
        });
        let after_ok = after.map_or(true, |c| {
            delimiters.contains(&c) || c.is_whitespace() || c == '<'
        });
        if before_ok && after_ok {
            return true;
        }
        search_start = abs_pos + 1;
    }
    false
}

/// Returns `true` if `content` contains a reference to `name` surrounded by
/// common delimiters.  Case-insensitive.
#[allow(dead_code)]
fn content_mentions(content: &str, name: &str) -> bool {
    content_mentions_lowered(&content.to_lowercase(), &name.to_lowercase())
}

// ── module ────────────────────────────────────────────────────────────────────

/// Cross-Referencer module.
pub struct SfpCrossref {
    client: Client,
    resolver: TokioAsyncResolver,
}

impl Default for SfpCrossref {
    fn default() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                .user_agent("Mozilla/5.0 (compatible; spiderfoot-rust/0.1)")
                .danger_accept_invalid_certs(true) // mirrors verify=False in Python
                .build()
                .expect("Failed to build reqwest Client"),
            resolver: TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()),
        }
    }
}

impl SfpCrossref {
    fn check_base(options: &ModuleOptions) -> bool {
        options
            .custom
            .get("checkbase")
            .map(|v| v.trim().to_lowercase() != "false")
            .unwrap_or(true)
    }

    /// Attempt to resolve `fqdn` via DNS (A or AAAA).
    /// Returns `true` if at least one record was found.
    /// Mirrors the Python `sf.resolveHost` / `sf.resolveHost6` guard.
    async fn resolves(&self, fqdn: &str) -> bool {
        self.resolver.lookup_ip(fqdn).await.is_ok()
    }

    /// Fetch `url`, respecting `options.timeout_seconds` and capping the
    /// response body at [`MAX_BODY_BYTES`].  Returns `None` on any error,
    /// non-2xx status, or empty body.
    async fn fetch(&self, url: &str, options: &ModuleOptions) -> Option<String> {
        let timeout_secs = if options.timeout_seconds > 0 {
            options.timeout_seconds
        } else {
            DEFAULT_TIMEOUT_SECS
        };

        let mut req = self
            .client
            .get(url)
            .timeout(Duration::from_secs(timeout_secs));
        if !options.user_agent.is_empty() {
            req = req.header(reqwest::header::USER_AGENT, &options.user_agent);
        }

        let resp = req.send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }

        let bytes = resp.bytes().await.ok()?;
        let truncated = if bytes.len() as u64 > MAX_BODY_BYTES {
            &bytes[..MAX_BODY_BYTES as usize]
        } else {
            &bytes
        };
        let text = String::from_utf8_lossy(truncated).to_string();
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    /// Check whether `content` mentions any of the `target_names`.
    /// Lowercases `content` once and reuses it for every name check.
    fn any_name_mentioned(content: &str, target_names: &[String]) -> bool {
        if target_names.is_empty() {
            return false;
        }
        let lower_content = content.to_lowercase();
        // target_names are already stored lowercased (normalised when parsed)
        target_names
            .iter()
            .any(|name| content_mentions_lowered(&lower_content, name))
    }
}

#[async_trait]
impl SpiderfootModule for SfpCrossref {
    fn name(&self) -> &'static str {
        "sfp_crossref"
    }

    fn description(&self) -> &'static str {
        "Identify whether other domains are associated ('Affiliates') of the target \
         by looking for links back to the target site(s)."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &[
            "LINKED_URL_EXTERNAL",
            "SIMILARDOMAIN",
            "CO_HOSTED_SITE",
            "DARKNET_MENTION_URL",
        ]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &["AFFILIATE_INTERNET_NAME", "AFFILIATE_WEB_CONTENT"]
    }

    fn tags(&self) -> &'static [&'static str] {
        &["active", "recon", "crawling"]
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
                &format!("sfp_crossref: skipping unsupported target type: {}", kind),
            );
            return Ok(());
        }

        // Derive the URL to probe.
        let raw = target.value();
        let url: String = match kind {
            "SIMILARDOMAIN" | "CO_HOSTED_SITE" => {
                format!("http://{}", raw.trim().to_lowercase())
            }
            _ => raw.trim().to_string(), // LINKED_URL_EXTERNAL, DARKNET_MENTION_URL
        };

        // Extract the FQDN so we can check it is truly external.
        let fqdn = match url_fqdn(&url) {
            Some(f) => f,
            None => {
                emitter.log(
                    LogLevel::Debug,
                    &format!("sfp_crossref: cannot parse FQDN from URL: {url}"),
                );
                return Ok(());
            }
        };

        // Collect the scan target's names from ModuleOptions.
        // Convention: "target_names" key holds a comma-separated list of names
        // the engine has registered for the current scan target.
        let target_names: Vec<String> = options
            .custom
            .get("target_names")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        if target_names.is_empty() {
            emitter.log(
                LogLevel::Debug,
                "sfp_crossref: no target_names configured; nothing to cross-reference against",
            );
            return Ok(());
        }

        // Skip if the URL's FQDN matches one of the scan target's own names
        // (i.e. this is not actually an external link).
        if target_names
            .iter()
            .any(|n| fqdn == *n || fqdn.ends_with(&format!(".{}", n)))
        {
            emitter.log(
                LogLevel::Debug,
                &format!("sfp_crossref: ignoring {url} — not external to scan target"),
            );
            return Ok(());
        }

        // DNS resolution guard — mirrors Python's resolveHost / resolveHost6 check.
        // Skip hosts that don't resolve to avoid wasting time on dead links.
        if !self.resolves(&fqdn).await {
            emitter.log(
                LogLevel::Debug,
                &format!("sfp_crossref: ignoring {url} — {fqdn} does not resolve"),
            );
            return Ok(());
        }

        // Track fetched URLs to avoid re-fetching the base URL if it equals
        // the exact URL already fetched in Phase 1.
        let mut seen: HashSet<String> = HashSet::new();

        // ── Phase 1: fetch the exact URL ──────────────────────────────────────
        seen.insert(url.clone());

        emitter.log(LogLevel::Debug, &format!("sfp_crossref: fetching {url}"));

        let content = match self.fetch(&url, options).await {
            Some(c) => c,
            None => {
                emitter.log(
                    LogLevel::Debug,
                    &format!("sfp_crossref: no content returned from {url}"),
                );
                // Fall through to base-URL check if applicable.
                String::new()
            }
        };

        let mut matched_url: Option<String> = None;
        let mut matched_content: Option<String> = None;

        if !content.is_empty() && Self::any_name_mentioned(&content, &target_names) {
            matched_url = Some(url.clone());
            matched_content = Some(content);
        }

        // ── Phase 2: fall back to base URL (LINKED_URL_EXTERNAL + checkbase) ─
        if matched_url.is_none() && kind == "LINKED_URL_EXTERNAL" && Self::check_base(options) {
            if let Some(base) = url_base(&url) {
                if base != url && seen.insert(base.clone()) {
                    emitter.log(
                        LogLevel::Debug,
                        &format!("sfp_crossref: checking base URL {base}"),
                    );

                    if let Some(base_content) = self.fetch(&base, options).await {
                        if Self::any_name_mentioned(&base_content, &target_names) {
                            matched_url = Some(base.clone());
                            matched_content = Some(base_content);
                        }
                    }
                }
            }
        }

        // ── Emit results ──────────────────────────────────────────────────────
        let (emit_url, emit_content) = match (matched_url, matched_content) {
            (Some(u), Some(c)) => (u, c),
            _ => {
                emitter.log(
                    LogLevel::Debug,
                    &format!("sfp_crossref: no cross-reference found for {url}"),
                );
                return Ok(());
            }
        };

        let affiliate_fqdn = match url_fqdn(&emit_url) {
            Some(f) => f,
            None => fqdn.clone(),
        };

        emitter.log(
            LogLevel::Info,
            &format!("sfp_crossref: found link to target from affiliate: {emit_url}"),
        );

        emitter.emit(
            "AFFILIATE_INTERNET_NAME",
            self.name(),
            target,
            affiliate_fqdn,
            Some(1.0),
        );

        emitter.emit(
            "AFFILIATE_WEB_CONTENT",
            self.name(),
            target,
            emit_content,
            Some(1.0),
        );

        Ok(())
    }
}

// ── unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── url_fqdn ─────────────────────────────────────────────────────────────

    #[test]
    fn test_url_fqdn_simple() {
        assert_eq!(
            url_fqdn("https://example.com/path?q=1"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_url_fqdn_with_port() {
        assert_eq!(
            url_fqdn("http://example.com:8080/"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_url_fqdn_subdomain() {
        assert_eq!(
            url_fqdn("https://sub.example.com/"),
            Some("sub.example.com".to_string())
        );
    }

    #[test]
    fn test_url_fqdn_invalid() {
        assert_eq!(url_fqdn("not-a-url"), None);
    }

    #[test]
    fn test_url_fqdn_lowercases() {
        assert_eq!(
            url_fqdn("https://EXAMPLE.COM/"),
            Some("example.com".to_string())
        );
    }

    // ── url_base ──────────────────────────────────────────────────────────────

    #[test]
    fn test_url_base_strips_path() {
        assert_eq!(
            url_base("https://example.com/foo/bar?q=1#frag"),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn test_url_base_keeps_port() {
        assert_eq!(
            url_base("http://example.com:9000/path"),
            Some("http://example.com:9000".to_string())
        );
    }

    #[test]
    fn test_url_base_root_url_unchanged() {
        assert_eq!(
            url_base("https://example.com"),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn test_url_base_invalid() {
        assert_eq!(url_base("not-a-url"), None);
    }

    // ── content_mentions ─────────────────────────────────────────────────────

    #[test]
    fn test_content_mentions_space_delimiters() {
        assert!(content_mentions("visit example.com today", "example.com"));
    }

    #[test]
    fn test_content_mentions_slash_delimiters() {
        assert!(content_mentions("href=\"/example.com/\"", "example.com"));
    }

    #[test]
    fn test_content_mentions_quote_delimiters() {
        assert!(content_mentions("\"example.com\"", "example.com"));
    }

    #[test]
    fn test_content_mentions_case_insensitive() {
        assert!(content_mentions(" EXAMPLE.COM ", "example.com"));
    }

    #[test]
    fn test_content_mentions_no_match_substring() {
        // "notexample.com" should NOT match "example.com" because the char
        // before 'e' is 't', not a delimiter.
        assert!(!content_mentions("notexample.com", "example.com"));
    }

    #[test]
    fn test_content_mentions_no_match_absent() {
        assert!(!content_mentions(
            "completely unrelated text",
            "example.com"
        ));
    }

    #[test]
    fn test_content_mentions_empty_name() {
        assert!(!content_mentions("some content", ""));
    }

    #[test]
    fn test_content_mentions_dot_prefix() {
        assert!(content_mentions(".example.com/path", "example.com"));
    }

    // ── check_base option ─────────────────────────────────────────────────────

    #[test]
    fn test_check_base_default_true() {
        let opts = ModuleOptions::default();
        assert!(SfpCrossref::check_base(&opts));
    }

    #[test]
    fn test_check_base_explicit_false() {
        let mut opts = ModuleOptions::default();
        opts.custom
            .insert("checkbase".to_string(), "false".to_string());
        assert!(!SfpCrossref::check_base(&opts));
    }

    #[test]
    fn test_check_base_explicit_true() {
        let mut opts = ModuleOptions::default();
        opts.custom
            .insert("checkbase".to_string(), "true".to_string());
        assert!(SfpCrossref::check_base(&opts));
    }

    // ── any_name_mentioned ────────────────────────────────────────────────────

    #[test]
    fn test_any_name_mentioned_first_name_matches() {
        let names = vec!["target.com".to_string(), "other.com".to_string()];
        assert!(SfpCrossref::any_name_mentioned(
            "see /target.com/ for details",
            &names
        ));
    }

    #[test]
    fn test_any_name_mentioned_second_name_matches() {
        let names = vec!["target.com".to_string(), "other.com".to_string()];
        assert!(SfpCrossref::any_name_mentioned(
            "visit 'other.com' now",
            &names
        ));
    }

    #[test]
    fn test_any_name_mentioned_none_match() {
        let names = vec!["target.com".to_string()];
        assert!(!SfpCrossref::any_name_mentioned(
            "nothing relevant here",
            &names
        ));
    }

    #[test]
    fn test_any_name_mentioned_empty_list() {
        assert!(!SfpCrossref::any_name_mentioned("target.com is here", &[]));
    }

    // ── module metadata ───────────────────────────────────────────────────────

    #[test]
    fn test_module_metadata() {
        let m = SfpCrossref::default();
        assert_eq!(m.name(), "sfp_crossref");
        assert!(m.target_types().contains(&"LINKED_URL_EXTERNAL"));
        assert!(m.target_types().contains(&"SIMILARDOMAIN"));
        assert!(m.target_types().contains(&"CO_HOSTED_SITE"));
        assert!(m.target_types().contains(&"DARKNET_MENTION_URL"));
        assert!(m
            .produced_event_types()
            .contains(&"AFFILIATE_INTERNET_NAME"));
        assert!(m.produced_event_types().contains(&"AFFILIATE_WEB_CONTENT"));
    }
}
