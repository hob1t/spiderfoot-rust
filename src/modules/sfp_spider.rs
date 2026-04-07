//! # sfp_spider — Web Spider / Crawler
//!
//! Ported from the Python SpiderFoot module `sfp_spider`.
//!
//! ## What it does
//! Performs a bounded BFS crawl starting from the root URL of a `DOMAIN` or
//! `URL` target.  For every page visited it:
//!
//! * Emits `TARGET_WEB_CONTENT` with the raw HTML body.
//! * Extracts all `<a href>`, `<img src>`, `<script src>`, `<link href>`,
//!   `<form action>` and `<iframe src>` attributes.
//! * Emits `LINKED_URL_INTERNAL` for in-scope links (same eTLD+1).
//! * Emits `LINKED_URL_EXTERNAL` for out-of-scope links.
//! * Emits `INTERNET_NAME` for every unique sub-domain found on internal links.
//!
//! ## Scope
//! A URL is *in-scope* when its registered domain (eTLD+1) matches the
//! registered domain of the seed URL.  Sub-domains are therefore in-scope
//! for crawling purposes (same behaviour as the Python original).
//!
//! ## Options (via `ModuleOptions`)
//! | field / key              | default | description |
//! |--------------------------|---------|-------------|
//! | `max_pages`              | `10`    | Maximum number of pages to crawl |
//! | `timeout_seconds`        | `30`    | Per-request HTTP timeout |
//! | `user_agent`             | `"spiderfoot-rust/0.1"` | User-Agent header |
//! | custom `"max_depth"`     | `"3"`   | Maximum BFS depth |
//! | custom `"filter_mime"`   | `"true"`| Skip non-HTML responses |
//!
//! ## Events consumed
//! `DOMAIN`, `URL`
//!
//! ## Events produced
//! `TARGET_WEB_CONTENT`, `LINKED_URL_INTERNAL`, `LINKED_URL_EXTERNAL`,
//! `INTERNET_NAME`

use crate::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use reqwest::{Client, Url};
use scraper::{Html, Selector};
use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::sync::LazyLock;
use std::time::Duration;

// ── constants ─────────────────────────────────────────────────────────────────

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_PAGES: u32 = 10;
const DEFAULT_MAX_DEPTH: u32 = 3;
/// Maximum response body accepted (10 MB).
const MAX_BODY_BYTES: usize = 10_000_000;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Return the *registered domain* (eTLD+1) for a URL, or `None` if the URL
/// cannot be parsed or has no host.
///
/// Uses the [`addr`] crate which ships a bundled public-suffix list.
/// For IP addresses (IPv4 or IPv6) and localhost, returns the host itself
/// so that the spider can still crawl them (e.g. in tests with wiremock).
pub(crate) fn registered_domain(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?;

    // IP addresses have no registered domain — return the host verbatim so
    // the spider treats the entire IP as its own "domain" scope.
    if parsed
        .host()
        .map(|h| matches!(h, url::Host::Ipv4(_) | url::Host::Ipv6(_)))
        .unwrap_or(false)
    {
        return Some(host.to_string());
    }

    // "localhost" is not in the public-suffix list; handle it explicitly.
    if host.eq_ignore_ascii_case("localhost") {
        return Some("localhost".to_string());
    }

    // addr::parse_domain_name handles plain hostnames.
    let domain = addr::parse_domain_name(host).ok()?;
    // registered() returns the eTLD+1 part, e.g. "example.com" for
    // "sub.example.com".  Returns None for bare TLDs or IP addresses.
    Some(domain.root()?.to_string())
}

/// Extract the FQDN (host) from a URL, lowercased and without trailing dot.
pub(crate) fn url_host(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    parsed
        .host_str()
        .map(|h| h.trim_end_matches('.').to_lowercase())
}

/// Resolve `href` relative to `base`, returning an absolute URL string.
/// Strips the fragment component.
pub(crate) fn resolve_url(base: &Url, href: &str) -> Option<String> {
    let joined = base.join(href).ok()?;
    // Only follow http/https
    if joined.scheme() != "http" && joined.scheme() != "https" {
        return None;
    }
    // Strip fragment — fragments are client-side and shouldn't trigger a new
    // HTTP request.
    let mut clean = joined;
    clean.set_fragment(None);
    Some(clean.into())
}

// ── static selectors ──────────────────────────────────────────────────────────

/// Pre-compiled CSS selectors paired with the attribute to extract.
/// Using `LazyLock` ensures they are built exactly once for the lifetime of
/// the process rather than on every page fetch.
static LINK_SELECTORS: LazyLock<Vec<(Selector, &'static str)>> = LazyLock::new(|| {
    vec![
        (Selector::parse("a").unwrap(), "href"),
        (Selector::parse("img").unwrap(), "src"),
        (Selector::parse("script").unwrap(), "src"),
        (Selector::parse("link").unwrap(), "href"),
        (Selector::parse("form").unwrap(), "action"),
        (Selector::parse("iframe").unwrap(), "src"),
    ]
});

/// Extract all link targets from an HTML document.
///
/// Covers the attributes that the Python original inspects:
/// `<a href>`, `<img src>`, `<script src>`, `<link href>`,
/// `<form action>`, `<iframe src>`.
///
/// Selectors are compiled once at first call via [`LINK_SELECTORS`].
pub(crate) fn extract_links(html: &str, base: &Url) -> Vec<String> {
    let document = Html::parse_document(html);
    let mut links = Vec::new();

    for (sel, attr) in LINK_SELECTORS.iter() {
        for element in document.select(sel) {
            if let Some(val) = element.value().attr(attr) {
                if let Some(abs) = resolve_url(base, val) {
                    links.push(abs);
                }
            }
        }
    }

    links
}

/// Returns `true` when the `Content-Type` header indicates an HTML response.
pub(crate) fn is_html_content_type(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.contains("text/html") || ct.contains("application/xhtml")
}

// ── module ────────────────────────────────────────────────────────────────────

pub struct SfpSpider {
    client: Client,
}

impl SfpSpider {
    /// Parse `max_depth` from `ModuleOptions::custom`.
    fn max_depth(options: &ModuleOptions) -> u32 {
        options
            .custom
            .get("max_depth")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(DEFAULT_MAX_DEPTH)
    }

    /// Parse `filter_mime` from `ModuleOptions::custom`.
    fn filter_mime(options: &ModuleOptions) -> bool {
        options
            .custom
            .get("filter_mime")
            .map(|v| v.trim().to_lowercase() != "false")
            .unwrap_or(true)
    }

    /// Effective `max_pages` from `ModuleOptions` (falls back to the constant).
    fn max_pages(options: &ModuleOptions) -> u32 {
        if options.max_pages > 0 {
            options.max_pages
        } else {
            DEFAULT_MAX_PAGES
        }
    }

    /// Effective `timeout_seconds` from `ModuleOptions`.
    fn timeout(options: &ModuleOptions) -> Duration {
        let secs = if options.timeout_seconds > 0 {
            options.timeout_seconds
        } else {
            DEFAULT_TIMEOUT_SECS
        };
        Duration::from_secs(secs)
    }

    /// Fetch a URL and return `(final_url, body)`.
    ///
    /// Returns `None` when:
    /// * The request fails (network error, timeout, …).
    /// * The response status is not 2xx.
    /// * `filter_mime` is `true` (via `options`) and the `Content-Type` is not HTML.
    /// * The body is empty.
    ///
    /// The `filter_mime` flag is derived from `options` internally so callers
    /// do not need to compute it separately.
    async fn fetch(
        &self,
        url: &str,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Option<(String, String)> {
        let mut req = self.client.get(url).timeout(Self::timeout(options));

        if !options.user_agent.is_empty() {
            req = req.header(reqwest::header::USER_AGENT, &options.user_agent);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                emitter.log(
                    LogLevel::Debug,
                    &format!("sfp_spider: fetch error for {url}: {e}"),
                );
                return None;
            }
        };

        if !resp.status().is_success() {
            emitter.log(
                LogLevel::Debug,
                &format!(
                    "sfp_spider: non-2xx status {} for {url}",
                    resp.status().as_u16()
                ),
            );
            return None;
        }

        // Content-Type filter — derived from options directly, no separate arg needed.
        if Self::filter_mime(options) {
            let ct = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !is_html_content_type(ct) {
                emitter.log(
                    LogLevel::Debug,
                    &format!("sfp_spider: skipping non-HTML content-type '{ct}' for {url}"),
                );
                return None;
            }
        }

        let final_url = resp.url().to_string();

        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                emitter.log(
                    LogLevel::Debug,
                    &format!("sfp_spider: body read error for {url}: {e}"),
                );
                return None;
            }
        };

        let truncated = if bytes.len() > MAX_BODY_BYTES {
            &bytes[..MAX_BODY_BYTES]
        } else {
            &bytes[..]
        };

        // `into_owned()` is the idiomatic way to convert `Cow<str>` → `String`.
        let body = String::from_utf8_lossy(truncated).into_owned();
        if body.is_empty() {
            return None;
        }

        Some((final_url, body))
    }
}

impl Default for SfpSpider {
    fn default() -> Self {
        // TLS certificate verification is intentionally enabled in the default
        // client.  Pass `custom["verify_tls"] = "false"` in `ModuleOptions` to
        // disable it at runtime via `SfpSpider::new_with_options`.
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                .user_agent("spiderfoot-rust/0.1")
                .redirect(reqwest::redirect::Policy::limited(5))
                .build()
                .expect("failed to build reqwest Client"),
        }
    }
}

impl SfpSpider {
    /// Build an `SfpSpider` whose HTTP client is configured from `options`.
    ///
    /// Reads `options.custom["verify_tls"]`; when set to `"false"` TLS
    /// certificate verification is disabled (equivalent to the removed
    /// `danger_accept_invalid_certs(true)` that was previously hardcoded).
    pub fn new_with_options(options: &ModuleOptions) -> Result<Self, reqwest::Error> {
        let verify_tls = options
            .custom
            .get("verify_tls")
            .map(|v| v.trim().to_lowercase() != "false")
            .unwrap_or(true);

        let timeout_secs = if options.timeout_seconds > 0 {
            options.timeout_seconds
        } else {
            DEFAULT_TIMEOUT_SECS
        };

        let ua = if options.user_agent.is_empty() {
            "spiderfoot-rust/0.1".to_string()
        } else {
            options.user_agent.clone()
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent(ua)
            .danger_accept_invalid_certs(!verify_tls)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;

        Ok(Self { client })
    }
}

#[async_trait]
impl SpiderfootModule for SfpSpider {
    fn name(&self) -> &'static str {
        "sfp_spider"
    }

    fn description(&self) -> &'static str {
        "Crawl a web target, extract links, sub-domains and page content."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &["DOMAIN", "URL"]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &[
            "TARGET_WEB_CONTENT",
            "LINKED_URL_INTERNAL",
            "LINKED_URL_EXTERNAL",
            "INTERNET_NAME",
        ]
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
                &format!(
                    "sfp_spider: skipping unsupported target type '{}' (value: {})",
                    kind,
                    target.value()
                ),
            );
            return Ok(());
        }

        // Build the seed URL.
        let seed_url: String = match target {
            Target::Domain(d) => format!("https://{}", d.trim()),
            Target::Url(u) => u.trim().to_string(),
            _ => return Ok(()),
        };

        let seed_registered = match registered_domain(&seed_url) {
            Some(rd) => rd,
            None => {
                emitter.log(
                    LogLevel::Error,
                    &format!("sfp_spider: cannot determine registered domain for {seed_url}"),
                );
                return Ok(());
            }
        };

        let max_pages = Self::max_pages(options);
        let max_depth = Self::max_depth(options);

        emitter.log(
            LogLevel::Info,
            &format!(
                "sfp_spider: starting crawl of {seed_url} \
                 (max_pages={max_pages}, max_depth={max_depth}, \
                 seed_domain={seed_registered})"
            ),
        );

        // Emit INTERNET_NAME for the seed host immediately so that callers
        // always receive at least one INTERNET_NAME even when the page has
        // no internal links (e.g. a single-page site or an IP-based URL in
        // tests).
        let mut emitted_names: HashSet<String> = HashSet::new();
        if let Some(seed_host) = url_host(&seed_url) {
            emitted_names.insert(seed_host.clone());
            emitter.emit("INTERNET_NAME", self.name(), target, seed_host, Some(1.0));
        }

        // BFS queue: (url, depth)
        let mut queue: VecDeque<(String, u32)> = VecDeque::new();
        queue.push_back((seed_url.clone(), 0));

        // Track visited URLs to avoid re-fetching.
        let mut visited: HashSet<String> = HashSet::new();
        // Track URLs already enqueued so that `LINKED_URL_INTERNAL` is emitted
        // exactly once per URL.  Without this a URL referenced on N pages at
        // the same BFS depth would be pushed N times before any of those
        // entries are dequeued and marked visited.
        let mut queued: HashSet<String> = HashSet::new();
        queued.insert(seed_url.clone());
        // Track emitted external links to avoid duplicates.
        let mut emitted_external: HashSet<String> = HashSet::new();

        let mut pages_fetched: u32 = 0;

        while let Some((url, depth)) = queue.pop_front() {
            if pages_fetched >= max_pages {
                emitter.log(
                    LogLevel::Debug,
                    &format!("sfp_spider: reached max_pages={max_pages}, stopping crawl"),
                );
                break;
            }

            if !visited.insert(url.clone()) {
                continue; // already seen
            }

            emitter.log(
                LogLevel::Debug,
                &format!("sfp_spider: fetching [{depth}] {url}"),
            );

            let (final_url, body) = match self.fetch(&url, options, emitter).await {
                Some(pair) => pair,
                None => continue,
            };

            pages_fetched += 1;

            // If the request was redirected, mark the final URL visited too.
            if final_url != url {
                visited.insert(final_url.clone());
            }

            // ── Extract links before emitting content (avoids cloning body) ──
            let links = if depth < max_depth {
                match Url::parse(&final_url) {
                    Ok(base) => extract_links(&body, &base),
                    Err(_) => vec![],
                }
            } else {
                emitter.log(
                    LogLevel::Debug,
                    &format!(
                        "sfp_spider: max depth {max_depth} reached at {final_url}, not following links"
                    ),
                );
                vec![]
            };

            // ── Emit page content (moves body — no clone needed) ──────────────
            emitter.emit("TARGET_WEB_CONTENT", self.name(), target, body, Some(1.0));

            for link in links {
                let link_registered = registered_domain(&link);

                let is_internal = link_registered
                    .as_deref()
                    .map(|rd| rd == seed_registered)
                    .unwrap_or(false);

                if is_internal {
                    // Emit LINKED_URL_INTERNAL and enqueue only the first time
                    // this URL is encountered.  `queued` is checked instead of
                    // `visited` so that a URL referenced from multiple pages at
                    // the same BFS depth is neither emitted nor enqueued more
                    // than once.
                    if !visited.contains(&link) && queued.insert(link.clone()) {
                        emitter.emit(
                            "LINKED_URL_INTERNAL",
                            self.name(),
                            target,
                            link.clone(),
                            Some(1.0),
                        );
                        // Enqueue for crawling.
                        queue.push_back((link.clone(), depth + 1));
                    }

                    // Emit INTERNET_NAME for sub-domains not yet seen.
                    if let Some(host) = url_host(&link) {
                        if emitted_names.insert(host.clone()) {
                            emitter.emit("INTERNET_NAME", self.name(), target, host, Some(1.0));
                        }
                    }
                } else {
                    // External link — emit once per unique URL.
                    if emitted_external.insert(link.clone()) {
                        emitter.emit("LINKED_URL_EXTERNAL", self.name(), target, link, Some(1.0));
                    }
                }
            }
        }

        emitter.log(
            LogLevel::Info,
            &format!("sfp_spider: crawl finished — {pages_fetched} page(s) fetched"),
        );

        Ok(())
    }
}

// ── unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── registered_domain ─────────────────────────────────────────────────────

    #[test]
    fn test_registered_domain_simple() {
        assert_eq!(
            registered_domain("https://example.com/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_registered_domain_subdomain() {
        assert_eq!(
            registered_domain("https://sub.example.com/"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_registered_domain_deep_subdomain() {
        assert_eq!(
            registered_domain("https://a.b.c.example.co.uk/"),
            Some("example.co.uk".to_string())
        );
    }

    #[test]
    fn test_registered_domain_invalid() {
        assert_eq!(registered_domain("not-a-url"), None);
    }

    // ── url_host ──────────────────────────────────────────────────────────────

    #[test]
    fn test_url_host_simple() {
        assert_eq!(
            url_host("https://example.com/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_url_host_subdomain() {
        assert_eq!(
            url_host("https://www.example.com/"),
            Some("www.example.com".to_string())
        );
    }

    #[test]
    fn test_url_host_lowercased() {
        assert_eq!(
            url_host("https://EXAMPLE.COM/"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_url_host_invalid() {
        assert_eq!(url_host("not-a-url"), None);
    }

    // ── resolve_url ───────────────────────────────────────────────────────────

    #[test]
    fn test_resolve_url_absolute() {
        let base = Url::parse("https://example.com/page").unwrap();
        assert_eq!(
            resolve_url(&base, "https://other.com/foo"),
            Some("https://other.com/foo".to_string())
        );
    }

    #[test]
    fn test_resolve_url_relative_path() {
        let base = Url::parse("https://example.com/dir/page.html").unwrap();
        assert_eq!(
            resolve_url(&base, "other.html"),
            Some("https://example.com/dir/other.html".to_string())
        );
    }

    #[test]
    fn test_resolve_url_absolute_path() {
        let base = Url::parse("https://example.com/dir/page.html").unwrap();
        assert_eq!(
            resolve_url(&base, "/about"),
            Some("https://example.com/about".to_string())
        );
    }

    #[test]
    fn test_resolve_url_strips_fragment() {
        let base = Url::parse("https://example.com/").unwrap();
        assert_eq!(
            resolve_url(&base, "/page#section"),
            Some("https://example.com/page".to_string())
        );
    }

    #[test]
    fn test_resolve_url_rejects_mailto() {
        let base = Url::parse("https://example.com/").unwrap();
        assert_eq!(resolve_url(&base, "mailto:user@example.com"), None);
    }

    #[test]
    fn test_resolve_url_rejects_javascript() {
        let base = Url::parse("https://example.com/").unwrap();
        assert_eq!(resolve_url(&base, "javascript:void(0)"), None);
    }

    // ── is_html_content_type ──────────────────────────────────────────────────

    #[test]
    fn test_is_html_content_type_html() {
        assert!(is_html_content_type("text/html; charset=utf-8"));
    }

    #[test]
    fn test_is_html_content_type_xhtml() {
        assert!(is_html_content_type("application/xhtml+xml"));
    }

    #[test]
    fn test_is_html_content_type_json() {
        assert!(!is_html_content_type("application/json"));
    }

    #[test]
    fn test_is_html_content_type_image() {
        assert!(!is_html_content_type("image/png"));
    }

    #[test]
    fn test_is_html_content_type_empty() {
        assert!(!is_html_content_type(""));
    }

    // ── extract_links ─────────────────────────────────────────────────────────

    #[test]
    fn test_extract_links_anchor() {
        let base = Url::parse("https://example.com/").unwrap();
        let html = r#"<a href="/about">About</a>"#;
        let links = extract_links(html, &base);
        assert!(links.contains(&"https://example.com/about".to_string()));
    }

    #[test]
    fn test_extract_links_img_src() {
        let base = Url::parse("https://example.com/").unwrap();
        let html = r#"<img src="/img/logo.png">"#;
        let links = extract_links(html, &base);
        assert!(links.contains(&"https://example.com/img/logo.png".to_string()));
    }

    #[test]
    fn test_extract_links_script_src() {
        let base = Url::parse("https://example.com/").unwrap();
        let html = r#"<script src="/js/app.js"></script>"#;
        let links = extract_links(html, &base);
        assert!(links.contains(&"https://example.com/js/app.js".to_string()));
    }

    #[test]
    fn test_extract_links_form_action() {
        let base = Url::parse("https://example.com/").unwrap();
        let html = r#"<form action="/submit"></form>"#;
        let links = extract_links(html, &base);
        assert!(links.contains(&"https://example.com/submit".to_string()));
    }

    #[test]
    fn test_extract_links_iframe_src() {
        let base = Url::parse("https://example.com/").unwrap();
        let html = r#"<iframe src="https://cdn.example.com/widget"></iframe>"#;
        let links = extract_links(html, &base);
        assert!(links.contains(&"https://cdn.example.com/widget".to_string()));
    }

    #[test]
    fn test_extract_links_link_href() {
        let base = Url::parse("https://example.com/").unwrap();
        let html = r#"<link rel="stylesheet" href="/css/style.css">"#;
        let links = extract_links(html, &base);
        assert!(links.contains(&"https://example.com/css/style.css".to_string()));
    }

    #[test]
    fn test_extract_links_skips_mailto() {
        let base = Url::parse("https://example.com/").unwrap();
        let html = r#"<a href="mailto:info@example.com">Contact</a>"#;
        let links = extract_links(html, &base);
        assert!(
            links.is_empty(),
            "mailto: links should be filtered out, got: {links:?}"
        );
    }

    #[test]
    fn test_extract_links_external() {
        let base = Url::parse("https://example.com/").unwrap();
        let html = r#"<a href="https://external.org/page">Ext</a>"#;
        let links = extract_links(html, &base);
        assert!(links.contains(&"https://external.org/page".to_string()));
    }

    #[test]
    fn test_extract_links_multiple() {
        let base = Url::parse("https://example.com/").unwrap();
        let html = r#"
            <a href="/a">A</a>
            <a href="/b">B</a>
            <img src="/img.png">
        "#;
        let links = extract_links(html, &base);
        assert!(links.contains(&"https://example.com/a".to_string()));
        assert!(links.contains(&"https://example.com/b".to_string()));
        assert!(links.contains(&"https://example.com/img.png".to_string()));
    }

    // ── option parsing ────────────────────────────────────────────────────────

    #[test]
    fn test_max_depth_default() {
        let opts = ModuleOptions::default();
        assert_eq!(SfpSpider::max_depth(&opts), DEFAULT_MAX_DEPTH);
    }

    #[test]
    fn test_max_depth_custom() {
        let mut opts = ModuleOptions::default();
        opts.custom.insert("max_depth".to_string(), "5".to_string());
        assert_eq!(SfpSpider::max_depth(&opts), 5);
    }

    #[test]
    fn test_max_depth_invalid_falls_back_to_default() {
        let mut opts = ModuleOptions::default();
        opts.custom
            .insert("max_depth".to_string(), "not_a_number".to_string());
        assert_eq!(SfpSpider::max_depth(&opts), DEFAULT_MAX_DEPTH);
    }

    #[test]
    fn test_filter_mime_default_true() {
        let opts = ModuleOptions::default();
        assert!(SfpSpider::filter_mime(&opts));
    }

    #[test]
    fn test_filter_mime_explicit_false() {
        let mut opts = ModuleOptions::default();
        opts.custom
            .insert("filter_mime".to_string(), "false".to_string());
        assert!(!SfpSpider::filter_mime(&opts));
    }

    #[test]
    fn test_max_pages_from_options() {
        let mut opts = ModuleOptions::default();
        opts.max_pages = 42;
        assert_eq!(SfpSpider::max_pages(&opts), 42);
    }

    #[test]
    fn test_max_pages_zero_falls_back_to_default() {
        let opts = ModuleOptions::default(); // max_pages = 0
        assert_eq!(SfpSpider::max_pages(&opts), DEFAULT_MAX_PAGES);
    }

    // ── module metadata ───────────────────────────────────────────────────────

    #[test]
    fn test_module_metadata() {
        let m = SfpSpider::default();
        assert_eq!(m.name(), "sfp_spider");
        assert!(!m.description().is_empty());
        assert!(m.target_types().contains(&"DOMAIN"));
        assert!(m.target_types().contains(&"URL"));
        assert!(m.produced_event_types().contains(&"TARGET_WEB_CONTENT"));
        assert!(m.produced_event_types().contains(&"LINKED_URL_INTERNAL"));
        assert!(m.produced_event_types().contains(&"LINKED_URL_EXTERNAL"));
        assert!(m.produced_event_types().contains(&"INTERNET_NAME"));
        assert!(m.tags().contains(&"active"));
        assert!(m.tags().contains(&"crawling"));
    }
}
