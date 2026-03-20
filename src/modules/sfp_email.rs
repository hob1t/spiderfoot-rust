use crate::core::{EventEmitter, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use regex::Regex;
use std::collections::HashSet;
use std::error::Error;
use std::sync::LazyLock;

/// Compiled once at first use; never recompiled on subsequent calls.
static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").expect("valid email regex")
});

/// Generic local-parts that map to `EMAILADDR_GENERIC`.
/// Computed once from the default list; callers that supply a custom
/// `_genericusers` option will build their own set at call time.
static DEFAULT_GENERIC_USERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "admin",
        "webmaster",
        "root",
        "info",
        "support",
        "contact",
        "mail",
        "postmaster",
        "hostmaster",
        "manager",
    ]
    .into_iter()
    .collect()
});

#[derive(Default)]
pub struct SfpEmail;

impl SfpEmail {
    fn extract_emails(text: &str) -> impl Iterator<Item = String> + '_ {
        EMAIL_RE.find_iter(text).map(|m| m.as_str().to_lowercase())
    }

    /// Returns `None` when the caller has not overridden `_genericusers`,
    /// signalling that `DEFAULT_GENERIC_USERS` should be used instead.
    /// This avoids a heap allocation on every `execute` call in the common case.
    fn custom_generic_users(options: &ModuleOptions) -> Option<HashSet<String>> {
        let raw = options.custom.get("_genericusers")?;
        let set = raw
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        Some(set)
    }

    fn valid_host(host: &str) -> bool {
        // Approximation of SpiderFoot's validHost():
        // - must be a valid dot-separated domain name
        // - no empty labels
        // - only [a-z0-9-] per label
        // - each label must not start/end with '-'
        // - must contain at least one dot
        let host = host.trim().trim_matches('.');
        if host.len() > 255 {
            return false;
        }
        if !host.contains('.') {
            return false;
        }

        for label in host.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
            if label.starts_with('-') || label.ends_with('-') {
                return false;
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return false;
            }
        }
        true
    }
}

#[async_trait]
impl SpiderfootModule for SfpEmail {
    fn name(&self) -> &'static str {
        "sfp_email"
    }

    fn description(&self) -> &'static str {
        "Identify e-mail addresses in any obtained data."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &[
            "TARGET_WEB_CONTENT",
            "BASE64_DATA",
            "AFFILIATE_DOMAIN_WHOIS",
            "CO_HOSTED_SITE_DOMAIN_WHOIS",
            "DOMAIN_WHOIS",
            "NETBLOCK_WHOIS",
            "LEAKSITE_CONTENT",
            "RAW_DNS_RECORDS",
            "RAW_FILE_META_DATA",
            "RAW_RIR_DATA",
            "SIMILARDOMAIN_WHOIS",
            "SSL_CERTIFICATE_RAW",
            "SSL_CERTIFICATE_ISSUED",
            "TCP_PORT_OPEN_BANNER",
            "WEBSERVER_BANNER",
            "WEBSERVER_HTTPHEADERS",
        ]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &["EMAILADDR", "EMAILADDR_GENERIC", "AFFILIATE_EMAILADDR"]
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
                crate::core::LogLevel::Debug,
                &format!(
                    "sfp_email skipping unsupported target: {} ({})",
                    target.value(),
                    kind
                ),
            );
            return Ok(());
        }

        let event_data = target.value();
        let is_affiliate_event = kind.starts_with("AFFILIATE_");

        // Use the pre-computed static set unless the caller has overridden
        // `_genericusers` in options — avoiding a heap allocation in the hot path.
        let custom = Self::custom_generic_users(options);
        let generic_users: &dyn Fn(&str) -> bool = match &custom {
            Some(set) => &|local: &str| set.contains(local),
            None => &|local: &str| DEFAULT_GENERIC_USERS.contains(local),
        };

        let mut seen: HashSet<String> = HashSet::new();
        for email in Self::extract_emails(event_data) {
            // Already lowercased by extract_emails; just strip trailing dots.
            let email = email.trim_end_matches('.').to_owned();

            if !seen.insert(email.clone()) {
                continue;
            }

            let (local, domain) = match email.split_once('@') {
                Some(v) => v,
                None => continue,
            };

            let mail_dom = domain.trim_matches('.');
            if !Self::valid_host(mail_dom) {
                continue;
            }

            let evttype = if is_affiliate_event {
                "AFFILIATE_EMAILADDR"
            } else if generic_users(local) {
                "EMAILADDR_GENERIC"
            } else {
                "EMAILADDR"
            };

            emitter.emit(evttype, self.name(), target, email, Some(1.0));
        }

        Ok(())
    }
}
