// src/modules/sfp_google_tag_manager.rs

use crate::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use regex::Regex;
use std::collections::HashSet;
use std::error::Error;

#[derive(Default)]
pub struct SfpGoogleTagManager;

impl SfpGoogleTagManager {
    fn is_valid_hostname(&self, hostname: &str) -> bool {
        if hostname.is_empty() || hostname.len() > 255 {
            return false;
        }
        let hostname = hostname.trim_end_matches('.');
        for part in hostname.split('.') {
            if part.is_empty() || part.len() > 63 {
                return false;
            }
            if part.starts_with('-') || part.ends_with('-') {
                return false;
            }
            for c in part.chars() {
                if !c.is_alphanumeric() && c != '-' && c != '_' {
                    return false;
                }
            }
        }
        true
    }

    async fn query_google_tag_id(
        &self,
        tag_id: &str,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<HashSet<String>, Box<dyn Error + Send + Sync>> {
        let url = format!("https://www.googletagmanager.com/gtm.js?id={}", tag_id);

        let client = reqwest::Client::builder()
            .user_agent(&options.user_agent)
            .timeout(std::time::Duration::from_secs(options.timeout_seconds))
            .build()?;

        let res = client.get(&url).send().await?;

        if !res.status().is_success() {
            emitter.log(LogLevel::Debug, &format!("Invalid GTM tag id: {}", tag_id));
            return Ok(HashSet::new());
        }

        let data = res.text().await?;
        if data.is_empty() {
            emitter.log(
                LogLevel::Debug,
                &format!("Empty response for GTM tag id: {}", tag_id),
            );
            return Ok(HashSet::new());
        }

        let mut hosts = HashSet::new();

        // Regex 1: "map","key","(.+?)"
        let re1 = Regex::new(r#""map","key","([^"]+)""#).unwrap();
        for cap in re1.captures_iter(&data) {
            let host = &cap[1];
            if host.contains('.') && self.is_valid_hostname(host) {
                hosts.insert(host.to_string());
            }
        }

        // Regex 2: ,"arg1":"(.+?)"
        let re2 = Regex::new(r#","arg1":"([^"]+)""#).unwrap();
        for cap in re2.captures_iter(&data) {
            let host = &cap[1];
            if host.contains('.') && self.is_valid_hostname(host) {
                hosts.insert(host.to_string());
            }
        }

        // Extract URLs (simplified version of SpiderFootHelpers.extractUrlsFromText)
        // The original code replaces \/ with / first
        let data_clean = data.replace(r"\/", "/");
        let url_re = Regex::new(r#"https?://[^\s"']+"#).unwrap();
        for cap in url_re.captures_iter(&data_clean) {
            let url_str = &cap[0];
            if let Ok(parsed_url) = reqwest::Url::parse(url_str) {
                if let Some(host) = parsed_url.host_str() {
                    if host.contains('.') {
                        hosts.insert(host.to_string());
                    }
                }
            }
        }

        Ok(hosts)
    }

    // Helper to check if a hostname is "local" or within target scope.
    // In a real SpiderFoot, this uses the target configuration.
    // For now, we'll implement a simple version or use a placeholder.
    fn is_in_scope(&self, host: &str, target: &Target) -> bool {
        // This is a simplification. SpiderFoot has complex logic for this.
        // We'll check if the host ends with the target domain if the target is a domain.
        match target {
            Target::Domain(d) => host == d || host.ends_with(&format!(".{}", d)),
            _ => false, // Default to affiliate if we can't be sure
        }
    }

    async fn process_tag_id(
        &self,
        tag_id: &str,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let hosts = self.query_google_tag_id(tag_id, options, emitter).await?;

        if hosts.is_empty() {
            emitter.log(LogLevel::Info, &format!("No hosts found for {}", tag_id));
            return Ok(());
        }

        emitter.log(
            LogLevel::Info,
            &format!("Retrieved {} results for {}", hosts.len(), tag_id),
        );

        let verify = options
            .custom
            .get("verify")
            .map(|v| v == "true")
            .unwrap_or(true);
        let resolver = if verify {
            Some(TokioAsyncResolver::tokio(
                ResolverConfig::default(),
                ResolverOpts::default(),
            ))
        } else {
            None
        };

        for host in hosts {
            if let Some(ref res) = resolver {
                let resolved = res.lookup_ip(&host).await.is_ok();
                if !resolved {
                    emitter.log(
                        LogLevel::Debug,
                        &format!("Potential host name '{}' could not be resolved", host),
                    );
                    continue;
                }
            }

            let in_scope = self.is_in_scope(&host, target);

            let (evt_type, dom_evt_type) = if in_scope {
                ("INTERNET_NAME", "DOMAIN_NAME")
            } else {
                ("AFFILIATE_INTERNET_NAME", "AFFILIATE_DOMAIN_NAME")
            };

            emitter.emit(evt_type, self.name(), target, host.clone(), Some(1.0));

            // In SpiderFoot, we'd check if it's a domain using a TLD list.
            // For now, we'll just emit it if it looks like a domain (contains a dot).
            // Usually INTERNET_NAME and DOMAIN_NAME are emitted together if it's a FQDN.
            emitter.emit(dom_evt_type, self.name(), target, host, Some(1.0));
        }

        Ok(())
    }
}

#[async_trait]
impl SpiderfootModule for SfpGoogleTagManager {
    fn name(&self) -> &'static str {
        "sfp_google_tag_manager"
    }

    fn description(&self) -> &'static str {
        "Search Google Tag Manager (GTM) for hosts sharing the same GTM code."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &["WEB_ANALYTICS_ID", "TARGET_WEB_CONTENT"]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &[
            "DOMAIN_NAME",
            "INTERNET_NAME",
            "AFFILIATE_DOMAIN_NAME",
            "AFFILIATE_INTERNET_NAME",
        ]
    }

    fn tags(&self) -> &'static [&'static str] {
        &["passive", "recon"]
    }

    async fn execute(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let event_data = target.value();

        match target.kind() {
            "WEB_ANALYTICS_ID" => {
                // Expected format: "Google Tag Manager: GTM-XXXXXX"
                let parts: Vec<&str> = event_data.split(": ").collect();
                if parts.len() != 2 || parts[0] != "Google Tag Manager" {
                    emitter.log(
                        LogLevel::Debug,
                        &format!("sfp_google_tag_manager skipping: {}", event_data),
                    );
                    return Ok(());
                }

                let tag_id = parts[1];
                self.process_tag_id(tag_id, target, options, emitter).await
            }
            "TARGET_WEB_CONTENT" => {
                // Search for GTM IDs in the web content
                // Regex for GTM-XXXXXX
                let re = Regex::new(r"GTM-[A-Z0-9]+").unwrap();
                let mut tag_ids = HashSet::new();
                for cap in re.captures_iter(event_data) {
                    tag_ids.insert(cap[0].to_string());
                }

                for tag_id in tag_ids {
                    let gtm_id_event = format!("Google Tag Manager: {}", tag_id);
                    emitter.emit(
                        "WEB_ANALYTICS_ID",
                        self.name(),
                        target,
                        gtm_id_event,
                        Some(1.0),
                    );
                    self.process_tag_id(&tag_id, target, options, emitter)
                        .await?;
                }
                Ok(())
            }
            _ => {
                emitter.log(
                    LogLevel::Debug,
                    &format!("sfp_google_tag_manager skipping: {}", target.kind()),
                );
                Ok(())
            }
        }
    }
}
