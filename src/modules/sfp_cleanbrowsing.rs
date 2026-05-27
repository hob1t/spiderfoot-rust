use crate::core::{EventEmitter, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::collections::HashSet;
use std::error::Error;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use tokio::sync::Mutex;

pub struct SfpCleanbrowsing {
    seen: Mutex<HashSet<String>>,
    security_resolver: TokioAsyncResolver,
    adult_resolver: TokioAsyncResolver,
    family_resolver: TokioAsyncResolver,
}

impl SfpCleanbrowsing {
    pub fn new() -> Self {
        let security_ns = ["185.228.168.9", "185.228.169.9"];
        let adult_ns = ["185.228.168.10", "185.228.169.11"];
        let family_ns = ["185.228.168.168", "185.228.168.169"];

        Self {
            seen: Mutex::new(HashSet::new()),
            security_resolver: Self::create_resolver(&security_ns),
            adult_resolver: Self::create_resolver(&adult_ns),
            family_resolver: Self::create_resolver(&family_ns),
        }
    }

    fn create_resolver(nameservers: &[&str]) -> TokioAsyncResolver {
        let mut config = ResolverConfig::new();
        for ns in nameservers {
            if let Ok(ip) = ns.parse::<IpAddr>() {
                config.add_name_server(NameServerConfig {
                    socket_addr: SocketAddr::new(ip, 53),
                    protocol: hickory_resolver::config::Protocol::Udp,
                    tls_dns_name: None,
                    trust_negative_responses: false,
                    bind_addr: None,
                });
            }
        }
        TokioAsyncResolver::tokio(config, ResolverOpts::default())
    }

    async fn dns_lookup(
        resolver: TokioAsyncResolver,
        fqdn: String,
        dns_override: Option<Vec<IpAddr>>,
    ) -> bool {
        if let Some(overrides) = dns_override {
            return !overrides.is_empty();
        }

        match resolver.lookup_ip(fqdn).await {
            Ok(lookup) => lookup.into_iter().next().is_some(),
            Err(_) => false,
        }
    }

    async fn join_all<T>(futures: Vec<Pin<Box<dyn Future<Output = T> + Send>>>) -> Vec<T> {
        let mut results = Vec::with_capacity(futures.len());
        for f in futures {
            results.push(f.await);
        }
        results
    }
}

impl Default for SfpCleanbrowsing {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SpiderfootModule for SfpCleanbrowsing {
    fn name(&self) -> &'static str {
        "CleanBrowsing.org"
    }

    fn description(&self) -> &'static str {
        "Check if a host would be blocked by CleanBrowsing.org DNS content filters."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &["INTERNET_NAME", "AFFILIATE_INTERNET_NAME", "CO_HOSTED_SITE"]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &[
            "BLACKLISTED_INTERNET_NAME",
            "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            "BLACKLISTED_COHOST",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST",
        ]
    }

    fn tags(&self) -> &'static [&'static str] {
        &["Reputation Systems"]
    }

    async fn execute(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.execute_inner(target, options, emitter, None, None, None)
            .await
    }
}

impl SfpCleanbrowsing {
    pub async fn execute_inner(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
        security_override: Option<&[IpAddr]>,
        adult_override: Option<&[IpAddr]>,
        family_override: Option<&[IpAddr]>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let event_data = target.value();

        {
            let mut seen = self.seen.lock().await;
            if seen.contains(event_data) {
                return Ok(());
            }
            seen.insert(event_data.to_string());
        }

        let (malicious_type, blacklist_type) = match target.kind() {
            "INTERNET_NAME" | "DOMAIN" => ("MALICIOUS_INTERNET_NAME", "BLACKLISTED_INTERNET_NAME"),
            "AFFILIATE_INTERNET_NAME" | "AFFILIATE_DOMAIN_WHOIS" => (
                "MALICIOUS_AFFILIATE_INTERNET_NAME",
                "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            ),
            "CO_HOSTED_SITE" | "CO_HOSTED_SITE_DOMAIN_WHOIS" => {
                ("MALICIOUS_COHOST", "BLACKLISTED_COHOST")
            }
            _ => return Ok(()),
        };

        let check_security = options.get_bool("check_security", true);
        let check_adult = options.get_bool("check_adult", true);
        let check_family = options.get_bool("check_family", true);

        let mut futures: Vec<Pin<Box<dyn Future<Output = bool> + Send>>> = Vec::new();

        if check_security {
            futures.push(Box::pin(Self::dns_lookup(
                self.security_resolver.clone(),
                event_data.to_string(),
                security_override.map(|o| o.to_vec()),
            )));
        }
        if check_adult {
            futures.push(Box::pin(Self::dns_lookup(
                self.adult_resolver.clone(),
                event_data.to_string(),
                adult_override.map(|o| o.to_vec()),
            )));
        }
        if check_family {
            futures.push(Box::pin(Self::dns_lookup(
                self.family_resolver.clone(),
                event_data.to_string(),
                family_override.map(|o| o.to_vec()),
            )));
        }

        if futures.is_empty() {
            return Ok(());
        }

        let results = Self::join_all(futures).await;
        let mut results_iter = results.into_iter();

        let security = if check_security {
            results_iter.next().unwrap_or(true)
        } else {
            true
        };
        let adult = if check_adult {
            results_iter.next().unwrap_or(true)
        } else {
            true
        };
        let family = if check_family {
            results_iter.next().unwrap_or(true)
        } else {
            true
        };

        if security && adult && family {
            return Ok(());
        }

        if check_security && !security {
            let msg = format!("CleanBrowsing DNS - Security [{}]", event_data);
            emitter.emit(blacklist_type, self.name(), target, msg.clone(), None);
            emitter.emit(malicious_type, self.name(), target, msg, None);
        }
        if check_adult && !adult {
            let msg = format!("CleanBrowsing DNS - Adult [{}]", event_data);
            emitter.emit(blacklist_type, self.name(), target, msg, None);
        }
        if check_family && !family {
            let msg = format!("CleanBrowsing DNS - Family [{}]", event_data);
            emitter.emit(blacklist_type, self.name(), target, msg, None);
        }

        Ok(())
    }
}
