use crate::core::{EventEmitter, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::collections::HashSet;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use tokio::sync::Mutex;

pub struct SfpComodo {
    seen: Mutex<HashSet<String>>,
    comodo_resolver: TokioAsyncResolver,
    standard_resolver: TokioAsyncResolver,
}

impl SfpComodo {
    pub fn new() -> Self {
        let nameservers = ["8.26.56.26", "8.20.247.20"];
        Self {
            seen: Mutex::new(HashSet::new()),
            comodo_resolver: Self::create_resolver(&nameservers),
            standard_resolver: TokioAsyncResolver::tokio(
                ResolverConfig::default(),
                ResolverOpts::default(),
            ),
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

    async fn dns_resolve(
        &self,
        fqdn: &str,
        resolver: &TokioAsyncResolver,
        dns_override: Option<&[IpAddr]>,
    ) -> bool {
        if let Some(overrides) = dns_override {
            return !overrides.is_empty();
        }

        match resolver.lookup_ip(fqdn).await {
            Ok(lookup) => lookup.into_iter().next().is_some(),
            Err(_) => false,
        }
    }
}

impl Default for SfpComodo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SpiderfootModule for SfpComodo {
    fn name(&self) -> &'static str {
        "Comodo Secure DNS"
    }

    fn description(&self) -> &'static str {
        "Check if a host would be blocked by Comodo Secure DNS."
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
        self.execute_inner(target, options, emitter, None, None)
            .await
    }
}

impl SfpComodo {
    pub async fn execute_inner(
        &self,
        target: &Target,
        _options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
        comodo_override: Option<&[IpAddr]>,
        standard_override: Option<&[IpAddr]>,
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
            "INTERNET_NAME" | "DOMAIN" | "CO_HOSTED_SITE" => {
                ("MALICIOUS_INTERNET_NAME", "BLACKLISTED_INTERNET_NAME")
            }
            "AFFILIATE_INTERNET_NAME" | "AFFILIATE_DOMAIN_WHOIS" => (
                "MALICIOUS_AFFILIATE_INTERNET_NAME",
                "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            ),
            "CO_HOSTED_SITE_DOMAIN_WHOIS" => ("MALICIOUS_COHOST", "BLACKLISTED_COHOST"),
            _ => return Ok(()),
        };

        // Check that it resolves via standard DNS first.
        // It becomes a valid malicious host only if NOT resolved by Comodo Secure DNS but IS resolved by standard DNS.
        if !self
            .dns_resolve(event_data, &self.standard_resolver, standard_override)
            .await
        {
            return Ok(());
        }

        let blocked = !self
            .dns_resolve(event_data, &self.comodo_resolver, comodo_override)
            .await;

        if blocked {
            let msg = format!("Comodo Secure DNS [{}]", event_data);
            emitter.emit(blacklist_type, self.name(), target, msg.clone(), None);
            emitter.emit(malicious_type, self.name(), target, msg, None);
        }

        Ok(())
    }
}
