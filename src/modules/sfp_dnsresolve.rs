use crate::core::{EventEmitter, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::error::Error;
use std::net::IpAddr;

pub struct SfpDnsResolve;

impl Default for SfpDnsResolve {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl SpiderfootModule for SfpDnsResolve {
    fn name(&self) -> &'static str {
        "sfp_dnsresolve"
    }

    fn description(&self) -> &'static str {
        "Resolves IP addresses, hostnames and other DNS records."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &["DOMAIN", "IP-ADDR", "IPV6-ADDR", "INTERNET_NAME"]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &[
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "DNS_NAME",
            "AFFILIATE_DNS_NAME",
            "PROVIDER_DNS_NAME",
            "DNS_RECORD",
        ]
    }

    fn tags(&self) -> &'static [&'static str] {
        &["passive", "recon"]
    }

    async fn execute(
        &self,
        target: &Target,
        _options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let query = target.value().trim().to_string();
        let kind = target.kind();

        if !self.target_types().contains(&kind) {
            emitter.log(
                crate::core::LogLevel::Debug,
                &format!(
                    "sfp_dnsresolve skipping unsupported target: {} ({})",
                    query, kind
                ),
            );
            return Ok(());
        }

        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        match kind {
            "DOMAIN" | "INTERNET_NAME" => {
                // Forward resolution: A and AAAA
                if let Ok(lookup) = resolver.lookup_ip(&query).await {
                    for ip in lookup.iter() {
                        match ip {
                            IpAddr::V4(v4) => {
                                emitter.emit(
                                    "IP_ADDRESS",
                                    self.name(),
                                    target,
                                    v4.to_string(),
                                    Some(1.0),
                                );
                            }
                            IpAddr::V6(v6) => {
                                emitter.emit(
                                    "IPV6_ADDRESS",
                                    self.name(),
                                    target,
                                    v6.to_string(),
                                    Some(1.0),
                                );
                            }
                        }
                    }
                }

                // Other DNS records (MX, NS, TXT, CNAME)
                // For a real implementation, we would check more record types
                if let Ok(mx_lookup) = resolver.mx_lookup(&query).await {
                    for mx in mx_lookup.iter() {
                        emitter.emit(
                            "DNS_RECORD",
                            self.name(),
                            target,
                            format!("MX: {}", mx.exchange()),
                            Some(1.0),
                        );
                        // Also emit the exchange as a DNS_NAME if it's within scope
                        emitter.emit(
                            "DNS_NAME",
                            self.name(),
                            target,
                            mx.exchange().to_utf8(),
                            Some(1.0),
                        );
                    }
                }

                if let Ok(ns_lookup) = resolver.ns_lookup(&query).await {
                    for ns in ns_lookup.iter() {
                        emitter.emit(
                            "DNS_RECORD",
                            self.name(),
                            target,
                            format!("NS: {}", ns.to_utf8()),
                            Some(1.0),
                        );
                        emitter.emit("DNS_NAME", self.name(), target, ns.to_utf8(), Some(1.0));
                    }
                }

                if let Ok(txt_lookup) = resolver.txt_lookup(&query).await {
                    for txt in txt_lookup.iter() {
                        let txt_str = txt
                            .iter()
                            .map(|b| String::from_utf8_lossy(b))
                            .collect::<Vec<_>>()
                            .join("");
                        emitter.emit(
                            "DNS_RECORD",
                            self.name(),
                            target,
                            format!("TXT: {}", txt_str),
                            Some(1.0),
                        );
                    }
                }
            }
            "IP-ADDR" | "IPV6-ADDR" => {
                // Reverse resolution: PTR
                if let Ok(ip) = query.parse::<IpAddr>() {
                    if let Ok(ptr_lookup) = resolver.reverse_lookup(ip).await {
                        for ptr in ptr_lookup.iter() {
                            emitter.emit("DNS_NAME", self.name(), target, ptr.to_utf8(), Some(1.0));
                        }
                    }
                }
            }
            _ => {
                emitter.log(
                    crate::core::LogLevel::Warn,
                    &format!("Unsupported target type for DNS resolution: {}", kind),
                );
            }
        }

        Ok(())
    }
}
