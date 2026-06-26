use crate::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use dashmap::DashSet;
use reqwest::Client;
use std::collections::HashSet;
use std::error::Error;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

// ── constants ─────────────────────────────────────────────────────────────────

const CLEANTALK_URL: &str = "https://iplists.firehol.org/files/cleantalk_7d.ipset";
const DEFAULT_CACHE_PERIOD_HOURS: u64 = 18;

// ── helper types ─────────────────────────────────────────────────────────────

struct CachedList {
    ips: HashSet<IpAddr>,
    subnets: Vec<ipnet::IpNet>,
    fetched_at: Instant,
}

// ── module struct ─────────────────────────────────────────────────────────────

pub struct SfpCleantalk {
    client: Client,
    cache: Arc<RwLock<Option<Arc<CachedList>>>>,
    seen: Arc<DashSet<String>>,
    error_state: Arc<AtomicBool>,
}

impl SfpCleantalk {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            cache: Arc::new(RwLock::new(None)),
            seen: Arc::new(DashSet::new()),
            error_state: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn get_blacklist(
        &self,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Option<Arc<CachedList>> {
        let cache_period =
            Duration::from_secs(options.get_u64("cacheperiod", DEFAULT_CACHE_PERIOD_HOURS) * 3600);

        {
            let cache = self.cache.read().await;
            if let Some(ref list) = *cache {
                if list.fetched_at.elapsed() < cache_period {
                    return Some(Arc::clone(list));
                }
            }
        }

        let mut cache = self.cache.write().await;
        // Re-check after acquiring write lock
        if let Some(ref list) = *cache {
            if list.fetched_at.elapsed() < cache_period {
                return Some(Arc::clone(list));
            }
        }

        emitter.log(LogLevel::Info, "Fetching CleanTalk Spam List...");
        let url = options
            .custom
            .get("_test_url")
            .map(|s| s.as_str())
            .unwrap_or(CLEANTALK_URL);

        let res = match self.client.get(url).send().await {
            Ok(r) => r,
            Err(e) => {
                emitter.log(
                    LogLevel::Error,
                    &format!("Failed to fetch CleanTalk Spam List: {}", e),
                );
                self.error_state.store(true, Ordering::Relaxed);
                return None;
            }
        };

        if !res.status().is_success() {
            emitter.log(
                LogLevel::Error,
                &format!(
                    "Unexpected HTTP response from CleanTalk Spam List: {}",
                    res.status()
                ),
            );
            self.error_state.store(true, Ordering::Relaxed);
            return None;
        }

        let body = match res.text().await {
            Ok(t) => t,
            Err(e) => {
                emitter.log(
                    LogLevel::Error,
                    &format!("Failed to read CleanTalk Spam List body: {}", e),
                );
                self.error_state.store(true, Ordering::Relaxed);
                return None;
            }
        };

        let (ips, subnets) = self.parse_blacklist(&body);
        let list = Arc::new(CachedList {
            ips,
            subnets,
            fetched_at: Instant::now(),
        });

        *cache = Some(Arc::clone(&list));

        Some(list)
    }

    fn parse_blacklist(&self, content: &str) -> (HashSet<IpAddr>, Vec<ipnet::IpNet>) {
        let mut ips = HashSet::new();
        let mut subnets = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.contains('/') {
                if let Ok(net) = line.parse::<ipnet::IpNet>() {
                    subnets.push(net);
                }
            } else if let Ok(ip) = line.parse::<IpAddr>() {
                ips.insert(ip);
            }
        }
        (ips, subnets)
    }

    async fn execute_inner(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if self.error_state.load(Ordering::Relaxed) {
            return Ok(());
        }

        let event_data = target.value().trim().to_string();
        if event_data.is_empty() {
            return Ok(());
        }

        if !self.seen.insert(event_data.clone()) {
            return Ok(());
        }

        let kind = target.kind();
        let (malicious_type, blacklist_type, is_netblock) = match kind {
            "IP_ADDRESS" | "IP-ADDR" => ("MALICIOUS_IPADDR", "BLACKLISTED_IPADDR", false),
            "AFFILIATE_IPADDR" => {
                if !options.get_bool("checkaffiliates", true) {
                    return Ok(());
                }
                (
                    "MALICIOUS_AFFILIATE_IPADDR",
                    "BLACKLISTED_AFFILIATE_IPADDR",
                    false,
                )
            }
            "NETBLOCK_OWNER" | "NETBLOCK_WHOIS" => {
                if !options.get_bool("checknetblocks", true) {
                    return Ok(());
                }
                ("MALICIOUS_NETBLOCK", "BLACKLISTED_NETBLOCK", true)
            }
            "NETBLOCK_MEMBER" => {
                if !options.get_bool("checksubnets", true) {
                    return Ok(());
                }
                ("MALICIOUS_SUBNET", "BLACKLISTED_SUBNET", true)
            }
            _ => return Ok(()),
        };

        let blacklist = match self.get_blacklist(options, emitter).await {
            Some(b) => b,
            None => return Ok(()),
        };

        let mut found = false;
        if is_netblock {
            if let Ok(target_net) = event_data.parse::<ipnet::IpNet>() {
                // Check if any blacklisted IP is in the target netblock
                for ip in &blacklist.ips {
                    if target_net.contains(ip) {
                        found = true;
                        break;
                    }
                }
                if !found {
                    // Check if any blacklisted subnet overlaps with the target netblock
                    for net in &blacklist.subnets {
                        match (target_net, net) {
                            (ipnet::IpNet::V4(t4), ipnet::IpNet::V4(n4)) => {
                                if t4.contains(n4) || n4.contains(&t4) {
                                    found = true;
                                    break;
                                }
                            }
                            (ipnet::IpNet::V6(t6), ipnet::IpNet::V6(n6)) => {
                                if t6.contains(n6) || n6.contains(&t6) {
                                    found = true;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        } else if let Ok(ip) = event_data.parse::<IpAddr>() {
            if blacklist.ips.contains(&ip) {
                found = true;
            } else {
                for net in &blacklist.subnets {
                    if net.contains(&ip) {
                        found = true;
                        break;
                    }
                }
            }
        }

        if found {
            let url = CLEANTALK_URL;
            let text = format!("CleanTalk Spam List [{}]\n{}", event_data, url);
            emitter.emit(malicious_type, self.name(), target, text.clone(), Some(1.0));
            emitter.emit(blacklist_type, self.name(), target, text, Some(1.0));
        }

        Ok(())
    }
}

impl Default for SfpCleantalk {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SpiderfootModule for SfpCleantalk {
    fn name(&self) -> &'static str {
        "sfp_cleantalk"
    }

    fn description(&self) -> &'static str {
        "Check if a netblock or IP address is on CleanTalk.org's spam IP list."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &[
            "IP_ADDRESS",
            "IP-ADDR",
            "AFFILIATE_IPADDR",
            "NETBLOCK_MEMBER",
            "NETBLOCK_OWNER",
            "NETBLOCK_WHOIS",
        ]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &[
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_SUBNET",
            "MALICIOUS_NETBLOCK",
        ]
    }

    fn tags(&self) -> &'static [&'static str] {
        &["passive", "reputation", "free"]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_blacklist() {
        let module = SfpCleantalk::new();
        let content = "# Comment\n1.2.3.4\n5.6.7.8/24\n\n9.10.11.12";
        let (ips, subnets) = module.parse_blacklist(content);

        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"9.10.11.12".parse::<IpAddr>().unwrap()));

        assert_eq!(subnets.len(), 1);
        assert_eq!(subnets[0], "5.6.7.8/24".parse::<ipnet::IpNet>().unwrap());
    }
}
