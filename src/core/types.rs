use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    // Identity & footprint
    InternetName, // domain name
    IpAddress,
    Netblock,
    Asn,
    AffiliateInternetName,
    AffiliateIpAddr, // or AffiliateIpAddress
    AffiliateNetblock,

    // Personal / contact
    EmailAddr,
    PhoneNumber,
    PersonName,
    Username,

    // Web / tech
    WebserverHttpHeaders,
    WebserverTechnology,
    DomainWhois,
    IpWhois,
    SslCertificate,
    DnsName,
    DnsRecord,

    // Dates / meta
    WhoisCreated,
    WhoisUpdated,
    WhoisRegistrar,
    WhoisRegistrant,
    CountryCode,

    // Others
    WebAnalyticsId,
    WebFrame,
    WebLink,
    PhysicalAddress,
    BitcoinAddress,

    // Internal
    Target,
    LogMessage,
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Optional: map back to original SpiderFoot-style uppercase strings for logs/JSON
        let s = match self {
            Self::InternetName => "INTERNET_NAME",
            Self::IpAddress => "IP_ADDRESS",
            // ... add all others
            Self::LogMessage => "LOG_MESSAGE",
            _ => return write!(f, "{:?}", self),
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub event_type: EventType,
    pub data: String,
    pub module: String,               // module name that produced this event
    pub source_event_id: Option<u64>, // optional parent event ID (for graphing/traceback)
    pub created_at: SystemTime,
    pub confidence: f32, // 0.0..=1.0
}

impl Event {
    pub fn new(event_type: EventType, data: impl Into<String>, module: impl Into<String>) -> Self {
        Self {
            event_type,
            data: data.into(),
            module: module.into(),
            source_event_id: None,
            created_at: SystemTime::now(),
            confidence: 1.0,
        }
    }

    pub fn with_source(mut self, source_id: u64) -> Self {
        self.source_event_id = Some(source_id);
        self
    }
}

// ── Target & ScanContext ────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Target {
    pub primary: String,
    pub target_type: EventType, // e.g. InternetName, IpAddress
    pub scope: HashSet<String>,
    pub exclude: HashSet<String>,
}

#[derive(Clone, Debug)]
pub struct ScanContext {
    pub scan_id: String,
    pub target: Target,
    pub start_time: SystemTime,
    pub config: ScanConfig,
}

#[derive(Clone, Debug, Default)]
pub struct ScanConfig {
    pub user_agent: String,
    pub timeout_seconds: u64,
    pub max_concurrent_requests: usize,
    pub api_keys: std::collections::HashMap<String, String>,
}
