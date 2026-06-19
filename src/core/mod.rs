// src/core/mod.rs

mod types;

use async_trait::async_trait;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub enum Target {
    Domain(String),
    IpAddr(String),
    Email(String),
    Username(String),
    Hash(String),
    Phone(String),
    Url(String),
    BitcoinAddress(String),
    WebContent { url: String, content: String },
    // WHOIS / raw data blobs — used by sfp_email and other text-mining modules
    DomainWhois(String),
    AffiliateDomainWhois(String),
    CoHostedSiteDomainWhois(String),
    NetblockWhois(String),
    SimilarDomainWhois(String),
    // Raw / banner / certificate data
    Base64Data(String),
    LeaksiteContent(String),
    RawDnsRecords(String),
    RawFileMetaData(String),
    RawRirData(String),
    SslCertificateRaw(String),
    SslCertificateIssued(String),
    TcpPortOpenBanner(String),
    WebserverBanner(String),
    WebserverHttpHeaders(String),
    // Catch-all for future / unknown types
    Other(String, String), // (type_label, value)
}

impl Target {
    pub fn kind(&self) -> &str {
        match self {
            Target::Domain(_) => "DOMAIN",
            Target::IpAddr(_) => "IP-ADDR",
            Target::Email(_) => "EMAIL-ADDR",
            Target::Username(_) => "USERNAME",
            Target::Hash(_) => "HASH",
            Target::Phone(_) => "PHONE-NUMBER",
            Target::Url(_) => "URL",
            Target::BitcoinAddress(_) => "BTC-ADDRESS",
            Target::WebContent { .. } => "TARGET_WEB_CONTENT",
            Target::DomainWhois(_) => "DOMAIN_WHOIS",
            Target::AffiliateDomainWhois(_) => "AFFILIATE_DOMAIN_WHOIS",
            Target::CoHostedSiteDomainWhois(_) => "CO_HOSTED_SITE_DOMAIN_WHOIS",
            Target::NetblockWhois(_) => "NETBLOCK_WHOIS",
            Target::SimilarDomainWhois(_) => "SIMILARDOMAIN_WHOIS",
            Target::Base64Data(_) => "BASE64_DATA",
            Target::LeaksiteContent(_) => "LEAKSITE_CONTENT",
            Target::RawDnsRecords(_) => "RAW_DNS_RECORDS",
            Target::RawFileMetaData(_) => "RAW_FILE_META_DATA",
            Target::RawRirData(_) => "RAW_RIR_DATA",
            Target::SslCertificateRaw(_) => "SSL_CERTIFICATE_RAW",
            Target::SslCertificateIssued(_) => "SSL_CERTIFICATE_ISSUED",
            Target::TcpPortOpenBanner(_) => "TCP_PORT_OPEN_BANNER",
            Target::WebserverBanner(_) => "WEBSERVER_BANNER",
            Target::WebserverHttpHeaders(_) => "WEBSERVER_HTTPHEADERS",
            Target::Other(label, _) => label,
        }
    }

    pub fn value(&self) -> &str {
        match self {
            Target::Domain(v)
            | Target::IpAddr(v)
            | Target::Email(v)
            | Target::Username(v)
            | Target::Hash(v)
            | Target::Phone(v)
            | Target::Url(v)
            | Target::BitcoinAddress(v)
            | Target::DomainWhois(v)
            | Target::AffiliateDomainWhois(v)
            | Target::CoHostedSiteDomainWhois(v)
            | Target::NetblockWhois(v)
            | Target::SimilarDomainWhois(v)
            | Target::Base64Data(v)
            | Target::LeaksiteContent(v)
            | Target::RawDnsRecords(v)
            | Target::RawFileMetaData(v)
            | Target::RawRirData(v)
            | Target::SslCertificateRaw(v)
            | Target::SslCertificateIssued(v)
            | Target::TcpPortOpenBanner(v)
            | Target::WebserverBanner(v)
            | Target::WebserverHttpHeaders(v)
            | Target::Other(_, v) => v,
            Target::WebContent { content, .. } => content,
        }
    }
}

/// Common metadata + execution interface for every SpiderFoot module
#[async_trait]
pub trait SpiderfootModule {
    /// Short, unique module identifier (used in CLI, config, logs)
    /// Examples: "sfp_shodan", "sfp_haveibeenpwned", "sfp_dnsresolve"
    fn name(&self) -> &'static str;

    /// One-sentence description shown in help / module list
    fn description(&self) -> &'static str;

    /// Which target types this module can meaningfully process
    /// Most modules will return 1–3 types
    fn target_types(&self) -> &'static [&'static str];

    /// Which data types this module produces / emits
    /// Very important for the event graph / dependency system
    fn produced_event_types(&self) -> &'static [&'static str];

    /// Optional: tags / categories (recon, passive, active, api, social, etc.)
    fn tags(&self) -> &'static [&'static str] {
        &[]
    }

    /// Main execution entry point
    ///
    /// Returns:
    /// - Ok(Vec<Event>) → new findings / data points
    /// - Err(e) → fatal module error (will be logged)
    ///
    /// Modules should **not panic** — prefer returning an error.
    fn execute<'life0, 'life1, 'life2, 'life3, 'async_trait>(
        &'life0 self,
        target: &'life1 Target,
        options: &'life2 ModuleOptions,
        emitter: &'life3 mut (dyn EventEmitter + Send),
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), Box<dyn Error + Send + Sync>>>
                + Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        Self: Sync + 'async_trait;
}

/// Very simple key-value bag for module configuration
/// Real implementation will likely use typed values + defaults + validation
#[derive(Debug, Clone, Default)]
pub struct ModuleOptions {
    pub api_keys: HashMap<String, String>,
    pub timeout_seconds: u64,
    pub user_agent: String,
    pub max_pages: u32,
    // ... more common settings
    pub custom: HashMap<String, String>,
}

impl ModuleOptions {
    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        match self.custom.get(key) {
            Some(v) => v.to_lowercase().parse::<bool>().unwrap_or(default),
            None => default,
        }
    }

    pub fn get_u64(&self, key: &str, default: u64) -> u64 {
        match self.custom.get(key) {
            Some(v) => v.parse::<u64>().unwrap_or(default),
            None => default,
        }
    }
}

/// Interface modules use to report findings
/// (in real SpiderFoot → this would push to an internal queue / event bus)
pub trait EventEmitter {
    /// Report a new piece of information
    fn emit(
        &mut self,
        event_type: &str,
        source_module: &str,
        target: &Target,
        data: String,
        confidence: Option<f32>, // 0.0–1.0
    );

    /// Optional: report progress / debug / warning messages
    fn log(&mut self, level: LogLevel, message: &str);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Helper — most modules will return this kind of error
#[derive(Debug)]
pub struct ModuleError {
    pub module: &'static str,
    pub message: String,
}

impl fmt::Display for ModuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.module, self.message)
    }
}

impl Error for ModuleError {}
