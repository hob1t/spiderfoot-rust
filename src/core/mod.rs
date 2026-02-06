// src/core/mod.rs

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

/// Represents the thing we're trying to investigate (IP, domain, email, username, hash, etc.)
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
    // Add more common target types as needed
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
            Target::Other(label, _) => label,
        }
    }

    pub fn value(&self) -> &str {
        match self {
            Target::Domain(v) | Target::IpAddr(v) | Target::Email(v) | Target::Username(v)
            | Target::Hash(v) | Target::Phone(v) | Target::Url(v) | Target::BitcoinAddress(v)
            | Target::Other(_, v) => v,
        }
    }
}

/// Common metadata + execution interface for every SpiderFoot module
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
    /// - Ok(Vec<Event>)        → new findings / data points
    /// - Err(e)                → fatal module error (will be logged)
    ///
    /// Modules should **not panic** — prefer returning an error.
    fn execute(
        &self,
        target: &Target,
        options: &ModuleOptions,     // API keys, timeouts, user settings, etc.
        emitter: &mut dyn EventEmitter,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;
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