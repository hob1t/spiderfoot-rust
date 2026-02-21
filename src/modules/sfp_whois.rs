// src/modules/sfp_whois.rs

use crate::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use std::error::Error;
use whois_service::{WhoisClient, WhoisResult};  // main types from the crate

#[derive(Default)]
pub struct SfpWhois;

#[async_trait]
impl SpiderfootModule for SfpWhois {
    fn name(&self) -> &'static str {
        "sfp_whois"
    }

    fn description(&self) -> &'static str {
        "Modern RDAP-first WHOIS lookup module with fallback. Extracts registrar, dates (incl. expires_in), contacts, country, etc."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &["DOMAIN", "IP-ADDR"]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &[
            "WHOIS_REGISTRAR",
            "WHOIS_CREATED",
            "WHOIS_UPDATED",
            "WHOIS_EXPIRES",
            "WHOIS_EXPIRES_IN_DAYS",   // ← derived / calculated field
            "EMAIL-ADDR",
            "PHONE-NUMBER",
            "COUNTRY_CODE",
            "ORGNAME",                 // often available in RDAP
            // Add more: "NAMESERVER", "STATUS", etc. later
        ]
    }

    fn tags(&self) -> &'static [&'static str] {
        &["passive", "recon", "rdap", "whois"]
    }

    async fn execute(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut dyn EventEmitter,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let query = target.value().trim().to_string();
        let kind = target.kind();

        if !self.target_types().contains(&kind) {
            emitter.log(LogLevel::Debug, &format!("sfp_whois skipping unsupported target: {} ({})", query, kind));
            return Ok(());
        }

        emitter.log(LogLevel::Info, &format!("sfp_whois (RDAP-first) querying: {}", query));

        // Create client (can be cached / reused across calls in real scanner)
        let client = WhoisClient::new().await?;   // auto-configures from IANA bootstrap + hardcoded fast paths

        // Optional: respect timeout from your ModuleOptions
        // let timeout = Duration::from_secs(options.timeout_seconds);

        let result: WhoisResult = client.lookup(&query).await?;

        // ── RDAP / WHOIS unified result ──────────────────────────────────────
        // The crate normalizes fields across RDAP and legacy WHOIS

        if let Some(registrar) = result.registrar_name() {
            emitter.emit("WHOIS_REGISTRAR", self.name(), target, registrar, Some(0.98));
        }

        if let Some(created) = result.created_date() {
            emitter.emit("WHOIS_CREATED", self.name(), target, created.to_rfc3339(), Some(0.95));
        }

        if let Some(updated) = result.last_changed() {
            emitter.emit("WHOIS_UPDATED", self.name(), target, updated.to_rfc3339(), Some(0.95));
        }

        if let Some(expires) = result.expiry_date() {
            emitter.emit("WHOIS_EXPIRES", self.name(), target, expires.to_rfc3339(), Some(0.95));
        }

        // ── Calculated / derived fields (big advantage of this crate) ────────
        if let Some(days) = result.expires_in_days() {   // or .expires_in() → Duration
            emitter.emit(
                "WHOIS_EXPIRES_IN_DAYS",
                self.name(),
                target,
                days.to_string(),
                Some(0.92),
            );
        }

        // Contacts — RDAP gives structured entities (registrant, admin, tech, billing)
        for email in result.emails() {  // .emails() aggregates from all contacts
            emitter.emit("EMAIL-ADDR", self.name(), target, email, Some(0.80));
        }

        for phone in result.phone_numbers() {
            emitter.emit("PHONE-NUMBER", self.name(), target, phone, Some(0.75));
        }

        if let Some(country) = result.country_code() {   // from registrant or RIR
            emitter.emit("COUNTRY_CODE", self.name(), target, country, Some(0.90));
        }

        if let Some(org) = result.organization() {
            emitter.emit("ORGNAME", self.name(), target, org, Some(0.85));
        }

        // Optional: emit raw JSON snippet if you want debugging / full fidelity
        // emitter.emit("WHOIS_RAW_JSON", self.name(), target, result.to_json_string()?, Some(0.50));

        emitter.log(LogLevel::Info, &format!("sfp_whois completed for {} (source: {})", query, result.source_protocol()));

        Ok(())
    }
}