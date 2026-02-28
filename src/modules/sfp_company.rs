use crate::core::{EventEmitter, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use regex::Regex;
use std::collections::HashSet;
use std::error::Error;

pub struct SfpCompany;

impl Default for SfpCompany {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl SpiderfootModule for SfpCompany {
    fn name(&self) -> &'static str {
        "sfp_company"
    }

    fn description(&self) -> &'static str {
        "Identify company names in any obtained data."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &[
            "TARGET_WEB_CONTENT",
            "SSL_CERTIFICATE_ISSUED",
            "DOMAIN_WHOIS",
            "NETBLOCK_WHOIS",
            "AFFILIATE_DOMAIN_WHOIS",
            "AFFILIATE_WEB_CONTENT",
        ]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &["COMPANY_NAME", "AFFILIATE_COMPANY_NAME"]
    }

    async fn execute(
        &self,
        target: &Target,
        options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let event_data = target.value();
        let event_type = target.kind();
        let is_affiliate = event_type.starts_with("AFFILIATE_");

        // filterjscss logic
        let filter_js_css = options
            .custom
            .get("filterjscss")
            .map(|v| v == "true")
            .unwrap_or(true);

        let mut processed_data = event_data.to_string();

        if (event_type == "TARGET_WEB_CONTENT" || event_type == "AFFILIATE_WEB_CONTENT")
            && filter_js_css
        {
            let mut skip = false;
            if let Target::WebContent { url, .. } = target {
                let url_lower = url.to_lowercase();
                if url_lower.ends_with(".js") || url_lower.ends_with(".css") {
                    skip = true;
                }
            }

            if skip {
                return Ok(());
            }

            // Strip script and style tags from the content to avoid false positives.
            let re_script = Regex::new(r#"(?is)<script.*?>.*?</script>"#)?;
            processed_data = re_script.replace_all(&processed_data, " ").to_string();
            let re_style = Regex::new(r#"(?is)<style.*?>.*?</style>"#)?;
            processed_data = re_style.replace_all(&processed_data, " ").to_string();

            // Heuristic to detect if the content is likely pure JS or CSS without HTML tags
            let trimmed = processed_data.trim();
            if (trimmed.starts_with("/*")
                || trimmed.starts_with("//")
                || trimmed.starts_with("body {")
                || trimmed.starts_with("function "))
                && !processed_data.to_lowercase().contains("<html")
            {
                return Ok(());
            }
        }
        if event_type == "SSL_CERTIFICATE_ISSUED" {
            if let Some(pos) = processed_data.find("O=") {
                processed_data = processed_data[pos + 2..].to_string();
            }
        }

        let pattern_match = [
            "LLC",
            "L.L.C",
            "AG",
            "A.G",
            "GmbH",
            "Pty",
            "Ltd",
            "Pte",
            "Inc",
            "INC",
            "Foundation",
            "Corp",
            "SA",
            "S.A",
            "SIA",
            "BV",
            "B.V",
            "NV",
            "N.V",
            "PLC",
            "Limited",
            "Pvt.",
            "SARL",
        ];

        let pattern_match_re = [
            "LLC",
            r#"L\.L\.C\.?"#,
            "AG",
            r#"A\.G\.?"#,
            "GmbH",
            r#"Pty\.?\s+Ltd\.?"#,
            r#"Ltd\.?"#,
            r#"Pte\.?"#,
            r#"Inc\.?"#,
            r#"INC\.?"#,
            "Incorporated",
            "Foundation",
            r#"Corp\.?"#,
            "Corporation",
            "SA",
            r#"S\.A\.?"#,
            "SIA",
            "BV",
            r#"B\.V\.?"#,
            "NV",
            r#"N\.V\.?"#,
            "PLC",
            "Limited",
            r#"Pvt\.?\s+Ltd\.?"#,
            "SARL",
        ];

        let footer_patterns = [Regex::new(
            r#"(?i)(?:©|&copy;|Copyright)\s*(?:\d{4})?\s*([A-Z][A-Za-z0-9\s&,\.\-]{2,})"#,
        )?];

        let title_h1_patterns = [
            Regex::new(r#"(?i)<title>\s*([^<\|\-\s]{2,})"#)?,
            Regex::new(r#"(?i)<h1>\s*([^<]{2,})"#)?,
        ];

        let filter_patterns = [Regex::new("Copyright")?, Regex::new(r#"\d{4}"#)?];

        let mut chunks = Vec::new();
        let mut found_companies = HashSet::new();

        // 1. Check title/H1
        for re in &title_h1_patterns {
            if let Some(cap) = re.captures(&processed_data) {
                if let Some(m) = cap.get(1) {
                    let mut company = m.as_str().trim().to_string();
                    if company.to_lowercase().starts_with("welcome to ") {
                        company = company[11..].trim().to_string();
                    }
                    if company.contains(" - ") {
                        company = company
                            .split(" - ")
                            .next()
                            .unwrap_or(&company)
                            .trim()
                            .to_string();
                    }
                    if company.contains(" | ") {
                        company = company
                            .split(" | ")
                            .next()
                            .unwrap_or(&company)
                            .trim()
                            .to_string();
                    }
                    if !company.is_empty()
                        && !found_companies.contains(&company)
                        && company.len() < 50
                    {
                        let emit_event_type = if is_affiliate {
                            "AFFILIATE_COMPANY_NAME"
                        } else {
                            "COMPANY_NAME"
                        };
                        emitter.emit(
                            emit_event_type,
                            self.name(),
                            target,
                            company.clone(),
                            Some(0.7),
                        );
                        found_companies.insert(company);
                    }
                }
            }
        }

        // 2. Check for footer-style patterns
        for re in &footer_patterns {
            for cap in re.captures_iter(&processed_data) {
                if let Some(m) = cap.get(1) {
                    let company = m.as_str().trim();
                    let mut company = company
                        .split("  ")
                        .next()
                        .unwrap_or(company)
                        .trim()
                        .to_string();
                    if company.to_lowercase().ends_with(". all rights reserved") {
                        company = company[..company.len() - 21].trim().to_string();
                    }
                    if !company.is_empty() && !found_companies.contains(&company) {
                        let emit_event_type = if is_affiliate {
                            "AFFILIATE_COMPANY_NAME"
                        } else {
                            "COMPANY_NAME"
                        };
                        emitter.emit(
                            emit_event_type,
                            self.name(),
                            target,
                            company.clone(),
                            Some(0.8),
                        );
                        found_companies.insert(company);
                    }
                }
            }
        }

        let pattern_suffix = r#"(?:[ \.,:<\)\'\"]|[$\n\r]|$)"#;

        for &pat in &pattern_match {
            let mut start = 0;
            while let Some(m) = processed_data[start..].find(pat) {
                let m_idx = start + m;
                // Boundary check: the suffix must match right after the pattern
                let suffix_start = m_idx + pat.len();
                let suffix_part =
                    &processed_data[suffix_start..(suffix_start + 1).min(processed_data.len())];

                let re_suffix = Regex::new(pattern_suffix)?;
                if suffix_part.is_empty() || re_suffix.is_match(suffix_part) {
                    let chunk_start = m_idx.saturating_sub(50);
                    let chunk_end = (m_idx + pat.len() + 1).min(processed_data.len());
                    chunks.push(&processed_data[chunk_start..chunk_end]);
                }
                start = m_idx + pat.len();
            }
        }

        for chunk in chunks {
            for &pat_re in &pattern_match_re {
                let full_re_str = format!(
                    r#"(?s)((?:[A-Z0-9\(\)][A-Za-z0-9\-&,\.][^ "'';:><]*)?\s*(?:[A-Z0-9\(\)][A-Za-z0-9\-&,\.]?[^ "'';:><]*|[Aa]nd)?\s*(?:[A-Z0-9\(\)][A-Za-z0-9\-&,\.]?[^ "'';:><]*))\s+({}){}"#,
                    pat_re, pattern_suffix
                );
                let re = Regex::new(&full_re_str)?;
                for cap in re.captures_iter(chunk) {
                    if let Some(company_prefix) = cap.get(1) {
                        let prefix_str = company_prefix.as_str().trim();
                        if prefix_str.is_empty() {
                            continue;
                        }

                        let suffix_str = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
                        let mut full_company =
                            format!("{} {}", prefix_str, suffix_str).trim().to_string();

                        // Filtering
                        let mut filtered = false;
                        for f_re in &filter_patterns {
                            if f_re.is_match(&full_company) {
                                filtered = true;
                                break;
                            }
                        }

                        if !filtered && !full_company.is_empty() {
                            if full_company.ends_with('.') || full_company.ends_with(',') {
                                full_company.pop();
                            }
                            if !found_companies.contains(&full_company) {
                                let emit_event_type = if is_affiliate {
                                    "AFFILIATE_COMPANY_NAME"
                                } else {
                                    "COMPANY_NAME"
                                };
                                emitter.emit(
                                    emit_event_type,
                                    self.name(),
                                    target,
                                    full_company.clone(),
                                    Some(1.0),
                                );
                                found_companies.insert(full_company);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
