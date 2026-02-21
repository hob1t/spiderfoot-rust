use crate::core::{EventEmitter, ModuleOptions, SpiderfootModule, Target};
use anyhow::Context;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;

// Minimal struct matching WhatsMyName schema (add more fields as needed)
#[derive(Debug, Clone, Deserialize)]
struct Site {
    name: String,
    #[serde(rename = "uri_check")]
    uri_check: String,
    #[serde(rename = "uri_pretty", default)]
    uri_pretty: Option<String>,
    #[serde(rename = "e_code")]
    expected_code: u16,
    #[serde(rename = "e_string")]
    expected_string: String,
    #[serde(rename = "m_code")]
    _missing_code: Option<u16>,
    #[serde(rename = "m_string")]
    _missing_string: Option<String>,
    #[serde(rename = "cat")]
    _category: Option<String>,
    #[serde(rename = "headers", default)]
    headers: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "post_body", default)]
    _post_body: Option<String>,
    // Add known, strip_bad_char, protection etc. later if needed
}

pub struct SfpAccounts {
    client: Client,
    sites: Arc<Vec<Site>>,
    // Add config later: max_concurrent, rate_per_domain, timeout, etc.
}

impl SfpAccounts {
    pub async fn new() -> anyhow::Result<Self> {
        let client = Client::builder()
            .user_agent("spiderfoot-rust/0.1[](https://github.com/hob1t/spiderfoot-rust)")
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        // Fetch once at creation (or make lazy)
        let sites = Self::load_sites().await?;

        Ok(Self {
            client,
            sites: Arc::new(sites),
        })
    }

    async fn load_sites() -> anyhow::Result<Vec<Site>> {
        let url = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json";
        let resp = reqwest::get(url).await?.json::<serde_json::Value>().await?;

        // The real structure is { "sites": [ ... ] }
        let sites_array = resp["sites"]
            .as_array()
            .context("No 'sites' array in JSON")?;

        let sites: Vec<Site> =
            serde_json::from_value(serde_json::Value::Array(sites_array.clone()))?;
        Ok(sites)
    }
}

#[async_trait]
impl SpiderfootModule for SfpAccounts {
    fn name(&self) -> &'static str {
        "sfp_accounts"
    }

    fn description(&self) -> &'static str {
        "Checks for username existence across hundreds of sites using WebBreacher/WhatsMyName data"
    }

    fn target_types(&self) -> &'static [&'static str] {
        &["USERNAME", "EMAIL-ADDR"]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &["ACCOUNT_ON_SITE"]
    }

    async fn execute(
        &self,
        target: &Target,
        _options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let username = target.value().trim().to_lowercase();

        // Launch concurrent checks
        let mut tasks = vec![];

        for site in self.sites.iter() {
            let site = site.clone();
            let client = self.client.clone();
            let username = username.clone();

            tasks.push(tokio::spawn(async move {
                let site_name = site.name.clone();
                let result = Self::check_site(&client, &site, &username).await;
                match result {
                    Ok(Some(url)) => (url, site_name),
                    _ => ("".to_string(), "".to_string()),
                }
            }));
        }

        // Wait for all and emit
        for task in tasks {
            if let Ok((url, _)) = task.await {
                if !url.is_empty() {
                    emitter.emit("ACCOUNT_ON_SITE", self.name(), target, url, Some(1.0));
                }
            }
        }

        Ok(())
    }
}

impl SfpAccounts {
    async fn check_site(
        client: &Client,
        site: &Site,
        account: &str,
    ) -> anyhow::Result<Option<String>> {
        let url_str = site.uri_check.replace("{account}", account);
        let url = reqwest::Url::parse(&url_str)?;

        let mut req = client.get(url.clone());

        // Add custom headers if present
        if let Some(headers) = &site.headers {
            for (k, v) in headers {
                req = req.header(k.as_str(), v.as_str());
            }
        }

        // TODO: handle POST if post_body exists (use .post() + body)

        let resp = req.send().await?;

        let status = resp.status().as_u16();

        // Basic match logic (expand with missing_string, redirects etc.)
        if status == site.expected_code {
            let body = resp.text().await.unwrap_or_default();

            if body.contains(&site.expected_string) {
                // Found!
                let pretty = site
                    .uri_pretty
                    .as_ref()
                    .map(|p| p.replace("{account}", account))
                    .unwrap_or(url_str);
                return Ok(Some(pretty));
            }
        }

        // Could add missing check here for higher confidence negative

        Ok(None)
    }
}
