use crate::core::{EventEmitter, ModuleOptions, SpiderfootModule, Target};
use async_trait::async_trait;
use reqwest::Client;
use std::error::Error;
use std::time::Duration;

pub struct SfpSpider {
    client: Client,
}

impl Default for SfpSpider {
    fn default() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("spiderfoot-rust/0.1")
                .build()
                .unwrap(),
        }
    }
}

#[async_trait]
impl SpiderfootModule for SfpSpider {
    fn name(&self) -> &'static str {
        "sfp_spider"
    }

    fn description(&self) -> &'static str {
        "Simple spider to fetch root page content of a domain."
    }

    fn target_types(&self) -> &'static [&'static str] {
        &["DOMAIN", "URL"]
    }

    fn produced_event_types(&self) -> &'static [&'static str] {
        &["TARGET_WEB_CONTENT"]
    }

    async fn execute(
        &self,
        target: &Target,
        _options: &ModuleOptions,
        emitter: &mut (dyn EventEmitter + Send),
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let url = match target {
            Target::Domain(d) => format!("https://{}", d),
            Target::Url(u) => u.to_string(),
            _ => return Ok(()),
        };

        match self.client.get(&url).send().await {
            Ok(resp) => {
                let final_url = resp.url().to_string();
                if let Ok(body) = resp.text().await {
                    emitter.emit(
                        "TARGET_WEB_CONTENT",
                        self.name(),
                        target,
                        body.clone(),
                        Some(1.0),
                    );
                    // Also emit a WebContent target for modules that can use it
                    let web_content_target = Target::WebContent {
                        url: final_url,
                        content: body.clone(),
                    };
                    emitter.emit(
                        "TARGET_WEB_CONTENT_URL",
                        self.name(),
                        &web_content_target,
                        body,
                        Some(1.0),
                    );
                }
            }
            Err(e) => {
                emitter.log(
                    crate::core::LogLevel::Error,
                    &format!("Failed to fetch {}: {}", url, e),
                );
            }
        }

        Ok(())
    }
}
