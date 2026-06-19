//! integration tests for `sfp_stevenblack_hosts`

#[path = "common/mod.rs"]
mod common;

use spiderfoot_rust::core::{ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_stevenblack_hosts::SfpStevenblackHosts;
use std::collections::HashMap;
use std::error::Error;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn setup_mock_server(content: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hosts"))
        .respond_with(ResponseTemplate::new(200).set_body_string(content))
        .mount(&server)
        .await;
    server
}

fn get_options(mock_url: String) -> ModuleOptions {
    let mut custom = HashMap::new();
    // We need a way to override the URL in the module, or just use a proxy?
    // Looking at sfp_stevenblack_hosts.rs, it uses a hardcoded constant.
    // I should probably have made it configurable for tests.
    custom.insert("_test_url".to_string(), mock_url);
    ModuleOptions {
        custom,
        ..Default::default()
    }
}

#[tokio::test]
async fn test_module_metadata() {
    let module = SfpStevenblackHosts::new();
    assert_eq!(module.name(), "sfp_stevenblack_hosts");
    assert!(module.description().contains("Steven Black Hosts"));
    assert!(module.target_types().contains(&"INTERNET_NAME"));
}

#[tokio::test]
async fn test_module_execution_listed() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "
0.0.0.0 malicious.com
0.0.0.0 another.bad
";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/hosts", server.uri());

    let module = SfpStevenblackHosts::new();
    let target = Target::Domain("malicious.com".to_string());
    let options = get_options(mock_url);
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    let emitted = emitter.emitted();
    assert_eq!(emitted.len(), 2);

    let types: Vec<String> = emitted.iter().map(|e| e.0.clone()).collect();
    assert!(types.contains(&"MALICIOUS_INTERNET_NAME".to_string()));
    assert!(types.contains(&"BLACKLISTED_INTERNET_NAME".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_module_execution_not_listed() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "0.0.0.0 malicious.com";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/hosts", server.uri());

    let module = SfpStevenblackHosts::new();
    let target = Target::Domain("safe.com".to_string());
    let options = get_options(mock_url);
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    assert_eq!(emitter.emitted().len(), 0);

    Ok(())
}
