//! integration tests for `sfp_voipbl`

#[path = "common/mod.rs"]
mod common;

use spiderfoot_rust::core::{ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_voipbl::SfpVoipbl;
use std::collections::HashMap;
use std::error::Error;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn setup_mock_server(content: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/update"))
        .respond_with(ResponseTemplate::new(200).set_body_string(content))
        .mount(&server)
        .await;
    server
}

fn get_options(mock_url: String) -> ModuleOptions {
    let mut custom = HashMap::new();
    custom.insert("_test_url".to_string(), mock_url);
    ModuleOptions {
        custom,
        ..Default::default()
    }
}

#[tokio::test]
async fn test_module_metadata() {
    let module = SfpVoipbl::new();
    assert_eq!(module.name(), "sfp_voipbl");
    assert!(module.description().contains("VoIP Blacklist"));
    assert!(module.target_types().contains(&"IP_ADDRESS"));
}

#[tokio::test]
async fn test_module_execution_listed_ip() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "1.2.3.4\n5.6.7.0/24";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/update", server.uri());

    let module = SfpVoipbl::new();
    let target = Target::IpAddr("1.2.3.4".to_string());
    let options = get_options(mock_url);
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    let emitted = emitter.emitted();
    assert_eq!(emitted.len(), 2);
    let types: Vec<String> = emitted.iter().map(|e| e.0.clone()).collect();
    assert!(types.contains(&"MALICIOUS_IPADDR".to_string()));
    assert!(types.contains(&"BLACKLISTED_IPADDR".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_module_execution_listed_in_subnet() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "5.6.7.0/24";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/update", server.uri());

    let module = SfpVoipbl::new();
    let target = Target::IpAddr("5.6.7.8".to_string());
    let options = get_options(mock_url);
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    let emitted = emitter.emitted();
    assert_eq!(emitted.len(), 2);
    Ok(())
}

#[tokio::test]
async fn test_module_execution_netblock_listed() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "1.2.3.4";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/update", server.uri());

    let module = SfpVoipbl::new();
    let target = Target::NetblockWhois("1.2.3.0/24".to_string());
    let options = get_options(mock_url);
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    let emitted = emitter.emitted();
    assert_eq!(emitted.len(), 2);
    let types: Vec<String> = emitted.iter().map(|e| e.0.clone()).collect();
    assert!(types.contains(&"MALICIOUS_NETBLOCK".to_string()));
    assert!(types.contains(&"BLACKLISTED_NETBLOCK".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_module_execution_not_listed() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "1.2.3.4";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/update", server.uri());

    let module = SfpVoipbl::new();
    let target = Target::IpAddr("8.8.8.8".to_string());
    let options = get_options(mock_url);
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    assert_eq!(emitter.emitted().len(), 0);

    Ok(())
}
