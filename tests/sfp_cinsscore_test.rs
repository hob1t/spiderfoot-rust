//! integration tests for `sfp_cinsscore`

#[path = "common/mod.rs"]
mod common;

use spiderfoot_rust::core::{ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_cinsscore::SfpCinsscore;
use std::collections::HashMap;
use std::error::Error;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn setup_mock_server(content: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/list/ci-badguys.txt"))
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
    let module = SfpCinsscore::new();
    assert_eq!(module.name(), "sfp_cinsscore");
    assert!(module.description().contains("CINS"));
    assert!(module.target_types().contains(&"IP-ADDR"));
    assert!(module.target_types().contains(&"NETBLOCK_WHOIS"));
    assert!(module.tags().contains(&"reputation"));
}

#[tokio::test]
async fn test_module_execution_listed_ip() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "# CINS Army List\n1.2.3.4\n5.6.7.0/24";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
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
async fn test_module_execution_ipv6() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "2001:db8::1";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
    let target = Target::IpAddr("2001:db8::1".to_string());
    let options = get_options(mock_url);
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    let emitted = emitter.emitted();
    assert_eq!(emitted.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_module_execution_listed_in_subnet() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "5.6.7.0/24";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
    let target = Target::IpAddr("5.6.7.8".to_string());
    let options = get_options(mock_url);
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    let emitted = emitter.emitted();
    assert_eq!(emitted.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_module_execution_netblock_with_listed_ip() -> Result<(), Box<dyn Error + Send + Sync>>
{
    let content = "1.2.3.4";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
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
async fn test_module_execution_netblock_with_listed_subnet(
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "5.6.7.0/24";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
    let target = Target::NetblockWhois("5.6.7.0/23".to_string());
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
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
    let target = Target::IpAddr("8.8.8.8".to_string());
    let options = get_options(mock_url);
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    assert_eq!(emitter.emitted().len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_module_execution_affiliate_ipaddr() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "1.2.3.4";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
    let target = Target::Other("AFFILIATE_IPADDR".to_string(), "1.2.3.4".to_string());
    let options = get_options(mock_url);
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    let emitted = emitter.emitted();
    assert_eq!(emitted.len(), 2);
    let types: Vec<String> = emitted.iter().map(|e| e.0.clone()).collect();
    assert!(types.contains(&"MALICIOUS_AFFILIATE_IPADDR".to_string()));
    assert!(types.contains(&"BLACKLISTED_AFFILIATE_IPADDR".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_module_execution_netblock_disabled() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "1.2.3.4";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
    let target = Target::NetblockWhois("1.2.3.0/24".to_string());
    let mut custom = HashMap::new();
    custom.insert("_test_url".to_string(), mock_url);
    custom.insert("checknetblocks".to_string(), "false".to_string());
    let options = ModuleOptions {
        custom,
        ..Default::default()
    };
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    assert_eq!(emitter.emitted().len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_module_execution_subnet_check_disabled() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "1.2.3.4";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
    let target = Target::Other("NETBLOCK_MEMBER".to_string(), "1.2.3.0/24".to_string());
    let mut custom = HashMap::new();
    custom.insert("_test_url".to_string(), mock_url);
    custom.insert("checksubnets".to_string(), "false".to_string());
    let options = ModuleOptions {
        custom,
        ..Default::default()
    };
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    assert_eq!(emitter.emitted().len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_module_execution_affiliate_check_disabled() -> Result<(), Box<dyn Error + Send + Sync>>
{
    let content = "1.2.3.4";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
    let target = Target::Other("AFFILIATE_IPADDR".to_string(), "1.2.3.4".to_string());
    let mut custom = HashMap::new();
    custom.insert("_test_url".to_string(), mock_url);
    custom.insert("checkaffiliates".to_string(), "false".to_string());
    let options = ModuleOptions {
        custom,
        ..Default::default()
    };
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    assert_eq!(emitter.emitted().len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_deduplication() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "1.2.3.4";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
    let target = Target::IpAddr("1.2.3.4".to_string());
    let options = get_options(mock_url.clone());
    let mut emitter = common::TestEmitter::new();

    // First execution
    module.execute(&target, &options, &mut emitter).await?;
    assert_eq!(emitter.emitted().len(), 2);

    // Second execution with same target (should be deduped)
    module.execute(&target, &options, &mut emitter).await?;
    assert_eq!(emitter.emitted().len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_netblock_member_event() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "192.168.0.0/16";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
    let target = Target::Other("NETBLOCK_MEMBER".to_string(), "192.168.1.0/24".to_string());
    let options = get_options(mock_url);
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    let emitted = emitter.emitted();
    assert_eq!(emitted.len(), 2);
    let types: Vec<String> = emitted.iter().map(|e| e.0.clone()).collect();
    assert!(types.contains(&"MALICIOUS_SUBNET".to_string()));
    assert!(types.contains(&"BLACKLISTED_SUBNET".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_mixed_ipv4_ipv6_list() -> Result<(), Box<dyn Error + Send + Sync>> {
    let content = "1.2.3.4\n2001:db8::1\n5.6.7.0/24\n2001:db8::/32";
    let server = setup_mock_server(content).await;
    let mock_url = format!("{}/list/ci-badguys.txt", server.uri());

    let module = SfpCinsscore::new();
    let target = Target::IpAddr("2001:db8::1".to_string());
    let options = get_options(mock_url);
    let mut emitter = common::TestEmitter::new();

    module.execute(&target, &options, &mut emitter).await?;

    let emitted = emitter.emitted();
    assert_eq!(emitted.len(), 2);

    Ok(())
}
