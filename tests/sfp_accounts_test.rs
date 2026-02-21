// tests/sfp_accounts_test.rs

use spiderfoot_rust::core::{EventEmitter, LogLevel, ModuleOptions, SpiderfootModule, Target};
use spiderfoot_rust::modules::sfp_accounts::SfpAccounts;
use std::error::Error;
use std::sync::{Arc, Mutex};

struct TestEmitter {
    events: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl EventEmitter for TestEmitter {
    fn emit(
        &mut self,
        event_type: &str,
        _source_module: &str,
        _target: &Target,
        data: String,
        _confidence: Option<f32>,
    ) {
        let mut events = self.events.lock().unwrap();
        events.push((event_type.to_string(), _source_module.to_string(), data));
    }

    fn log(&mut self, _level: LogLevel, _message: &str) {
        println!("[{:?}] {}", _level, _message);
    }
}

unsafe impl Send for TestEmitter {}

#[tokio::test]
#[ignore = "live network test – hits real websites, may be rate-limited or flaky"]
async fn live_accounts_check_known_username() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpAccounts::new().await?;
    let test_username = "dummyuser";
    let target = Target::Username(test_username.to_string());
    let options = ModuleOptions::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut emitter = TestEmitter {
        events: events.clone(),
    };

    module.execute(&target, &options, &mut emitter).await?;

    let emitted = events.lock().unwrap().clone();
    println!(
        "[TEST] Emitted {} events for username '{}'",
        emitted.len(),
        test_username
    );

    let found_accounts: Vec<_> = emitted
        .iter()
        .filter(|(t, _, _)| t == "ACCOUNT_ON_SITE")
        .collect();

    assert!(
        !found_accounts.is_empty(),
        "Expected at least some account hits for a known username"
    );

    let reliable_sites = vec!["github.com", "bitbucket.org", "gitlab.com"];
    let has_reliable_hit = emitted.iter().any(|(_, _, url)| {
        reliable_sites
            .iter()
            .any(|site| url.contains(site) && url.contains(test_username))
    });

    assert!(
        has_reliable_hit,
        "Expected at least one reliable site hit (GitHub/Bitbucket/GitLab) for '{}'",
        test_username
    );

    Ok(())
}

#[tokio::test]
async fn module_initialization_smoke() -> Result<(), Box<dyn Error + Send + Sync>> {
    let module = SfpAccounts::new().await?;
    assert_eq!(module.name(), "sfp_accounts");
    // We can't easily access 'sites' now as it's private, but we can check if it initializes.
    Ok(())
}
