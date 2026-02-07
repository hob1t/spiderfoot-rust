#![allow(dead_code)]
#![allow(unused_variables)]

use governor::Jitter;
use spiderfoot_rust::rate_limit::{RateLimitManager};
use std::time::{Duration, Instant};

#[tokio::test]
async fn test_burst_behavior() {
    let manager = RateLimitManager::new(2.0, 3);
    let limiter = manager.get_limiter("example.com", Some(2.0), Some(3));

    let start = Instant::now();

    for i in 0..3 {
        limiter.until_ready().await;
        println!("Request {} allowed after {:?}", i + 1, start.elapsed());
    }

    let after_burst = start.elapsed();
    assert!(after_burst < Duration::from_millis(200));

    limiter.until_ready().await;
    let after_fourth = start.elapsed();
    println!("4th request allowed after {:?}", after_fourth);

    assert!(after_fourth >= Duration::from_millis(400));
    assert!(after_fourth < Duration::from_millis(800));
}

#[tokio::test]
async fn test_different_keys_are_independent() {
    let manager = RateLimitManager::new(10.0, 20);
    let lim_a = manager.get_limiter("a.example.com", Some(1.0), Some(1));
    let lim_b = manager.get_limiter("b.example.com", Some(5.0), Some(5));

    let start = Instant::now();

    lim_a.until_ready().await;
    let time_a1 = start.elapsed();

    lim_b.until_ready().await;
    let time_b1 = start.elapsed();

    println!("A first: {:?} | B first: {:?}", time_a1, time_b1);

    lim_a.until_ready().await;
    let time_a2 = start.elapsed();

    assert!(time_b1 < Duration::from_millis(100));
    assert!(time_a2 > Duration::from_millis(900));
}

#[tokio::test]
async fn test_global_limiter_as_safety_net() {
    // 3.0 RPS with a burst of 1 (strictly 3 per second, no initial freebies)
    let manager = RateLimitManager::new(3.0, 1);

    let lim1 = manager.get_limiter("host1", Some(100.0), Some(2));
    let lim2 = manager.get_limiter("host2", Some(100.0), Some(2));
    let lim3 = manager.get_limiter("host3", Some(100.0), Some(2));

    let global = manager.global_limiter();
    let start = Instant::now();

    // 30 iterations * 1 request per iteration = 30 requests
    // At 3 RPS, this should take ~10 seconds
    for _ in 0..30 {
        // These will be instant because 100 RPS is very fast
        lim1.until_ready().await;

        // This is the bottleneck
        global.until_ready().await;
    }

    let total_time = start.elapsed();
    println!("30 global waits took {:?}", total_time);

    // 30 requests / 3 RPS = 10 seconds.
    // We allow some buffer for execution time.
    assert!(total_time >= Duration::from_secs(9));
    assert!(total_time < Duration::from_secs(12));
}

#[tokio::test]
async fn test_jitter_spreads_requests() {
    let manager = RateLimitManager::new(5.0, 5);
    let limiter = manager.get_limiter("test.com", Some(5.0), Some(2)); // small burst for testing

    let mut times = Vec::new();
    let start = Instant::now();

    for _ in 0..8 {
        limiter
            .until_ready_with_jitter(Jitter::up_to(Duration::from_millis(100)))
            .await;
        times.push(start.elapsed());
    }

    println!("Request times: {:?}", times);

    // Skip checking first few diffs (burst window)
    let start_check = 2; // after burst of 2
    for i in start_check..times.len() {
        let diff = times[i] - times[i - 1];
        assert!(
            diff > Duration::from_millis(50),
            "Diff too small: {:?}",
            diff
        );
    }
}
