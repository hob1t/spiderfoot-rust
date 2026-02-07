#![allow(dead_code)]
#![allow(unused_variables)]

use dashmap::DashMap;
use governor::{
    clock::{Clock, QuantaClock},
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
//use nonzero_ext::nonzero;
use std::num::NonZeroU32;
use std::sync::Arc;

// Inner (non-keyed) limiter type — each bucket has its own quota
type InnerLimiter = RateLimiter<
    NotKeyed,
    InMemoryState,
    QuantaClock,
    NoOpMiddleware<<QuantaClock as Clock>::Instant>,
>;

#[derive(Clone)]
pub struct RateLimitManager {
    // Different limiter (different quota) per key
    per_key: Arc<DashMap<String, Arc<InnerLimiter>>>,
    // Global fallback limiter
    global: Arc<InnerLimiter>,
}

impl RateLimitManager {
    pub fn new(global_rps: f32, global_burst: u32) -> Self {
        let global_quota = quota_from_rps_burst(global_rps, global_burst);

        // Fixed: no & here
        let global = Arc::new(RateLimiter::direct_with_clock(
            global_quota,
            Default::default(),
        ));

        Self {
            per_key: Arc::new(DashMap::new()),
            global,
        }
    }

    /// Get or create a limiter for a specific key (domain, api name, etc.)
    /// Uses provided rps/burst if given, otherwise reasonable default
    pub fn get_limiter(
        &self,
        key: &str,
        rps: Option<f32>,
        burst: Option<u32>,
    ) -> Arc<InnerLimiter> {
        let key = key.to_string();

        self.per_key
            .entry(key)
            .or_insert_with(|| {
                let rps = rps.unwrap_or(5.0);
                let burst = burst.unwrap_or(10);
                let quota = quota_from_rps_burst(rps, burst);

                // Fixed: no & here
                Arc::new(RateLimiter::direct_with_clock(quota, Default::default()))
            })
            .value()
            .clone()
    }

    /// Global limiter as fallback/safety net
    pub fn global_limiter(&self) -> Arc<InnerLimiter> {
        self.global.clone()
    }
}

// Helper to create Quota from rps + burst
pub fn quota_from_rps_burst(rps: f32, burst: u32) -> Quota {
    let cells_per_second = rps.ceil().max(1.0) as u32;

    // Use NonZeroU32::new(...).unwrap() since we know .max(1) is > 0
    let nz_cells = NonZeroU32::new(cells_per_second).unwrap();
    let nz_burst = NonZeroU32::new(burst.max(1)).unwrap();

    Quota::per_second(nz_cells).allow_burst(nz_burst)
}
