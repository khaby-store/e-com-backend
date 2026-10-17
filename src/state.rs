use std::sync::Arc;

use crate::config::Config;
use crate::db::controller::DbController;
use crate::security::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub controller: DbController,
    pub config: Arc<Config>,
    pub limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(controller: DbController, config: Arc<Config>) -> Self {
        let limiter = Arc::new(RateLimiter::new(config.rate_limit_per_minute));
        Self {
            controller,
            config,
            limiter,
        }
    }
}
