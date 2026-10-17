use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use crate::error::AppError;
use crate::state::AppState;

const WINDOW: Duration = Duration::from_secs(60);
const PRUNE_EVERY: Duration = Duration::from_secs(30);
const MAX_TRACKED_CLIENTS: usize = 8_192;

/// Fixed-window per-client rate limiter kept in process memory.
pub struct RateLimiter {
    limit: u32,
    inner: Mutex<Inner>,
}

struct Inner {
    windows: HashMap<IpAddr, Window>,
    last_prune: Instant,
}

struct Window {
    start: Instant,
    count: u32,
}

pub enum RateDecision {
    Allowed { remaining: u32 },
    Limited { retry_after_secs: u64 },
}

impl RateLimiter {
    pub fn new(limit_per_minute: u32) -> Self {
        Self {
            limit: limit_per_minute,
            inner: Mutex::new(Inner {
                windows: HashMap::new(),
                last_prune: Instant::now(),
            }),
        }
    }

    pub fn limit(&self) -> u32 {
        self.limit
    }

    pub fn check(&self, ip: IpAddr) -> RateDecision {
        if self.limit == 0 {
            return RateDecision::Allowed {
                remaining: u32::MAX,
            };
        }

        let now = Instant::now();
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return RateDecision::Allowed { remaining: 0 },
        };

        if now.duration_since(inner.last_prune) > PRUNE_EVERY {
            inner
                .windows
                .retain(|_, w| now.duration_since(w.start) < WINDOW);
            inner.last_prune = now;
            if inner.windows.len() > MAX_TRACKED_CLIENTS {
                inner.windows.clear();
            }
        }

        let window = inner.windows.entry(ip).or_insert(Window {
            start: now,
            count: 0,
        });
        if now.duration_since(window.start) >= WINDOW {
            window.start = now;
            window.count = 0;
        }

        window.count = window.count.saturating_add(1);
        if window.count > self.limit {
            let elapsed = now.duration_since(window.start);
            let retry = WINDOW.saturating_sub(elapsed).as_secs().saturating_add(1);
            RateDecision::Limited {
                retry_after_secs: retry,
            }
        } else {
            RateDecision::Allowed {
                remaining: self.limit - window.count,
            }
        }
    }
}

/// Rejects any request that does not present a valid `X-API-Key`.
/// Comparison runs in constant time and never short-circuits across keys.
pub async fn require_api_key(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let provided = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::as_bytes);

    let valid = provided.is_some_and(|p| keys_match(p, &state.config.api_keys));
    if !valid {
        tracing::warn!(path = %req.uri().path(), "rejected request with bad api key");
        return Err(AppError::Unauthorized);
    }

    Ok(next.run(req).await)
}

fn keys_match(provided: &[u8], expected: &[Vec<u8>]) -> bool {
    let mut matched = 0u8;
    for key in expected {
        // Always compare the full slice; length mismatch folds into the
        // accumulator instead of early-returning.
        let same_len = u8::from(key.len() == provided.len());
        let same_bytes = if key.len() == provided.len() {
            u8::from(bool::from(key.as_slice().ct_eq(provided)))
        } else {
            0
        };
        matched |= same_len & same_bytes;
    }
    matched == 1
}

/// Fixed-window throttling keyed by peer address, plus rate-limit headers.
pub async fn rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));

    let decision = state.limiter.check(ip);
    let limit_header = HeaderValue::from_str(&state.limiter.limit().to_string())
        .unwrap_or_else(|_| HeaderValue::from_static("0"));

    match decision {
        RateDecision::Limited { retry_after_secs } => {
            tracing::warn!(%ip, "rate limit exceeded");
            let mut res = (
                StatusCode::TOO_MANY_REQUESTS,
                [
                    (
                        header::RETRY_AFTER,
                        HeaderValue::from_str(&retry_after_secs.to_string())
                            .unwrap_or_else(|_| HeaderValue::from_static("60")),
                    ),
                    (HeaderName::from_static("x-ratelimit-limit"), limit_header),
                ],
                axum::Json(serde_json::json!({
                    "error": "rate limit exceeded",
                    "status": 429,
                })),
            )
                .into_response();
            res.headers_mut().insert(
                HeaderName::from_static("x-ratelimit-remaining"),
                HeaderValue::from_static("0"),
            );
            res
        }
        RateDecision::Allowed { remaining } => {
            let mut res = next.run(req).await;
            let headers = res.headers_mut();
            headers.insert(HeaderName::from_static("x-ratelimit-limit"), limit_header);
            if let Ok(v) = HeaderValue::from_str(&remaining.to_string()) {
                headers.insert(HeaderName::from_static("x-ratelimit-remaining"), v);
            }
            headers.insert(
                HeaderName::from_static("x-ratelimit-policy"),
                HeaderValue::from_static("60s-fixed-window"),
            );
            res
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn api_key_comparison() {
        let keys: Vec<Vec<u8>> = vec![b"correct-horse-battery".to_vec()];
        assert!(keys_match(b"correct-horse-battery", &keys));
        assert!(!keys_match(b"wrong-key-wrong-key!", &keys));
        assert!(!keys_match(b"", &keys));
        assert!(!keys_match(b"correct-horse-batter", &keys));
        assert!(!keys_match(b"longer-than-any-key-here", &keys));
        assert!(!keys_match(b"x", &[]));
    }

    #[test]
    fn rate_limiter_enforces_and_recovers() {
        let limiter = RateLimiter::new(3);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..3 {
            assert!(matches!(limiter.check(ip), RateDecision::Allowed { .. }));
        }
        assert!(matches!(limiter.check(ip), RateDecision::Limited { .. }));
        let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(matches!(limiter.check(other), RateDecision::Allowed { .. }));
    }

    #[test]
    fn zero_limit_disables_throttling() {
        let limiter = RateLimiter::new(0);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..100 {
            assert!(matches!(limiter.check(ip), RateDecision::Allowed { .. }));
        }
    }
}
