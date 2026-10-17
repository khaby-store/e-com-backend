use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::db::controller::validate_prefix;
use crate::error::AppError;
use crate::security::{rate_limit, require_api_key};
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let body_limit = state.config.max_body_bytes;

    let protected = Router::new()
        .route("/v1/keys", get(list_keys))
        .route("/v1/k/{key}", get(get_key).put(put_key).delete(delete_key))
        .route("/v1/stats", get(stats))
        .route("/v1/backup", post(backup))
        .route("/v1/flush", post(flush))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));

    Router::new()
        .route("/health", get(health))
        .merge(protected)
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(TraceLayer::new_for_http())
        .layer(cors(state.config.cors_origins.as_slice()))
        .with_state(state)
}

fn cors(origins: &[String]) -> CorsLayer {
    if origins.is_empty() {
        // Nothing configured: emit no CORS headers, so browsers stay
        // same-origin and preflights fail closed.
        return CorsLayer::new();
    }

    let values: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();

    CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::PUT,
            Method::DELETE,
            Method::POST,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, HeaderName::from_static("x-api-key")])
        .expose_headers([
            HeaderName::from_static("x-ratelimit-limit"),
            HeaderName::from_static("x-ratelimit-remaining"),
            HeaderName::from_static("x-ratelimit-policy"),
            header::RETRY_AFTER,
        ])
        .allow_origin(AllowOrigin::list(values))
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn list_keys(
    State(state): State<AppState>,
    Query(q): Query<ListParams>,
) -> Result<Json<Value>, AppError> {
    validate_prefix(&q.prefix).map_err(AppError::from)?;
    let page = state
        .controller
        .keys(&q.prefix, q.limit.clamp(1, 1_000), q.offset)
        .await;
    Ok(Json(serde_json::to_value(page).unwrap_or_default()))
}

async fn get_key(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<Json<Value>, AppError> {
    match state.controller.get(&key).await? {
        Some(v) => Ok(Json(v)),
        None => Err(AppError::NotFound),
    }
}

async fn put_key(
    State(state): State<AppState>,
    Path(key): Path<String>,
    Json(value): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let receipt = state.controller.set(&key, value).await?;
    let status = if receipt.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(serde_json::to_value(receipt).unwrap_or_default()),
    ))
}

async fn delete_key(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<Response, AppError> {
    if state.controller.delete(&key).await? {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(AppError::NotFound)
    }
}

async fn stats(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let s = state.controller.stats().await;
    Ok(Json(serde_json::to_value(s).unwrap_or_default()))
}

async fn backup(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let path = state.controller.backup().await?;
    Ok(Json(json!({ "backup": path.display().to_string() })))
}

async fn flush(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let bytes = state.controller.flush().await?;
    Ok(Json(json!({ "bytes_written": bytes })))
}

#[derive(Debug, Deserialize)]
struct ListParams {
    #[serde(default)]
    prefix: String,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

fn default_limit() -> usize {
    100
}
