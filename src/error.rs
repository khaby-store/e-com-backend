use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

use crate::db::DbError;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("missing or invalid API key")]
    Unauthorized,
    #[error("resource not found")]
    NotFound,
    #[error(transparent)]
    Db(#[from] DbError),
}

impl AppError {
    fn status(&self) -> StatusCode {
        match self {
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Db(DbError::InvalidKey(_)) => StatusCode::BAD_REQUEST,
            AppError::Db(DbError::TooLarge(_)) => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Public message. Storage, crypto and parser failures are deliberately
    /// opaque so disk paths and internal detail never reach the client.
    fn public_message(&self) -> &'static str {
        match self {
            AppError::Unauthorized => "missing or invalid API key",
            AppError::NotFound => "resource not found",
            AppError::Db(DbError::InvalidKey(_)) => "invalid key",
            AppError::Db(DbError::TooLarge(_)) => "value too large",
            AppError::Db(_) => "internal error",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();

        match status {
            StatusCode::INTERNAL_SERVER_ERROR => {
                tracing::error!(error = %self, "request failed");
            }
            StatusCode::UNAUTHORIZED
            | StatusCode::NOT_FOUND
            | StatusCode::BAD_REQUEST
            | StatusCode::PAYLOAD_TOO_LARGE => {
                tracing::warn!(error = %self, status = %status, "request rejected");
            }
            _ => {}
        }

        let mut resp = (
            status,
            Json(json!({
                "error": self.public_message(),
                "status": status.as_u16(),
            })),
        )
            .into_response();

        if status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(
                axum::http::HeaderName::from_static("www-authenticate"),
                axum::http::HeaderValue::from_static("ApiKey"),
            );
        }
        resp
    }
}
