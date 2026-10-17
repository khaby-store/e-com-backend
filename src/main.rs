mod config;
mod db;
mod error;
mod routes;
mod security;
mod state;

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::db::Db;
use crate::db::controller::DbController;
use crate::db::storage::Storage;
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("ecom_secure_db=info,tower_http=info")),
        )
        .with_target(false)
        .init();

    let config = Config::from_env()?;

    let storage = Storage::new(&config.db_path);
    let db = Db::open(
        storage,
        config.master_key.clone(),
        config.zstd_level,
        config.max_value_bytes,
    )
    .await
    .map_err(|e| anyhow::anyhow!("refusing to start, store could not be opened: {e}"))?;

    let records = db.count().await;
    let on_disk = db.on_disk_bytes();
    tracing::info!(
        path = %config.db_path.display(),
        records,
        on_disk_bytes = on_disk,
        zstd_level = config.zstd_level,
        "store unlocked and mounted"
    );

    let controller = DbController::new(db);
    let state = AppState::new(controller, config.clone());
    let app = routes::router(state);

    let listener = TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("failed to bind {}", config.bind))?;

    tracing::info!(
        bind = %config.bind,
        api_keys = config.api_keys.len(),
        rate_limit_per_min = config.rate_limit_per_minute,
        max_body_bytes = config.max_body_bytes,
        "listening (AES-256-GCM at rest, X-API-Key required on /v1/*)"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
