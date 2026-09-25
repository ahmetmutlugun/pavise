//! `pavise-server`: the web UI and upload API. Handlers and routing live in
//! `pavise::server` so integration tests exercise the same router.

use anyhow::Result;
use std::{net::SocketAddr, sync::Arc};

use pavise::server::{build_router, config::Config, spawn_eviction_task, state::AppState};

// ── Tracing setup ─────────────────────────────────────────────────────────────

/// Initialise tracing.
///
/// Writes structured logs to stderr (captured by `docker logs`) and — when
/// `PAVISE_LOG_DIR` is set — also to a daily-rotated file under that directory
/// so logs survive container restarts when the directory is volume-mounted.
fn init_tracing() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("pavise=info,pavise_server=info,tower_http=info"));

    let stderr_layer = fmt::layer().with_writer(std::io::stderr);

    let (file_layer, guard) = match std::env::var("PAVISE_LOG_DIR") {
        Ok(dir) if !dir.is_empty() => {
            if let Err(e) = std::fs::create_dir_all(&dir) {
                eprintln!("Could not create PAVISE_LOG_DIR='{dir}': {e}; file logging disabled");
                (None, None)
            } else {
                let appender = tracing_appender::rolling::daily(&dir, "pavise.log");
                let (nb, guard) = tracing_appender::non_blocking(appender);
                let layer = fmt::layer().with_ansi(false).with_writer(nb);
                (Some(layer), Some(guard))
            }
        }
        _ => (None, None),
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .with(file_layer)
        .init();

    guard
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Keep guard alive for the lifetime of the program; dropping it flushes any
    // buffered log lines to disk.
    let _log_guard = init_tracing();

    let config = match Config::from_env() {
        Ok(c) => Arc::new(c),
        Err(errors) => {
            for e in &errors {
                eprintln!("Config error: {e}");
            }
            anyhow::bail!(
                "Server startup aborted: {} configuration error(s) — fix the above and retry",
                errors.len()
            );
        }
    };

    let state = AppState::new(Arc::clone(&config));
    spawn_eviction_task(&state);
    let app = build_router(state);
    let port = config.port;

    let addr = format!("0.0.0.0:{port}");
    eprintln!("Pavise server listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
