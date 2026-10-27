#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use sanct_classifier::api::{self, AppState};
use sanct_classifier::clamd::Clamd;
use sanct_classifier::classify::{parse_extensions, Classifier, Policy};
use sanct_classifier::config::Config;
use sanct_classifier::features::Extractor;
use sanct_classifier::model::Model;
use sanct_classifier::secure_alloc::ZeroizingAllocator;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[global_allocator]
static ALLOCATOR: ZeroizingAllocator = ZeroizingAllocator;

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutting down");
}

async fn run() -> anyhow::Result<()> {
    sanct_classifier::hardening::apply()?;
    let config = Config::from_env()?;
    let model = Model::load(&config.model_path)?;
    let extractor = Extractor::new().context("compiling feature regexes")?;
    let clamd = config
        .clamd_address
        .as_deref()
        .map(|address| Clamd::new(address, config.clamd_timeout))
        .transpose()?;

    match &clamd {
        Some(clamd) => match clamd.version().await {
            Ok(version) => tracing::info!(version = %version, "clamd connected"),
            Err(err) => tracing::warn!(error = %err, "clamd not reachable yet"),
        },
        None => tracing::warn!("CLAMD_ADDRESS not set, attachment virus scanning disabled"),
    }

    let threshold = config.threshold.unwrap_or(model.threshold);
    tracing::info!(
        model = %model.trained_at,
        weights_sha256 = %model.weights_sha256,
        threshold,
        "model loaded"
    );

    let classifier = Classifier {
        extractor,
        model,
        clamd,
        policy: Policy {
            threshold,
            clamd_fail_closed: config.clamd_fail_closed,
            blocked_extensions: parse_extensions(&config.blocked_extensions),
            max_attachments: config.max_attachments,
        },
    };
    let state = Arc::new(AppState::new(
        classifier,
        &config.secret,
        config.max_request_bytes,
        config.memory_budget_bytes,
        config.max_concurrency,
    ));
    let app = api::router(state, config.request_timeout);

    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    tracing::info!(address = %config.listen, "listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving")?;
    Ok(())
}

fn healthcheck() -> ExitCode {
    let port = std::env::var("CLASSIFIER_LISTEN")
        .ok()
        .and_then(|listen| listen.parse::<SocketAddr>().ok())
        .map_or(8080, |addr| addr.port());
    let probe = || -> std::io::Result<bool> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut head = [0u8; 12];
        stream.read_exact(&mut head)?;
        Ok(head.ends_with(b" 200"))
    };
    match probe() {
        Ok(true) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck();
    }
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "fatal");
            ExitCode::FAILURE
        }
    }
}
