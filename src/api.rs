use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;

use crate::classify::Classifier;

const SECRET_HEADER: &str = "x-api-secret";
const PERMIT_WAIT: Duration = Duration::from_secs(10);
const MEMORY_OVERHEAD_FACTOR: usize = 3;
const MEMORY_UNIT: usize = 1024;
const LABELS: [&str; 3] = ["ham", "spam", "malicious"];
const SCANS: [&str; 5] = ["skipped", "disabled", "clean", "infected", "error"];
const ERRORS: [u16; 7] = [400, 401, 408, 411, 413, 500, 503];

#[derive(Default)]
pub struct Metrics {
    labels: [AtomicU64; 3],
    scans: [AtomicU64; 5],
    errors: [AtomicU64; 7],
    latency_micros: AtomicU64,
    latency_count: AtomicU64,
}

impl Metrics {
    fn bump<const N: usize>(counters: &[AtomicU64; N], names: &[&str; N], name: &str) {
        if let Some(i) = names.iter().position(|n| *n == name) {
            counters[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    fn error(&self, status: StatusCode) {
        if let Some(i) = ERRORS.iter().position(|s| *s == status.as_u16()) {
            self.errors[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    fn render(&self) -> String {
        let mut out = String::new();
        for (name, counter) in LABELS.iter().zip(&self.labels) {
            let _ = writeln!(
                out,
                "sanct_classifier_classifications_total{{label=\"{name}\"}} {}",
                counter.load(Ordering::Relaxed)
            );
        }
        for (name, counter) in SCANS.iter().zip(&self.scans) {
            let _ = writeln!(
                out,
                "sanct_classifier_virus_scans_total{{status=\"{name}\"}} {}",
                counter.load(Ordering::Relaxed)
            );
        }
        for (status, counter) in ERRORS.iter().zip(&self.errors) {
            let _ = writeln!(
                out,
                "sanct_classifier_errors_total{{status=\"{status}\"}} {}",
                counter.load(Ordering::Relaxed)
            );
        }
        let micros = self.latency_micros.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "sanct_classifier_request_seconds_sum {}.{:06}",
            micros / 1_000_000,
            micros % 1_000_000
        );
        let _ = writeln!(
            out,
            "sanct_classifier_request_seconds_count {}",
            self.latency_count.load(Ordering::Relaxed)
        );
        out
    }
}

pub struct AppState {
    pub classifier: Classifier,
    secret_digest: [u8; 32],
    max_request_bytes: usize,
    memory_units: u32,
    memory: Arc<Semaphore>,
    inflight: Arc<Semaphore>,
    metrics: Metrics,
}

impl AppState {
    pub fn new(
        classifier: Classifier,
        secret: &str,
        max_request_bytes: usize,
        memory_budget_bytes: usize,
        max_concurrency: usize,
    ) -> Self {
        let memory_units = u32::try_from(memory_budget_bytes / MEMORY_UNIT)
            .unwrap_or(u32::MAX)
            .min(Semaphore::MAX_PERMITS as u32)
            .max(1);
        Self {
            classifier,
            secret_digest: Sha256::digest(secret.as_bytes()).into(),
            max_request_bytes,
            memory_units,
            memory: Arc::new(Semaphore::new(memory_units as usize)),
            inflight: Arc::new(Semaphore::new(max_concurrency)),
            metrics: Metrics::default(),
        }
    }

    fn authorized(&self, provided: &[u8]) -> bool {
        let digest: [u8; 32] = Sha256::digest(provided).into();
        digest.ct_eq(&self.secret_digest).into()
    }

    fn memory_cost(&self, length: usize) -> u32 {
        let units = length.saturating_mul(MEMORY_OVERHEAD_FACTOR) / MEMORY_UNIT + 64;
        u32::try_from(units)
            .unwrap_or(u32::MAX)
            .min(self.memory_units)
    }
}

fn error(state: &AppState, status: StatusCode, message: &'static str) -> Response {
    state.metrics.error(status);
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

async fn guard(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let provided = request
        .headers()
        .get(SECRET_HEADER)
        .map(HeaderValue::as_bytes)
        .unwrap_or_default();
    if !state.authorized(provided) {
        return error(&state, StatusCode::UNAUTHORIZED, "unauthorized");
    }

    let Some(length) = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
    else {
        return error(
            &state,
            StatusCode::LENGTH_REQUIRED,
            "content-length required",
        );
    };
    if length > state.max_request_bytes {
        return error(&state, StatusCode::PAYLOAD_TOO_LARGE, "request too large");
    }

    let cost = state.memory_cost(length);
    let Ok(Ok(memory)) =
        tokio::time::timeout(PERMIT_WAIT, state.memory.clone().acquire_many_owned(cost)).await
    else {
        return error(&state, StatusCode::SERVICE_UNAVAILABLE, "busy");
    };
    let Ok(Ok(inflight)) =
        tokio::time::timeout(PERMIT_WAIT, state.inflight.clone().acquire_owned()).await
    else {
        return error(&state, StatusCode::SERVICE_UNAVAILABLE, "busy");
    };

    let response = next.run(request).await;
    drop(inflight);
    drop(memory);
    response
}

async fn classify(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let started = Instant::now();
    let worker = state.clone();
    let prepared = tokio::task::spawn_blocking(move || worker.classifier.prepare(&body)).await;
    let prepared = match prepared {
        Ok(Ok(prepared)) => prepared,
        Ok(Err(err)) => {
            state.metrics.error(StatusCode::BAD_REQUEST);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": err.to_string() })),
            )
                .into_response();
        }
        Err(_) => return error(&state, StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };

    let result = state.classifier.finish(prepared).await;
    let elapsed = started.elapsed();
    let metrics = &state.metrics;
    Metrics::bump(&metrics.labels, &LABELS, result.label);
    Metrics::bump(&metrics.scans, &SCANS, result.virus_scan);
    metrics.latency_micros.fetch_add(
        u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    metrics.latency_count.fetch_add(1, Ordering::Relaxed);
    tracing::info!(
        label = result.label,
        spam_score = result.spam_score,
        virus = result.virus.as_deref(),
        virus_scan = result.virus_scan,
        reasons = ?result.reasons,
        ms = elapsed.as_secs_f64() * 1000.0,
        "classified"
    );
    Json(result).into_response()
}

async fn healthz() -> Response {
    Json(serde_json::json!({ "status": "ok" })).into_response()
}

async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    let clamd = match &state.classifier.clamd {
        Some(clamd) => clamd.ping().await.unwrap_or(false),
        None => true,
    };
    let status = if clamd {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(serde_json::json!({ "model": true, "clamd": clamd })),
    )
        .into_response()
}

async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )],
        state.metrics.render(),
    )
        .into_response()
}

async fn not_found(State(state): State<Arc<AppState>>) -> Response {
    error(&state, StatusCode::NOT_FOUND, "not found")
}

pub fn router(state: Arc<AppState>, request_timeout: Duration) -> Router {
    let classify_route =
        post(classify).route_layer(middleware::from_fn_with_state(state.clone(), guard));
    Router::new()
        .route("/", classify_route.clone())
        .route("/classify", classify_route.clone())
        .route("/v1/classify", classify_route)
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(state.max_request_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        .layer(CatchPanicLayer::new())
        .layer(SetResponseHeaderLayer::overriding(
            CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            CONNECTION,
            HeaderValue::from_static("close"),
        ))
        .with_state(state)
}
