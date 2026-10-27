use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use http_body_util::BodyExt;
use sanct_classifier::api::{router, AppState};
use sanct_classifier::clamd::{Clamd, Verdict};
use sanct_classifier::classify::{
    parse_extensions, Classifier, Policy, DEFAULT_BLOCKED_EXTENSIONS,
};
use sanct_classifier::features::{Extractor, DIM};
use sanct_classifier::model::Model;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

const SECRET: &str = "test-secret-0123456789-0123456789-abcdef";
const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const MAX_REQUEST: usize = 256 * 1024;

struct FakeClamd {
    _dir: tempfile::TempDir,
    address: String,
}

async fn fake_clamd(fail_scan: bool) -> FakeClamd {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clamd.sock");
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut command = Vec::new();
                loop {
                    let byte = stream.read_u8().await.unwrap();
                    command.push(byte);
                    if byte == 0 {
                        break;
                    }
                }
                let reply: &[u8] = match command.as_slice() {
                    b"zPING\0" => b"PONG\0",
                    b"zVERSION\0" => b"ClamAV 1.5.4/fake\0",
                    b"zINSTREAM\0" => {
                        let mut payload = Vec::new();
                        loop {
                            let size = stream.read_u32().await.unwrap() as usize;
                            if size == 0 {
                                break;
                            }
                            let mut chunk = vec![0; size];
                            stream.read_exact(&mut chunk).await.unwrap();
                            payload.extend_from_slice(&chunk);
                        }
                        if fail_scan {
                            b"INSTREAM size limit exceeded. ERROR\0"
                        } else if payload.windows(EICAR.len()).any(|w| w == EICAR) {
                            b"stream: Eicar-Test-Signature FOUND\0"
                        } else {
                            b"stream: OK\0"
                        }
                    }
                    _ => b"UNKNOWN COMMAND\0",
                };
                let _ = stream.write_all(reply).await;
            });
        }
    });
    FakeClamd {
        address: format!("unix://{}", path.display()),
        _dir: dir,
    }
}

fn tiny_model() -> Model {
    let extractor = Extractor::new().unwrap();
    let mut weights = vec![0.0f32; DIM];
    for word in ["viagra", "lottery", "winner"] {
        let vector = extractor.vectorize("", word);
        let groups = extractor.tokens("", word);
        let token = format!("w:{word}");
        assert!(groups[3].contains(&token));
        let hash = crc32fast::hash(token.as_bytes());
        let index = (hash & ((1 << 20) - 1)) as usize;
        let sign = if hash & 0x8000_0000 != 0 { 1.0 } else { -1.0 };
        assert!(vector.contains_key(&(index as u32)));
        weights[index] = 40.0 * sign;
    }
    Model::from_parts(weights, -3.0, 0.5, "test".into(), "test".into()).unwrap()
}

fn app(clamd: Option<Clamd>, fail_closed: bool) -> Router {
    let classifier = Classifier {
        extractor: Extractor::new().unwrap(),
        model: tiny_model(),
        clamd,
        policy: Policy {
            threshold: 0.5,
            clamd_fail_closed: fail_closed,
            blocked_extensions: parse_extensions(DEFAULT_BLOCKED_EXTENSIONS),
            max_attachments: 4,
        },
    };
    let state = Arc::new(AppState::new(
        classifier,
        SECRET,
        MAX_REQUEST,
        4 * MAX_REQUEST,
        4,
    ));
    router(state, Duration::from_secs(10))
}

async fn call(
    app: &Router,
    secret: Option<&str>,
    body: Vec<u8>,
    content_length: bool,
) -> (StatusCode, Value) {
    let mut request = Request::post("/classify").header("content-type", "application/json");
    if let Some(secret) = secret {
        request = request.header("x-api-secret", secret);
    }
    if content_length {
        request = request.header("content-length", body.len());
    }
    let response = tower::ServiceExt::oneshot(app.clone(), request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn classify(app: &Router, payload: Value) -> (StatusCode, Value) {
    call(
        app,
        Some(SECRET),
        serde_json::to_vec(&payload).unwrap(),
        true,
    )
    .await
}

fn b64(data: &[u8]) -> String {
    BASE64.encode(data)
}

#[tokio::test]
async fn rust_client_shape_is_ham() {
    let app = app(None, false);
    let (status, result) = classify(
        &app,
        json!({"text": "Hi team, notes from today's meeting.", "spf": "pass", "dkim": "pass", "dmarc": "pass"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["label"], "ham");
    assert_eq!(result["virus"], Value::Null);
    assert_eq!(result["virus_scan"], "skipped");
}

#[tokio::test]
async fn spam_text_is_spam() {
    let (_, result) = classify(&app(None, false), json!({"text": "lottery winner viagra"})).await;
    assert_eq!(result["label"], "spam");
}

#[tokio::test]
async fn subject_and_body_override_text() {
    let (_, result) = classify(
        &app(None, false),
        json!({"text": "lottery winner viagra", "subject": "Lunch", "body": "Noon works."}),
    )
    .await;
    assert_eq!(result["label"], "ham");
}

#[tokio::test]
async fn auth_failures_raise_score() {
    let app = app(None, false);
    let (_, pass) = classify(
        &app,
        json!({"text": "report", "spf": "pass", "dkim": "pass", "dmarc": "pass"}),
    )
    .await;
    let (_, fail) = classify(
        &app,
        json!({"text": "report", "spf": "fail", "dkim": "fail", "dmarc": "fail"}),
    )
    .await;
    assert!(fail["spam_score"].as_f64() > pass["spam_score"].as_f64());
}

#[tokio::test]
async fn virus_is_malicious() {
    let fake = fake_clamd(false).await;
    let app = app(
        Some(Clamd::new(&fake.address, Duration::from_secs(5)).unwrap()),
        false,
    );
    let mut big = vec![b'A'; 100 * 1024];
    big.extend_from_slice(EICAR);
    let (status, result) = classify(
        &app,
        json!({"text": "invoice", "attachments": [
            {"filename": "notes.txt", "content_base64": b64(b"plain")},
            {"filename": "invoice.pdf", "content_base64": b64(&big)}
        ]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["label"], "malicious");
    assert_eq!(result["virus"], "Eicar-Test-Signature");
    assert_eq!(result["virus_scan"], "infected");
}

#[tokio::test]
async fn clean_attachment() {
    let fake = fake_clamd(false).await;
    let app = app(
        Some(Clamd::new(&fake.address, Duration::from_secs(5)).unwrap()),
        false,
    );
    let (_, result) = classify(&app, json!({"text": "photo", "attachments": [{"filename": "a.png", "content_base64": b64(b"png")}]})).await;
    assert_eq!(result["virus_scan"], "clean");
    assert_eq!(result["label"], "ham");
}

#[tokio::test]
async fn blocked_extension_is_malicious() {
    let (_, result) = classify(
        &app(None, false),
        json!({"text": "see attached", "attachments": [{"filename": "Invoice.PDF.exe ", "content_base64": b64(b"MZ")}]}),
    )
    .await;
    assert_eq!(result["label"], "malicious");
    assert_eq!(result["reasons"], json!(["blocked_extension.exe"]));
}

#[tokio::test]
async fn scan_errors_fail_open_or_closed() {
    let fake = fake_clamd(true).await;
    let payload =
        json!({"text": "hi", "attachments": [{"filename": "a.txt", "content_base64": b64(b"x")}]});
    let open = app(
        Some(Clamd::new(&fake.address, Duration::from_secs(5)).unwrap()),
        false,
    );
    let (_, result) = classify(&open, payload.clone()).await;
    assert_eq!(result["virus_scan"], "error");
    assert_eq!(result["label"], "ham");
    let closed = app(
        Some(Clamd::new(&fake.address, Duration::from_secs(5)).unwrap()),
        true,
    );
    let (_, result) = classify(&closed, payload).await;
    assert_eq!(result["label"], "malicious");
}

#[tokio::test]
async fn rejects_bad_secret_missing_length_and_oversize() {
    let app = app(None, false);
    let body = serde_json::to_vec(&json!({"text": "x"})).unwrap();
    assert_eq!(
        call(&app, Some("wrong"), body.clone(), true).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, None, body.clone(), true).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, Some(SECRET), body, false).await.0,
        StatusCode::LENGTH_REQUIRED
    );
    let huge = vec![b' '; MAX_REQUEST + 1];
    assert_eq!(
        call(&app, Some(SECRET), huge, true).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn rejects_malformed_input() {
    let app = app(None, false);
    let (status, result) = call(&app, Some(SECRET), b"{nope".to_vec(), true).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(result["error"], "invalid request body");
    assert_eq!(
        classify(&app, json!({"text": "x", "extra": 1})).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        classify(
            &app,
            json!({"text": "x", "attachments": [{"filename": "a", "content_base64": "!!!"}]})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let many: Vec<Value> = (0..5)
        .map(|_| json!({"filename": "a", "content_base64": ""}))
        .collect();
    assert_eq!(
        classify(&app, json!({"text": "x", "attachments": many}))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn health_ready_and_metrics() {
    let fake = fake_clamd(false).await;
    let app = app(
        Some(Clamd::new(&fake.address, Duration::from_secs(5)).unwrap()),
        false,
    );
    for path in ["/healthz", "/readyz", "/metrics"] {
        let response = tower::ServiceExt::oneshot(
            app.clone(),
            Request::get(path).body(Body::empty()).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
    let down = self::app(
        Some(Clamd::new("tcp://127.0.0.1:1", Duration::from_secs(1)).unwrap()),
        false,
    );
    let response =
        tower::ServiceExt::oneshot(down, Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn clamd_client_parses_replies() {
    let fake = fake_clamd(false).await;
    let clamd = Clamd::new(&fake.address, Duration::from_secs(5)).unwrap();
    assert!(clamd.ping().await.unwrap());
    assert_eq!(clamd.scan(b"").await.unwrap(), Verdict::Clean);
    assert_eq!(
        clamd.scan(EICAR).await.unwrap(),
        Verdict::Infected("Eicar-Test-Signature".into())
    );
    assert!(Clamd::new("http://clamav:3310", Duration::from_secs(1)).is_err());
    assert!(Clamd::new("tcp://clamav", Duration::from_secs(1)).is_err());
}
