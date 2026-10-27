use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, ensure, Context};

use crate::classify::DEFAULT_BLOCKED_EXTENSIONS;

const MIN_SECRET_BYTES: usize = 32;

pub struct Config {
    pub listen: SocketAddr,
    pub secret: String,
    pub model_path: PathBuf,
    pub threshold: Option<f64>,
    pub max_request_bytes: usize,
    pub memory_budget_bytes: usize,
    pub max_concurrency: usize,
    pub max_attachments: usize,
    pub request_timeout: Duration,
    pub clamd_address: Option<String>,
    pub clamd_timeout: Duration,
    pub clamd_fail_closed: bool,
    pub blocked_extensions: String,
}

fn var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn parse<T: FromStr>(name: &str, default: T) -> anyhow::Result<T> {
    match var(name) {
        Some(value) => value
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("{name} has an invalid value")),
        None => Ok(default),
    }
}

fn secret() -> anyhow::Result<String> {
    let secret = match (
        var("CLASSIFIER_API_SECRET"),
        var("CLASSIFIER_API_SECRET_FILE"),
    ) {
        (Some(_), Some(_)) => {
            bail!("set only one of CLASSIFIER_API_SECRET and CLASSIFIER_API_SECRET_FILE")
        }
        (Some(secret), None) => secret,
        (None, Some(path)) => fs::read_to_string(&path)
            .with_context(|| format!("reading CLASSIFIER_API_SECRET_FILE {path}"))?
            .trim_end_matches(['\r', '\n'])
            .to_string(),
        (None, None) => bail!("CLASSIFIER_API_SECRET or CLASSIFIER_API_SECRET_FILE is required"),
    };
    ensure!(
        secret.len() >= MIN_SECRET_BYTES,
        "the API secret must be at least {MIN_SECRET_BYTES} bytes"
    );
    Ok(secret)
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let threshold = match var("CLASSIFIER_THRESHOLD") {
            Some(value) => {
                let t: f64 = value.trim().parse().context("CLASSIFIER_THRESHOLD")?;
                ensure!(t > 0.0 && t < 1.0, "CLASSIFIER_THRESHOLD must be in (0, 1)");
                Some(t)
            }
            None => None,
        };
        let config = Self {
            listen: parse("CLASSIFIER_LISTEN", SocketAddr::from(([0, 0, 0, 0], 8080)))?,
            secret: secret()?,
            model_path: PathBuf::from(
                var("CLASSIFIER_MODEL").unwrap_or_else(|| "models/sanct-spam.json".to_string()),
            ),
            threshold,
            max_request_bytes: parse("CLASSIFIER_MAX_REQUEST_BYTES", 72 * 1024 * 1024)?,
            memory_budget_bytes: parse("CLASSIFIER_MEMORY_BUDGET_BYTES", 256 * 1024 * 1024)?,
            max_concurrency: parse("CLASSIFIER_MAX_CONCURRENCY", 16)?,
            max_attachments: parse("CLASSIFIER_MAX_ATTACHMENTS", 100)?,
            request_timeout: Duration::from_secs(parse("CLASSIFIER_REQUEST_TIMEOUT_SECS", 120)?),
            clamd_address: var("CLAMD_ADDRESS"),
            clamd_timeout: Duration::from_secs(parse("CLAMD_TIMEOUT_SECS", 60)?),
            clamd_fail_closed: parse("CLAMD_FAIL_CLOSED", false)?,
            blocked_extensions: env::var("CLASSIFIER_BLOCKED_EXTENSIONS")
                .unwrap_or_else(|_| DEFAULT_BLOCKED_EXTENSIONS.to_string()),
        };
        ensure!(
            config.max_request_bytes > 0,
            "CLASSIFIER_MAX_REQUEST_BYTES must be positive"
        );
        ensure!(
            config.max_concurrency > 0,
            "CLASSIFIER_MAX_CONCURRENCY must be positive"
        );
        ensure!(
            config.memory_budget_bytes >= config.max_request_bytes,
            "CLASSIFIER_MEMORY_BUDGET_BYTES must be at least CLASSIFIER_MAX_REQUEST_BYTES"
        );
        Ok(config)
    }
}
