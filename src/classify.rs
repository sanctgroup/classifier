use std::collections::HashSet;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::clamd::{Clamd, Verdict};
use crate::features::Extractor;
use crate::model::{sigmoid, Model};

pub const DEFAULT_BLOCKED_EXTENSIONS: &str = ".ace .apk .app .appx .bat .cab .chm .cmd .com .cpl .dll .exe .hta .img .inf .iso .jar .js .jse .lnk .msc .msi .msix .msp .pif .ps1 .reg .scr .sct .shb .sys .url .vb .vbe .vbs .vhd .vhdx .wsc .wsf .wsh .xll";

const AUTH_ADJUSTMENTS: &[(&str, &str, f64)] = &[
    ("spf", "fail", 0.8),
    ("spf", "softfail", 0.3),
    ("spf", "pass", -0.15),
    ("dkim", "fail", 0.6),
    ("dkim", "pass", -0.15),
    ("dmarc", "fail", 1.2),
    ("dmarc", "pass", -0.3),
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifyRequest {
    #[serde(default)]
    text: String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    spf: String,
    #[serde(default)]
    dkim: String,
    #[serde(default)]
    dmarc: String,
    #[serde(default)]
    attachments: Vec<AttachmentInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentInput {
    #[serde(default)]
    filename: String,
    content_base64: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct ClassifyResponse {
    pub label: &'static str,
    pub confidence: f64,
    pub virus: Option<String>,
    pub spam_score: f64,
    pub threshold: f64,
    pub virus_scan: &'static str,
    pub reasons: Vec<String>,
    pub model: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RequestError {
    #[error("invalid request body")]
    InvalidBody,
    #[error("too many attachments")]
    TooManyAttachments,
    #[error("attachment content_base64 is not valid base64")]
    InvalidBase64,
}

pub struct Policy {
    pub threshold: f64,
    pub clamd_fail_closed: bool,
    pub blocked_extensions: HashSet<String>,
    pub max_attachments: usize,
}

pub fn parse_extensions(list: &str) -> HashSet<String> {
    list.split_whitespace()
        .map(|e| {
            let e = e.to_ascii_lowercase();
            if e.starts_with('.') {
                e
            } else {
                format!(".{e}")
            }
        })
        .collect()
}

pub struct Prepared {
    spam_score: f64,
    auth_reasons: Vec<String>,
    extension_reasons: Vec<String>,
    attachments: Vec<Vec<u8>>,
}

pub struct Classifier {
    pub extractor: Extractor,
    pub model: Model,
    pub clamd: Option<Clamd>,
    pub policy: Policy,
}

fn round6(x: f64) -> f64 {
    (x * 1e6).round() / 1e6
}

impl Classifier {
    fn auth_adjustment(&self, request: &ClassifyRequest) -> (f64, Vec<String>) {
        let mut total = 0.0;
        let mut reasons = Vec::new();
        for (name, value) in [
            ("spf", &request.spf),
            ("dkim", &request.dkim),
            ("dmarc", &request.dmarc),
        ] {
            let value = value.trim().to_ascii_lowercase();
            if let Some(&(_, _, delta)) = AUTH_ADJUSTMENTS
                .iter()
                .find(|(n, v, _)| *n == name && *v == value)
            {
                total += delta;
                if delta > 0.0 {
                    reasons.push(format!("{name}_{value}"));
                }
            }
        }
        (total, reasons)
    }

    fn blocked_extension(&self, filename: &str) -> Option<String> {
        let lowered = filename.to_lowercase();
        let trimmed = lowered.trim_end_matches(['.', ' ']);
        let extension = Path::new(trimmed).extension()?.to_str()?;
        let extension = format!(".{extension}");
        self.policy
            .blocked_extensions
            .contains(&extension)
            .then(|| format!("blocked_extension{extension}"))
    }

    pub fn prepare(&self, body: &[u8]) -> Result<Prepared, RequestError> {
        let request: ClassifyRequest =
            serde_json::from_slice(body).map_err(|_| RequestError::InvalidBody)?;
        if request.attachments.len() > self.policy.max_attachments {
            return Err(RequestError::TooManyAttachments);
        }

        let mut extension_reasons = Vec::new();
        let mut attachments = Vec::with_capacity(request.attachments.len());
        for attachment in &request.attachments {
            if let Some(reason) = self.blocked_extension(&attachment.filename) {
                if !extension_reasons.contains(&reason) {
                    extension_reasons.push(reason);
                }
            }
            let data = BASE64
                .decode(attachment.content_base64.as_bytes())
                .map_err(|_| RequestError::InvalidBase64)?;
            attachments.push(data);
        }

        let subject = request.subject.as_deref().unwrap_or("");
        let mut text = request.body.as_deref().unwrap_or("");
        if subject.is_empty() && text.is_empty() {
            text = &request.text;
        }

        let (adjustment, auth_reasons) = self.auth_adjustment(&request);
        let vector = self.extractor.vectorize(subject, text);
        let spam_score = sigmoid(self.model.logit(&vector) + adjustment);

        Ok(Prepared {
            spam_score,
            auth_reasons,
            extension_reasons,
            attachments,
        })
    }

    async fn scan(&self, attachments: Vec<Vec<u8>>) -> (Option<String>, &'static str) {
        if attachments.is_empty() {
            return (None, "skipped");
        }
        let Some(clamd) = &self.clamd else {
            return (None, "disabled");
        };
        let mut threats: Vec<String> = Vec::new();
        for data in attachments {
            match clamd.scan(&data).await {
                Ok(Verdict::Clean) => {}
                Ok(Verdict::Infected(signature)) => {
                    if !threats.contains(&signature) {
                        threats.push(signature);
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "clamd scan failed");
                    let virus = (!threats.is_empty()).then(|| threats.join(", "));
                    return (virus, "error");
                }
            }
        }
        if threats.is_empty() {
            (None, "clean")
        } else {
            (Some(threats.join(", ")), "infected")
        }
    }

    pub async fn finish(&self, prepared: Prepared) -> ClassifyResponse {
        let Prepared {
            spam_score,
            auth_reasons,
            mut extension_reasons,
            attachments,
        } = prepared;
        let (virus, virus_scan) = self.scan(attachments).await;

        let (label, confidence, reasons) = if virus.is_some() {
            extension_reasons.push("virus".to_string());
            ("malicious", 1.0, extension_reasons)
        } else if !extension_reasons.is_empty() {
            ("malicious", spam_score.max(0.99), extension_reasons)
        } else if virus_scan == "error" && self.policy.clamd_fail_closed {
            ("malicious", 0.5, vec!["scan_error".to_string()])
        } else if spam_score >= self.policy.threshold {
            ("spam", spam_score, auth_reasons)
        } else {
            ("ham", 1.0 - spam_score, Vec::new())
        };

        ClassifyResponse {
            label,
            confidence: round6(confidence),
            virus,
            spam_score: round6(spam_score),
            threshold: self.policy.threshold,
            virus_scan,
            reasons,
            model: self.model.trained_at.clone(),
        }
    }
}
