use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use anyhow::{bail, ensure, Context};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::features::{DIM, DIM_BITS, FEATURE_VERSION};

#[derive(Deserialize)]
struct ModelMeta {
    feature_version: u32,
    dim_bits: u32,
    weights_file: String,
    weights_sha256: String,
    bias: f64,
    threshold: f64,
    trained_at: String,
}

pub struct Model {
    weights: Vec<f32>,
    bias: f64,
    pub threshold: f64,
    pub trained_at: String,
    pub weights_sha256: String,
}

pub fn sigmoid(x: f64) -> f64 {
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let z = x.exp();
        z / (1.0 + z)
    }
}

impl Model {
    pub fn load(meta_path: &Path) -> anyhow::Result<Self> {
        let raw_meta = fs::read(meta_path)
            .with_context(|| format!("reading model metadata {}", meta_path.display()))?;
        let meta: ModelMeta =
            serde_json::from_slice(&raw_meta).context("parsing model metadata")?;

        ensure!(
            meta.feature_version == FEATURE_VERSION,
            "model feature_version {} does not match runtime {FEATURE_VERSION}",
            meta.feature_version
        );
        ensure!(
            meta.dim_bits == DIM_BITS,
            "model dim_bits {} does not match runtime {DIM_BITS}",
            meta.dim_bits
        );
        if Path::new(&meta.weights_file).file_name() != Some(OsStr::new(&meta.weights_file)) {
            bail!("weights_file must be a bare file name");
        }

        let weights_path = meta_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(&meta.weights_file);
        let raw = fs::read(&weights_path)
            .with_context(|| format!("reading model weights {}", weights_path.display()))?;
        let digest = format!("{:x}", Sha256::digest(&raw));
        ensure!(
            digest == meta.weights_sha256.to_ascii_lowercase(),
            "model weights checksum mismatch"
        );
        ensure!(
            raw.len() == DIM * 4,
            "expected {} weight bytes, found {}",
            DIM * 4,
            raw.len()
        );

        let weights: Vec<f32> = raw
            .chunks_exact(4)
            .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect();
        ensure!(
            weights.iter().all(|w| w.is_finite()),
            "model weights contain non-finite values"
        );

        Self::from_parts(weights, meta.bias, meta.threshold, meta.trained_at, digest)
    }

    pub fn from_parts(
        weights: Vec<f32>,
        bias: f64,
        threshold: f64,
        trained_at: String,
        weights_sha256: String,
    ) -> anyhow::Result<Self> {
        ensure!(weights.len() == DIM, "expected {DIM} weights");
        ensure!(bias.is_finite(), "model bias must be finite");
        ensure!(
            threshold > 0.0 && threshold < 1.0,
            "model threshold must be in (0, 1)"
        );
        Ok(Self {
            weights,
            bias,
            threshold,
            trained_at,
            weights_sha256,
        })
    }

    pub fn logit(&self, vector: &HashMap<u32, f64>) -> f64 {
        self.bias
            + vector
                .iter()
                .map(|(&i, &v)| f64::from(self.weights.get(i as usize).copied().unwrap_or(0.0)) * v)
                .sum::<f64>()
    }
}
