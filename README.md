# Sanct Classifier

Spam and malware verdicts for mail arriving at `sanct-smtp-inbound`, before it is sealed to the recipient's key.

- **Rust service** (`src/`): hashed n-gram linear model plus ClamAV over a Unix socket. About 11 MiB idle, under 50 MiB under load, hard memory budget for large attachments.
- **Python training** (`training/`): builds the model from public Hugging Face corpora. Never trained on user mail.
- **Parity tests** guarantee the Rust feature extractor reproduces the Python one exactly.

## Zero knowledge posture

Mail from outside senders reaches `smtp-inbound` as plaintext and is held in memory until `SealedEnvelope::seal` encrypts it. The classifier runs inside that same window and must not widen it:

| Guarantee | How |
| --- | --- |
| Plaintext never leaves the pod | Deploy as sidecars of `smtp-inbound` (`deploy/smtp-inbound-sidecars.yaml`): the API binds `127.0.0.1`, clamd is reached over a Unix socket on an in-memory volume, nothing else in the cluster can connect |
| Nothing is written to disk | No content logging, clamd temp files on tmpfs, core dumps disabled (`RLIMIT_CORE=0`) |
| Nothing survives the request in RAM | Global zeroizing allocator wipes every heap byte on free (request buffers, parsed JSON, decoded attachments, tokens, reallocation leftovers); every response closes the connection so read buffers are freed too; clamd runs with `glibc.malloc.perturb` and tcache disabled so its frees are scrubbed |
| No other process can read it | `PR_SET_DUMPABLE=0`, non-root, read-only root filesystem, all capabilities dropped, `no-new-privileges`, seccomp `RuntimeDefault` |
| No third parties | Model and ClamAV run locally; freshclam only downloads signatures |
| No learning from users | Training data is public corpora only |

`scripts/memscan/run.sh` proves the third row: it sends a message containing a random marker, then dumps the live memory of both processes from a privileged container and searches for the marker in plaintext and base64. With the previous build (no zeroizing) the scan found 10 copies in the classifier heap and 1 in clamd; with this build it finds none, including right after a 5,000 request burst.

Residual exposure outside this service: the kernel socket buffers and freed kernel pages (enable `init_on_free=1` on the node to scrub them), and swap (keep it off, as Kubernetes requires). The verdict itself (the `spam` label) is stored in plaintext by `smtp-inbound`, like `sender_address` already is.

## API

`POST /classify` (also `/` and `/v1/classify`), header `X-API-Secret`:

```json
{"subject": "...", "body": "...", "spf": "pass", "dkim": "pass", "dmarc": "pass",
 "attachments": [{"filename": "a.pdf", "content_base64": "..."}]}
```

A single `text` field is also accepted in place of `subject` and `body`. Unknown fields are rejected.

```json
{"label": "ham|spam|malicious", "confidence": 0.99, "virus": null,
 "spam_score": 0.01, "threshold": 0.976428, "virus_scan": "skipped|disabled|clean|infected|error",
 "reasons": [], "model": "2026-10-27T09:00:37+00:00"}
```

- `malicious`: ClamAV found a signature (`smtp-inbound` rejects with 554), or an attachment has a blocked executable extension (quarantined).
- `spam`: model score plus a small SPF/DKIM/DMARC adjustment is at or above the threshold (quarantined).
- If clamd fails, the scan reports `error` and the verdict falls back to the text model, unless `CLAMD_FAIL_CLOSED=true`.

`GET /healthz`, `GET /readyz` (checks clamd), `GET /metrics` (Prometheus counters, no content).

## Security controls

- Secret compared in constant time (SHA-256 then `subtle`), checked before any body byte is read.
- `Content-Length` required; requests above `CLASSIFIER_MAX_REQUEST_BYTES` are refused before reading.
- Memory budget semaphore reserves 3x the body size per request, so total RAM stays bounded under a flood of 50 MB messages (verified: 16 concurrent 28 MB requests under a 320 MiB cgroup limit, no OOM).
- Model weights are SHA-256 verified at startup; the service refuses to start on any mismatch.
- `#![forbid(unsafe_code)]` in the binary, `#![deny(unsafe_code)]` in the library; the only `unsafe` is the 20 line allocator in `src/secure_alloc.rs`.
- Distroless image pinned by digest, runs as UID 65532, built with `--locked`, overflow checks on in release.
- Logs contain label, score, scan status, virus name and timing only.

## Model

Hashed features (2^20 dims): words, word bigrams, 4-char grams, URL hosts and TLDs, HTML, caps, money and obfuscation signals. Logistic regression (SGD), Platt calibrated, threshold chosen for a 0.2% false positive rate on validation.

Datasets (pinned revisions in `training/datasets.py`), 207,003 unique emails after cross-corpus dedup:

- `puyang2025/seven-phishing-email-datasets`: TREC-05/06/07, CEAS-08, Enron, SpamAssassin, Ling
- `kudzaiprichard/aura-phishing-email-corpus`: Nazario phishing, Nigerian fraud (CC-BY-4.0)
- `Dizzzy0x00/LLMGen-Phishing-Email-Dataset`: modern LLM-written phishing and legitimate mail (Apache-2.0)

Held-out test set (21,290 emails):

| Input | AUC | Precision | Recall | False positive rate |
| --- | --- | --- | --- | --- |
| Subject and full body | 0.9992 | 99.8% | 93.7% | 0.15% |
| 200 char snippet only | 0.9970 | 99.8% | 81.7% | 0.18% |

`smtp-inbound` sends `subject` and up to 40,000 characters of `body`, which is about 12 points more recall than the snippet. With the sidecar layout this does not widen the trust boundary, since `smtp-inbound` already holds the full message.

## Run locally

```bash
export CLASSIFIER_API_SECRET="$(openssl rand -base64 48)"
docker compose up -d --build
curl -s localhost:8080/readyz
./scripts/memscan/run.sh
```

Then point `sanct` at it with `MAIL_CLASSIFY_URL=http://127.0.0.1:8080/classify` and the same secret in `MAIL_CLASSIFY_SECRET`.

## Train

```bash
uv sync
uv run python -m training.train
uv run python -m training.golden
cargo test --release -- --include-ignored
```

Training takes about 2 minutes on an M5 (peak 4 GB RAM). `training.golden` writes the parity fixtures for the new model; commit `models/` and `tests/fixtures/` together. Changing anything in `training/features.py` requires the same change in `src/features.rs` and a bump of `FEATURE_VERSION` in both.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `CLASSIFIER_API_SECRET` / `CLASSIFIER_API_SECRET_FILE` | required | at least 32 bytes |
| `CLASSIFIER_LISTEN` | `0.0.0.0:8080` | use `127.0.0.1:8080` as a sidecar |
| `CLASSIFIER_MODEL` | `models/sanct-spam.json` | |
| `CLASSIFIER_THRESHOLD` | from model | override the spam threshold |
| `CLASSIFIER_MAX_REQUEST_BYTES` | 72 MiB | fits a 50 MB message in base64 |
| `CLASSIFIER_MEMORY_BUDGET_BYTES` | 256 MiB | shared across in-flight requests |
| `CLASSIFIER_MAX_CONCURRENCY` | 16 | |
| `CLASSIFIER_MAX_ATTACHMENTS` | 100 | |
| `CLASSIFIER_REQUEST_TIMEOUT_SECS` | 120 | |
| `CLASSIFIER_BLOCKED_EXTENSIONS` | executables and scripts | space separated, empty disables |
| `CLAMD_ADDRESS` | unset (scanning disabled) | `unix:///path` or `tcp://host:port` |
| `CLAMD_TIMEOUT_SECS` | 60 | covers database reload pauses |
| `CLAMD_FAIL_CLOSED` | `false` | quarantine when a scan errors |

## Resource use

| | Idle | Under load |
| --- | --- | --- |
| classifier | 11 MiB | 50 MiB peak, 320 MiB hard cap |
| clamd | 990 MiB | 1.2 GiB peak |

clamd memory is the official signature database and cannot be trimmed without losing coverage. `ConcurrentDatabaseReload no` keeps it from doubling during signature updates, at the cost of a pause in scanning during each reload.
