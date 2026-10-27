# Sanct Classifier

Spam and malware detection for Sanct inbound mail. A small Rust service that scores messages with a linear text model and scans attachments with ClamAV.

- Runs as a sidecar next to the mail server, so message content never leaves the pod
- Wipes every request from memory once it is answered
- Trained only on public datasets, never on user mail
- About 11 MiB of RAM when idle

## Quick start

```bash
export CLASSIFIER_API_SECRET="$(openssl rand -base64 48)"
docker compose up -d --build
curl -s localhost:8080/readyz
```

## API

`POST /classify` with header `X-API-Secret`:

```json
{
  "subject": "...",
  "body": "...",
  "spf": "pass",
  "dkim": "pass",
  "dmarc": "pass",
  "attachments": [{ "filename": "a.pdf", "content_base64": "..." }]
}
```

Response:

```json
{ "label": "ham", "confidence": 0.99, "spam_score": 0.01, "virus": null, "virus_scan": "clean" }
```

`label` is `ham`, `spam`, or `malicious` (ClamAV match or a blocked executable attachment).

Also: `GET /healthz`, `GET /readyz`, `GET /metrics`.

## Model

| Test set | AUC | Precision | Recall | False positives |
| --- | --- | --- | --- | --- |
| 21,290 emails | 0.9992 | 99.8% | 93.7% | 0.15% |

Trained on [seven-phishing-email-datasets](https://huggingface.co/datasets/puyang2025/seven-phishing-email-datasets), [aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus), and [LLMGen-Phishing-Email-Dataset](https://huggingface.co/datasets/Dizzzy0x00/LLMGen-Phishing-Email-Dataset).

To retrain:

```bash
uv sync
uv run python -m training.train
uv run python -m training.golden
cargo test --release
```

## Configuration

| Variable | Default |
| --- | --- |
| `CLASSIFIER_API_SECRET` or `CLASSIFIER_API_SECRET_FILE` | required, at least 32 bytes |
| `CLASSIFIER_LISTEN` | `0.0.0.0:8080` |
| `CLAMD_ADDRESS` | unset, scanning disabled (`unix:///path` or `tcp://host:port`) |
| `CLAMD_FAIL_CLOSED` | `false` |
| `CLASSIFIER_THRESHOLD` | from the model |
| `CLASSIFIER_MAX_REQUEST_BYTES` | 72 MiB |
| `CLASSIFIER_MEMORY_BUDGET_BYTES` | 256 MiB |
| `CLASSIFIER_MAX_CONCURRENCY` | 16 |

## License

[Apache 2.0](LICENSE)
