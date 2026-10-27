import csv
import hashlib
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

DATA_DIR = Path(os.environ.get("SANCT_DATA_DIR", Path(__file__).resolve().parent.parent / "data")) / "hf"

SOURCES = [
    {
        "repo": "puyang2025/seven-phishing-email-datasets",
        "revision": "b7f3f8d99ebd4fd0af0a5afe027420e53f08d1a4",
        "license": "research corpora (TREC, CEAS, Enron, SpamAssassin, Ling)",
        "files": ["train.parquet", "eval.parquet", "test.parquet"],
    },
    {
        "repo": "kudzaiprichard/aura-phishing-email-corpus",
        "revision": "539567cee21d03c83bd2fb1b142c18a80904eb72",
        "license": "cc-by-4.0",
        "files": ["Nazario_5.csv", "Nigerian_5.csv"],
    },
    {
        "repo": "Dizzzy0x00/LLMGen-Phishing-Email-Dataset",
        "revision": "d717e5457b71cb44dd038dafe6a81cea5e0badab",
        "license": "apache-2.0",
        "files": ["GPT_Phishing_Email_dataset.csv"],
    },
]

WS_RE = re.compile(r"\s+")
LLMGEN_HEADER_RE = re.compile(
    r"^\W*subject\W*:\W*(?P<subject>.*?)\s+\W*from\W*:.*?"
    r"(?=(?:dear|hi|hello|greetings|good (?:morning|afternoon|evening))\b|---|$)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True)
class Email:
    source: str
    subject: str
    body: str
    label: int
    key: str

    @property
    def split(self):
        bucket = int(self.key[:8], 16) % 100
        if bucket < 80:
            return "train"
        if bucket < 90:
            return "val"
        return "test"


def download():
    from huggingface_hub import hf_hub_download

    paths = {}
    for source in SOURCES:
        for name in source["files"]:
            paths[(source["repo"], name)] = Path(
                hf_hub_download(
                    repo_id=source["repo"],
                    filename=name,
                    repo_type="dataset",
                    revision=source["revision"],
                    local_dir=DATA_DIR / source["repo"].replace("/", "__"),
                )
            )
    return paths


def dedup_key(subject, body):
    normalized = WS_RE.sub(" ", f"{subject}\n{body[:5000]}".casefold()).strip()
    return hashlib.sha1(normalized.encode("utf-8")).hexdigest()


def _clean(value):
    if value is None:
        return ""
    return str(value).replace("\x00", "")


def _label(value):
    return 1 if str(value).strip() in {"1", "1.0", "spam", "phishing"} else 0


def _read_parquet(path):
    import pyarrow.parquet as pq

    table = pq.read_table(path, columns=["text", "subject", "label", "dataset_name"])
    for row in table.to_pylist():
        yield row["dataset_name"] or "seven", _clean(row["subject"]), _clean(row["text"]), _label(row["label"])


def _read_aura(path):
    source = path.stem.split("_")[0].lower()
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        for row in csv.DictReader(handle):
            yield source, _clean(row.get("subject")), _clean(row.get("body")), _label(row.get("label"))


def _read_llmgen(path):
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        for row in csv.DictReader(handle):
            content = _clean(row.get("content")).strip()
            subject = ""
            match = LLMGEN_HEADER_RE.match(content)
            if match:
                subject = match.group("subject").strip(" *")
                content = content[match.end() :].lstrip(" -")
            yield "llmgen", subject, content, _label(row.get("label"))


def load(paths=None):
    csv.field_size_limit(sys.maxsize)
    paths = paths or download()
    seen = {}
    conflicts = set()
    for (repo, name), path in paths.items():
        if name.endswith(".parquet"):
            rows = _read_parquet(path)
        elif repo.startswith("kudzaiprichard"):
            rows = _read_aura(path)
        else:
            rows = _read_llmgen(path)
        for source, subject, body, label in rows:
            if not subject.strip() and not body.strip():
                continue
            key = dedup_key(subject, body)
            existing = seen.get(key)
            if existing is None:
                seen[key] = Email(source, subject, body, label, key)
            elif existing.label != label:
                conflicts.add(key)
    for key in conflicts:
        del seen[key]
    return list(seen.values()), len(conflicts)


if __name__ == "__main__":
    for (repo, name), path in download().items():
        print(f"{repo}/{name} -> {path} ({path.stat().st_size} bytes)")
