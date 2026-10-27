import argparse
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from scipy import sparse
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import log_loss, roc_auc_score

from training import datasets, features

VIEWS = ("full", "snippet")
SPLITS = ("train", "val", "test")
MODEL_NAME = "sanct-spam"
DEFAULT_GRID = [
    {"alpha": alpha, "average": average}
    for alpha in (1e-7, 3e-7, 1e-6, 3e-6, 1e-5)
    for average in (False, True)
]


def _vectorize_chunk(pairs):
    indptr = [0]
    indices = []
    data = []
    for subject, body in pairs:
        vector = features.vectorize(subject, body)
        indices.extend(vector.keys())
        data.extend(vector.values())
        indptr.append(len(indices))
    return (
        np.asarray(indptr, dtype=np.int64),
        np.asarray(indices, dtype=np.int32),
        np.asarray(data, dtype=np.float32),
    )


def featurize(pairs, workers, chunk_size=2000):
    chunks = [pairs[i : i + chunk_size] for i in range(0, len(pairs), chunk_size)]
    with Pool(workers) as pool:
        parts = pool.map(_vectorize_chunk, chunks)
    offsets = []
    offset = 0
    for indptr, _, _ in parts:
        offsets.append(indptr[:-1] + offset)
        offset += int(indptr[-1])
    offsets.append(np.asarray([offset], dtype=np.int64))
    return sparse.csr_matrix(
        (
            np.concatenate([p[2] for p in parts]),
            np.concatenate([p[1] for p in parts]),
            np.concatenate(offsets),
        ),
        shape=(len(pairs), features.DIM),
    )


def prepare(out_dir, workers):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()
    emails, conflicts = datasets.load()

    pairs, labels, splits, views, sources = [], [], [], [], []
    for email in emails:
        for view in VIEWS:
            subject, body = (
                (email.subject, email.body)
                if view == "full"
                else features.snippet_view(email.subject, email.body)
            )
            pairs.append((subject, body))
            labels.append(email.label)
            splits.append(SPLITS.index(email.split))
            views.append(VIEWS.index(view))
            sources.append(email.source)

    X = featurize(pairs, workers)
    sparse.save_npz(out_dir / "X.npz", X, compressed=False)
    np.savez(
        out_dir / "meta.npz",
        y=np.asarray(labels, dtype=np.int8),
        split=np.asarray(splits, dtype=np.int8),
        view=np.asarray(views, dtype=np.int8),
        source=np.asarray(sources),
    )

    counts = {}
    for email in emails:
        bucket = counts.setdefault(email.source, {"ham": 0, "spam": 0})
        bucket["spam" if email.label else "ham"] += 1
    stats = {
        "emails": len(emails),
        "label_conflicts_dropped": conflicts,
        "rows": X.shape[0],
        "nnz": int(X.nnz),
        "per_source": counts,
        "per_split": {s: sum(1 for e in emails if e.split == s) for s in SPLITS},
        "seconds": round(time.time() - started, 1),
    }
    (out_dir / "stats.json").write_text(json.dumps(stats, indent=2))
    return stats


def load_prepared(data_dir):
    data_dir = Path(data_dir)
    X = sparse.load_npz(data_dir / "X.npz").tocsr()
    meta = dict(np.load(data_dir / "meta.npz"))
    return X, meta


def _mask(meta, split, view=None, source=None, exclude_source=None):
    mask = meta["split"] == SPLITS.index(split)
    if view is not None:
        mask &= meta["view"] == VIEWS.index(view)
    if source is not None:
        mask &= meta["source"] == source
    if exclude_source is not None:
        mask &= meta["source"] != exclude_source
    return mask


def _sigmoid(x):
    return 0.5 * (1.0 + np.tanh(0.5 * x))


def fit(X, meta, params, holdout=None):
    started = time.time()
    train = _mask(meta, "train", exclude_source=holdout)
    clf = SGDClassifier(
        loss="log_loss",
        alpha=params["alpha"],
        average=params["average"],
        max_iter=params.get("epochs", 40),
        tol=1e-5,
        random_state=0,
    )
    clf.fit(X[train], meta["y"][train])
    coef = clf.coef_.ravel().astype(np.float32)
    bias = float(clf.intercept_[0])
    result = {
        "params": params,
        "holdout": holdout,
        "train_rows": int(train.sum()),
        "seconds": round(time.time() - started, 1),
    }

    if holdout is None:
        val = _mask(meta, "val")
        p = _sigmoid(X[val] @ coef + bias)
        result["val_logloss"] = float(log_loss(meta["y"][val], p, labels=[0, 1]))
        result["val_auc"] = float(roc_auc_score(meta["y"][val], p))
        result["coef"] = coef.tobytes()
        result["bias"] = bias
    else:
        rows = (meta["source"] == holdout) & (meta["split"] != SPLITS.index("train"))
        rows &= meta["view"] == VIEWS.index("full")
        y = meta["y"][rows]
        p = _sigmoid(X[rows] @ coef + bias)
        result["holdout_rows"] = int(rows.sum())
        result["holdout_accuracy"] = float(((p >= 0.5) == y).mean())
        if 0 < y.sum() < len(y):
            result["holdout_auc"] = float(roc_auc_score(y, p))
    return result


def _binary_metrics(y, p, threshold):
    pred = p >= threshold
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    tn = int((~pred & (y == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    metrics = {
        "n": int(len(y)),
        "accuracy": round((tp + tn) / len(y), 5) if len(y) else 0.0,
        "precision": round(precision, 5),
        "recall": round(recall, 5),
        "f1": round(2 * precision * recall / (precision + recall), 5) if precision + recall else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 5) if fp + tn else 0.0,
    }
    if 0 < y.sum() < len(y):
        metrics["auc"] = round(float(roc_auc_score(y, p)), 5)
    return metrics


def finalize(X, meta, best, max_fpr, stats=None, grid=None, holdouts=None):
    coef = np.frombuffer(best["coef"], dtype=np.float32).astype(np.float64)
    bias = best["bias"]

    val = _mask(meta, "val")
    val_logits = X[val] @ coef + bias
    calibrator = LogisticRegression(C=1e4).fit(val_logits.reshape(-1, 1), meta["y"][val])
    scale = float(calibrator.coef_[0, 0])
    offset = float(calibrator.intercept_[0])

    weights = (coef * scale).astype("<f4")
    final_bias = bias * scale + offset

    def score(mask):
        return _sigmoid(X[mask] @ weights.astype(np.float64) + final_bias)

    p_val = score(val)
    ham_scores = np.sort(p_val[meta["y"][val] == 0])
    allowed = int(np.floor(max_fpr * len(ham_scores)))
    threshold = float(np.nextafter(ham_scores[len(ham_scores) - 1 - allowed], 1.0))
    threshold = min(max(threshold, 0.5), 0.999)

    test_metrics = {}
    for view in VIEWS:
        mask = _mask(meta, "test", view=view)
        y = meta["y"][mask]
        p = score(mask)
        by_source = {}
        for source in sorted(set(meta["source"][mask].tolist())):
            sub = meta["source"][mask] == source
            by_source[source] = _binary_metrics(y[sub], p[sub], threshold)
        test_metrics[view] = {"overall": _binary_metrics(y, p, threshold), "by_source": by_source}

    raw = weights.tobytes()
    meta_json = {
        "name": MODEL_NAME,
        "feature_version": features.FEATURE_VERSION,
        "dim_bits": features.DIM_BITS,
        "weights_file": f"{MODEL_NAME}.bin",
        "weights_sha256": hashlib.sha256(raw).hexdigest(),
        "bias": final_bias,
        "threshold": round(threshold, 6),
        "max_val_fpr": max_fpr,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "params": best["params"],
        "calibration": {"scale": scale, "offset": offset},
        "datasets": [
            {"repo": s["repo"], "revision": s["revision"], "files": s["files"], "license": s["license"]}
            for s in datasets.SOURCES
        ],
        "data": stats,
        "grid": [
            {k: r[k] for k in ("params", "val_logloss", "val_auc", "seconds")} for r in grid or []
        ],
        "holdout": [
            {k: v for k, v in r.items() if k.startswith("holdout") or k == "train_rows"}
            for r in holdouts or []
        ],
        "test": test_metrics,
    }
    return raw, meta_json


def write_model(raw, meta_json, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / meta_json["weights_file"]).write_bytes(raw)
    (out_dir / f"{MODEL_NAME}.json").write_text(json.dumps(meta_json, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Train the Sanct spam model locally")
    parser.add_argument("--work-dir", default="data/prepared")
    parser.add_argument("--out-dir", default="models")
    parser.add_argument("--workers", type=int, default=os.cpu_count())
    parser.add_argument("--max-fpr", type=float, default=0.002)
    parser.add_argument("--skip-prepare", action="store_true")
    args = parser.parse_args()

    stats = None if args.skip_prepare else prepare(args.work_dir, args.workers)
    X, meta = load_prepared(args.work_dir)
    grid = [fit(X, meta, params) for params in DEFAULT_GRID]
    best = min(grid, key=lambda r: r["val_logloss"])
    raw, meta_json = finalize(X, meta, best, args.max_fpr, stats=stats, grid=grid)
    write_model(raw, meta_json, args.out_dir)
    print(json.dumps(meta_json["test"], indent=2))


if __name__ == "__main__":
    main()
