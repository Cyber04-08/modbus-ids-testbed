"""
Evaluation harness - the head-to-head comparison (Phase 4 core).

Runs the rule-based detector and the ML anomaly detector over the SAME labeled
test traffic and reports, for each, exactly the metrics the proposal commits to:

  * Detection quality: precision, recall, F1, false-positive rate (FPR).
    (Raw accuracy is reported too but is not the headline - the dataset is
    deliberately benign-heavy, so accuracy is easy to inflate.)
  * Mean detection latency: wall-clock time from the first malicious packet of
    an attack to the detector's first alert on that attack.
  * Operational cost: mean per-request processing time and peak memory, the
    "can this run next to real equipment?" numbers that neither prior work
    reports for a head-to-head.

Datasets (kept separate to avoid train/test leakage):
  * train = data/baseline_capture.csv  (normal only; ML trains on this)
  * test  = data/labeled.csv           (benign + replay + injection)

Usage:
    python detectors/evaluate.py
    python detectors/evaluate.py <train_csv> <test_csv>
"""

from __future__ import annotations

import sys
import time
import tracemalloc
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import load_requests               # noqa: E402
from ml_anomaly import MLAnomalyDetector          # noqa: E402
from rule_based import RuleBasedDetector          # noqa: E402


def quality_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / len(y_true) if len(y_true) else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": precision,
            "recall": recall, "f1": f1, "fpr": fpr, "accuracy": accuracy}


def detection_latency(df, y_pred: np.ndarray) -> dict:
    """Per attack type, seconds from the first true malicious request to the
    first correctly-flagged malicious request. None if the attack was missed."""
    out = {}
    labels = df["label"].to_numpy() if "label" in df.columns else None
    if labels is None:
        return out
    wall = df["wall_time"].to_numpy()
    for atk in ("replay", "injection"):
        idx = np.where(labels == atk)[0]
        if len(idx) == 0:
            continue
        first_attack_t = wall[idx].min()
        flagged = idx[(y_pred[idx] == 1)]
        if len(flagged) == 0:
            out[atk] = None
        else:
            out[atk] = float(wall[flagged].min() - first_attack_t)
    return out


def eval_rule_based(train_df, test_df):
    y = test_df["is_attack"].to_numpy()
    det = RuleBasedDetector()  # config-driven; no training needed
    rows = list(test_df.itertuples(index=False))

    tracemalloc.start()
    t0 = time.perf_counter()
    preds = np.array([det.score_request(r)[0] for r in rows])
    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return preds, {
        "per_request_ms": 1000 * elapsed / max(len(rows), 1),
        "peak_kb": peak / 1024,
        "train_ms": 0.0,
    }


def eval_ml(train_df, test_df, contamination):
    tracemalloc.start()
    t0 = time.perf_counter()
    det = MLAnomalyDetector(contamination=contamination).fit(train_df)
    train_ms = 1000 * (time.perf_counter() - t0)

    t1 = time.perf_counter()
    preds = det.predict(test_df)
    predict_elapsed = time.perf_counter() - t1
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return preds, {
        "per_request_ms": 1000 * predict_elapsed / max(len(test_df), 1),
        "peak_kb": peak / 1024,
        "train_ms": train_ms,
    }


def print_report(name, q, cost, latency):
    print(f"\n=== {name} ===")
    print(f"  precision {q['precision']:.3f}   recall {q['recall']:.3f}   "
          f"F1 {q['f1']:.3f}   FPR {q['fpr']:.3f}   accuracy {q['accuracy']:.3f}")
    print(f"  confusion: TP={q['TP']} FP={q['FP']} FN={q['FN']} TN={q['TN']}")
    lat_bits = []
    for atk, v in latency.items():
        lat_bits.append(f"{atk}={'MISSED' if v is None else f'{v:.3f}s'}")
    print(f"  detection latency: {'  '.join(lat_bits) if lat_bits else 'n/a'}")
    print(f"  cost: {cost['per_request_ms']:.4f} ms/request   "
          f"peak {cost['peak_kb']:.0f} KB"
          + (f"   train {cost['train_ms']:.1f} ms" if cost['train_ms'] else ""))


def main() -> None:
    train_csv = sys.argv[1] if len(sys.argv) > 1 else "data/baseline_capture.csv"
    test_csv = sys.argv[2] if len(sys.argv) > 2 else "data/labeled.csv"

    for pth in (train_csv, test_csv):
        if not Path(pth).exists():
            raise SystemExit(
                f"Missing {pth}. Generate datasets first:\n"
                "  python testbed/capture_baseline.py     # -> data/baseline_capture.csv\n"
                "  python attacks/run_scenario.py && python data/label_dataset.py")

    train_df = load_requests(train_csv)
    test_df = load_requests(test_csv)
    y = test_df["is_attack"].to_numpy()

    # Set ML contamination to the actual attack fraction in the test set - the
    # proposal's "tuned to reflect the expected imbalance" rather than default.
    attack_fraction = float(y.mean())
    contamination = min(max(attack_fraction, 0.01), 0.5)

    print("Modbus/TCP IDS - detector comparison")
    print(f"  train (normal only): {len(train_df)} requests  <- {train_csv}")
    print(f"  test  (mixed):       {len(test_df)} requests "
          f"({int(y.sum())} attack / {int((y == 0).sum())} benign)  <- {test_csv}")
    print(f"  ML contamination set to observed attack fraction: {contamination:.3f}")

    rb_pred, rb_cost = eval_rule_based(train_df, test_df)
    rb_q = quality_metrics(y, rb_pred)
    rb_lat = detection_latency(test_df, rb_pred)
    print_report("Rule-based detector", rb_q, rb_cost, rb_lat)

    ml_pred, ml_cost = eval_ml(train_df, test_df, contamination)
    ml_q = quality_metrics(y, ml_pred)
    ml_lat = detection_latency(test_df, ml_pred)
    print_report("ML anomaly detector (Isolation Forest)", ml_q, ml_cost, ml_lat)

    # Compact side-by-side for the report.
    print("\n=== side-by-side ===")
    hdr = f"{'metric':<18}{'rule-based':>14}{'ML (iForest)':>16}"
    print(hdr)
    print("-" * len(hdr))
    for key, label in [("precision", "precision"), ("recall", "recall"),
                       ("f1", "F1"), ("fpr", "false-pos rate"),
                       ("accuracy", "accuracy")]:
        print(f"{label:<18}{rb_q[key]:>14.3f}{ml_q[key]:>16.3f}")
    print(f"{'ms/request':<18}{rb_cost['per_request_ms']:>14.4f}"
          f"{ml_cost['per_request_ms']:>16.4f}")
    print(f"{'peak KB':<18}{rb_cost['peak_kb']:>14.0f}{ml_cost['peak_kb']:>16.0f}")


if __name__ == "__main__":
    main()
