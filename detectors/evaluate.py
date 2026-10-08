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
    reports for a head-to-head. Training (one-time) and detection (recurring)
    are measured separately so the ML training step does not inflate its
    detection cost.

Three independent capture sessions, never mixed (no train/tune/test leakage):
  * train = data/baseline_capture.csv  (normal only; the ML model fits on this)
  * tune  = data/tuning_labeled.csv    (its own labeled scenario session; the
                                        ML contamination is set from it)
  * test  = data/labeled.csv           (benign + replay + injection; used only
                                        for final scoring, its labels are never
                                        used to configure a detector)

Only scored requests are graded: PLC responses and the replay's seed packet
are kept in the stream the detectors see but are left out of the metrics.

Cost is the detector's own processing cost on the monitoring host. The
detectors read a copy of the traffic and are not in the control path, so they
add no delay to the PLC/HMI control cycle by construction.

Usage:
    python detectors/evaluate.py
    python detectors/evaluate.py <train_csv> <test_csv> [<tune_csv>]
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


def scored_mask(df) -> np.ndarray:
    return df["scored"].to_numpy() if "scored" in df.columns else np.ones(len(df), bool)


def contamination_from(tune_df) -> float:
    """ML contamination = attack fraction of the scored requests in the
    separate tuning session (the proposal's "tuned to the expected imbalance"),
    clamped to the range IsolationForest accepts."""
    y = tune_df["is_attack"].to_numpy()[scored_mask(tune_df)]
    return min(max(float(y.mean()), 0.01), 0.5)


# Memory is measured in separate tracemalloc windows so training and detection
# are never mixed:
#   train_peak_kb - peak while building the detector (ML: fitting the forest;
#                   rules: loading the config). A one-time, offline cost.
#   model_kb      - memory the built detector keeps holding afterwards; it
#                   must stay resident for as long as detection runs.
#   peak_kb       - peak extra memory while scoring the test traffic, the
#                   recurring cost compared head-to-head.
# Each detector is exercised once, unmeasured, before its first measurement:
# the first scikit-learn fit/predict in a process loads code and caches that
# would otherwise be counted as model memory in that one run only.

_warmed: set[str] = set()


def _warm_up(name, fn) -> None:
    if name not in _warmed:
        fn()
        _warmed.add(name)


def eval_rule_based(train_df, test_df):
    _warm_up("rule-based", lambda: [RuleBasedDetector().score_request(r)
                                    for r in test_df.head(5).itertuples(index=False)])
    tracemalloc.start()
    det = RuleBasedDetector()  # config-driven; no training needed
    model_bytes, build_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

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
        "train_peak_kb": build_peak / 1024,
        "model_kb": model_bytes / 1024,
    }


def eval_ml(train_df, test_df, contamination, random_state=None):
    kw = {} if random_state is None else {"random_state": random_state}
    _warm_up("ml", lambda: MLAnomalyDetector(contamination=contamination, **kw)
             .fit(train_df).predict(test_df.head(5)))
    tracemalloc.start()
    t0 = time.perf_counter()
    det = MLAnomalyDetector(contamination=contamination, **kw).fit(train_df)
    train_ms = 1000 * (time.perf_counter() - t0)
    model_bytes, train_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    tracemalloc.start()
    t1 = time.perf_counter()
    preds = det.predict(test_df)
    predict_elapsed = time.perf_counter() - t1
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return preds, {
        "per_request_ms": 1000 * predict_elapsed / max(len(test_df), 1),
        "peak_kb": peak / 1024,
        "train_ms": train_ms,
        "train_peak_kb": train_peak / 1024,
        "model_kb": model_bytes / 1024,
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
    print(f"  detection cost: {cost['per_request_ms']:.4f} ms/request   "
          f"peak {cost['peak_kb']:.0f} KB   (model held: {cost['model_kb']:.0f} KB)")
    print(f"  build/training cost (one-time): {cost['train_ms']:.1f} ms   "
          f"peak {cost['train_peak_kb']:.0f} KB")


def main() -> None:
    train_csv = sys.argv[1] if len(sys.argv) > 1 else "data/baseline_capture.csv"
    test_csv = sys.argv[2] if len(sys.argv) > 2 else "data/labeled.csv"
    tune_csv = sys.argv[3] if len(sys.argv) > 3 else "data/tuning_labeled.csv"

    for pth in (train_csv, test_csv, tune_csv):
        if not Path(pth).exists():
            raise SystemExit(
                f"Missing {pth}. Generate the three sessions first:\n"
                "  python testbed/capture_baseline.py     # train -> data/baseline_capture.csv\n"
                "  python attacks/capture_tuning.py       # tune  -> data/tuning_labeled.csv\n"
                "  python attacks/run_scenario.py && python data/label_dataset.py   # test")

    train_df = load_requests(train_csv)
    tune_df = load_requests(tune_csv)
    test_df = load_requests(test_csv)
    mask = scored_mask(test_df)
    y = test_df["is_attack"].to_numpy()[mask]
    contamination = contamination_from(tune_df)

    print("Modbus/TCP IDS - detector comparison")
    print(f"  train (normal only): {len(train_df)} requests  <- {train_csv}")
    print(f"  tune  (own session): ML contamination = {contamination:.3f}  <- {tune_csv}")
    print(f"  test  (scored):      {len(y)} requests "
          f"({int(y.sum())} attack / {int((y == 0).sum())} benign)  <- {test_csv}")

    rb_pred, rb_cost = eval_rule_based(train_df, test_df)
    rb_q = quality_metrics(y, rb_pred[mask])
    rb_lat = detection_latency(test_df, rb_pred)
    print_report("Rule-based detector", rb_q, rb_cost, rb_lat)

    ml_pred, ml_cost = eval_ml(train_df, test_df, contamination)
    ml_q = quality_metrics(y, ml_pred[mask])
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
    print(f"{'detect peak KB':<18}{rb_cost['peak_kb']:>14.0f}{ml_cost['peak_kb']:>16.0f}")
    print(f"{'model held KB':<18}{rb_cost['model_kb']:>14.0f}{ml_cost['model_kb']:>16.0f}")
    print(f"{'train peak KB':<18}{rb_cost['train_peak_kb']:>14.0f}{ml_cost['train_peak_kb']:>16.0f}")
    print(f"{'train ms':<18}{rb_cost['train_ms']:>14.1f}{ml_cost['train_ms']:>16.1f}")


if __name__ == "__main__":
    main()
