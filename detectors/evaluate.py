"""
Evaluation harness - the head-to-head comparison (Phase 4 core).

Runs the rule-based detector and the ML anomaly detectors (Isolation Forest,
as originally configured and tuned, and a one-class SVM) over the SAME labeled
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
                                        ML contamination, and the tuned ML
                                        detector's alert threshold, are set
                                        from it)
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
from ocsvm import OneClassSVMDetector             # noqa: E402
from rule_based import RuleBasedDetector          # noqa: E402


NAN = float("nan")


def ratio(num: int, den: int) -> float:
    """num / den, or NaN when den is 0. An undefined metric (precision of a
    detector that never alerted, recall on a session with no attacks) must not
    read as 0.0, which is indistinguishable from 'always wrong'."""
    return num / den if den else NAN


def quality_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    # F1 = 2TP / (2TP + FP + FN): defined (0) when there are attacks or
    # alerts but no hits, undefined only when there are neither.
    f1 = ratio(2 * tp, 2 * tp + fp + fn)
    fpr = ratio(fp, fp + tn)
    accuracy = ratio(tp + tn, len(y_true))
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": precision,
            "recall": recall, "f1": f1, "fpr": fpr, "accuracy": accuracy}


def check_separate_sessions(**sessions) -> None:
    """Abort if any two of the train / tune / test sessions share captured
    requests. capture_tuning.py saves the tuning session by copying the
    latest labeled.csv, so running the defaults right after it would score
    the tuning session against itself."""
    keys = {name: set(zip(df["wall_time"], df["raw_hex"])) for name, df in sessions.items()}
    names = list(keys)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            shared = len(keys[a] & keys[b])
            if shared:
                raise SystemExit(
                    f"The {a} and {b} sessions share {shared} captured requests; "
                    "they must be separate captures. If labeled.csv was just "
                    "copied to tuning_labeled.csv, capture a fresh test session "
                    "(attacks/run_scenario.py + data/label_dataset.py) or pass "
                    "a saved run: python detectors/evaluate.py <train> data/runs/run_01.csv")


def label_problems(df) -> dict:
    """Counts of requests the labeler could not attribute (they are left
    unscored, which silently shrinks the denominator if not reported)."""
    if "label" not in df.columns:
        return {}
    counts = df["label"].value_counts()
    return {k: int(counts[k]) for k in ("unmatched", "unknown") if k in counts}


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
    if len(y) == 0:
        raise ValueError("tuning session has no scored requests")
    share = float(y.mean())
    clamped = min(max(share, 0.01), 0.5)
    if clamped != share:
        print(f"[evaluate] WARNING: tuning-session attack share {share:.3f} is outside "
              f"0.01-0.5; contamination clamped to {clamped:.3f}", file=sys.stderr)
    return clamped


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


def eval_ml(train_df, test_df, contamination, random_state=None, tune_df=None):
    """ML detector. With tune_df, the tuned variant: first-gap fill plus an
    alert threshold calibrated on that tuning session (counted as training)."""
    kw = {} if random_state is None else {"random_state": random_state}
    tuned = tune_df is not None

    def build():
        det = MLAnomalyDetector(contamination=contamination, fill_first_gap=tuned,
                                **kw).fit(train_df)
        return det.calibrate(tune_df) if tuned else det

    _warm_up("ml-tuned" if tuned else "ml", lambda: build().predict(test_df.head(5)))
    tracemalloc.start()
    t0 = time.perf_counter()
    det = build()
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


def eval_ocsvm(train_df, test_df, tune_df):
    """One-class SVM: trained on normal traffic, threshold calibrated on the
    tuning session (calibration counted as part of training)."""
    def build():
        return OneClassSVMDetector().fit(train_df).calibrate(tune_df)

    _warm_up("ocsvm", lambda: build().predict(test_df.head(5)))
    tracemalloc.start()
    t0 = time.perf_counter()
    det = build()
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
    check_separate_sessions(train=train_df, tune=tune_df, test=test_df)
    mask = scored_mask(test_df)
    y = test_df["is_attack"].to_numpy()[mask]
    contamination = contamination_from(tune_df)
    problems = label_problems(test_df)
    if problems:
        print(f"[evaluate] WARNING: test requests the labeler could not attribute "
              f"(left unscored): {problems}", file=sys.stderr)
    if not (y == 1).any() or not (y == 0).any():
        print("[evaluate] WARNING: the test session lacks attacks or benign requests; "
              "recall or FPR is undefined (nan)", file=sys.stderr)

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
    print_report("ML anomaly detector (Isolation Forest, contamination cut-off)",
                 ml_q, ml_cost, ml_lat)

    mt_pred, mt_cost = eval_ml(train_df, test_df, contamination, tune_df=tune_df)
    mt_q = quality_metrics(y, mt_pred[mask])
    mt_lat = detection_latency(test_df, mt_pred)
    print_report("ML anomaly detector (Isolation Forest, threshold tuned on tuning session)",
                 mt_q, mt_cost, mt_lat)

    sv_pred, sv_cost = eval_ocsvm(train_df, test_df, tune_df)
    sv_q = quality_metrics(y, sv_pred[mask])
    sv_lat = detection_latency(test_df, sv_pred)
    print_report("ML anomaly detector #2 (one-class SVM, threshold tuned on tuning session)",
                 sv_q, sv_cost, sv_lat)

    # Compact side-by-side for the report.
    print("\n=== side-by-side ===")
    hdr = (f"{'metric':<18}{'rule-based':>14}{'ML (iForest)':>16}{'ML (tuned)':>14}"
           f"{'OC-SVM':>10}")
    print(hdr)
    print("-" * len(hdr))
    for key, label in [("precision", "precision"), ("recall", "recall"),
                       ("f1", "F1"), ("fpr", "false-pos rate"),
                       ("accuracy", "accuracy")]:
        print(f"{label:<18}{rb_q[key]:>14.3f}{ml_q[key]:>16.3f}{mt_q[key]:>14.3f}"
              f"{sv_q[key]:>10.3f}")
    for key, label, fmt in [("per_request_ms", "ms/request", ".4f"),
                            ("peak_kb", "detect peak KB", ".0f"),
                            ("model_kb", "model held KB", ".0f"),
                            ("train_peak_kb", "train peak KB", ".0f"),
                            ("train_ms", "train ms", ".1f")]:
        print(f"{label:<18}{rb_cost[key]:>14{fmt}}{ml_cost[key]:>16{fmt}}{mt_cost[key]:>14{fmt}}"
              f"{sv_cost[key]:>10{fmt}}")


if __name__ == "__main__":
    main()
