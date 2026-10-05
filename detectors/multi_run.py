"""
Multi-run evaluation - turns the single-capture comparison into a statistic.

One scenario run contains only tens of attack requests, so a single
precision/recall figure is illustrative, not conclusive. This script repeats
the whole pipeline N times on freshly generated traffic and reports each
metric as mean, standard deviation and a 95% confidence interval.

Each run:
    1. attacks/run_scenario.py   - new benign traffic (random jitter/setpoints)
                                   with the replay + injection attacks
    2. data/label_dataset.py     - label it into data/labeled.csv
    3. copy that to data/runs/run_XX.csv so every run is kept
    4. score it with both detectors (evaluate.py's functions), the Isolation
       Forest re-seeded per run so its randomness is part of the spread

The ML training set (data/baseline_capture.csv) is captured once and reused
for every run, mirroring deployment: train once on normal traffic, then face
many unseen traffic windows.

Outputs:
    data/runs/run_XX.csv            - each run's labeled test set
    data/multi_run_results.csv      - one row per (run, detector)
    data/multi_run_summary.csv      - mean / std / 95% CI per metric

Usage:
    python detectors/multi_run.py              # 10 runs (~9 min)
    python detectors/multi_run.py 5 --quick    # 5 short runs
    python detectors/multi_run.py --reuse      # re-score saved runs, no capture
"""

from __future__ import annotations

import csv
import math
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import (detection_latency, eval_ml, eval_rule_based,  # noqa: E402
                      quality_metrics)
from features import load_requests                                 # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
DATA_DIR = ROOT / "data"
RUNS_DIR = DATA_DIR / "runs"
TRAIN_CSV = DATA_DIR / "baseline_capture.csv"
RESULTS_CSV = DATA_DIR / "multi_run_results.csv"
SUMMARY_CSV = DATA_DIR / "multi_run_summary.csv"

METRICS = ["precision", "recall", "f1", "fpr", "accuracy",
           "latency_replay_s", "latency_injection_s",
           "per_request_ms", "peak_kb"]

# Two-sided 95% Student-t critical values by degrees of freedom (n - 1).
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447,
       7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179,
       13: 2.160, 14: 2.145, 15: 2.131, 19: 2.093, 24: 2.064, 29: 2.045}


def t_crit(df: int) -> float:
    if df in T95:
        return T95[df]
    smaller = [k for k in T95 if k <= df]
    return T95[max(smaller)] if smaller else T95[1]


def capture_run(i: int, quick: bool) -> Path:
    args = [PY, str(ROOT / "attacks" / "run_scenario.py")] + (["--quick"] if quick else [])
    subprocess.run(args, check=True, cwd=ROOT, stdout=subprocess.DEVNULL)
    subprocess.run([PY, str(DATA_DIR / "label_dataset.py")], check=True, cwd=ROOT,
                   stdout=subprocess.DEVNULL)
    out = RUNS_DIR / f"run_{i:02d}.csv"
    shutil.copyfile(DATA_DIR / "labeled.csv", out)
    return out


def score_run(train_df, test_csv: Path, seed: int) -> list[dict]:
    test_df = load_requests(str(test_csv))
    y = test_df["is_attack"].to_numpy()
    contamination = min(max(float(y.mean()), 0.01), 0.5)

    rows = []
    for name, (pred, cost) in (
        ("rule-based", eval_rule_based(train_df, test_df)),
        ("ml-iforest", eval_ml(train_df, test_df, contamination, random_state=seed)),
    ):
        q = quality_metrics(y, pred)
        lat = detection_latency(test_df, pred)
        rows.append({
            "run": test_csv.stem, "detector": name,
            "n_requests": len(test_df), "n_attack": int(y.sum()),
            **{k: q[k] for k in ("TP", "FP", "FN", "TN", "precision",
                                 "recall", "f1", "fpr", "accuracy")},
            # A missed attack has no latency; left blank and counted separately.
            "latency_replay_s": lat.get("replay"),
            "latency_injection_s": lat.get("injection"),
            "per_request_ms": cost["per_request_ms"],
            "peak_kb": cost["peak_kb"],
        })
    return rows


def summarize(results: list[dict]) -> list[dict]:
    summary = []
    for det in ("rule-based", "ml-iforest"):
        dr = [r for r in results if r["detector"] == det]
        for m in METRICS:
            vals = np.array([r[m] for r in dr if r[m] is not None], dtype=float)
            n = len(vals)
            mean = float(vals.mean()) if n else math.nan
            std = float(vals.std(ddof=1)) if n > 1 else 0.0
            half = t_crit(n - 1) * std / math.sqrt(n) if n > 1 else 0.0
            summary.append({"detector": det, "metric": m, "n": n,
                            "missed": len(dr) - n, "mean": mean, "std": std,
                            "ci95_low": mean - half, "ci95_high": mean + half})
        # Pooled confusion matrix over all runs: a micro-averaged view that
        # is not skewed by runs with very few attack requests.
        tp, fp, fn, tn = (sum(r[k] for r in dr) for k in ("TP", "FP", "FN", "TN"))
        for m, v in (("pooled_precision", tp / (tp + fp) if tp + fp else 0.0),
                     ("pooled_recall", tp / (tp + fn) if tp + fn else 0.0),
                     ("pooled_fpr", fp / (fp + tn) if fp + tn else 0.0)):
            summary.append({"detector": det, "metric": m, "n": len(dr), "missed": 0,
                            "mean": v, "std": "", "ci95_low": "", "ci95_high": ""})
    return summary


def write_csv(path: Path, rows: list[dict]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    nums = [a for a in sys.argv[1:] if a.isdigit()]
    n_runs = int(nums[0]) if nums else 10
    quick = "--quick" in sys.argv
    reuse = "--reuse" in sys.argv

    if not TRAIN_CSV.exists():
        raise SystemExit(f"Missing {TRAIN_CSV}; run: python testbed/capture_baseline.py")
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    train_df = load_requests(str(TRAIN_CSV))

    if reuse:
        run_files = sorted(RUNS_DIR.glob("run_*.csv"))
        if not run_files:
            raise SystemExit(f"No saved runs in {RUNS_DIR}")
    else:
        run_files = []
        for i in range(1, n_runs + 1):
            print(f"[multi-run] capturing run {i}/{n_runs}...", flush=True)
            run_files.append(capture_run(i, quick))

    results = []
    for seed, f in enumerate(run_files):
        results.extend(score_run(train_df, f, seed))
    write_csv(RESULTS_CSV, results)
    summary = summarize(results)
    write_csv(SUMMARY_CSV, summary)

    print(f"\nModbus/TCP IDS - {len(run_files)}-run comparison "
          f"(train: {len(train_df)} benign requests)")
    print(f"{'metric':<22}{'rule-based':>26}{'ML (iForest)':>26}")
    print("-" * 74)
    by = {(s["detector"], s["metric"]): s for s in summary}
    for m in METRICS:
        cells = []
        for det in ("rule-based", "ml-iforest"):
            s = by[(det, m)]
            fmt = ".4f" if m == "per_request_ms" else (".0f" if m == "peak_kb" else ".3f")
            cell = f"{s['mean']:{fmt}} ± {s['ci95_high'] - s['mean']:{fmt}}"
            if s["missed"]:
                cell += f" ({s['missed']} missed)"
            cells.append(cell)
        print(f"{m:<22}{cells[0]:>26}{cells[1]:>26}")
    for m in ("pooled_precision", "pooled_recall", "pooled_fpr"):
        print(f"{m:<22}{by[('rule-based', m)]['mean']:>26.3f}"
              f"{by[('ml-iforest', m)]['mean']:>26.3f}")
    print("\n(± is the 95% confidence half-width over runs)")
    print(f"per-run rows -> {RESULTS_CSV}\nsummary      -> {SUMMARY_CSV}")


if __name__ == "__main__":
    main()
