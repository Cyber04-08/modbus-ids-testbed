"""
Training-length curve - how much normal traffic does the ML detector need?

Takes one long normal-only capture (e.g. 60 minutes, recorded with
`python testbed/capture_baseline.py 3600 data/baseline_60min.csv`) and trains
the Isolation Forest on its first 1, 2, 5, ... minutes. Each training length
is scored on the same saved test runs (data/runs/run_XX.csv), for both ML
variants:

    ml-iforest - contamination cut-off (0.177 from the tuning session)
    ml-tuned   - first-gap fill + threshold calibrated on the tuning session

Train, tune and test are still separate sessions: only the amount of the
training session used changes. The Isolation Forest is re-seeded per run as
in multi_run.py.

Output: data/training_curve.csv (one row per training length and detector,
pooled over all runs).

Usage:
    python detectors/training_curve.py [data/baseline_60min.csv]
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import contamination_from, eval_ml, quality_metrics, scored_mask  # noqa: E402
from features import load_requests                                           # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
MINUTES = [1, 2, 5, 10, 20, 30, 45, 60]


def main() -> None:
    long_csv = Path(sys.argv[1]) if len(sys.argv) > 1 else DATA_DIR / "baseline_60min.csv"
    full = load_requests(str(long_csv))
    tune_df = load_requests(str(DATA_DIR / "tuning_labeled.csv"))
    contamination = contamination_from(tune_df)
    runs = [load_requests(str(f)) for f in sorted((DATA_DIR / "runs").glob("run_*.csv"))]
    span_min = (full["wall_time"].iloc[-1] - full["wall_time"].iloc[0]) / 60

    rows = []
    print(f"long capture: {len(full)} requests over {span_min:.1f} min; "
          f"{len(runs)} test runs; contamination {contamination:.3f}")
    print(f"{'minutes':>7}{'requests':>9}  {'detector':<11}{'precision':>10}{'recall':>8}"
          f"{'FPR':>7}{'FPR range':>14}{'train ms':>10}{'model KB':>10}")
    for minutes in MINUTES:
        if minutes > span_min + 0.5:
            break
        train = full[full["wall_time"] < full["wall_time"].iloc[0] + 60 * minutes]
        for name, tune in (("ml-iforest", None), ("ml-tuned", tune_df)):
            tot = np.zeros(4, int)
            fprs, train_ms, model_kb = [], [], []
            for seed, test in enumerate(runs):
                mask = scored_mask(test)
                pred, cost = eval_ml(train, test, contamination, random_state=seed,
                                     tune_df=tune)
                q = quality_metrics(test["is_attack"].to_numpy()[mask], pred[mask])
                tot += [q["TP"], q["FP"], q["FN"], q["TN"]]
                fprs.append(q["fpr"])
                train_ms.append(cost["train_ms"])
                model_kb.append(cost["model_kb"])
            tp, fp, fn, tn = (int(v) for v in tot)
            row = {"minutes": minutes, "train_requests": len(train), "detector": name,
                   "TP": tp, "FP": fp, "FN": fn, "TN": tn,
                   "precision": tp / (tp + fp) if tp + fp else 0.0,
                   "recall": tp / (tp + fn) if tp + fn else 0.0,
                   "fpr": fp / (fp + tn) if fp + tn else 0.0,
                   "fpr_min": min(fprs), "fpr_max": max(fprs),
                   "train_ms": float(np.mean(train_ms)),
                   "model_kb": float(np.mean(model_kb))}
            rows.append(row)
            print(f"{minutes:>7}{len(train):>9}  {name:<11}{row['precision']:>10.3f}"
                  f"{row['recall']:>8.3f}{row['fpr']:>7.3f}"
                  f"{row['fpr_min']:>8.3f}-{row['fpr_max']:.3f}"
                  f"{row['train_ms']:>10.0f}{row['model_kb']:>10.0f}", flush=True)

    out = DATA_DIR / "training_curve.csv"
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"-> {out}")


if __name__ == "__main__":
    main()
