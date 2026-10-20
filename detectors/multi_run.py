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

Three kinds of independent capture session, never mixed:
    train - data/baseline_capture.csv (normal only), captured once; the ML
            model fits on it, mirroring deployment (train once, then face many
            unseen traffic windows)
    tune  - data/tuning_labeled.csv, its own labeled scenario session (made by
            attacks/capture_tuning.py if missing); the ML contamination and
            the tuned ML detector's alert threshold are set from it, never
            from a test run
    test  - one fresh scenario session per run, used only for scoring
Only scored requests are graded (PLC responses and the replay's seed packet
stay in the stream the detectors see but are not graded).

Outputs:
    data/runs/run_XX.csv            - each run's labeled test set
    data/multi_run_results.csv      - one row per (run, detector)
    data/multi_run_summary.csv      - mean / std / 95% CI per metric, plus
                                      pooled counts with Wilson 95% intervals
    data/multi_run_provenance.json  - SHA-256 of the train, tune and every
                                      run file, the git commit and the seeds,
                                      so a result can be traced to its inputs

Why both kinds of interval: every test session replays the same attack
script, so a detector that misses one fixed packet misses it in every run and
the over-runs spread is exactly 0. That 0 says the runs agree, not that the
rate is known exactly. The pooled Wilson interval treats the pooled requests
as the sample and gives an honest range (e.g. 0 false alarms in ~600 benign
requests still allows a true rate up to ~0.6%).

Usage:
    python detectors/multi_run.py              # 10 runs (~9 min)
    python detectors/multi_run.py 5 --quick    # 5 short runs
    python detectors/multi_run.py --reuse      # re-score saved runs, no capture
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import (check_separate_sessions, contamination_from,  # noqa: E402
                      detection_latency, eval_ml, eval_ocsvm, eval_rule_based,
                      label_problems, quality_metrics, ratio, scored_mask)
from features import load_requests                                 # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
DATA_DIR = ROOT / "data"
RUNS_DIR = DATA_DIR / "runs"
TRAIN_CSV = DATA_DIR / "baseline_capture.csv"
TUNE_CSV = DATA_DIR / "tuning_labeled.csv"
RESULTS_CSV = DATA_DIR / "multi_run_results.csv"
SUMMARY_CSV = DATA_DIR / "multi_run_summary.csv"
PROVENANCE_JSON = DATA_DIR / "multi_run_provenance.json"

METRICS = ["precision", "recall", "f1", "fpr", "accuracy",
           "recall_replay", "recall_injection",
           "latency_replay_s", "latency_injection_s",
           "per_request_ms", "peak_kb", "model_kb", "train_peak_kb", "train_ms"]

DETECTORS = ("rule-based", "ml-iforest", "ml-tuned", "ocsvm")

# Two-sided 95% Student-t critical values by degrees of freedom (n - 1).
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447,
       7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179,
       13: 2.160, 14: 2.145, 15: 2.131, 19: 2.093, 24: 2.064, 29: 2.045}


def t_crit(df: int) -> float:
    if df in T95:
        return T95[df]
    smaller = [k for k in T95 if k <= df]
    return T95[max(smaller)] if smaller else T95[1]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95% interval for a proportion k/n (well behaved at 0 and
    1, unlike the normal approximation)."""
    if n == 0:
        return math.nan, math.nan
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_head() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def run_step(args: list) -> None:
    """Run a pipeline step quietly, but show its output if it fails (the
    labeler exits non-zero when packets could not be matched)."""
    p = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if p.returncode != 0:
        sys.stderr.write(p.stdout + p.stderr)
        raise SystemExit(f"[multi-run] step failed ({Path(args[1]).name}, exit "
                         f"{p.returncode}); output above")


def capture_run(i: int, quick: bool) -> Path:
    run_step([PY, str(ROOT / "attacks" / "run_scenario.py")] + (["--quick"] if quick else []))
    run_step([PY, str(DATA_DIR / "label_dataset.py")])
    out = RUNS_DIR / f"run_{i:02d}.csv"
    shutil.copyfile(DATA_DIR / "labeled.csv", out)
    return out


def score_run(train_df, tune_df, test_csv: Path, seed: int,
              contamination: float) -> list[dict]:
    test_df = load_requests(str(test_csv))
    check_separate_sessions(train=train_df, tune=tune_df, test=test_df)
    problems = label_problems(test_df)
    if problems:
        raise SystemExit(f"[multi-run] {test_csv.name}: requests the labeler could "
                         f"not attribute: {problems}; fix the labels before scoring")
    mask = scored_mask(test_df)
    y = test_df["is_attack"].to_numpy()[mask]
    labels = test_df["label"].to_numpy()[mask]

    rows = []
    for name, (pred, cost) in (
        ("rule-based", eval_rule_based(train_df, test_df)),
        ("ml-iforest", eval_ml(train_df, test_df, contamination, random_state=seed)),
        ("ml-tuned", eval_ml(train_df, test_df, contamination, random_state=seed,
                             tune_df=tune_df)),
        ("ocsvm", eval_ocsvm(train_df, test_df, tune_df)),
    ):
        q = quality_metrics(y, pred[mask])
        lat = detection_latency(test_df, pred)
        p = pred[mask]
        per_type = {}
        for atk in ("replay", "injection"):
            m = labels == atk
            per_type[f"tp_{atk}"] = int((p[m] == 1).sum())
            per_type[f"n_{atk}"] = int(m.sum())
            per_type[f"recall_{atk}"] = ratio(per_type[f"tp_{atk}"], per_type[f"n_{atk}"])
        rows.append({
            "run": test_csv.stem, "detector": name,
            "n_requests": len(y), "n_attack": int(y.sum()),
            **{k: q[k] for k in ("TP", "FP", "FN", "TN", "precision",
                                 "recall", "f1", "fpr", "accuracy")},
            **per_type,
            # A missed attack has no latency; left blank and counted separately.
            "latency_replay_s": lat.get("replay"),
            "latency_injection_s": lat.get("injection"),
            "per_request_ms": cost["per_request_ms"],
            "peak_kb": cost["peak_kb"],
            "model_kb": cost["model_kb"],
            "train_peak_kb": cost["train_peak_kb"],
            "train_ms": cost["train_ms"],
        })
    return rows


def summarize(results: list[dict]) -> list[dict]:
    summary = []
    for det in DETECTORS:
        dr = [r for r in results if r["detector"] == det]
        for m in METRICS:
            # None = attack missed (latency); NaN = metric undefined in that
            # run. Both are left out of the mean and counted in "missed".
            vals = np.array([r[m] for r in dr if r[m] is not None], dtype=float)
            vals = vals[~np.isnan(vals)]
            n = len(vals)
            mean = float(vals.mean()) if n else math.nan
            std = float(vals.std(ddof=1)) if n > 1 else 0.0
            half = t_crit(n - 1) * std / math.sqrt(n) if n > 1 else 0.0
            summary.append({"detector": det, "metric": m, "n": n,
                            "missed": len(dr) - n, "mean": mean, "std": std,
                            "ci95_low": mean - half, "ci95_high": mean + half})
        # Pooled confusion matrix over all runs: a micro-averaged view that
        # is not skewed by runs with very few attack requests.
        # The interval columns hold the Wilson 95% interval of the pooled
        # proportion and "n" its denominator.
        tp, fp, fn, tn = (sum(r[k] for r in dr) for k in ("TP", "FP", "FN", "TN"))
        pooled = [("pooled_precision", tp, tp + fp), ("pooled_recall", tp, tp + fn),
                  ("pooled_fpr", fp, fp + tn)]
        for atk in ("replay", "injection"):
            pooled.append((f"pooled_recall_{atk}", sum(r[f"tp_{atk}"] for r in dr),
                           sum(r[f"n_{atk}"] for r in dr)))
        for m, k, n in pooled:
            lo, hi = wilson(k, n)
            summary.append({"detector": det, "metric": m, "n": n, "missed": 0,
                            "mean": ratio(k, n), "std": "", "ci95_low": lo, "ci95_high": hi})
    return summary


def write_provenance(train: Path, tune: Path, run_files: list[Path]) -> None:
    PROVENANCE_JSON.write_text(json.dumps({
        "git_head": git_head(),
        "train": {"file": train.name, "sha256": sha256(train)},
        "tune": {"file": tune.name, "sha256": sha256(tune)},
        "runs": [{"file": f.name, "sha256": sha256(f), "iforest_seed": seed}
                 for seed, f in enumerate(run_files)],
        "ocsvm_nu": 0.05,
    }, indent=2) + "\n")


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
    if not TUNE_CSV.exists():
        print("[multi-run] no tuning session yet - capturing one...", flush=True)
        run_step([PY, str(ROOT / "attacks" / "capture_tuning.py")])
    tune_df = load_requests(str(TUNE_CSV))
    contamination = contamination_from(tune_df)

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
        results.extend(score_run(train_df, tune_df, f, seed, contamination))
    write_csv(RESULTS_CSV, results)
    summary = summarize(results)
    write_csv(SUMMARY_CSV, summary)
    write_provenance(TRAIN_CSV, TUNE_CSV, run_files)

    print(f"\nModbus/TCP IDS - {len(run_files)}-run comparison "
          f"(train: {len(train_df)} benign requests; ML contamination "
          f"{contamination:.3f} from the tuning session)")
    print(f"{'metric':<22}{'rule-based':>22}{'ML (iForest)':>22}{'ML (tuned)':>22}"
          f"{'OC-SVM':>22}")
    print("-" * 110)
    by = {(s["detector"], s["metric"]): s for s in summary}
    for m in METRICS:
        cells = []
        for det in DETECTORS:
            s = by[(det, m)]
            fmt = (".4f" if m == "per_request_ms" else
                   ".0f" if m in ("peak_kb", "model_kb", "train_peak_kb") else
                   ".1f" if m == "train_ms" else ".3f")
            cell = f"{s['mean']:{fmt}} ± {s['ci95_high'] - s['mean']:{fmt}}"
            if s["missed"]:
                cell += f" ({s['missed']} missed)"
            cells.append(cell)
        print(f"{m:<22}" + "".join(f"{c:>22}" for c in cells))
    for m in ("pooled_precision", "pooled_recall", "pooled_fpr",
              "pooled_recall_replay", "pooled_recall_injection"):
        cells = []
        for d in DETECTORS:
            s = by[(d, m)]
            cells.append(f"{s['mean']:.3f} [{s['ci95_low']:.3f}-{s['ci95_high']:.3f}]")
        print(f"{m:<22}" + "".join(f"{c:>22}" for c in cells))
    print("\n(± is the 95% confidence half-width over runs; [a-b] is the Wilson 95%\n"
          " interval of the pooled proportion; peak_kb is detection only,\n"
          " train_peak_kb / train_ms are the one-time training step, model_kb is what\n"
          " the built detector keeps in memory while detecting)")
    print(f"per-run rows -> {RESULTS_CSV}\nsummary      -> {SUMMARY_CSV}\n"
          f"provenance   -> {PROVENANCE_JSON}")


if __name__ == "__main__":
    main()
