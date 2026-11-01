"""
Generalization check - do the detectors still work when the attack changes?

Limitation 3 of the official results: every tuning and test session ran the
SAME attack script (same frames, same order, same timing), and the ML alert
thresholds were set at the best F1 on the tuning session. A threshold tuned
on an attack and then tested on copies of that attack can look better than it
would against an attack it has never seen. This script measures how much.

Four measurements, all with the detectors trained once on the same normal-only
training session (data/baseline_capture.csv):

  1. Varied attacks. Test sessions made with run_scenario.py --vary: each
     draws its own attack order, frames, counts and timing (seeded, recorded
     in each run's manifest). Captured with --capture N.
  2. Three ways to set the ML alert threshold, compared on the same runs:
       tune-fixed   best F1 on the original fixed-sequence tuning session
                    (the official protocol)
       tune-varied  best F1 on a separate varied tuning session
       label-free   no attack labels at all: the score above which at most
                    0.5% of a separate normal-only session would alert
                    (data/baseline_60min.csv by default)
  3. Leave-one-attack-type-out. The threshold is tuned on the varied tuning
     session with one attack type removed, then scored only on the other
     type (plus benign traffic): "loao-tuned-on-replay" is graded on
     injections it never saw during tuning, and vice versa.
  4. Threshold-free quality: ROC AUC and PR AUC (average precision) of each ML
     score, per run and pooled, so a result does not hinge on where one
     threshold was placed. Curve points are written for plotting.

The rule-based detector has no threshold; it is scored once per run as is.

Usage:
    python detectors/generalization.py --capture 10            # varied tune + 10 varied runs, then score
    python detectors/generalization.py                         # re-score saved varied runs
    python detectors/generalization.py --runs data/runs        # the same analysis on the fixed runs
    python detectors/generalization.py --validation <csv>      # another normal-only session

Outputs (in data/varied/, tag = "varied" or the --runs folder name):
    generalization_<tag>_results.csv    one row per (run, detector, threshold)
    generalization_<tag>_summary.csv    mean / 95% CI over runs + pooled Wilson
    generalization_<tag>_curves.csv     pooled ROC and PR curve points
    generalization_<tag>_provenance.json  input hashes, seeds, git commit
"""

from __future__ import annotations

import csv
import json
import math
import shutil
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import (average_precision_score, precision_recall_curve,
                             roc_auc_score, roc_curve)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import (check_separate_sessions, contamination_from,  # noqa: E402
                      eval_rule_based, label_problems, quality_metrics, ratio,
                      scored_mask)
from features import load_requests                                 # noqa: E402
from ml_anomaly import (MLAnomalyDetector, best_f1_threshold,       # noqa: E402
                        normal_quantile_threshold)
from multi_run import git_head, run_step, sha256, t_crit, wilson     # noqa: E402
from ocsvm import OneClassSVMDetector                                # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
DATA_DIR = ROOT / "data"
VARIED_DIR = DATA_DIR / "varied"
VARIED_RUNS = VARIED_DIR / "runs"
VARIED_TUNE = VARIED_DIR / "tune.csv"
TRAIN_CSV = DATA_DIR / "baseline_capture.csv"
FIXED_TUNE = DATA_DIR / "tuning_labeled.csv"
VALIDATION_CSV = DATA_DIR / "baseline_60min.csv"

TARGET_FPR = 0.005
TUNE_SEED = 1000          # varied tuning session; test run i uses seed i
IFOREST_SEED = 42
ATTACKS = ("replay", "injection")
THRESHOLDS = ("tune-fixed", "tune-varied", "label-free",
              "loao-tuned-on-replay", "loao-tuned-on-injection")
SUMMARY_METRICS = ("precision", "recall", "f1", "fpr", "recall_replay",
                   "recall_injection", "roc_auc", "pr_auc")


def arg(name: str, default=None):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


def capture_varied(out_csv: Path, seed: int, quick: bool) -> Path:
    """One varied scenario session, labeled, saved with its manifest."""
    run_step([PY, str(ROOT / "attacks" / "run_scenario.py"), "--vary", "--seed", str(seed)]
             + (["--quick"] if quick else []))
    run_step([PY, str(DATA_DIR / "label_dataset.py")])
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(DATA_DIR / "labeled.csv", out_csv)
    shutil.copyfile(DATA_DIR / "attack_manifest.json", out_csv.with_suffix(".json"))
    return out_csv


def without(df, attack: str):
    """The session with one attack type's requests removed."""
    return df[df["label"] != attack]


def per_type_recall(labels, pred) -> dict:
    out = {}
    for atk in ATTACKS:
        m = labels == atk
        out[f"tp_{atk}"] = int((pred[m] == 1).sum())
        out[f"n_{atk}"] = int(m.sum())
        out[f"recall_{atk}"] = ratio(out[f"tp_{atk}"], out[f"n_{atk}"])
    return out


def result_row(run, det, thr, y, pred, labels, extra=None) -> dict:
    q = quality_metrics(y, pred)
    return {"run": run, "detector": det, "threshold": thr, "n_requests": len(y),
            "n_attack": int(y.sum()),
            **{k: q[k] for k in ("TP", "FP", "FN", "TN", "precision", "recall", "f1", "fpr")},
            **per_type_recall(labels, pred), "roc_auc": math.nan, "pr_auc": math.nan,
            **(extra or {})}


def build_detectors(train_df, fixed_tune) -> dict:
    contamination = contamination_from(fixed_tune)
    return {
        "ml-tuned": MLAnomalyDetector(contamination=contamination, fill_first_gap=True,
                                      random_state=IFOREST_SEED).fit(train_df),
        "ocsvm": OneClassSVMDetector().fit(train_df),
    }


def thresholds_for(det, fixed_tune, varied_tune, validation) -> dict:
    return {
        "tune-fixed": best_f1_threshold(det, fixed_tune),
        "tune-varied": best_f1_threshold(det, varied_tune),
        "label-free": normal_quantile_threshold(det, validation, TARGET_FPR),
        # Tuned on one attack type only; graded on the other.
        "loao-tuned-on-replay": best_f1_threshold(det, without(varied_tune, "injection")),
        "loao-tuned-on-injection": best_f1_threshold(det, without(varied_tune, "replay")),
    }


def score_runs(run_files, train_df, fixed_tune, varied_tune, validation):
    detectors = build_detectors(train_df, fixed_tune)
    thresholds = {n: thresholds_for(d, fixed_tune, varied_tune, validation)
                  for n, d in detectors.items()}
    # Realized false-alarm rate of the label-free threshold on the very
    # session it was set from (should be <= TARGET_FPR).
    val_fpr = {n: float((d.score(validation) >= thresholds[n]["label-free"]).mean())
               for n, d in detectors.items()}

    rows, pooled = [], {n: ([], []) for n in detectors}
    for f in run_files:
        df = load_requests(str(f))
        check_separate_sessions(train=train_df, validation=validation,
                                tune_fixed=fixed_tune, tune_varied=varied_tune, test=df)
        problems = label_problems(df)
        if problems:
            raise SystemExit(f"[generalization] {f.name}: requests the labeler could not "
                             f"attribute: {problems}; fix the labels before scoring")
        mask = scored_mask(df)
        y = df["is_attack"].to_numpy()[mask]
        labels = df["label"].to_numpy()[mask]

        rb_pred, _ = eval_rule_based(train_df, df)
        rows.append(result_row(f.stem, "rule-based", "none", y, rb_pred[mask], labels))

        for name, det in detectors.items():
            s = det.score(df)[mask]
            pooled[name][0].append(y)
            pooled[name][1].append(s)
            auc = {"roc_auc": roc_auc_score(y, s), "pr_auc": average_precision_score(y, s)}
            for thr in ("tune-fixed", "tune-varied", "label-free"):
                t = thresholds[name][thr]
                rows.append(result_row(f.stem, name, thr, y, (s >= t).astype(int), labels,
                                       {**auc, "threshold_value": t}))
            for tuned_on in ATTACKS:
                # Grade only the attack type left out of tuning (+ benign).
                keep = labels != tuned_on
                thr = f"loao-tuned-on-{tuned_on}"
                t = thresholds[name][thr]
                rows.append(result_row(f.stem, name, thr, y[keep],
                                       (s[keep] >= t).astype(int), labels[keep],
                                       {"threshold_value": t}))
    return rows, pooled, thresholds, val_fpr


def summarize(rows) -> list[dict]:
    summary = []
    keys = sorted({(r["detector"], r["threshold"]) for r in rows},
                  key=lambda k: (k[0], THRESHOLDS.index(k[1]) if k[1] in THRESHOLDS else -1))
    for det, thr in keys:
        dr = [r for r in rows if r["detector"] == det and r["threshold"] == thr]
        for m in SUMMARY_METRICS:
            vals = np.array([r[m] for r in dr], dtype=float)
            vals = vals[~np.isnan(vals)]
            n = len(vals)
            if n == 0:
                continue
            mean = float(vals.mean())
            std = float(vals.std(ddof=1)) if n > 1 else 0.0
            half = t_crit(n - 1) * std / math.sqrt(n) if n > 1 else 0.0
            summary.append({"detector": det, "threshold": thr, "metric": m, "n": n,
                            "mean": mean, "std": std, "ci95_low": mean - half,
                            "ci95_high": mean + half})
        tp, fp, fn, tn = (sum(r[k] for r in dr) for k in ("TP", "FP", "FN", "TN"))
        pooled = [("pooled_recall", tp, tp + fn), ("pooled_fpr", fp, fp + tn)]
        for atk in ATTACKS:
            pooled.append((f"pooled_recall_{atk}", sum(r[f"tp_{atk}"] for r in dr),
                           sum(r[f"n_{atk}"] for r in dr)))
        for m, k, n in pooled:
            if n == 0:
                continue
            lo, hi = wilson(k, n)
            summary.append({"detector": det, "threshold": thr, "metric": m, "n": n,
                            "mean": ratio(k, n), "std": "", "ci95_low": lo, "ci95_high": hi})
    return summary


def curve_rows(pooled) -> tuple[list[dict], dict]:
    rows, aucs = [], {}
    for name, (ys, ss) in pooled.items():
        y, s = np.concatenate(ys), np.concatenate(ss)
        aucs[name] = (roc_auc_score(y, s), average_precision_score(y, s))
        fpr, tpr, thr = roc_curve(y, s)
        rows += [{"detector": name, "curve": "roc", "x": a, "y": b, "threshold": t}
                 for a, b, t in zip(fpr, tpr, thr)]
        prec, rec, thr = precision_recall_curve(y, s)
        # precision_recall_curve returns one more (precision, recall) point
        # than thresholds: the final point (recall 0, precision 1) has none.
        rows += [{"detector": name, "curve": "pr", "x": r, "y": p, "threshold": t}
                 for r, p, t in zip(rec, prec, list(thr) + [math.nan])]
    return rows, aucs


def write_csv(path: Path, rows: list[dict]) -> None:
    fields = list(dict.fromkeys(k for r in rows for k in r))
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    quick = "--quick" in sys.argv
    n_capture = int(arg("--capture", 0))
    runs_dir = Path(arg("--runs", VARIED_RUNS)).resolve()
    validation_csv = Path(arg("--validation", VALIDATION_CSV)).resolve()
    tag = "varied" if runs_dir == VARIED_RUNS.resolve() else runs_dir.name

    for p in (TRAIN_CSV, FIXED_TUNE, validation_csv):
        if not p.exists():
            raise SystemExit(f"Missing {p}")
    if n_capture:
        if runs_dir != VARIED_RUNS.resolve():
            raise SystemExit("--capture writes to data/varied/runs; drop --runs")
        if not VARIED_TUNE.exists():
            print(f"[generalization] capturing the varied tuning session (seed {TUNE_SEED})...",
                  flush=True)
            capture_varied(VARIED_TUNE, TUNE_SEED, quick)
        for i in range(1, n_capture + 1):
            out = VARIED_RUNS / f"run_{i:02d}.csv"
            if out.exists():
                print(f"[generalization] {out.name} exists, kept", flush=True)
                continue
            print(f"[generalization] capturing varied run {i}/{n_capture} (seed {i})...",
                  flush=True)
            capture_varied(out, i, quick)
    if not VARIED_TUNE.exists():
        raise SystemExit(f"Missing {VARIED_TUNE}; run with --capture N first")
    run_files = sorted(runs_dir.glob("run_*.csv"))
    if not run_files:
        raise SystemExit(f"No runs in {runs_dir}; run with --capture N first")

    train_df = load_requests(str(TRAIN_CSV))
    fixed_tune = load_requests(str(FIXED_TUNE))
    varied_tune = load_requests(str(VARIED_TUNE))
    validation = load_requests(str(validation_csv))
    check_separate_sessions(train=train_df, validation=validation,
                            tune_fixed=fixed_tune, tune_varied=varied_tune)

    rows, pooled, thresholds, val_fpr = score_runs(run_files, train_df, fixed_tune,
                                                   varied_tune, validation)
    summary = summarize(rows)
    curves, aucs = curve_rows(pooled)

    VARIED_DIR.mkdir(parents=True, exist_ok=True)
    out = {k: VARIED_DIR / f"generalization_{tag}_{k}" for k in
           ("results.csv", "summary.csv", "curves.csv", "provenance.json")}
    write_csv(out["results.csv"], rows)
    write_csv(out["summary.csv"], summary)
    write_csv(out["curves.csv"], curves)
    manifests = [f.with_suffix(".json") for f in run_files]
    out["provenance.json"].write_text(json.dumps({
        "git_head": git_head(),
        "train": {"file": TRAIN_CSV.name, "sha256": sha256(TRAIN_CSV)},
        "tune_fixed": {"file": FIXED_TUNE.name, "sha256": sha256(FIXED_TUNE)},
        "tune_varied": {"file": str(VARIED_TUNE.relative_to(ROOT)), "sha256": sha256(VARIED_TUNE)},
        "validation": {"file": validation_csv.name, "sha256": sha256(validation_csv),
                       "requests": len(validation)},
        "runs": [{"file": f.name, "sha256": sha256(f),
                  "session_seed": (json.loads(m.read_text()).get("session_plan", {}).get("seed")
                                   if m.exists() else None)}
                 for f, m in zip(run_files, manifests)],
        "target_fpr": TARGET_FPR, "iforest_seed": IFOREST_SEED,
        "thresholds": thresholds, "label_free_validation_fpr": val_fpr,
    }, indent=2) + "\n")

    by = {(s["detector"], s["threshold"], s["metric"]): s for s in summary}
    print(f"\nGeneralization check on {len(run_files)} {tag} runs (train {len(train_df)} "
          f"benign; validation {len(validation)} normal requests, target FPR {TARGET_FPR})")
    hdr = (f"{'detector':<11}{'threshold':<25}{'F1':>14}{'recall':>14}{'FPR':>14}"
           f"{'rec replay':>12}{'rec inject':>12}")
    print(hdr)
    print("-" * len(hdr))

    def cell(d, t, m, w=14):
        s = by.get((d, t, m))
        if s is None:
            return f"{'-':>{w}}"
        return f"{s['mean']:.3f}±{s['ci95_high'] - s['mean']:.3f}".rjust(w)

    def pooled_cell(d, t, m, w=12):
        s = by.get((d, t, f"pooled_{m}"))
        return f"{'-':>{w}}" if s is None else f"{s['mean']:.3f}".rjust(w)

    for d, t in dict.fromkeys((r["detector"], r["threshold"]) for r in rows):
        print(f"{d:<11}{t:<25}{cell(d, t, 'f1')}{cell(d, t, 'recall')}{cell(d, t, 'fpr')}"
              f"{pooled_cell(d, t, 'recall_replay')}{pooled_cell(d, t, 'recall_injection')}")
    print("\nThreshold-free (pooled over runs):")
    for name, (roc, pr) in aucs.items():
        print(f"  {name:<10} ROC AUC {roc:.3f}   PR AUC {pr:.3f}   "
              f"label-free threshold alerts on {val_fpr[name]:.2%} of the validation session")
    print("\n(± = 95% CI half-width over runs; loao rows are graded only on the attack type\n"
          " left out of tuning, so their recall is that type's recall)")
    for k, p in out.items():
        print(f"{k:<16}-> {p}")


if __name__ == "__main__":
    main()
