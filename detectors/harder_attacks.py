"""
Harder attacks and countermeasures (limitations 1 and 2).

The generalization check (detectors/generalization.py) left two limitations of
the detectors standing:

  1. The one-class SVM separated the earlier injection largely on timing: an
     injected write arrived in its own gap, not a few ms after a poll.
  2. Replay detection (the rule's replay_reused_txid, the SVM's txid_delta)
     keyed on a reused transaction ID.

attacks/harder_scenario.py runs two attacks built to defeat exactly those:
  * txid_replay.py     - resends one captured command with fresh, incrementing
                         transaction IDs, paced like the operator (role "replay")
  * mimic_injection.py - injects in-band writes 1-5 ms after its own cover
                         polls, so timing and values both look routine
                         (role "injection")
and from two origins: a separate host (127.0.0.66) and the operator's own
address (spoof, 127.0.0.1).

This script measures, for each of four detector configurations, how far each
attack gets and what the countermeasures recover:

  rule-base    rule-based detector, content/behaviour invariants only
  rule-ident   + sender identity: writes from a host that did not appear in
               the normal training session are flagged (unknown_source)
  ocsvm-base   one-class SVM on the original features, label-free threshold
               (<= TARGET_FPR of a normal-only session alerts)
  ocsvm-ctx    + value-change features repeat_run and write_step
  ocsvm-both   alert if EITHER ocsvm-base or ocsvm-ctx fires. The context
               features recover the rewritten replay but, used alone, weaken
               the one-class SVM on the Section 5 varied attacks (the two extra
               columns move its label-free threshold); combining the two
               feature views keeps the varied-attack recall and adds the
               replay catch. Each half keeps its own 0.5 %% threshold, so the
               combined false-alarm budget is at most twice TARGET_FPR.

Two views per attack type, pooled over sessions:
  * packet recall   - fraction of that type's malicious requests flagged
  * attack detected - fraction of sessions in which at least one of that
                      type's requests was flagged (an operator sees one alert
                      and investigates; missing later packets still counts as
                      caught)
plus the false-alarm rate on benign requests.

A regression check then scores ocsvm-base and ocsvm-ctx on the saved varied
runs (data/varied/runs), to confirm the added features do not weaken the
earlier result or raise false alarms.

Usage:
    python detectors/harder_attacks.py --capture 10     # 10 sessions per origin, then score
    python detectors/harder_attacks.py                  # re-score saved sessions
"""

from __future__ import annotations

import csv
import json
import math
import shutil
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import label_problems, ratio, scored_mask           # noqa: E402
from features import (OCSVM_CONTEXT_FEATURE_COLUMNS,               # noqa: E402
                      OCSVM_FEATURE_COLUMNS, load_requests)
from ml_anomaly import normal_quantile_threshold                   # noqa: E402
from multi_run import git_head, run_step, sha256, t_crit, wilson   # noqa: E402
from ocsvm import OneClassSVMDetector                              # noqa: E402
from rule_based import RuleBasedDetector                          # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
DATA_DIR = ROOT / "data"
HARDER_DIR = DATA_DIR / "harder"
TRAIN_CSV = DATA_DIR / "baseline_capture.csv"
VALIDATION_CSV = DATA_DIR / "baseline_60min.csv"
VARIED_RUNS = DATA_DIR / "varied" / "runs"

ORIGINS = ("separate", "spoof")
ATTACKS = ("replay", "injection")
CONFIGS = ("rule-base", "rule-ident", "ocsvm-base", "ocsvm-ctx", "ocsvm-both")
TARGET_FPR = 0.005


def arg(name, default=None):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


def capture(origin: str, i: int, seed: int, quick: bool) -> Path:
    run_step([PY, str(ROOT / "attacks" / "harder_scenario.py"), "--origin", origin,
              "--seed", str(seed)] + (["--quick"] if quick else []))
    run_step([PY, str(DATA_DIR / "label_dataset.py")])
    out = HARDER_DIR / origin / f"run_{i:02d}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(DATA_DIR / "labeled.csv", out)
    shutil.copyfile(DATA_DIR / "attack_manifest.json", out.with_suffix(".json"))
    return out


class Detectors:
    """The four configurations, trained once and thresholded label-free."""
    def __init__(self, train_df, validation_df, known_sources):
        self.known_sources = known_sources
        self.svm = {
            "ocsvm-base": OneClassSVMDetector(columns=OCSVM_FEATURE_COLUMNS).fit(train_df),
            "ocsvm-ctx": OneClassSVMDetector(columns=OCSVM_CONTEXT_FEATURE_COLUMNS).fit(train_df),
        }
        self.thr = {k: normal_quantile_threshold(d, validation_df, TARGET_FPR)
                    for k, d in self.svm.items()}

    def predict(self, config: str, df) -> np.ndarray:
        if config == "rule-base":
            det = RuleBasedDetector()
        elif config == "rule-ident":
            det = RuleBasedDetector(known_sources=self.known_sources)
        elif config == "ocsvm-both":
            return (self._svm_pred("ocsvm-base", df) | self._svm_pred("ocsvm-ctx", df))
        elif config in self.svm:
            return self._svm_pred(config, df)
        else:
            return np.array([det.score_request(r)[0] for r in df.itertuples(index=False)])
        return np.array([det.score_request(r)[0] for r in df.itertuples(index=False)])

    def _svm_pred(self, config: str, df) -> np.ndarray:
        return (self.svm[config].score(df) >= self.thr[config]).astype(int)


def score_session(dets: Detectors, df) -> list[dict]:
    mask = scored_mask(df)
    y = df["is_attack"].to_numpy()[mask]
    labels = df["label"].to_numpy()[mask]
    rows = []
    for cfg in CONFIGS:
        pred = dets.predict(cfg, df)[mask]
        fp = int(((pred == 1) & (y == 0)).sum())
        tn = int(((pred == 0) & (y == 0)).sum())
        row = {"config": cfg, "FP": fp, "TN": tn}
        for atk in ATTACKS:
            m = labels == atk
            row[f"tp_{atk}"] = int((pred[m] == 1).sum())
            row[f"n_{atk}"] = int(m.sum())
            # Whole-attack detection: at least one packet of this type flagged.
            row[f"detected_{atk}"] = int(m.any() and (pred[m] == 1).any())
            row[f"present_{atk}"] = int(m.any())
        rows.append(row)
    return rows


def known_sources_from(train_df) -> set:
    return set(train_df["src_ip"].astype(str).unique())


def summarize(results: dict) -> list[dict]:
    """results[origin] = list of per-session, per-config rows."""
    out = []
    for origin in ORIGINS:
        rows = results.get(origin, [])
        for cfg in CONFIGS:
            cr = [r for r in rows if r["config"] == cfg]
            if not cr:
                continue
            rec = {"origin": origin, "config": cfg, "sessions": len(cr)}
            fp = sum(r["FP"] for r in cr)
            tn = sum(r["TN"] for r in cr)
            rec["fpr"] = ratio(fp, fp + tn)
            rec["fpr_lo"], rec["fpr_hi"] = wilson(fp, fp + tn)
            for atk in ATTACKS:
                tp = sum(r[f"tp_{atk}"] for r in cr)
                n = sum(r[f"n_{atk}"] for r in cr)
                det = sum(r[f"detected_{atk}"] for r in cr)
                present = sum(r[f"present_{atk}"] for r in cr)
                rec[f"packet_recall_{atk}"] = ratio(tp, n)
                rec[f"attack_detection_{atk}"] = ratio(det, present)
                rec[f"n_{atk}"] = n
            out.append(rec)
    return out


def regression_check(train_df, validation_df) -> list[dict]:
    """ocsvm-base vs ocsvm-ctx on the saved varied runs: recall/FPR should not
    get worse when the value-change features are added."""
    run_files = sorted(VARIED_RUNS.glob("run_*.csv"))
    if not run_files:
        return []
    svm = {"ocsvm-base": OneClassSVMDetector(columns=OCSVM_FEATURE_COLUMNS).fit(train_df),
           "ocsvm-ctx": OneClassSVMDetector(columns=OCSVM_CONTEXT_FEATURE_COLUMNS).fit(train_df)}
    thr = {k: normal_quantile_threshold(d, validation_df, TARGET_FPR) for k, d in svm.items()}
    agg = {k: {"tp": 0, "n": 0, "fp": 0, "tn": 0} for k in ("ocsvm-base", "ocsvm-ctx", "ocsvm-both")}
    for f in run_files:
        df = load_requests(str(f))
        mask = scored_mask(df)
        y = df["is_attack"].to_numpy()[mask]
        preds = {k: (d.score(df) >= thr[k]).astype(int) for k, d in svm.items()}
        preds["ocsvm-both"] = preds["ocsvm-base"] | preds["ocsvm-ctx"]
        for k, pred in preds.items():
            pm = pred[mask]
            a = agg[k]
            a["tp"] += int(((pm == 1) & (y == 1)).sum())
            a["n"] += int((y == 1).sum())
            a["fp"] += int(((pm == 1) & (y == 0)).sum())
            a["tn"] += int(((pm == 0) & (y == 0)).sum())
    return [{"config": k, "runs": len(run_files), "recall": ratio(a["tp"], a["n"]),
             "fpr": ratio(a["fp"], a["fp"] + a["tn"]), "n_attack": a["n"]}
            for k, a in agg.items()]


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    fields = list(dict.fromkeys(k for r in rows for k in r))
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    quick = "--quick" in sys.argv
    n_capture = int(arg("--capture", 0))
    validation_csv = Path(arg("--validation", VALIDATION_CSV)).resolve()
    for p in (TRAIN_CSV, validation_csv):
        if not p.exists():
            raise SystemExit(f"Missing {p}")

    if n_capture:
        for origin in ORIGINS:
            for i in range(1, n_capture + 1):
                out = HARDER_DIR / origin / f"run_{i:02d}.csv"
                if out.exists():
                    print(f"[harder] {origin}/{out.name} exists, kept", flush=True)
                    continue
                print(f"[harder] capturing {origin} session {i}/{n_capture}...", flush=True)
                capture(origin, i, seed=i, quick=quick)

    train_df = load_requests(str(TRAIN_CSV))
    validation_df = load_requests(str(validation_csv))
    known = known_sources_from(train_df)
    dets = Detectors(train_df, validation_df, known)

    results, run_files_by_origin = {}, {}
    for origin in ORIGINS:
        run_files = sorted((HARDER_DIR / origin).glob("run_*.csv"))
        run_files_by_origin[origin] = run_files
        rows = []
        for f in run_files:
            df = load_requests(str(f))
            problems = label_problems(df)
            if problems:
                raise SystemExit(f"[harder] {f}: unattributed requests {problems}")
            rows.extend(score_session(dets, df))
        results[origin] = rows
    if not any(run_files_by_origin.values()):
        raise SystemExit("No harder sessions found; run with --capture N first")

    summary = summarize(results)
    regression = regression_check(train_df, validation_df)

    HARDER_DIR.mkdir(parents=True, exist_ok=True)
    write_csv(HARDER_DIR / "harder_summary.csv", summary)
    write_csv(HARDER_DIR / "harder_regression.csv", regression)
    per_session = [{"origin": o, **r} for o in ORIGINS for r in results.get(o, [])]
    write_csv(HARDER_DIR / "harder_results.csv", per_session)
    (HARDER_DIR / "harder_provenance.json").write_text(json.dumps({
        "git_head": git_head(),
        "train": {"file": TRAIN_CSV.name, "sha256": sha256(TRAIN_CSV), "known_sources": sorted(known)},
        "validation": {"file": validation_csv.name, "sha256": sha256(validation_csv)},
        "target_fpr": TARGET_FPR,
        "sessions": {o: [f.name for f in fs] for o, fs in run_files_by_origin.items()},
    }, indent=2) + "\n")

    by = {(s["origin"], s["config"]): s for s in summary}
    print(f"\nHarder attacks vs countermeasures (train {len(train_df)} benign from "
          f"{sorted(known)}; label-free threshold at {TARGET_FPR:.1%} on "
          f"{len(validation_df)} normal requests)")
    for origin in ORIGINS:
        n = len(run_files_by_origin[origin])
        if not n:
            continue
        print(f"\n  attacker origin: {origin}  ({n} sessions)")
        print(f"    {'config':<12}{'replay pkt':>11}{'replay det':>11}"
              f"{'inject pkt':>11}{'inject det':>11}{'FPR':>9}")
        for cfg in CONFIGS:
            s = by.get((origin, cfg))
            if not s:
                continue
            print(f"    {cfg:<12}"
                  f"{s['packet_recall_replay']:>11.2f}{s['attack_detection_replay']:>11.2f}"
                  f"{s['packet_recall_injection']:>11.2f}{s['attack_detection_injection']:>11.2f}"
                  f"{s['fpr']:>9.3f}")
    if regression:
        print("\n  regression on the saved varied runs (value-change features must not hurt):")
        for r in regression:
            print(f"    {r['config']:<12} recall {r['recall']:.3f}  FPR {r['fpr']:.3f}  "
                  f"({r['runs']} runs, {r['n_attack']} attack reqs)")
    print("\n('pkt' = fraction of that attack's requests flagged; 'det' = fraction of\n"
          " sessions where at least one was flagged. rule-ident adds the sender-identity\n"
          " rule; ocsvm-ctx adds repeat_run + write_step.)")
    print(f"\nsummary    -> {HARDER_DIR / 'harder_summary.csv'}")
    print(f"regression -> {HARDER_DIR / 'harder_regression.csv'}")


if __name__ == "__main__":
    main()
