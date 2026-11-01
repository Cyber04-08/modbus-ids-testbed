"""
Harder attacks on the GRFICSv2 plant (second-half item 5 replicated on the
higher-fidelity testbed).

tools/grfics_harder_attack.py, run from the sensor host, sends a
transaction-ID-rewriting replay and a timing-mimicking in-band injection to a
real remote-IO device while the plant keeps running; tools/grfics_harder_capture.sh
captures each session with tcpdump. Sessions are converted to CSV by
tools/pcap_to_csv.py (`--convert`) and labeled here from the attack script's
manifest of exact bytes sent (matched by exact bytes plus the attacker's IP, as
in the Python testbed): "attack" -> injection, "replay" -> replay; "seed" and
"cover" are unscored, as are responses. All other traffic is benign.

Detector configurations (as in detectors/harder_attacks.py):
  rule-plant   plant-map rules: write to an unused register, reused txid
  rule-ident   + sender identity: an FC16 write from a host that wrote nothing
               in the normal training session
  ocsvm-base   one-class SVM, original features, label-free threshold
               (<= TARGET_FPR of a normal-only validation session alerts)
  ocsvm-ctx    + value-change features repeat_run and write_step
  ocsvm-both   alert if either SVM view fires

Reports packet recall and whole-attack detection per attack type, and the
false-alarm rate on benign plant traffic.

Usage:
    python detectors/grfics_harder_eval.py --convert   # pcaps -> csv, then score
    python detectors/grfics_harder_eval.py
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import ratio                                         # noqa: E402
from features import (OCSVM_CONTEXT_FEATURE_COLUMNS,               # noqa: E402
                      OCSVM_FEATURE_COLUMNS, load_requests)
from grfics_eval import ACTUATOR_ADDR, ATTACKER_IP                 # noqa: E402
from ml_anomaly import normal_quantile_threshold                   # noqa: E402
from multi_run import wilson                                       # noqa: E402
from ocsvm import OneClassSVMDetector                              # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "grfics"
HARDER = DATA / "harder"
TRAIN_CSV = DATA / "normal_train.csv"
VAL_CSV = HARDER / "normal_val.csv"
TARGET_FPR = 0.005
CONFIGS = ("rule-plant", "rule-ident", "ocsvm-base", "ocsvm-ctx", "ocsvm-both")
ATTACKS = ("replay", "injection")
KIND_TO_LABEL = {"attack": "injection", "replay": "replay"}
WRITE_FCS = (5, 6, 15, 16)


def convert_all() -> None:
    for pcap in sorted(HARDER.glob("*.pcap")):
        out = pcap.with_suffix(".csv")
        subprocess.run([sys.executable, str(ROOT / "tools" / "pcap_to_csv.py"),
                        str(pcap), str(out)], check=True, capture_output=True)
        print(f"converted {pcap.name}")


def label_session(csv_path: Path) -> pd.DataFrame:
    """Load a session and label it from its manifest."""
    df = load_requests(str(csv_path))
    manifest = json.loads(csv_path.with_suffix(".json").read_text())
    kinds = {p["raw_hex"]: p["kind"] for p in manifest["packets"]}
    df["label"] = "benign"
    df["is_attack"] = 0
    df["scored"] = True
    unmatched = 0
    for i in df.index[df["src_ip"] == ATTACKER_IP]:
        kind = kinds.get(df.at[i, "raw_hex"])
        if kind is None:
            df.at[i, "label"], df.at[i, "scored"] = "unmatched", False
            unmatched += 1
        elif kind in KIND_TO_LABEL:
            df.at[i, "label"], df.at[i, "is_attack"] = KIND_TO_LABEL[kind], 1
        else:                                       # seed / cover
            df.at[i, "label"], df.at[i, "scored"] = kind, False
    if unmatched:
        print(f"[grfics-harder] WARNING {csv_path.name}: {unmatched} attacker request(s) "
              "not in the manifest (left unscored)", file=sys.stderr)
    return df


SPOOF_IP = "192.168.95.2"          # the PLC's own address (a known writer)


def spoof_src_ip(df: pd.DataFrame) -> pd.DataFrame:
    """Model a source-IP spoof: after labeling, the attacker's requests are
    rewritten to carry the PLC's own address instead of the sensor's. Only
    sender identity reads src_ip, so this is the one change a spoof makes to
    the detectors' inputs; a live spoof capture is unreliable (the real PLC
    owns that address on the segment), so it is modelled here. The attacker
    keeps its own client ports, so the per-connection feature rows the SVM
    uses, keyed on (src_ip, client_port), are unchanged apart from the IP tag."""
    df = df.copy()
    df.loc[df["src_ip"] == ATTACKER_IP, "src_ip"] = SPOOF_IP
    return df


def rule_plant(df: pd.DataFrame, known_writers: set | None) -> np.ndarray:
    """Plant-map rules (writes only to the actuator register; a reused txid
    with identical bytes is a replay), optionally with sender identity."""
    pred = np.zeros(len(df), dtype=int)
    seen: dict[tuple, str] = {}
    for i, r in enumerate(df.itertuples(index=False)):
        if int(r.function_code) not in WRITE_FCS:
            continue
        if int(r.address) != ACTUATOR_ADDR:
            pred[i] = 1
        elif known_writers is not None and str(r.src_ip) not in known_writers:
            pred[i] = 1
        key = (r.src_ip, int(r.client_port), int(r.transaction_id))
        if seen.get(key) == r.raw_hex:
            pred[i] = 1
        seen[key] = r.raw_hex
    return pred


class Detectors:
    def __init__(self, train, val):
        writers = train[train["function_code"].isin(WRITE_FCS)]["src_ip"].astype(str)
        self.known_writers = set(writers.unique())
        self.svm = {
            "ocsvm-base": OneClassSVMDetector(nu=0.05, columns=OCSVM_FEATURE_COLUMNS).fit(train),
            "ocsvm-ctx": OneClassSVMDetector(nu=0.05, columns=OCSVM_CONTEXT_FEATURE_COLUMNS).fit(train),
        }
        self.thr = {k: normal_quantile_threshold(d, val, TARGET_FPR) for k, d in self.svm.items()}

    def predict(self, cfg: str, df) -> np.ndarray:
        if cfg == "rule-plant":
            return rule_plant(df, None)
        if cfg == "rule-ident":
            return rule_plant(df, self.known_writers)
        base = (self.svm["ocsvm-base"].score(df) >= self.thr["ocsvm-base"]).astype(int)
        ctx = (self.svm["ocsvm-ctx"].score(df) >= self.thr["ocsvm-ctx"]).astype(int)
        return {"ocsvm-base": base, "ocsvm-ctx": ctx, "ocsvm-both": base | ctx}[cfg]


def score_session(dets: Detectors, df) -> list[dict]:
    m = df["scored"].to_numpy()
    y, lab = df["is_attack"].to_numpy()[m], df["label"].to_numpy()[m]
    rows = []
    for cfg in CONFIGS:
        pred = dets.predict(cfg, df)[m]
        row = {"config": cfg, "FP": int(((pred == 1) & (y == 0)).sum()),
               "TN": int(((pred == 0) & (y == 0)).sum())}
        for a in ATTACKS:
            sel = lab == a
            row[f"tp_{a}"], row[f"n_{a}"] = int((pred[sel] == 1).sum()), int(sel.sum())
            row[f"detected_{a}"] = int(sel.any() and (pred[sel] == 1).any())
            row[f"present_{a}"] = int(sel.any())
        rows.append(row)
    return rows


def summarize(all_rows) -> list[dict]:
    out = []
    for cfg in CONFIGS:
        cr = [r for r in all_rows if r["config"] == cfg]
        fp, tn = sum(r["FP"] for r in cr), sum(r["TN"] for r in cr)
        rec = {"config": cfg, "sessions": len(cr) , "fpr": ratio(fp, fp + tn)}
        rec["fpr_lo"], rec["fpr_hi"] = wilson(fp, fp + tn)
        for a in ATTACKS:
            rec[f"packet_recall_{a}"] = ratio(sum(r[f"tp_{a}"] for r in cr), sum(r[f"n_{a}"] for r in cr))
            rec[f"attack_detection_{a}"] = ratio(sum(r[f"detected_{a}"] for r in cr),
                                                 sum(r[f"present_{a}"] for r in cr))
            rec[f"n_{a}"] = sum(r[f"n_{a}"] for r in cr)
        out.append(rec)
    return out


GROUPS = {"attack": "replay resent every 0.3 s (not paced)",
          "paced": "replay copies the PLC's ~50 ms read+write rhythm"}


def main() -> None:
    if "--convert" in sys.argv:
        convert_all()
    if not VAL_CSV.exists():
        raise SystemExit("Need data/grfics/harder/normal_val.csv; capture, then run with --convert")
    train, val = load_requests(str(TRAIN_CSV)), load_requests(str(VAL_CSV))
    dets = Detectors(train, val)
    print(f"GRFICSv2 harder attacks: trained on {len(train)} benign plant requests, "
          f"threshold from {len(val)} normal requests at {TARGET_FPR:.1%}; "
          f"known writers {sorted(dets.known_writers)}")

    spoof = "--spoof" in sys.argv
    summary = []
    for prefix, desc in GROUPS.items():
        sessions = sorted(HARDER.glob(f"{prefix}_*.csv"))
        if not sessions:
            continue
        for src, tag in ((False, prefix), (True, f"{prefix}-spoof")) if spoof else ((False, prefix),):
            rows = []
            for f in sessions:
                df = label_session(f)
                if src:
                    df = spoof_src_ip(df)
                rows.extend(score_session(dets, df))
            group = summarize(rows)
            note = desc + ("; attacker spoofs the PLC's source IP" if src else "")
            _emit(summary, group, tag, len(sessions), note)
    print("\n'pkt' = share of requests flagged; 'det' = share of sessions with at least one flagged.")

    out = HARDER / "grfics_harder_summary.csv"
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(summary[0]))
        w.writeheader()
        w.writerows(summary)
    print(f"summary -> {out}")


def _emit(summary, group, tag, n_sessions, desc) -> None:
    print(f"\n{tag}: {n_sessions} sessions, {desc}")
    print(f"  {'config':<12}{'replay pkt':>11}{'replay det':>11}{'inject pkt':>11}"
          f"{'inject det':>11}{'FPR':>9}   FPR 95% CI")
    for rec in group:
        rec["group"] = tag
        summary.append(rec)
        print(f"  {rec['config']:<12}{rec['packet_recall_replay']:>11.2f}"
              f"{rec['attack_detection_replay']:>11.2f}"
              f"{rec['packet_recall_injection']:>11.2f}{rec['attack_detection_injection']:>11.2f}"
              f"{rec['fpr']:>9.4f}   [{rec['fpr_lo']:.4f}, {rec['fpr_hi']:.4f}]")
    print(f"  ({group[0]['n_replay']} replay and {group[0]['n_injection']} injection requests)")


if __name__ == "__main__":
    main()
