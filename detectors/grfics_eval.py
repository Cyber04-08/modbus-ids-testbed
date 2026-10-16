"""
Evaluate the detectors on the GRFICSv2 plant - the higher-fidelity cross-check
for the results measured on the Python testbed.

Traffic was captured passively on the plant's ICS network (tcpdump on the
sensor host), converted to our CSV schema by tools/pcap_to_csv.py, and labeled
here by source IP: every frame from the attack host (ATTACKER_IP) is an
attack, the plant's own PLC->IO and HMI->PLC traffic is benign.

Sessions (data/grfics/):
    normal_train.csv - ~3 min of plant traffic, no attacks (ML training set)
    attack_tune.csv  - one attack run (threshold calibration)
    attack_test*.csv - four more attack runs (scoring only)

Attack labels within the attacker's frames:
    injection   - FC16 writes the PLC never makes: to an unused register, or
                  the crafted ones to the actuator register
    replay      - the repeated verbatim FC16 write (reused transaction ID);
                  its first send is the unscored seed

What differs from the testbed, and why it matters, is printed as notes.

Usage:
    python detectors/grfics_eval.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import load_requests                 # noqa: E402
from ml_anomaly import MLAnomalyDetector           # noqa: E402
from ocsvm import OneClassSVMDetector              # noqa: E402
from evaluate import quality_metrics               # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data" / "grfics"
ATTACKER_IP = "192.168.95.50"
ACTUATOR_ADDR = 1


def load_grfics(csv: str) -> pd.DataFrame:
    """Load as usual, then recompute per-connection features grouped by
    (src_ip, client_port): the plant has several hosts, so a port alone does
    not identify a connection."""
    df = load_requests(csv)
    g = df.groupby(["src_ip", "client_port"])
    df["inter_arrival"] = g["wall_time"].diff().fillna(0.0)
    df["first_on_connection"] = g.cumcount() == 0
    df["txid_delta"] = g["transaction_id"].diff().fillna(1.0)
    return df


def label(df: pd.DataFrame) -> pd.DataFrame:
    """Add is_attack / scored / label by source IP and the attack pattern."""
    df = df.copy()
    is_atk = df["src_ip"] == ATTACKER_IP
    df["label"] = "benign"
    df["is_attack"] = 0
    df["scored"] = True
    # Among the attacker's requests, the repeated reused-txid write is the
    # replay (first occurrence = seed, unscored); the rest are injections.
    for (port, txid), grp in df[is_atk].groupby(["client_port", "transaction_id"]):
        idx = grp.index
        if len(idx) > 1:                         # reused txid -> replay burst
            df.loc[idx[0], ["label", "scored"]] = ["replay_seed", False]
            df.loc[idx[1:], ["label", "is_attack"]] = ["replay", 1]
        else:
            df.loc[idx, ["label", "is_attack"]] = ["injection", 1]
    return df


def rule_based_plant(df: pd.DataFrame) -> np.ndarray:
    """The rule-based detector adapted to the plant's map: the PLC only ever
    writes FC16 to the actuator register, and a master's transaction IDs
    strictly increment, so a reused ID with identical bytes is a replay."""
    pred = np.zeros(len(df), dtype=int)
    seen: dict[tuple, str] = {}
    for i, r in enumerate(df.itertuples(index=False)):
        if int(r.function_code) in (5, 6, 15, 16):
            if int(r.address) != ACTUATOR_ADDR:
                pred[i] = 1                                   # write to unused reg
                continue
            key = (r.src_ip, int(r.client_port), int(r.transaction_id))
            if key in seen and seen[key] == r.raw_hex:
                pred[i] = 1                                   # replay
            seen[key] = r.raw_hex
    return pred


def score(name, pred, df):
    m = df["scored"].to_numpy()
    return quality_metrics(df["is_attack"].to_numpy()[m], pred[m])


def main() -> None:
    train = load_grfics(str(DATA / "normal_train.csv"))
    tune = label(load_grfics(str(DATA / "attack_tune.csv")))
    tests = [label(load_grfics(str(DATA / f"attack_test{i}.csv"))) for i in range(1, 5)]

    n_atk = sum(int(t["is_attack"].sum()) for t in tests)
    n_ben = sum(int((t["scored"] & (t["is_attack"] == 0)).sum()) for t in tests)
    print(f"GRFICSv2 plant - detectors trained on {len(train)} benign plant "
          f"requests (~3 min)")
    print(f"scored over {len(tests)} attack sessions: {n_atk} attack / {n_ben} "
          f"benign requests\n")

    iforest = MLAnomalyDetector(contamination=0.05, fill_first_gap=True).fit(train).calibrate(tune)
    svm = OneClassSVMDetector(nu=0.05).fit(train).calibrate(tune)

    detectors = {
        "rule-based (plant map)": rule_based_plant,
        "Isolation Forest (tuned)": iforest.predict,
        "one-class SVM": svm.predict,
    }
    print(f"{'detector':<26}{'precision':>10}{'recall':>8}{'F1':>7}{'FPR':>7}"
          f"{'TP':>5}{'FP':>5}{'FN':>5}")
    for name, fn in detectors.items():
        tot = np.zeros(4, int)
        for t in tests:
            q = score(name, np.asarray(fn(t)), t)
            tot += [q["TP"], q["FP"], q["FN"], q["TN"]]
        tp, fp, fn, tn = tot
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        print(f"{name:<26}{p:>10.3f}{r:>8.3f}{f1:>7.3f}{fpr:>7.3f}{tp:>5}{fp:>5}{fn:>5}")

    # Per-label recall, to show which attacks each detector catches.
    print("\nper-attack-type recall (one-class SVM):")
    for lab in ("injection", "replay"):
        tot_tp = tot_n = 0
        for t in tests:
            m = (t["label"] == lab).to_numpy()
            pred = np.asarray(svm.predict(t))
            tot_tp += int(pred[m].sum()); tot_n += int(m.sum())
        print(f"  {lab:<12} {tot_tp}/{tot_n}")
    print("\nNotes:")
    print("- The plant actuator legitimately uses the full 0-65535 value range,")
    print("  so value-range checks (used on the water tank) do not apply here;")
    print("  detection rests on address validity and replay/transaction-ID logic.")
    print("- Normal writes only ever target the actuator register, and the PLC's")
    print("  transaction IDs strictly increment, so both transfer to this plant.")


if __name__ == "__main__":
    main()
