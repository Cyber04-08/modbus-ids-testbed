"""
Score the off-the-shelf network IDS tools (Suricata, Zeek) on the same test
sessions as our detectors, with the same metrics.

Inputs:
  data/runs/run_XX.csv        labeled test sessions (ground truth)
  data/nids/<config>/run_XX/  tool output from tools/nids/run_nids.sh, run on
                              the pcaps exported by tools/export_pcap.py
  data/nids/timing.csv        wall-clock seconds per tool run
  data/multi_run_results.csv  our detectors' results on the same runs

Each alert is mapped back to the request it fired on:
  * Suricata: by connection (client port) and Suricata's transaction number
    within that connection (`tx_id`: 0 = first request, 1 = second, ...),
    cross-checked against the Modbus transaction ID it logs. Its alert
    timestamp is NOT used: Suricata inspects a Modbus transaction when a
    later packet arrives and stamps the alert with that packet's time (an
    alert for a setpoint write can carry the time of the next poll).
  * Zeek: by connection, Modbus transaction ID and time (the script logs the
    request packet's own time).
Alerts on PLC responses or on the replay's
seed packet are not graded, exactly as for our detectors. A request counts as
flagged if at least one alert maps to it.

Usage:
    python detectors/nids_compare.py
"""

from __future__ import annotations

import csv
import json
import sys
from datetime import datetime
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import detection_latency, quality_metrics, scored_mask  # noqa: E402
from features import load_requests                                    # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
NIDS = DATA / "nids"
CONFIGS = ["suricata-stock", "suricata-project", "zeek-stock", "zeek-project"]
TOL = 0.0005   # seconds; timestamps match to the microsecond in practice


def suricata_alerts(d: Path) -> list[dict]:
    out = []
    eve = d / "eve.json"
    if not eve.exists():
        return out
    for line in eve.read_text().splitlines():
        ev = json.loads(line)
        if ev.get("event_type") != "alert":
            continue
        req = ev.get("modbus", {}).get("request", {})
        out.append({"port": int(ev["src_port"]), "tx_id": ev.get("tx_id"),
                    "tid": req.get("transaction_id"),
                    "ts": datetime.fromisoformat(ev["timestamp"]).timestamp(),
                    "sig": ev["alert"]["signature"]})
    return out


def zeek_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    fields, rows = None, []
    for line in path.read_text().splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif not line.startswith("#") and fields:
            rows.append(dict(zip(fields, line.split("\t"))))
    return rows


def zeek_alerts(d: Path) -> list[dict]:
    out = [{"port": int(r["port_"]), "tid": int(r["tid"]), "ts": float(r["ts"]),
            "sig": r["rule"]} for r in zeek_log(d / "modbus_project.log")]
    for name in ("notice.log", "weird.log"):
        for r in zeek_log(d / name):
            port = r.get("id.orig_p", "-")
            if port not in ("-", ""):
                out.append({"port": int(port), "tid": None, "ts": float(r["ts"]),
                            "sig": r.get("note") or r.get("name", name)})
    return out


def flag_requests(df, alerts) -> tuple[np.ndarray, int, int]:
    """1 for each request an alert maps to. Also returns the number of alerts
    that map to no client request (e.g. raised on a PLC response) and the
    number whose logged Modbus transaction ID disagrees with the request they
    were mapped to (a check on the mapping; expected 0)."""
    pred = np.zeros(len(df), dtype=int)
    ports = df["client_port"].to_numpy()
    times = df["wall_time"].to_numpy()
    tids = df["transaction_id"].to_numpy()
    by_conn = {p: np.where(ports == p)[0] for p in np.unique(ports)}  # time order
    unmapped = mismatched = 0
    for a in alerts:
        rows = by_conn.get(a["port"], np.array([], dtype=int))
        if a.get("tx_id") is not None:                         # Suricata
            hit = rows[a["tx_id"]:a["tx_id"] + 1]
        else:                                                  # Zeek
            hit = rows[np.abs(times[rows] - a["ts"]) <= TOL]
            if a["tid"] is not None:
                hit = hit[tids[hit] == a["tid"]]
        if len(hit) == 0:
            unmapped += 1
            continue
        if a.get("tid") is not None and tids[hit[0]] != a["tid"]:
            mismatched += 1
        pred[hit] = 1
    return pred, unmapped, mismatched


def main() -> None:
    timing = {}
    with open(NIDS / "timing.csv") as f:
        for r in csv.DictReader(f):
            timing[(r["config"], r["session"])] = float(r["seconds"])

    runs = sorted((DATA / "runs").glob("run_*.csv"))
    rows = []
    for cfg in CONFIGS:
        for f in runs:
            df = load_requests(str(f))
            d = NIDS / cfg / f.stem
            alerts = suricata_alerts(d) if cfg.startswith("suricata") else zeek_alerts(d)
            pred, unmapped, mismatched = flag_requests(df, alerts)
            mask = scored_mask(df)
            q = quality_metrics(df["is_attack"].to_numpy()[mask], pred[mask])
            lat = detection_latency(df, pred)
            rows.append({"config": cfg, "run": f.stem, **q,
                         "alerts": len(alerts), "unmapped_alerts": unmapped,
                         "tid_mismatches": mismatched,
                         "latency_replay_s": lat.get("replay"),
                         "latency_injection_s": lat.get("injection"),
                         "seconds": timing.get((cfg, f.stem), float("nan")),
                         "requests": len(df)})

    with open(NIDS / "nids_results.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # Our detectors on the same runs, for the side-by-side.
    ours = {}
    mr = DATA / "multi_run_results.csv"
    if mr.exists():
        with open(mr) as fh:
            for r in csv.DictReader(fh):
                ours.setdefault(r["detector"], []).append(r)

    def pooled(rs):
        tp, fp, fn, tn = (sum(int(r[k]) for r in rs) for k in ("TP", "FP", "FN", "TN"))
        p = tp / (tp + fp) if tp + fp else 0.0
        rcl = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * p * rcl / (p + rcl) if p + rcl else 0.0
        return p, rcl, f1, fp / (fp + tn) if fp + tn else 0.0, tp, fp, fn

    print(f"Off-the-shelf NIDS vs our detectors - {len(runs)} test runs, pooled")
    print(f"{'detector':<20}{'precision':>10}{'recall':>8}{'F1':>7}{'FPR':>7}"
          f"{'TP':>5}{'FP':>5}{'FN':>5}{'s/run':>8}")
    for cfg in CONFIGS:
        rs = [r for r in rows if r["config"] == cfg]
        p, rcl, f1, fpr, tp, fp, fn = pooled(rs)
        secs = np.nanmean([r["seconds"] for r in rs])
        print(f"{cfg:<20}{p:>10.3f}{rcl:>8.3f}{f1:>7.3f}{fpr:>7.3f}{tp:>5}{fp:>5}{fn:>5}{secs:>8.2f}")
    for det in ("rule-based", "ml-tuned", "ocsvm"):
        if det in ours:
            p, rcl, f1, fpr, tp, fp, fn = pooled(ours[det])
            print(f"{'ours: ' + det:<20}{p:>10.3f}{rcl:>8.3f}{f1:>7.3f}{fpr:>7.3f}{tp:>5}{fp:>5}{fn:>5}{'':>8}")
    unm = {cfg: sum(r["unmapped_alerts"] for r in rows if r["config"] == cfg) for cfg in CONFIGS}
    mis = {cfg: sum(r["tid_mismatches"] for r in rows if r["config"] == cfg) for cfg in CONFIGS}
    print(f"\nalerts not on a client request (e.g. on responses), ignored: {unm}")
    print(f"mapping check - alerts whose Modbus transaction ID disagrees with "
          f"the request they were mapped to (expected 0): {mis}")
    print(f"per-run rows -> {NIDS / 'nids_results.csv'}")
    print("(s/run is the tool's whole run on one ~45 s session, including start-up)")


if __name__ == "__main__":
    main()
