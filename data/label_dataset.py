"""
Label a raw capture into the ground-truth dataset (Phase 2 output).

Reads the passive capture (data/capture.csv) and the scenario's ground-truth
manifest (data/attack_manifest.json), and writes data/labeled.csv with two
added columns:

    label        - "benign" | "replay" | "injection"
    is_attack    - 0 | 1

Primary labeling is by client_port -> role (from the manifest's
source_port_roles), which is exact for this testbed. As an independent
cross-check it also verifies each attack-labeled frame falls inside that
attack's recorded wall-clock window, and reports any disagreement rather than
silently trusting one signal.

Uses only the standard library (csv/json) so it runs with no extra installs;
pandas isn't needed until the Phase 3 feature engineering.

Usage:
    python data/label_dataset.py
"""

import csv
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent
CAPTURE_CSV = DATA_DIR / "capture.csv"
MANIFEST = DATA_DIR / "attack_manifest.json"
LABELED_CSV = DATA_DIR / "labeled.csv"


def main() -> None:
    if not CAPTURE_CSV.exists():
        raise SystemExit(f"No capture at {CAPTURE_CSV} - run attacks/run_scenario.py first.")
    if not MANIFEST.exists():
        raise SystemExit(f"No manifest at {MANIFEST} - run attacks/run_scenario.py first.")

    manifest = json.loads(MANIFEST.read_text())
    # JSON object keys are strings; normalize to int ports.
    port_roles = {int(p): role for p, role in manifest["source_port_roles"].items()}
    windows = manifest.get("attack_windows", [])

    def window_for(role: str):
        for w in windows:
            if w["type"] == role:
                return w
        return None

    counts = {"benign": 0, "replay": 0, "injection": 0, "unknown": 0}
    window_mismatches = 0
    total = 0

    with open(CAPTURE_CSV, newline="") as fin, open(LABELED_CSV, "w", newline="") as fout:
        reader = csv.DictReader(fin)
        fieldnames = reader.fieldnames + ["label", "is_attack"]
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            total += 1
            try:
                port = int(row["client_port"])
            except (KeyError, ValueError):
                port = -1
            role = port_roles.get(port, "unknown")

            # Cross-check: an attack-labeled frame should sit in its window.
            if role in ("replay", "injection"):
                w = window_for(role)
                try:
                    t = float(row["wall_time"])
                except (KeyError, ValueError):
                    t = None
                if w and t is not None and not (w["start"] - 1 <= t <= w["end"] + 1):
                    window_mismatches += 1

            row["label"] = role
            row["is_attack"] = 0 if role == "benign" else (1 if role in ("replay", "injection") else "")
            counts[role if role in counts else "unknown"] += 1
            writer.writerow(row)

    print(f"Labeled {total} frames -> {LABELED_CSV}")
    for k in ("benign", "replay", "injection", "unknown"):
        print(f"  {k:10s}: {counts[k]}")
    if counts["unknown"]:
        print(f"  NOTE: {counts['unknown']} frames from unrecognized source ports "
              "(unexpected client) - left unlabeled.")
    if window_mismatches:
        print(f"  WARNING: {window_mismatches} attack frames fell outside their "
              "recorded time window - port/time ground truth disagree, investigate.")
    else:
        print("  Cross-check OK: all attack frames fall within their recorded windows.")


if __name__ == "__main__":
    main()
