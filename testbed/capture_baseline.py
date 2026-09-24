"""
Capture a normal-traffic-only window (the ML detector's training set).

Starts the PLC, the passive tap, and the benign HMI - no attacks - and records
to data/baseline_capture.csv. The ML anomaly detector is trained only on this
(per the proposal: "trained only on features extracted from normal traffic"),
kept separate from the mixed attack scenario used for testing so there's no
train/test leakage.

Usage:
    python testbed/capture_baseline.py           # ~60s of normal traffic
    python testbed/capture_baseline.py 90        # custom duration (seconds)
"""

import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
DATA_DIR = ROOT / "data"
BASELINE_CSV = DATA_DIR / "baseline_capture.csv"


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def main() -> None:
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 60.0
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    procs = {}
    try:
        procs["plc"] = subprocess.Popen([PY, str(ROOT / "testbed" / "plc_simulator.py")])
        if not wait_for_port("127.0.0.1", 5020):
            raise SystemExit("PLC simulator did not come up on :5020")
        procs["tap"] = subprocess.Popen([PY, str(ROOT / "testbed" / "modbus_tap.py"),
                                         str(BASELINE_CSV)])
        if not wait_for_port("127.0.0.1", 5021):
            raise SystemExit("Capture tap did not come up on :5021")

        print(f"[baseline] capturing {duration:.0f}s of normal traffic -> {BASELINE_CSV}")
        procs["hmi"] = subprocess.Popen([PY, str(ROOT / "testbed" / "hmi_client.py"),
                                         str(duration)])
        time.sleep(duration + 2)
    finally:
        for name in ("hmi", "tap", "plc"):
            p = procs.get(name)
            if p and p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        if BASELINE_CSV.exists():
            rows = sum(1 for _ in open(BASELINE_CSV)) - 1
            print(f"[baseline] done: {rows} frames -> {BASELINE_CSV}")


if __name__ == "__main__":
    main()
