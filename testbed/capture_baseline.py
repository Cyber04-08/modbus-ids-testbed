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
    python testbed/capture_baseline.py 3600 data/baseline_60min.csv   # custom output

An existing output file is moved to data/backups/ (timestamped) first, never
overwritten: on 2026-10-16 a short capture replaced the 90-request training
session that the reported results were made with.
"""

import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
DATA_DIR = ROOT / "data"
BASELINE_CSV = DATA_DIR / "baseline_capture.csv"
BACKUP_DIR = DATA_DIR / "backups"
# The HMI polls about once a second and writes now and then, so a healthy
# capture has at least ~1 request per second of duration.
MIN_REQUESTS_PER_S = 1.0


def back_up(path: Path) -> None:
    """Move an existing data file aside so a new capture cannot destroy it."""
    if path.exists():
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dest = BACKUP_DIR / f"{path.stem}.{stamp}{path.suffix}"
        shutil.move(str(path), dest)
        print(f"[backup] previous {path.name} kept as {dest}")


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
    out_csv = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else BASELINE_CSV
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    back_up(out_csv)
    procs = {}
    hmi_rc = None
    try:
        procs["plc"] = subprocess.Popen([PY, str(ROOT / "testbed" / "plc_simulator.py")])
        if not wait_for_port("127.0.0.1", 5020):
            raise SystemExit("PLC simulator did not come up on :5020")
        procs["tap"] = subprocess.Popen([PY, str(ROOT / "testbed" / "modbus_tap.py"),
                                         str(out_csv)])
        if not wait_for_port("127.0.0.1", 5021):
            raise SystemExit("Capture tap did not come up on :5021")

        print(f"[baseline] capturing {duration:.0f}s of normal traffic -> {out_csv}")
        procs["hmi"] = subprocess.Popen([PY, str(ROOT / "testbed" / "hmi_client.py"),
                                         str(duration)])
        time.sleep(duration + 2)
        hmi_rc = procs["hmi"].poll()
        if procs["plc"].poll() is not None or procs["tap"].poll() is not None:
            print("[baseline] WARNING: the PLC or the tap exited during the capture",
                  file=sys.stderr)
    finally:
        for name in ("hmi", "tap", "plc"):
            p = procs.get(name)
            if p and p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        if out_csv.exists():
            with open(out_csv) as fh:
                lines = fh.read().splitlines()[1:]
            requests = sum(1 for ln in lines if ",req," in ln)
            print(f"[baseline] done: {len(lines)} frames ({requests} requests) -> {out_csv}")
            if requests < MIN_REQUESTS_PER_S * duration:
                print(f"[baseline] WARNING: only {requests} requests in {duration:.0f}s "
                      f"(expected at least {MIN_REQUESTS_PER_S * duration:.0f})",
                      file=sys.stderr)
        if hmi_rc not in (None, 0):
            print(f"[baseline] WARNING: the HMI exited with status {hmi_rc}", file=sys.stderr)


if __name__ == "__main__":
    main()
