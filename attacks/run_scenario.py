"""
End-to-end data-generation scenario (Phase 2 orchestrator).

Brings up the whole testbed, runs a window of normal traffic with two attacks
injected at known times, and writes a ground-truth manifest - so the resulting
capture can be labeled automatically, with no hand-annotation.

Sequence:
    1. start the simulated PLC          (testbed/plc_simulator.py, :5020)
    2. start the passive capture tap     (testbed/modbus_tap.py,   :5021 -> CSV)
    3. start continuous benign HMI traffic for the whole run
    4. [baseline] let normal traffic accumulate
    5. inject the REPLAY attack, recording its wall-clock window
    6. [baseline] gap of normal traffic
    7. inject the COMMAND-INJECTION attack, recording its window
    8. [baseline] tail of normal traffic
    9. tear everything down, write data/attack_manifest.json

Ground truth is assigned two independent ways (belt and suspenders):
  * by source port - each client uses an ephemeral port and reports it back,
    and this script records which port belongs to which role; and
  * by wall-clock attack window - recorded here.
The labeler uses the source port as primary truth and the windows as a check.

Usage:
    python attacks/run_scenario.py                 # default timing
    python attacks/run_scenario.py --quick         # shorter windows
"""

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
DATA_DIR = ROOT / "data"
CAPTURE_CSV = DATA_DIR / "capture.csv"
MANIFEST = DATA_DIR / "attack_manifest.json"
HMI_PORT_FILE = DATA_DIR / ".hmi_port"

# Timing (seconds). --quick roughly halves the baseline padding.
BASELINE_PRE = 15
GAP = 10
BASELINE_POST = 12


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def run_attack(script: str, label: str) -> tuple[float, float, int]:
    """Run an attack script, echo its output, and return
    (window_start, window_end, source_port). The script prints
    `SOURCE_PORT=<n>` so we can attribute its captured frames as ground truth."""
    start = time.time()
    proc = subprocess.run([PY, str(ROOT / "attacks" / script)],
                          capture_output=True, text=True)
    end = time.time()
    source_port = -1
    for line in proc.stdout.splitlines():
        if line.startswith("SOURCE_PORT="):
            source_port = int(line.split("=", 1)[1])
        else:
            print(line)
    if proc.stderr.strip():
        print(proc.stderr, file=sys.stderr)
    if source_port == -1:
        print(f"[scenario] WARNING: {script} did not report a source port - "
              "its frames cannot be labeled.")
    return start, end, source_port


def main() -> None:
    quick = "--quick" in sys.argv
    pre = BASELINE_PRE // 2 if quick else BASELINE_PRE
    gap = GAP // 2 if quick else GAP
    post = BASELINE_POST // 2 if quick else BASELINE_POST

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    procs = {}
    windows = []

    def now():
        return time.time()

    try:
        # 1. PLC
        procs["plc"] = subprocess.Popen([PY, str(ROOT / "testbed" / "plc_simulator.py")])
        if not wait_for_port("127.0.0.1", 5020):
            raise SystemExit("PLC simulator did not come up on :5020")

        # 2. tap
        procs["tap"] = subprocess.Popen([PY, str(ROOT / "testbed" / "modbus_tap.py"),
                                         str(CAPTURE_CSV)])
        if not wait_for_port("127.0.0.1", 5021):
            raise SystemExit("Capture tap did not come up on :5021")

        run_start = now()

        # 3. continuous benign HMI for the full run length; it records its
        #    ephemeral source port to HMI_PORT_FILE so we can label its frames.
        total = pre + 2 + gap + 4 + post + 6  # padding for attack durations
        if HMI_PORT_FILE.exists():
            HMI_PORT_FILE.unlink()
        procs["hmi"] = subprocess.Popen([PY, str(ROOT / "testbed" / "hmi_client.py"),
                                         str(total), str(HMI_PORT_FILE)])
        hmi_port = -1
        for _ in range(50):  # wait up to ~5s for the HMI to report its port
            if HMI_PORT_FILE.exists():
                hmi_port = int(HMI_PORT_FILE.read_text().strip())
                break
            time.sleep(0.1)

        # 4. baseline
        print(f"[scenario] baseline for {pre}s...")
        time.sleep(pre)

        # 5. replay attack
        print("[scenario] injecting REPLAY attack...")
        r_start, r_end, r_port = run_attack("replay_attack.py", "replay")
        windows.append({"type": "replay", "start": r_start, "end": r_end,
                        "source_port": r_port})

        # 6. gap
        print(f"[scenario] baseline gap for {gap}s...")
        time.sleep(gap)

        # 7. injection attack
        print("[scenario] injecting COMMAND-INJECTION attack...")
        i_start, i_end, i_port = run_attack("command_injection.py", "injection")
        windows.append({"type": "injection", "start": i_start, "end": i_end,
                        "source_port": i_port})

        # 8. tail
        print(f"[scenario] baseline tail for {post}s...")
        time.sleep(post)

        run_end = now()

        # Ground-truth port->role map, built from the ports each client actually
        # used this run (ephemeral, so they differ every run).
        source_port_roles = {}
        if hmi_port != -1:
            source_port_roles[hmi_port] = "benign"
        if r_port != -1:
            source_port_roles[r_port] = "replay"
        if i_port != -1:
            source_port_roles[i_port] = "injection"

        manifest = {
            "run_start": run_start,
            "run_end": run_end,
            "capture_csv": CAPTURE_CSV.name,
            "source_port_roles": source_port_roles,
            "attack_windows": windows,
            "notes": (
                "Ground truth: label each captured frame by its client_port via "
                "source_port_roles (primary); attack_windows give the wall-clock "
                "span of each attack as an independent cross-check. Single-host "
                "loopback testbed, so all frames share IP 127.0.0.1 and are "
                "distinguished by source port - GRFICSv2 provides true per-host "
                "IP separation when higher fidelity is wanted."
            ),
        }
        MANIFEST.write_text(json.dumps(manifest, indent=2))
        print(f"[scenario] wrote manifest -> {MANIFEST}")

    finally:
        # Stop children in reverse dependency order; give the tap a moment to
        # flush the last rows before it's killed.
        for name in ("hmi", "tap", "plc"):
            p = procs.get(name)
            if p and p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        print("[scenario] all processes stopped.")
        if CAPTURE_CSV.exists():
            rows = sum(1 for _ in open(CAPTURE_CSV)) - 1
            print(f"[scenario] capture: {rows} frames logged -> {CAPTURE_CSV}")


if __name__ == "__main__":
    main()
