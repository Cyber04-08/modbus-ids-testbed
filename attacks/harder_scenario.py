"""
Harder-attack scenario (limitations 1 and 2).

Same testbed and ground-truth machinery as attacks/run_scenario.py, but the
two attacks are the harder variants:
  * txid_replay.py     - a replay with rewritten transaction IDs  (role "replay")
  * mimic_injection.py - an injection that copies the operator's poll timing
                         and uses in-band values                  (role "injection")

The attacker's origin is chosen with --origin:
  * separate - the attacker connects from 127.0.0.66, a second loopback
               address standing in for a separate host on the ICS LAN. The
               operator used 127.0.0.1 in training, so the sender-identity
               rule can tell them apart.
  * spoof    - the attacker connects from 127.0.0.1, the operator's own
               address (it is on the operator's machine, or spoofs it). The
               sender-identity rule cannot help here; this case shows what the
               content-based countermeasures can do on their own.

The operator (testbed/hmi_client.py) always runs from 127.0.0.1. A manifest
compatible with data/label_dataset.py is written, with the attacker's drawn
parameters and origin recorded so a session can be reproduced.

Usage:
    python attacks/harder_scenario.py [--origin separate|spoof] [--seed N] [--quick]
"""

import json
import random
import socket
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

OPERATOR_IP = "127.0.0.1"
SEPARATE_ATTACKER_IP = "127.0.0.66"

# role -> attack script
ATTACKS = {"replay": "txid_replay.py", "injection": "mimic_injection.py"}


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def run_attack(script: str, src_ip: str, seed: int | None) -> dict:
    args = [PY, str(ROOT / "attacks" / script), "--src-ip", src_ip]
    if seed is not None:
        args += ["--seed", str(seed)]
    start = time.time()
    proc = subprocess.run(args, capture_output=True, text=True)
    end = time.time()
    source_port, packets, params = -1, [], None
    for line in proc.stdout.splitlines():
        if line.startswith("SOURCE_PORT="):
            source_port = int(line.split("=", 1)[1])
        elif line.startswith("PACKET="):
            packets.append(json.loads(line.split("=", 1)[1]))
        elif line.startswith("PARAMS="):
            params = json.loads(line.split("=", 1)[1])
        else:
            print(line)
    if proc.stderr.strip():
        print(proc.stderr, file=sys.stderr)
    if source_port == -1:
        print(f"[harder] WARNING: {script} did not report a source port.")
    return {"start": start, "end": end, "source_port": source_port,
            "packets": packets, "params": params, "seed": seed}


def main() -> None:
    quick = "--quick" in sys.argv
    origin = sys.argv[sys.argv.index("--origin") + 1] if "--origin" in sys.argv else "separate"
    if origin not in ("separate", "spoof"):
        raise SystemExit("--origin must be 'separate' or 'spoof'")
    seed_arg = sys.argv[sys.argv.index("--seed") + 1] if "--seed" in sys.argv else None
    session_seed = int(seed_arg) if seed_arg is not None else random.SystemRandom().randrange(2**31)
    rng = random.Random(session_seed)
    attacker_ip = OPERATOR_IP if origin == "spoof" else SEPARATE_ATTACKER_IP

    scale = 0.5 if quick else 1.0
    pre = round(rng.uniform(5, 15) * scale, 1)
    gap = round(rng.uniform(4, 12) * scale, 1)
    post = round(rng.uniform(4, 12) * scale, 1)
    order = ["replay", "injection"]
    rng.shuffle(order)
    attack_seeds = {role: rng.randrange(2**31) for role in order}
    print(f"[harder] origin {origin} (attacker {attacker_ip}), seed {session_seed}: "
          f"order {order}, pre {pre}s gap {gap}s post {post}s")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    procs = {}
    windows = []
    try:
        procs["plc"] = subprocess.Popen([PY, str(ROOT / "testbed" / "plc_simulator.py")])
        if not wait_for_port("127.0.0.1", 5020):
            raise SystemExit("PLC simulator did not come up on :5020")
        procs["tap"] = subprocess.Popen([PY, str(ROOT / "testbed" / "modbus_tap.py"), str(CAPTURE_CSV)])
        if not wait_for_port("127.0.0.1", 5021):
            raise SystemExit("Capture tap did not come up on :5021")

        run_start = time.time()
        total = pre + gap + post + 90
        if HMI_PORT_FILE.exists():
            HMI_PORT_FILE.unlink()
        procs["hmi"] = subprocess.Popen([PY, str(ROOT / "testbed" / "hmi_client.py"),
                                         str(total), str(HMI_PORT_FILE)])
        hmi_port = -1
        for _ in range(50):
            if HMI_PORT_FILE.exists():
                hmi_port = int(HMI_PORT_FILE.read_text().strip())
                break
            time.sleep(0.1)

        print(f"[harder] baseline for {pre}s...")
        time.sleep(pre)
        for k, role in enumerate(order):
            if k:
                print(f"[harder] baseline gap for {gap}s...")
                time.sleep(gap)
            print(f"[harder] running {role} ({ATTACKS[role]}) from {attacker_ip}...")
            windows.append({"type": role,
                            **run_attack(ATTACKS[role], attacker_ip, attack_seeds[role])})
        print(f"[harder] baseline tail for {post}s...")
        time.sleep(post)
        run_end = time.time()

        ports = {w["type"]: w["source_port"] for w in windows}
        source_port_roles = {}
        if hmi_port != -1:
            source_port_roles[hmi_port] = "benign"
        for role, port in ports.items():
            if port != -1:
                source_port_roles[port] = role

        manifest = {
            "run_start": run_start, "run_end": run_end,
            "capture_csv": CAPTURE_CSV.name,
            "source_port_roles": source_port_roles,
            "harder": True, "origin": origin, "attacker_ip": attacker_ip,
            "operator_ip": OPERATOR_IP, "session_seed": session_seed,
            "attack_windows": windows,
            "notes": ("Harder-attack session: txid-rewriting replay + "
                      "timing-mimicking in-band injection. Ground truth is the "
                      "per-packet log each attack script wrote (kind attack / "
                      "cover / seed); the labeler matches captured requests by "
                      "exact bytes, as in run_scenario.py. src_ip distinguishes "
                      "the operator from the attacker."),
        }
        MANIFEST.write_text(json.dumps(manifest, indent=2))
        print(f"[harder] wrote manifest -> {MANIFEST}")
    finally:
        for name in ("hmi", "tap", "plc"):
            p = procs.get(name)
            if p and p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        print("[harder] all processes stopped.")
        if CAPTURE_CSV.exists():
            rows = sum(1 for _ in open(CAPTURE_CSV)) - 1
            print(f"[harder] capture: {rows} frames logged -> {CAPTURE_CSV}")


if __name__ == "__main__":
    main()
