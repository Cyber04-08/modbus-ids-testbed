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

Ground truth comes from the attack scripts' own logs, per packet:
  * each client uses an ephemeral source port and reports it back, so this
    script records which connection belongs to which role;
  * each attack script logs every request it sends (exact bytes, transaction
    ID, and kind: "attack", or "seed" for the replay's stand-in for the
    recorded operator command), collected into the manifest; and
  * the wall-clock window of each attack is recorded as a cross-check.
The labeler matches every captured request on an attack connection to its
logged record and checks it falls inside the window.

Varied sessions (`--vary`): by default every session runs the same attack
script (replay first, then injection, same frames, same timing), so a
threshold tuned on one session has effectively seen the attack it is later
tested on. With --vary the session draws its own baseline padding, the order
of the two attacks, and a seed for each attack script, which then draws its
own frames, counts and timing (see plan() in replay_attack.py and
command_injection.py). The session seed (--seed N, or a random one) and
every drawn parameter are written to the manifest, so a varied session can
be re-created exactly.

Usage:
    python attacks/run_scenario.py                 # default timing
    python attacks/run_scenario.py --quick         # shorter windows
    python attacks/run_scenario.py --vary          # randomized attacks
    python attacks/run_scenario.py --vary --seed 3 # ... reproducibly
"""

import json
import random
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


def run_attack(script: str, seed: int | None = None) -> dict:
    """Run an attack script, echo its output, and return its attack-window
    record (start, end, source_port, packets, params). The script prints
    `SOURCE_PORT=<n>` so we can attribute its connection, one `PACKET=<json>`
    line per request it sends (exact bytes, transaction ID, and kind
    "attack"/"seed") so every packet is labeled individually, and a
    `PARAMS=<json>` line with the parameters it used."""
    args = [PY, str(ROOT / "attacks" / script)]
    if seed is not None:
        args += ["--seed", str(seed)]
    start = time.time()
    proc = subprocess.run(args, capture_output=True, text=True)
    end = time.time()
    source_port = -1
    packets = []
    params = None
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
        print(f"[scenario] WARNING: {script} did not report a source port - "
              "its frames cannot be labeled.")
    return {"start": start, "end": end, "source_port": source_port,
            "packets": packets, "params": params, "seed": seed}


def session_plan(quick: bool, vary: bool, seed: int | None) -> dict:
    """Baseline padding, attack order and per-attack seeds for one session.
    Fixed unless vary; with vary, drawn from the session seed."""
    scale = 0.5 if quick else 1.0
    if not vary:
        return {"seed": None, "pre": int(BASELINE_PRE * scale), "gap": int(GAP * scale),
                "post": int(BASELINE_POST * scale), "order": ["replay", "injection"],
                "attack_seeds": {"replay": None, "injection": None}}
    if seed is None:
        seed = random.SystemRandom().randrange(2**31)
    rng = random.Random(seed)
    order = ["replay", "injection"]
    rng.shuffle(order)
    return {"seed": seed,
            "pre": round(rng.uniform(5, 20) * scale, 1),
            "gap": round(rng.uniform(3, 15) * scale, 1),
            "post": round(rng.uniform(4, 15) * scale, 1),
            "order": order,
            "attack_seeds": {a: rng.randrange(2**31) for a in ("replay", "injection")}}


ATTACK_SCRIPTS = {"replay": "replay_attack.py", "injection": "command_injection.py"}


def main() -> None:
    quick = "--quick" in sys.argv
    vary = "--vary" in sys.argv
    seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else None
    if seed is not None and not vary:
        raise SystemExit("--seed only applies with --vary")
    sp = session_plan(quick, vary, seed)
    pre, gap, post = sp["pre"], sp["gap"], sp["post"]
    if vary:
        print(f"[scenario] varied session, seed {sp['seed']}: order {sp['order']}, "
              f"pre {pre}s, gap {gap}s, post {post}s")

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
        if vary:
            # Varied attacks last up to ~20 s each; the HMI is stopped at
            # teardown anyway, so a generous length costs nothing.
            total = pre + gap + post + 60
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

        # 5-7. the two attacks (replay then injection unless varied), with a
        #      gap of normal traffic between them
        for k, atk in enumerate(sp["order"]):
            if k:
                print(f"[scenario] baseline gap for {gap}s...")
                time.sleep(gap)
            print(f"[scenario] injecting {atk.upper()} attack...")
            windows.append({"type": atk,
                            **run_attack(ATTACK_SCRIPTS[atk], sp["attack_seeds"][atk])})
        ports = {w["type"]: w["source_port"] for w in windows}
        r_port, i_port = ports["replay"], ports["injection"]

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
            "session_plan": sp,
            "attack_windows": windows,
            "notes": (
                "Ground truth: each attack window lists every request the attack "
                "script sent (exact bytes, txid, kind attack/seed), logged by the "
                "script itself. The labeler matches captured requests on that "
                "connection (client_port, via source_port_roles) to these records "
                "one by one; the wall-clock window is a cross-check. Single-host "
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
