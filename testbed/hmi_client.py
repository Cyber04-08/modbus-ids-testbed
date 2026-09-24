"""
Normal operator (HMI/master) traffic generator - the benign baseline.

Emulates what a real control loop and operator do against the PLC: poll the
tank level frequently, and occasionally adjust the pump setpoint or toggle a
valve as the process demands. Setpoint changes and poll timing both carry
deliberate variation/jitter so the baseline is *not* artificially uniform -
a too-regular baseline would let both detectors look better than they would
in practice (this is called out explicitly in the proposal).

It connects through the tap (TAP_PORT), not straight to the PLC, so every
request it makes is captured. It uses an ordinary ephemeral source port and,
if given a port-file path, writes that port there so the orchestrator can
record which captured frames are the benign baseline - no label is embedded
in the packets the detectors will see.

Usage:
    python testbed/hmi_client.py                     # run until Ctrl+C
    python testbed/hmi_client.py 120                 # run for ~120 seconds
    python testbed/hmi_client.py 120 data/.hmi_port  # also record source port
"""

import random
import sys
import time
from pathlib import Path

from pymodbus.client import ModbusTcpClient

TAP_HOST = "127.0.0.1"
TAP_PORT = 5021

HR_LEVEL = 0
HR_PUMP_SETPOINT = 1
COIL_INLET_VALVE = 0
COIL_OUTLET_VALVE = 1

POLL_INTERVAL = 1.0       # nominal seconds between level polls
POLL_JITTER = 0.25        # +/- jitter so polling isn't perfectly periodic


def connect() -> ModbusTcpClient:
    client = ModbusTcpClient(TAP_HOST, port=TAP_PORT)
    if not client.connect():
        raise SystemExit(f"HMI could not connect to tap {TAP_HOST}:{TAP_PORT}")
    return client


def main() -> None:
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else None
    port_file = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    deadline = time.monotonic() + duration if duration else None

    client = connect()
    source_port = client.socket.getsockname()[1]
    if port_file is not None:
        port_file.write_text(str(source_port))
    print(f"HMI client sending normal traffic via tap {TAP_HOST}:{TAP_PORT} "
          f"(source port {source_port})"
          + (f" for ~{duration:.0f}s" if duration else " until Ctrl+C"))

    setpoint = 40
    inlet_open = False
    outlet_open = False
    polls = 0
    try:
        while deadline is None or time.monotonic() < deadline:
            # Frequent poll of the tank level (the bread-and-butter of an HMI).
            client.read_holding_registers(address=HR_LEVEL, count=1)
            polls += 1

            # Occasionally act on the process, like an operator/control loop:
            if random.random() < 0.20:
                # Nudge the pump setpoint within a plausible operating band.
                setpoint = max(20, min(90, setpoint + random.choice([-10, -5, 5, 10])))
                client.write_register(address=HR_PUMP_SETPOINT, value=setpoint)
            if random.random() < 0.10:
                inlet_open = not inlet_open
                client.write_coil(address=COIL_INLET_VALVE, value=inlet_open)
            if random.random() < 0.08:
                outlet_open = not outlet_open
                client.write_coil(address=COIL_OUTLET_VALVE, value=outlet_open)

            time.sleep(max(0.1, POLL_INTERVAL + random.uniform(-POLL_JITTER, POLL_JITTER)))
    except KeyboardInterrupt:
        pass
    finally:
        client.close()
        print(f"HMI client stopped after {polls} polls.")


if __name__ == "__main__":
    main()
