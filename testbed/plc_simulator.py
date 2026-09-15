"""
Simulated Modbus/TCP PLC for the intrusion-detection testbed.

Stands in for OpenPLC/GRFICS while the VM-based testbed is being built out
(see docs/SETUP_LOG.md). Models a small water storage tank process:

  Holding registers (function codes 3/6/16):
    HR0 - tank level, 0-1000 (0.0-100.0%, scaled x10)
    HR1 - pump speed setpoint, 0-100 (%)

  Coils (function codes 1/5/15):
    C0  - inlet valve (True = open)
    C1  - outlet valve (True = open)

A background thread advances the physical process each tick so the tank
level actually responds to valve/pump state instead of sitting static -
a too-uniform baseline makes both detectors look artificially good.
"""

import logging
import threading
import time

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartTcpServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("plc_sim")

HOST = "127.0.0.1"
PORT = 5020  # unprivileged port; use 502 only if run elevated
TICK_SECONDS = 1.0

HR_LEVEL = 0
HR_PUMP_SETPOINT = 1
COIL_INLET_VALVE = 0
COIL_OUTLET_VALVE = 1


def run_process_model(context: ModbusSlaveContext, stop_event: threading.Event) -> None:
    """Advance tank level based on valve/pump state; add small timing jitter
    so traffic isn't perfectly periodic."""
    level = 500  # start at 50.0%

    while not stop_event.is_set():
        inlet_open = context.getValues(1, COIL_INLET_VALVE, count=1)[0]
        outlet_open = context.getValues(1, COIL_OUTLET_VALVE, count=1)[0]
        pump_pct = context.getValues(3, HR_PUMP_SETPOINT, count=1)[0]

        inflow = (pump_pct / 100.0) * 8 if inlet_open else 0
        outflow = 6 if outlet_open else 0
        level = max(0, min(1000, level + int(inflow - outflow)))

        context.setValues(3, HR_LEVEL, [level])

        jitter = 0.15 * (time.time() % 1 - 0.5)
        time.sleep(max(0.1, TICK_SECONDS + jitter))


def main() -> None:
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 16),
        co=ModbusSequentialDataBlock(0, [0, 0] + [0] * 14),
        hr=ModbusSequentialDataBlock(0, [500, 40] + [0] * 14),
        ir=ModbusSequentialDataBlock(0, [0] * 16),
    )
    context = ModbusServerContext(slaves=store, single=True)

    stop_event = threading.Event()
    sim_thread = threading.Thread(
        target=run_process_model, args=(store, stop_event), daemon=True
    )
    sim_thread.start()

    log.info("Simulated PLC listening on %s:%s (Modbus/TCP)", HOST, PORT)
    try:
        StartTcpServer(context=context, address=(HOST, PORT))
    finally:
        stop_event.set()


if __name__ == "__main__":
    main()
