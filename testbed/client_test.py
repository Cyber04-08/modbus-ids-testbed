"""Sanity-check client: confirms the simulated PLC responds correctly to
normal Modbus/TCP reads and writes before any attack/detector code is built
on top of it."""

from pymodbus.client import ModbusTcpClient

HOST = "127.0.0.1"
PORT = 5020


def main() -> None:
    client = ModbusTcpClient(HOST, port=PORT)
    if not client.connect():
        raise SystemExit(f"Could not connect to simulated PLC at {HOST}:{PORT}")

    try:
        level = client.read_holding_registers(address=0, count=1)
        pump = client.read_holding_registers(address=1, count=1)
        print(f"Tank level: {level.registers[0] / 10:.1f}%")
        print(f"Pump setpoint: {pump.registers[0]}%")

        print("Opening inlet valve, setting pump to 60%...")
        client.write_coil(address=0, value=True)
        client.write_register(address=1, value=60)

        coils = client.read_coils(address=0, count=2)
        print(f"Inlet valve open: {coils.bits[0]}, Outlet valve open: {coils.bits[1]}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
