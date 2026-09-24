"""
Raw Modbus/TCP frame helpers, shared by the attack scripts.

The attack scripts build frames at the byte level (raw sockets) rather than
through pymodbus so they have full control over every field - in particular
the MBAP transaction ID, which a replay attack must be able to *reuse*
verbatim and an injection attack must be able to set freely. pymodbus's
client would manage (and auto-increment) that field for us, which is exactly
the control we need to take away from it here.

MBAP header (7 bytes) + PDU:
    transaction_id (2) | protocol_id (2, always 0) | length (2) |
    unit_id (1) | function_code (1) | data (...)
The `length` field counts unit_id + PDU.
"""

import struct

PROTOCOL_ID = 0

# Function codes used in this testbed.
FC_READ_COILS = 0x01
FC_READ_HOLDING = 0x03
FC_WRITE_SINGLE_COIL = 0x05
FC_WRITE_SINGLE_REGISTER = 0x06
FC_WRITE_MULTIPLE_REGISTERS = 0x10  # 16

COIL_ON = 0xFF00
COIL_OFF = 0x0000


def build_frame(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    """Wrap a PDU in an MBAP header. length = unit_id byte + PDU."""
    length = len(pdu) + 1
    header = struct.pack(">HHHB", transaction_id, PROTOCOL_ID, length, unit_id)
    return header + pdu


def write_single_register(transaction_id: int, address: int, value: int,
                          unit_id: int = 1) -> bytes:
    """FC6 - write one holding register (e.g. pump setpoint)."""
    pdu = struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER, address, value)
    return build_frame(transaction_id, unit_id, pdu)


def write_single_coil(transaction_id: int, address: int, on: bool,
                      unit_id: int = 1) -> bytes:
    """FC5 - write one coil (e.g. inlet/outlet valve)."""
    pdu = struct.pack(">BHH", FC_WRITE_SINGLE_COIL, address,
                      COIL_ON if on else COIL_OFF)
    return build_frame(transaction_id, unit_id, pdu)


def write_multiple_registers(transaction_id: int, address: int,
                             values: list[int], unit_id: int = 1) -> bytes:
    """FC16 - write a block of holding registers in one request."""
    count = len(values)
    byte_count = count * 2
    pdu = struct.pack(">BHHB", FC_WRITE_MULTIPLE_REGISTERS, address, count,
                      byte_count) + b"".join(struct.pack(">H", v) for v in values)
    return build_frame(transaction_id, unit_id, pdu)


def read_holding(transaction_id: int, address: int, count: int,
                 unit_id: int = 1) -> bytes:
    """FC3 - read holding registers (used to prime a replay capture)."""
    pdu = struct.pack(">BHH", FC_READ_HOLDING, address, count)
    return build_frame(transaction_id, unit_id, pdu)


def parse_transaction_id(frame: bytes) -> int:
    return struct.unpack(">H", frame[0:2])[0]
