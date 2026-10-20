import struct

import pytest

import modbus_frames as mf


def test_mbap_length_counts_unit_id_plus_pdu():
    frame = mf.write_single_register(7, address=1, value=55)
    tid, proto, length, unit = struct.unpack(">HHHB", frame[:7])
    assert (tid, proto, unit) == (7, 0, 1)
    assert length == len(frame) - 6          # unit_id + PDU


@pytest.mark.parametrize("txid", [0, 1, 255, 65535])
def test_transaction_id_round_trips(txid):
    assert mf.parse_transaction_id(mf.read_holding(txid, 0, 1)) == txid


def test_coil_encodings():
    assert mf.write_single_coil(1, 0, True)[-2:] == b"\xff\x00"
    assert mf.write_single_coil(1, 0, False)[-2:] == b"\x00\x00"


def test_fc16_block_layout():
    frame = mf.write_multiple_registers(3, address=0, values=[10, 60000])
    fc, addr, count, nbytes = struct.unpack(">BHHB", frame[7:13])
    assert (fc, addr, count, nbytes) == (16, 0, 2, 4)
    assert struct.unpack(">HH", frame[13:]) == (10, 60000)
