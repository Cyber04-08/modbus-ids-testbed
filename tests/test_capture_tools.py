"""The live tap's framing, the pcap exporter / converter round trip, and the
capture scripts' protection of existing data files."""
import csv
import struct

import capture_baseline
import modbus_frames as mf
from export_pcap import export
from modbus_tap import frame_row, iter_frames
from pcap_to_csv import convert


def test_iter_frames_splits_and_keeps_partial():
    a, b = mf.read_holding(1, 0, 1), mf.read_holding(2, 0, 1)
    buf = bytearray(a + b + b[:3])
    assert list(iter_frames(buf)) == [a, b]
    assert bytes(buf) == b[:3]                 # partial frame waits for more bytes


def test_impossible_length_is_flushed_not_waited_on():
    """Regression: a length field of 0xFFFF made the tap wait for ~65 KB, so
    every later frame on the connection went unlogged."""
    bad = struct.pack(">HHHB", 1, 0, 0xFFFF, 1) + b"\x03\x00\x00"
    buf = bytearray(bad)
    assert list(iter_frames(buf)) == [bad]
    assert not buf


def test_short_frame_is_recorded_with_blank_fields():
    """Regression: frames under 8 bytes were dropped without a trace."""
    row = frame_row("req", 5000, b"\x00\x01\x00\x00\x00\x01\x01")
    assert row["raw_hex"] == "00010000000101"
    assert row["function_code"] == ""


def _capture_csv(path, rows):
    fields = ["wall_time", "monotonic", "direction", "client_port", "transaction_id",
              "protocol_id", "length", "unit_id", "function_code", "address", "count",
              "values", "raw_hex"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for t, d, port, frame in rows:
            w.writerow({"wall_time": f"{t:.6f}", "monotonic": f"{t:.6f}",
                        "direction": d, "client_port": port, "raw_hex": frame.hex()})


def test_pcap_round_trip_keeps_frames_with_tied_last_timestamp(tmp_path):
    """Regression: the exporter closed a connection at the first frame with
    the last timestamp, so tied final frames came after the FIN and were
    lost (23 responses and 1 request across the 10 saved runs)."""
    w1 = mf.write_single_register(1, 1, 50)
    w2 = mf.write_single_register(2, 1, 60)
    rows = [(1.0, "req", 5000, w1), (1.0, "resp", 5000, w1),
            (2.0, "req", 5000, w2), (2.0, "resp", 5000, w2)]    # last two tied
    src, pcap, out = tmp_path / "s.csv", tmp_path / "s.pcap", tmp_path / "o.csv"
    _capture_csv(src, rows)
    export(src, pcap)
    assert convert(pcap, out) == 4
    with open(out, newline="") as f:
        got = [(r["direction"], r["raw_hex"]) for r in csv.DictReader(f)]
    assert got == [(d, fr.hex()) for _, d, _, fr in rows]


def test_converter_skips_other_ports(tmp_path):
    rows = [(1.0, "req", 5000, mf.read_holding(1, 0, 1))]
    src, pcap, out = tmp_path / "s.csv", tmp_path / "s.pcap", tmp_path / "o.csv"
    _capture_csv(src, rows)
    export(src, pcap)                          # exporter puts the PLC on port 502
    assert convert(pcap, out, port=502) == 1
    assert convert(pcap, out, port=503) == 0   # nothing on 503: no rows invented


def test_capture_moves_existing_file_aside(tmp_path, monkeypatch):
    """Regression: a new capture overwrote the training session the reported
    results were made with."""
    monkeypatch.setattr(capture_baseline, "BACKUP_DIR", tmp_path / "backups")
    f = tmp_path / "baseline_capture.csv"
    f.write_text("old data")
    capture_baseline.back_up(f)
    assert not f.exists()
    [kept] = (tmp_path / "backups").iterdir()
    assert kept.read_text() == "old data"
