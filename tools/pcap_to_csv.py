"""
Convert a real Modbus/TCP packet capture (pcap, e.g. captured passively on the
GRFICSv2 plant network with tcpdump) into the same per-frame CSV our detectors
read (testbed/modbus_tap.py's schema), so the exact detector code used on the
Python testbed also runs on real plant traffic.

The GRFICSv2 plant differs from the Python testbed in ways the schema must
carry, so two columns are ADDED after the originals:
  * src_ip, dst_ip - the plant has several real hosts (the PLC master, the
    HMI, six remote-IO devices), each with its own IP; the single-host testbed
    had only 127.0.0.1. Detectors that use sender identity need this.
A connection is identified by (src_ip, src_port); `client_port` is kept for the
existing per-connection features, but see pcap_to_csv_group() below - ports can
repeat across hosts, so grouping should use (src_ip, client_port).

Only TCP payload bytes are read; this parser reassembles each TCP stream in
capture order before splitting it into Modbus frames (a frame can span two
segments, and a segment can hold several frames - the live tap handled the
same thing). Linux cooked and Ethernet link types are both handled.

Usage:
    python tools/pcap_to_csv.py in.pcap out.csv
"""

from __future__ import annotations

import csv
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "testbed"))
from modbus_tap import decode_pdu, iter_frames  # noqa: E402

CSV_FIELDS = [
    "wall_time", "monotonic", "direction", "client_port",
    "transaction_id", "protocol_id", "length", "unit_id",
    "function_code", "address", "count", "values", "raw_hex",
    "src_ip", "dst_ip",
]

# pcap link-layer header types we handle.
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276


def _read_pcap(path: Path):
    """Yield (ts, link_bytes) for each record in a classic .pcap file."""
    data = path.read_bytes()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        le = magic == b"\xd4\xc3\xb2\xa1"
    else:
        raise SystemExit(f"{path}: not a classic pcap (magic {magic.hex()}); "
                         "save tcpdump output with -w, not pcapng")
    end = "<" if le else ">"
    linktype = struct.unpack(end + "I", data[20:24])[0]
    off, n = 24, len(data)
    while off + 16 <= n:
        ts_sec, ts_usec, caplen, _ = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        yield ts_sec + ts_usec / 1e6, linktype, data[off:off + caplen]
        off += caplen


def _parse_l3(linktype: int, pkt: bytes):
    """Strip the link layer; return the IPv4 payload (proto, src, dst, l4) or None."""
    if linktype == LINKTYPE_ETHERNET:
        if len(pkt) < 14 or pkt[12:14] != b"\x08\x00":
            return None
        ip = pkt[14:]
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(pkt) < 16 or pkt[14:16] != b"\x08\x00":
            return None
        ip = pkt[16:]
    elif linktype == LINKTYPE_LINUX_SLL2:
        if len(pkt) < 20 or pkt[0:2] != b"\x08\x00":
            return None
        ip = pkt[20:]
    else:
        return None
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 6:                       # not TCP
        return None
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    total_len = struct.unpack(">H", ip[2:4])[0]
    return src, dst, ip[ihl:total_len]


def _parse_tcp(seg: bytes):
    """Return (src_port, dst_port, seq, payload) or None."""
    if len(seg) < 20:
        return None
    src_port, dst_port, seq = struct.unpack(">HHI", seg[:8])
    data_off = (seg[12] >> 4) * 4
    return src_port, dst_port, seq, seg[data_off:]


def convert(pcap_path: Path, csv_path: Path) -> int:
    # Reassemble each TCP stream in sequence-number order, skipping
    # retransmitted / already-seen bytes (a real capture, unlike the live
    # proxy tap, contains TCP retransmissions; counting them would duplicate
    # Modbus frames).
    streams: dict[tuple, dict] = {}
    records = []
    for ts, linktype, pkt in _read_pcap(pcap_path):
        l3 = _parse_l3(linktype, pkt)
        if not l3:
            continue
        src, dst, seg = l3
        tcp = _parse_tcp(seg)
        if not tcp or not tcp[3]:
            continue
        sport, dport, seq, payload = tcp
        key = (src, sport, dst, dport)
        st = streams.setdefault(key, {"buf": bytearray(), "next": None})
        if st["next"] is None:
            st["next"] = seq                       # first payload byte seen
        offset = (seq - st["next"]) & 0xFFFFFFFF    # distance past next expected
        if offset > len(payload) and offset < 0x80000000:
            # Gap (a lost/earlier segment); resync to this segment.
            st["next"] = seq
            offset = 0
        if offset >= len(payload):
            continue                               # fully retransmitted; skip
        payload = payload[offset:]
        st["buf"].extend(payload)
        st["next"] = (st["next"] + len(payload)) & 0xFFFFFFFF
        for frame in iter_frames(st["buf"]):
            records.append((ts, src, dst, sport, dport, frame))

    records.sort(key=lambda r: r[0])
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for ts, src, dst, sport, dport, frame in records:
            if len(frame) < 8:
                continue
            tid, pid, length, unit = struct.unpack(">HHHB", frame[:7])
            fc = frame[7]
            direction = "req" if dport == 502 else "resp"
            client_port = sport if direction == "req" else dport
            address, count, values = decode_pdu(fc, frame[8:], direction)
            w.writerow({
                "wall_time": f"{ts:.6f}", "monotonic": f"{ts:.6f}",
                "direction": direction, "client_port": client_port,
                "transaction_id": tid, "protocol_id": pid, "length": length,
                "unit_id": unit, "function_code": fc,
                "address": "" if address is None else address,
                "count": "" if count is None else count,
                "values": values, "raw_hex": frame.hex(),
                "src_ip": src, "dst_ip": dst,
            })
            n += 1
    return n


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    n = convert(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"{sys.argv[1]} -> {sys.argv[2]} ({n} Modbus frames)")


if __name__ == "__main__":
    main()
