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

Only TCP traffic to or from the Modbus port (502 unless --port is given) is
converted. Everything skipped is counted by reason and printed, so a capture
that lost data, or used another port, cannot silently produce a short CSV.

Usage:
    python tools/pcap_to_csv.py in.pcap out.csv [--port 502]
"""

from __future__ import annotations

import csv
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "testbed"))
from modbus_tap import frame_row, iter_frames  # noqa: E402

MODBUS_PORT = 502

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


def _read_pcap(path: Path, skipped: Counter):
    """Yield (ts, linktype, link_bytes) for each record in a classic .pcap
    file, counting records cut short by the snapshot length or by the file
    ending mid-record."""
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
        ts_sec, ts_usec, caplen, orig_len = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        if off + caplen > n:
            skipped["record cut off at end of file"] += 1
            break
        if caplen < orig_len:
            skipped["packet truncated by snapshot length (kept, may lose bytes)"] += 1
        yield ts_sec + ts_usec / 1e6, linktype, data[off:off + caplen]
        off += caplen
    if 0 < n - off < 16:
        skipped["record cut off at end of file"] += 1


def _parse_l3(linktype: int, pkt: bytes):
    """Strip the link layer; return (src, dst, tcp_segment), or a string
    naming why the packet is not an IPv4 TCP packet we can read."""
    if linktype == LINKTYPE_ETHERNET:
        if len(pkt) < 14:
            return "short link header"
        ethertype, ip = pkt[12:14], pkt[14:]
        if ethertype == b"\x81\x00" and len(pkt) >= 18:     # one 802.1Q VLAN tag
            ethertype, ip = pkt[16:18], pkt[18:]
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(pkt) < 16:
            return "short link header"
        ethertype, ip = pkt[14:16], pkt[16:]
    elif linktype == LINKTYPE_LINUX_SLL2:
        if len(pkt) < 20:
            return "short link header"
        ethertype, ip = pkt[0:2], pkt[20:]
    else:
        return f"unsupported link type {linktype}"
    if ethertype != b"\x08\x00":
        return "not IPv4 (e.g. ARP, IPv6)"
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return "bad IPv4 header"
    if ip[9] != 6:
        return "not TCP"
    if struct.unpack(">H", ip[6:8])[0] & 0x3FFF:          # MF flag or fragment offset
        return "IP fragment (not reassembled)"
    ihl = (ip[0] & 0x0F) * 4
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


def _seq_diff(a: int, b: int) -> int:
    """a - b in 32-bit TCP sequence space, as a signed number."""
    d = (a - b) & 0xFFFFFFFF
    return d - 0x100000000 if d >= 0x80000000 else d


def convert(pcap_path: Path, csv_path: Path, port: int = MODBUS_PORT,
            skipped: Counter | None = None) -> int:
    # Reassemble each TCP stream in sequence-number order, skipping
    # retransmitted / already-seen bytes (a real capture, unlike the live
    # proxy tap, contains TCP retransmissions; counting them would duplicate
    # Modbus frames).
    skipped = Counter() if skipped is None else skipped
    streams: dict[tuple, dict] = {}
    records = []
    for ts, linktype, pkt in _read_pcap(pcap_path, skipped):
        l3 = _parse_l3(linktype, pkt)
        if isinstance(l3, str):
            skipped[l3] += 1
            continue
        src, dst, seg = l3
        tcp = _parse_tcp(seg)
        if not tcp:
            skipped["bad TCP header"] += 1
            continue
        sport, dport, seq, payload = tcp
        if port not in (sport, dport):
            skipped[f"TCP not on port {port}"] += 1
            continue
        if not payload:
            continue                               # handshake / pure ACK / FIN
        key = (src, sport, dst, dport)
        st = streams.setdefault(key, {"buf": bytearray(), "next": None, "ts": ts})
        if st["next"] is None:
            st["next"] = seq                       # first payload byte seen
        ahead = _seq_diff(seq, st["next"])         # >0 gap, <0 overlap, 0 in order
        if ahead > 0:
            # Bytes between the last segment and this one were never
            # captured. Whatever frame was being assembled is broken: log it
            # as malformed and restart framing at this segment.
            skipped["TCP gap (bytes missing from capture)"] += 1
            if st["buf"]:
                records.append((st["ts"], src, dst, sport, dport, bytes(st["buf"])))
                st["buf"].clear()
            st["next"] = seq
        elif ahead < 0:
            if -ahead >= len(payload):
                skipped["TCP retransmission (already seen)"] += 1
                continue
            payload = payload[-ahead:]             # keep only the new tail
        st["buf"].extend(payload)
        st["next"] = (st["next"] + len(payload)) & 0xFFFFFFFF
        st["ts"] = ts
        for frame in iter_frames(st["buf"]):
            records.append((ts, src, dst, sport, dport, frame))

    for (src, sport, dst, dport), st in streams.items():
        if st["buf"]:
            skipped["incomplete frame at end of stream (logged as malformed)"] += 1
            records.append((st["ts"], src, dst, sport, dport, bytes(st["buf"])))

    records.sort(key=lambda r: r[0])               # stable: ties keep stream order
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for ts, src, dst, sport, dport, frame in records:
            direction = "req" if dport == port else "resp"
            client_port = sport if direction == "req" else dport
            w.writerow({"wall_time": f"{ts:.6f}", "monotonic": f"{ts:.6f}",
                        **frame_row(direction, client_port, frame),
                        "src_ip": src, "dst_ip": dst})
            n += 1
    return n


def main() -> None:
    args = sys.argv[1:]
    port = MODBUS_PORT
    if "--port" in args:
        i = args.index("--port")
        port = int(args[i + 1])
        del args[i:i + 2]
    if len(args) != 2:
        raise SystemExit(__doc__)
    skipped = Counter()
    n = convert(Path(args[0]), Path(args[1]), port, skipped)
    print(f"{args[0]} -> {args[1]} ({n} Modbus frames)")
    for reason, count in skipped.most_common():
        print(f"  skipped/flagged: {count:6d}  {reason}")


if __name__ == "__main__":
    main()
