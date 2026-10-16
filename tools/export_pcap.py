"""
Export a captured session (CSV from the tap) as a standard .pcap file, so the
same traffic our detectors score can be fed to off-the-shelf network IDS
tools (Zeek, Suricata) for a like-for-like comparison.

The tap records every Modbus/TCP frame byte-for-byte (`raw_hex`, the full
MBAP header + PDU) with its time, direction and client connection. The TCP/IP
layers around those bytes are rebuilt here, since the tap works at the socket
level and never saw them:

  * one TCP connection per recorded client port, opened with a SYN /
    SYN-ACK / ACK handshake 1 ms before its first frame and closed with FIN
    after its last, with correct sequence/ack numbers, so stream-reassembling
    tools accept it;
  * every client shares one IP address (on the testbed they all ran on
    127.0.0.1, so no extra identity information is added) and the PLC gets
    another;
  * the PLC side uses port 502, the standard Modbus/TCP port (the testbed
    listens on 5020/5021 only because ports below 1024 need admin rights),
    so Zeek and Suricata recognize the traffic as Modbus without custom
    port configuration.

The Modbus bytes, their order and their timestamps are exactly as captured.

Usage:
    python tools/export_pcap.py data/runs/run_01.csv out/run_01.pcap
    python tools/export_pcap.py --all out_dir     # runs + tuning + training
"""

from __future__ import annotations

import csv
import struct
import sys
from pathlib import Path

CLIENT_IP = bytes([192, 168, 95, 5])
PLC_IP = bytes([192, 168, 95, 2])
PLC_PORT = 502
CLIENT_MAC = bytes.fromhex("020000000005")
PLC_MAC = bytes.fromhex("020000000002")

SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b"") -> bytes:
    tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 5 << 4, flags,
                          65535, 0, 0)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp_hdr) + len(payload))
    csum = _checksum(pseudo + tcp_hdr + payload)
    tcp_hdr = tcp_hdr[:16] + struct.pack("!H", csum) + tcp_hdr[18:]
    total = 20 + len(tcp_hdr) + len(payload)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0,
                         src_ip, dst_ip)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", _checksum(ip_hdr)) + ip_hdr[12:]
    src_mac, dst_mac = (CLIENT_MAC, PLC_MAC) if src_ip == CLIENT_IP else (PLC_MAC, CLIENT_MAC)
    return dst_mac + src_mac + b"\x08\x00" + ip_hdr + tcp_hdr + payload


class _Conn:
    def __init__(self, port: int):
        self.port = port
        self.c_seq = 1000          # client's next sequence number
        self.s_seq = 5000          # PLC's next sequence number


def export(csv_path: Path, pcap_path: Path) -> int:
    with open(csv_path, newline="") as f:
        rows = [r for r in csv.DictReader(f) if r.get("raw_hex")]
    rows.sort(key=lambda r: float(r["wall_time"]))

    last_seen: dict[int, float] = {}
    for r in rows:
        last_seen[int(r["client_port"])] = float(r["wall_time"])

    packets: list[tuple[float, bytes]] = []
    conns: dict[int, _Conn] = {}

    def c2s(c, t, flags, payload=b""):
        packets.append((t, _packet(CLIENT_IP, PLC_IP, c.port, PLC_PORT, c.c_seq, c.s_seq,
                                   flags, payload)))
        c.c_seq += len(payload) + (1 if flags & (SYN | FIN) else 0)

    def s2c(c, t, flags, payload=b""):
        packets.append((t, _packet(PLC_IP, CLIENT_IP, PLC_PORT, c.port, c.s_seq, c.c_seq,
                                   flags, payload)))
        c.s_seq += len(payload) + (1 if flags & (SYN | FIN) else 0)

    for r in rows:
        t = float(r["wall_time"])
        port = int(r["client_port"])
        if port not in conns:
            c = conns[port] = _Conn(port)
            packets.append((t - 0.0010, _packet(CLIENT_IP, PLC_IP, port, PLC_PORT,
                                                c.c_seq, 0, SYN)))
            c.c_seq += 1
            s2c(c, t - 0.0009, SYN | ACK)
            c2s(c, t - 0.0008, ACK)
        c = conns[port]
        payload = bytes.fromhex(r["raw_hex"])
        if r["direction"] == "req":
            c2s(c, t, PSH | ACK, payload)
        else:
            s2c(c, t, PSH | ACK, payload)
        if t == last_seen[port]:
            c2s(c, t + 0.0010, FIN | ACK)
            s2c(c, t + 0.0011, FIN | ACK)
            c2s(c, t + 0.0012, ACK)

    packets.sort(key=lambda p: p[0])
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    with open(pcap_path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, pkt in packets:
            sec = int(t)
            usec = int(round((t - sec) * 1e6))
            if usec == 1_000_000:
                sec, usec = sec + 1, 0
            f.write(struct.pack("<IIII", sec, usec, len(pkt), len(pkt)) + pkt)
    return len(packets)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    if len(sys.argv) >= 2 and sys.argv[1] == "--all":
        out = Path(sys.argv[2]) if len(sys.argv) > 2 else root / "data" / "pcap"
        sources = sorted((root / "data" / "runs").glob("run_*.csv"))
        sources += [root / "data" / "tuning_labeled.csv", root / "data" / "baseline_capture.csv"]
        for src in sources:
            n = export(src, out / (src.stem + ".pcap"))
            print(f"{src.name:<24} -> {out / (src.stem + '.pcap')}  ({n} packets)")
    elif len(sys.argv) == 3:
        n = export(Path(sys.argv[1]), Path(sys.argv[2]))
        print(f"{sys.argv[1]} -> {sys.argv[2]} ({n} packets)")
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
