"""
Passive Modbus/TCP capture tap (bump-in-the-wire logger).

Sits between the clients (HMI + attackers) and the PLC: it listens on
TAP_PORT, forwards every byte to the real PLC on PLC_PORT, and records every
Modbus frame in both directions to a CSV. It never modifies or drops a
frame - it only observes - so it is a faithful stand-in for a network tap /
tcpdump capture, but works on Windows loopback with no npcap or admin rights
(which raw-socket sniffing of loopback would require).

Each client's source port is logged, which is how the labeler later assigns
ground truth: the attack orchestrator pins each attacker to a known local
port, so a frame's source port tells us which script emitted it without
having to embed any label in the traffic the detectors will see.

Usage:
    python testbed/modbus_tap.py                 # logs to data/capture.csv
    python testbed/modbus_tap.py my_run.csv      # custom output path
"""

import csv
import socket
import struct
import sys
import threading
import time
from pathlib import Path

TAP_HOST = "127.0.0.1"
TAP_PORT = 5021          # clients connect here
PLC_HOST = "127.0.0.1"
PLC_PORT = 5020          # the real simulated PLC
DEFAULT_CSV = Path(__file__).resolve().parent.parent / "data" / "capture.csv"

CSV_FIELDS = [
    "wall_time", "monotonic", "direction", "client_port",
    "transaction_id", "protocol_id", "length", "unit_id",
    "function_code", "address", "count", "values", "raw_hex",
]

# Function-code decoders for the fields the detectors care about. Requests
# carry address/qty/value; responses mostly echo or return data, so we decode
# what is cheap and leave the rest to raw_hex.
_READ_FCS = {0x01, 0x02, 0x03, 0x04}
_WRITE_SINGLE_FCS = {0x05, 0x06}
_WRITE_MULTI_FCS = {0x0F, 0x10}


def decode_pdu(function_code: int, pdu_data: bytes, direction: str):
    """Return (address, count, values) decoded from a request PDU where
    possible; responses and anything unexpected fall back to (None, None, None)
    and are still fully preserved in raw_hex."""
    try:
        if direction == "req" and function_code in _READ_FCS and len(pdu_data) >= 4:
            address, count = struct.unpack(">HH", pdu_data[:4])
            return address, count, ""
        if direction == "req" and function_code in _WRITE_SINGLE_FCS and len(pdu_data) >= 4:
            address, value = struct.unpack(">HH", pdu_data[:4])
            return address, 1, str(value)
        if direction == "req" and function_code in _WRITE_MULTI_FCS and len(pdu_data) >= 5:
            address, count, byte_count = struct.unpack(">HHB", pdu_data[:5])
            body = pdu_data[5:5 + byte_count]
            if function_code == 0x10:
                vals = [struct.unpack(">H", body[i:i + 2])[0]
                        for i in range(0, len(body) - 1, 2)]
            else:  # 0x0F write multiple coils - report the raw bitmask bytes
                vals = list(body)
            return address, count, " ".join(str(v) for v in vals)
    except struct.error:
        pass
    return None, None, ""


class CsvLogger:
    """Thread-safe append-only CSV writer, flushed per row so a capture is
    durable even if the run is killed mid-attack."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "w", newline="")
        self._writer = csv.DictWriter(self._fh, fieldnames=CSV_FIELDS)
        self._writer.writeheader()
        self._fh.flush()
        self._lock = threading.Lock()
        self.path = path

    def log(self, row: dict) -> None:
        with self._lock:
            self._writer.writerow(row)
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            self._fh.close()


def iter_frames(buffer: bytearray):
    """Yield complete Modbus/TCP frames from a rolling byte buffer, leaving
    any partial trailing frame in place. A single TCP segment can carry more
    than one frame, or split one across segments - both are handled here."""
    while len(buffer) >= 7:
        length = struct.unpack(">H", buffer[4:6])[0]
        total = 6 + length  # 6 header bytes before length's own coverage + length
        if len(buffer) < total:
            break
        frame = bytes(buffer[:total])
        del buffer[:total]
        yield frame


def log_frame(logger: CsvLogger, direction: str, client_port: int, frame: bytes) -> None:
    if len(frame) < 8:
        return
    transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", frame[:7])
    function_code = frame[7]
    pdu_data = frame[8:]
    address, count, values = decode_pdu(function_code, pdu_data, direction)
    logger.log({
        "wall_time": f"{time.time():.6f}",
        "monotonic": f"{time.monotonic():.6f}",
        "direction": direction,
        "client_port": client_port,
        "transaction_id": transaction_id,
        "protocol_id": protocol_id,
        "length": length,
        "unit_id": unit_id,
        "function_code": function_code,
        "address": "" if address is None else address,
        "count": "" if count is None else count,
        "values": values,
        "raw_hex": frame.hex(),
    })


def pump(src: socket.socket, dst: socket.socket, direction: str,
         client_port: int, logger: CsvLogger) -> None:
    """Forward bytes src->dst, parsing and logging each complete frame."""
    buffer = bytearray()
    try:
        while True:
            chunk = src.recv(4096)
            if not chunk:
                break
            dst.sendall(chunk)
            buffer.extend(chunk)
            for frame in iter_frames(buffer):
                log_frame(logger, direction, client_port, frame)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle_client(client_sock: socket.socket, client_addr, logger: CsvLogger) -> None:
    client_port = client_addr[1]
    plc_sock = socket.create_connection((PLC_HOST, PLC_PORT))
    threads = [
        threading.Thread(target=pump, args=(client_sock, plc_sock, "req", client_port, logger), daemon=True),
        threading.Thread(target=pump, args=(plc_sock, client_sock, "resp", client_port, logger), daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for s in (client_sock, plc_sock):
        try:
            s.close()
        except OSError:
            pass


def main() -> None:
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CSV
    logger = CsvLogger(out_path)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((TAP_HOST, TAP_PORT))
    listener.listen(8)
    print(f"Modbus tap listening on {TAP_HOST}:{TAP_PORT} -> "
          f"{PLC_HOST}:{PLC_PORT}, logging to {logger.path}")
    try:
        while True:
            client_sock, client_addr = listener.accept()
            threading.Thread(target=handle_client,
                             args=(client_sock, client_addr, logger),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\nTap stopped.")
    finally:
        listener.close()
        logger.close()


if __name__ == "__main__":
    main()
