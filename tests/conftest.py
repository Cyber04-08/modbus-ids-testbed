"""Shared helpers for the test suite. Puts the project's script folders on
the import path (the scripts import each other by module name, not as a
package).

Run from the repo root:
    pip install pytest
    python -m pytest tests
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
for sub in ("detectors", "attacks", "data", "testbed", "tools"):
    sys.path.insert(0, str(REPO / sub))

HEADER = ("wall_time,monotonic,direction,client_port,transaction_id,protocol_id,"
          "length,unit_id,function_code,address,count,values,raw_hex")


@pytest.fixture
def write_capture(tmp_path):
    """Write capture rows (dicts) to a CSV in the project's capture format."""
    cols = HEADER.split(",")

    def _write(rows, extra_cols=(), name="cap.csv"):
        path = tmp_path / name
        all_cols = cols + list(extra_cols)
        lines = [",".join(all_cols)]
        for r in rows:
            lines.append(",".join(str(r.get(c, "")) for c in all_cols))
        path.write_text("\n".join(lines) + "\n")
        return path
    return _write


def req(t, port, txid, fc, addr, count="", values="", raw="", **kw):
    return dict(wall_time=t, monotonic=t, direction="req", client_port=port,
                transaction_id=txid, protocol_id=0, length=6, unit_id=1,
                function_code=fc, address=addr, count=count, values=values,
                raw_hex=raw or f"{txid:04x}{fc:02x}{addr:04x}{values}", **kw)


def resp(t, port, txid, fc, **kw):
    return dict(wall_time=t, monotonic=t, direction="resp", client_port=port,
                transaction_id=txid, protocol_id=0, length=5, unit_id=1,
                function_code=fc, raw_hex=f"r{txid:04x}", **kw)
