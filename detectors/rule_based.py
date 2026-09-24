"""
Rule-based Modbus/TCP intrusion detector.

A passive detector that checks each request against protocol- and
process-specific invariants derived from how this testbed's PLC is actually
used (see testbed/plc_simulator.py). It observes *unmodified* Modbus/TCP - no
frame changes, no gateway software - which is the key difference from Rajesh &
Satyanarayana (2021), whose rule-based scheme rewrites the wire format (see
docs/PREWORK_NOTES.md).

Invariants checked (each firing sets is_attack=1 and names the rule):

  1. function_code_not_allowed - FC outside the set this system ever uses.
  2. write_to_readonly_address - a write whose target register/coil isn't one
     the process ever writes. HR0 (tank level) is a *sensor*: the HMI only
     reads it, so any write to it is illegitimate. Catches the injection's
     FC16 block-write that includes HR0.
  3. value_out_of_range        - a pump-setpoint write outside 0-100%, or a
     coil write that isn't ON/OFF. Catches the injection's 60000 setpoint.
  4. replay_reused_txid        - on a single connection, a write that reuses a
     transaction ID already seen with an identical payload. A well-behaved
     master strictly increments its transaction ID, so a verbatim re-send with
     a stale ID is the replay signature. Gating on *reused txid* (not merely a
     repeated value) means a legitimate controller holding a setpoint steady -
     same value, fresh incrementing txids - is NOT flagged.

Note on source identity: the Wiley frame-filter also allowlists by source IP.
On this single-host loopback testbed every client is 127.0.0.1, so source-IP
allowlisting collapses and this detector relies on content/behaviour
invariants instead; the GRFICSv2 VM testbed provides true per-host IPs when
that rule is wanted. This is a documented limitation, not an oversight.

Usage:
    python detectors/rule_based.py [data/labeled.csv]   # score + print summary
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import load_requests  # noqa: E402

# --- Process/protocol spec (from testbed/plc_simulator.py) -------------------
FC_READ_COILS, FC_READ_DISCRETE, FC_READ_HOLDING, FC_READ_INPUT = 1, 2, 3, 4
FC_WRITE_COIL, FC_WRITE_REGISTER = 5, 6
FC_WRITE_MULTI_COILS, FC_WRITE_MULTI_REGISTERS = 15, 16

ALLOWED_FUNCTION_CODES = {
    FC_READ_COILS, FC_READ_HOLDING, FC_WRITE_COIL,
    FC_WRITE_REGISTER, FC_WRITE_MULTI_REGISTERS,
}
WRITE_FUNCTION_CODES = {FC_WRITE_COIL, FC_WRITE_REGISTER,
                        FC_WRITE_MULTI_COILS, FC_WRITE_MULTI_REGISTERS}

HR_LEVEL, HR_PUMP_SETPOINT = 0, 1          # holding registers
COIL_INLET, COIL_OUTLET = 0, 1             # coils

# Only these targets are ever written in normal operation. HR_LEVEL is a
# read-only sensor.
WRITABLE_HOLDING = {HR_PUMP_SETPOINT}
WRITABLE_COILS = {COIL_INLET, COIL_OUTLET}
SETPOINT_RANGE = (0, 100)                  # plausible pump setpoint, percent
COIL_VALUES = {0, 0xFF00}                   # Modbus OFF / ON encodings


class RuleBasedDetector:
    def __init__(self):
        # Per-connection memory for the replay rule.
        self._seen_txid_payload: dict[int, dict[int, str]] = {}

    def reset(self) -> None:
        self._seen_txid_payload.clear()

    def score_request(self, row) -> tuple[int, str]:
        """Return (is_attack, rule_fired) for one request row. Stateful: must
        be called in capture order (the replay rule tracks history)."""
        fc = int(row.function_code)
        addr = int(row.address)
        count = int(row.count) or 1
        value0 = float(row.value0)
        port = int(row.client_port)
        txid = int(row.transaction_id)
        raw = str(row.raw_hex)

        if fc not in ALLOWED_FUNCTION_CODES:
            return 1, "function_code_not_allowed"

        if fc in WRITE_FUNCTION_CODES:
            # Address-range / read-only checks.
            if fc in (FC_WRITE_REGISTER, FC_WRITE_MULTI_REGISTERS):
                targets = range(addr, addr + count)
                if any(t not in WRITABLE_HOLDING for t in targets):
                    return 1, "write_to_readonly_address"
                if fc == FC_WRITE_REGISTER and not (SETPOINT_RANGE[0] <= value0 <= SETPOINT_RANGE[1]):
                    return 1, "value_out_of_range"
                # For a block write to the (single) writable setpoint, the same
                # range applies.
                if fc == FC_WRITE_MULTI_REGISTERS and HR_PUMP_SETPOINT in targets:
                    if not (SETPOINT_RANGE[0] <= value0 <= SETPOINT_RANGE[1]):
                        return 1, "value_out_of_range"
            elif fc in (FC_WRITE_COIL, FC_WRITE_MULTI_COILS):
                if addr not in WRITABLE_COILS:
                    return 1, "write_to_readonly_address"
                if fc == FC_WRITE_COIL and int(value0) not in COIL_VALUES:
                    return 1, "value_out_of_range"

            # Replay rule: reused transaction ID with identical payload on the
            # same connection.
            seen = self._seen_txid_payload.setdefault(port, {})
            if txid in seen and seen[txid] == raw:
                return 1, "replay_reused_txid"
            seen[txid] = raw

        return 0, ""


def score_dataframe(df):
    """Score every request in a loaded DataFrame; return (predictions, rules)."""
    detector = RuleBasedDetector()
    preds, rules = [], []
    for row in df.itertuples(index=False):
        p, r = detector.score_request(row)
        preds.append(p)
        rules.append(r)
    return preds, rules


def main() -> None:
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "data/labeled.csv"
    df = load_requests(csv_path)
    preds, rules = score_dataframe(df)

    df = df.assign(pred=preds, rule=rules)
    n = len(df)
    alerts = int(sum(preds))
    print(f"Rule-based detector scored {n} requests from {csv_path}")
    print(f"  alerts raised: {alerts}")
    fired = {}
    for r in rules:
        if r:
            fired[r] = fired.get(r, 0) + 1
    for rule, c in sorted(fired.items(), key=lambda kv: -kv[1]):
        print(f"    {rule:28s}: {c}")
    if "is_attack" in df.columns:
        tp = int(((df.pred == 1) & (df.is_attack == 1)).sum())
        fp = int(((df.pred == 1) & (df.is_attack == 0)).sum())
        fn = int(((df.pred == 0) & (df.is_attack == 1)).sum())
        tn = int(((df.pred == 0) & (df.is_attack == 0)).sum())
        print(f"  vs ground truth: TP={tp} FP={fp} FN={fn} TN={tn}")


if __name__ == "__main__":
    main()
