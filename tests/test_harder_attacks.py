"""Harder attacks (limitations 1 and 2): attack plans, value-change features,
and the sender-identity rule."""
import numpy as np
import pytest

import mimic_injection
import txid_replay
from features import (OCSVM_CONTEXT_FEATURE_COLUMNS, load_requests)
from modbus_frames import parse_transaction_id
from rule_based import RuleBasedDetector


# --- attack plans -----------------------------------------------------------

def test_txid_replay_default_is_one_repeated_command():
    p = txid_replay.plan()
    assert (p["target"], p["value"], p["count"]) == ("setpoint", 55, 8)


@pytest.mark.parametrize("seed", range(40))
def test_txid_replay_rewrites_txids_but_repeats_the_command(seed):
    p = txid_replay.plan(seed)
    assert p == txid_replay.plan(seed)
    frames = [txid_replay.frame_with_txid(p, p["start_txid"] + 1 + i) for i in range(p["count"])]
    # Every resend carries a distinct, incrementing transaction ID ...
    txids = [parse_transaction_id(f) for f in frames]
    assert txids == sorted(txids) and len(set(txids)) == len(txids)
    assert all(t <= 0xFFFF for t in txids)
    # ... but the command bytes after the MBAP header are identical.
    assert len({f[6:] for f in frames}) == 1


@pytest.mark.parametrize("seed", range(40))
def test_mimic_injection_uses_in_band_values(seed):
    p = mimic_injection.plan(seed)
    assert p == mimic_injection.plan(seed)
    assert 2 <= len(p["writes"]) <= 5 and 8 <= p["polls"] <= 16
    for w in p["writes"]:
        if w["fc"] == 6:
            assert 20 <= w["value"] <= 90        # operator's normal band
        else:
            assert w["fc"] == 5 and w["value"] in (0, 1)


# --- value-change features --------------------------------------------------

def test_repeat_run_grows_on_identical_writes(write_capture):
    rows = [dict(wall_time=1.0 + i, monotonic=1.0 + i, direction="req", client_port=5000,
                 transaction_id=i, protocol_id=0, length=6, unit_id=1, function_code=6,
                 address=1, count=1, values="55", raw_hex=f"{i:04x}") for i in range(3)]
    df = load_requests(str(write_capture(rows)))
    assert df["repeat_run"].tolist() == [1, 2, 3]      # same value three times
    assert df["write_step"].fillna(-1).tolist() == [-1, 0.0, 0.0]


def test_repeat_run_resets_when_value_changes(write_capture):
    vals = [55, 55, 60, 60, 60]
    rows = [dict(wall_time=1.0 + i, monotonic=1.0 + i, direction="req", client_port=5000,
                 transaction_id=i, protocol_id=0, length=6, unit_id=1, function_code=6,
                 address=1, count=1, values=str(v), raw_hex=f"{i:04x}") for i, v in enumerate(vals)]
    df = load_requests(str(write_capture(rows)))
    assert df["repeat_run"].tolist() == [1, 2, 1, 2, 3]
    assert df["write_step"].fillna(-1).tolist() == [-1, 0.0, 5.0, 0.0, 0.0]


def test_reads_have_no_value_change(write_capture):
    rows = [dict(wall_time=1.0, monotonic=1.0, direction="req", client_port=5000,
                 transaction_id=1, protocol_id=0, length=6, unit_id=1, function_code=3,
                 address=0, count=1, values="", raw_hex="aa")]
    df = load_requests(str(write_capture(rows)))
    assert df["repeat_run"].tolist() == [0] and df["write_step"].tolist() == [0.0]


def test_context_columns_present_and_numeric(write_capture):
    from features import build_feature_matrix
    rows = [dict(wall_time=1.0, monotonic=1.0, direction="req", client_port=5000,
                 transaction_id=1, protocol_id=0, length=6, unit_id=1, function_code=6,
                 address=1, count=1, values="40", raw_hex="bb")]
    df = load_requests(str(write_capture(rows)))
    X = build_feature_matrix(df, OCSVM_CONTEXT_FEATURE_COLUMNS)
    assert X.shape == (1, len(OCSVM_CONTEXT_FEATURE_COLUMNS))


# --- sender-identity rule ---------------------------------------------------

def _rows_from(ip):
    r = dict(wall_time=1.0, monotonic=1.0, direction="req", client_port=5000,
             transaction_id=1, protocol_id=0, length=6, unit_id=1, function_code=6,
             address=1, count=1, values="40", raw_hex="cc", src_ip=ip)
    return r


def test_unknown_source_flags_foreign_host(write_capture):
    df = load_requests(str(write_capture([_rows_from("127.0.0.66")], extra_cols=["src_ip"])))
    det = RuleBasedDetector(known_sources={"127.0.0.1"})
    pred, rule = det.score_request(next(df.itertuples(index=False)))
    assert pred == 1 and rule == "unknown_source"


def test_known_source_not_flagged_by_identity(write_capture):
    df = load_requests(str(write_capture([_rows_from("127.0.0.1")], extra_cols=["src_ip"])))
    det = RuleBasedDetector(known_sources={"127.0.0.1"})
    assert det.score_request(next(df.itertuples(index=False)))[0] == 0


def test_identity_rule_off_by_default(write_capture):
    df = load_requests(str(write_capture([_rows_from("127.0.0.66")], extra_cols=["src_ip"])))
    det = RuleBasedDetector()           # no known_sources -> rule disabled
    assert det.score_request(next(df.itertuples(index=False)))[0] == 0
