from types import SimpleNamespace as Row

import pytest

from rule_based import RuleBasedDetector


def row(fc, addr=1, value0=50, count=1, port=5000, txid=1, raw=None):
    return Row(function_code=fc, address=addr, value0=value0, count=count,
               client_port=port, transaction_id=txid,
               raw_hex=raw or f"{txid}-{fc}-{addr}-{value0}")


@pytest.mark.parametrize("r, rule", [
    (row(8), "function_code_not_allowed"),
    (row(6, addr=0), "write_to_readonly_address"),               # tank level
    (row(16, addr=0, count=2, value0=10), "write_to_readonly_address"),
    (row(6, value0=60000), "value_out_of_range"),
    (row(5, addr=7, value0=0xFF00), "write_to_readonly_address"),
    (row(5, addr=0, value0=1), "value_out_of_range"),            # not ON/OFF
], ids=["fc8", "write-HR0", "fc16-over-HR0", "setpoint-60000",
        "coil-7", "coil-bad-encoding"])
def test_each_rule_fires(r, rule):
    assert RuleBasedDetector().score_request(r) == (1, rule)


@pytest.mark.parametrize("r", [
    row(3, addr=0, value0=0),
    row(6, value0=0), row(6, value0=100),                        # range edges
    row(5, addr=1, value0=0xFF00), row(5, addr=0, value0=0),
], ids=["read", "setpoint-0", "setpoint-100", "coil-on", "coil-off"])
def test_normal_requests_pass(r):
    assert RuleBasedDetector().score_request(r) == (0, "")


def test_replay_reused_txid_same_connection():
    d = RuleBasedDetector()
    assert d.score_request(row(6, txid=9, raw="AA"))[0] == 0
    assert d.score_request(row(6, txid=9, raw="AA")) == (1, "replay_reused_txid")


def test_steady_setpoint_with_fresh_txids_not_flagged():
    d = RuleBasedDetector()
    for txid in range(1, 6):
        assert d.score_request(row(6, value0=50, txid=txid))[0] == 0


def test_same_bytes_on_other_connection_not_flagged():
    d = RuleBasedDetector()
    d.score_request(row(6, txid=9, raw="AA", port=5000))
    assert d.score_request(row(6, txid=9, raw="AA", port=6000))[0] == 0


def test_malformed_request_alerts():
    r = row(5, addr=0, value0=0)                 # would pass as coil-OFF
    r.malformed = True
    assert RuleBasedDetector().score_request(r) == (1, "malformed_request")


def test_replay_memory_is_per_host_connection():
    """Same port and txid from two different hosts is not a replay."""
    d = RuleBasedDetector()
    a = row(6, txid=9, raw="AA")
    a.conn = "10.0.0.1:5000"
    b = row(6, txid=9, raw="AA")
    b.conn = "10.0.0.2:5000"
    d.score_request(a)
    assert d.score_request(b)[0] == 0


def test_reset_clears_replay_memory():
    d = RuleBasedDetector()
    d.score_request(row(6, txid=9, raw="AA"))
    d.reset()
    assert d.score_request(row(6, txid=9, raw="AA"))[0] == 0
