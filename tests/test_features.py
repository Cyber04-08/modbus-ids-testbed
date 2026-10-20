import pytest

from conftest import req, resp
from features import (ML_FEATURE_COLUMNS, OCSVM_FEATURE_COLUMNS,
                      build_feature_matrix, load_requests)


def test_values_parsed_as_text_when_capture_has_no_fc16(write_capture):
    """Regression for the 2026-10-15 bug: a normal-only capture with only
    single-value writes made pandas read `values` as numbers, and every
    training write value became 0."""
    path = write_capture([
        req(1.0, 5000, 1, 6, 1, values="42"),
        req(1.5, 5000, 2, 6, 1, values="77"),
        req(2.0, 5000, 3, 3, 0, count=1),            # read: no value
    ])
    df = load_requests(str(path))
    assert df["value0"].tolist() == [42.0, 77.0, 0.0]


def test_fc16_uses_first_value(write_capture):
    path = write_capture([req(1.0, 5000, 1, 16, 0, count=2, values="10 60000")])
    assert load_requests(str(path))["value0"].iloc[0] == 10.0


def test_responses_are_dropped(write_capture):
    path = write_capture([req(1.0, 5000, 1, 3, 0, count=1), resp(1.01, 5000, 1, 3)])
    assert load_requests(str(path))["direction"].tolist() == ["req"]


def test_rows_sorted_by_time(write_capture):
    path = write_capture([req(2.0, 5000, 2, 3, 0), req(1.0, 5000, 1, 3, 0)])
    assert load_requests(str(path))["transaction_id"].tolist() == [1, 2]


def test_inter_arrival_and_txid_delta_are_per_connection(write_capture):
    path = write_capture([
        req(1.0, 5000, 1, 3, 0),
        req(1.2, 6000, 9, 6, 1, values="50"),       # different connection
        req(1.5, 5000, 2, 3, 0),
        req(1.6, 6000, 9, 6, 1, values="50"),       # replay: same txid
    ])
    df = load_requests(str(path)).set_index(["client_port", "wall_time"])
    assert df.loc[(5000, 1.5), "inter_arrival"] == pytest.approx(0.5)
    assert df.loc[(6000, 1.6), "inter_arrival"] == pytest.approx(0.4)
    assert df.loc[(5000, 1.5), "txid_delta"] == 1
    assert df.loc[(6000, 1.6), "txid_delta"] == 0      # replay signature
    assert df.loc[(5000, 1.0), "first_on_connection"]
    assert not df.loc[(5000, 1.5), "first_on_connection"]


def test_blank_is_attack_is_kept_but_not_scored(write_capture):
    path = write_capture([
        req(1.0, 5000, 1, 3, 0, is_attack=0),
        req(1.1, 6000, 5, 6, 1, values="50", is_attack=""),   # replay seed
        req(1.2, 6000, 5, 6, 1, values="50", is_attack=1),
    ], extra_cols=["is_attack"])
    df = load_requests(str(path))
    assert df["scored"].tolist() == [True, False, True]
    assert df["is_attack"].tolist() == [0, 0, 1]


def test_tied_timestamps_keep_file_order(write_capture):
    """Regression: the default (unstable) sort could reorder requests that
    share a timestamp, scrambling txid_delta and the replay rule's history."""
    rows = [req(1.0, 5000, txid, 3, 0) for txid in range(1, 40)]   # all tied
    df = load_requests(str(write_capture(rows)))
    assert df["transaction_id"].tolist() == list(range(1, 40))
    assert (df["txid_delta"] == 1).all()


def test_truncated_write_is_marked_malformed_not_coil_off(write_capture):
    """Regression: a write too short to decode used to read as 'write coil 0,
    value 0', indistinguishable from a normal coil-OFF."""
    path = write_capture([req(1.0, 5000, 1, 5, "", count="", values="", raw="0001")])
    df = load_requests(str(path))
    assert df["malformed"].tolist() == [True]


def test_unparseable_value_is_marked_malformed(write_capture):
    path = write_capture([req(1.0, 5000, 1, 6, 1, count=1, values="x7")])
    df = load_requests(str(path))
    assert df["malformed"].tolist() == [True]
    assert df["value0"].tolist() == [0.0]


def test_normal_requests_are_not_malformed(write_capture):
    path = write_capture([req(1.0, 5000, 1, 3, 0, count=1),
                          req(1.1, 5000, 2, 6, 1, count=1, values="50"),
                          req(1.2, 5000, 3, 16, 1, count=1, values="50")])
    assert not load_requests(str(path))["malformed"].any()


def test_is_attack_typo_is_an_error(write_capture):
    path = write_capture([req(1.0, 5000, 1, 3, 0, is_attack="attack")],
                         extra_cols=["is_attack"])
    with pytest.raises(ValueError, match="is_attack"):
        load_requests(str(path))


def test_connection_is_ip_and_port_when_capture_has_ips(write_capture):
    """Two hosts using the same source port are two connections."""
    path = write_capture([
        req(1.0, 5000, 1, 3, 0, src_ip="10.0.0.1"),
        req(1.1, 5000, 9, 3, 0, src_ip="10.0.0.2"),
        req(1.5, 5000, 2, 3, 0, src_ip="10.0.0.1"),
    ], extra_cols=["src_ip"])
    df = load_requests(str(path))
    assert df["first_on_connection"].tolist() == [True, True, False]
    assert df["txid_delta"].tolist() == [1, 1, 1]


def test_feature_matrix_columns(write_capture):
    path = write_capture([req(1.0, 5000, 1, 6, 1, values="42")])
    df = load_requests(str(path))
    assert build_feature_matrix(df).shape == (1, len(ML_FEATURE_COLUMNS))
    assert build_feature_matrix(df, OCSVM_FEATURE_COLUMNS).shape == (1, 6)
