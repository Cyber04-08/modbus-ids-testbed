import csv
import json

import pytest

import label_dataset
from conftest import req, resp


@pytest.fixture
def labeler(tmp_path, monkeypatch, write_capture):
    """Run the labeler on a tiny capture + manifest in a temp folder. Returns
    (labels, exit_code); the labeled file is written either way."""
    def _run(rows, manifest):
        cap = write_capture(rows, name="capture.csv")
        man = tmp_path / "attack_manifest.json"
        man.write_text(json.dumps(manifest))
        out = tmp_path / "labeled.csv"
        monkeypatch.setattr(label_dataset, "CAPTURE_CSV", cap)
        monkeypatch.setattr(label_dataset, "MANIFEST", man)
        monkeypatch.setattr(label_dataset, "LABELED_CSV", out)
        code = 0
        try:
            label_dataset.main()
        except SystemExit as e:
            if not isinstance(e.code, int):
                raise                     # aborted before writing (bad manifest)
            code = e.code
        with open(out, newline="") as f:
            return [(r["label"], r["is_attack"]) for r in csv.DictReader(f)], code
    return _run


def manifest(packets, start=0.0, end=10.0, roles=None):
    return {"source_port_roles": roles or {"5000": "benign", "6000": "replay"},
            "attack_windows": [{"type": "replay", "source_port": 6000,
                                "start": start, "end": end, "packets": packets}]}


def test_labels_by_exact_bytes(labeler):
    rows = [req(1.0, 5000, 1, 3, 0, raw="aa"), resp(1.01, 5000, 1, 3),
            req(2.0, 6000, 5, 6, 1, raw="bb"), req(3.0, 6000, 5, 6, 1, raw="bb")]
    pk = [{"kind": "seed", "raw_hex": "bb"}, {"kind": "attack", "raw_hex": "bb"}]
    labels, code = labeler(rows, manifest(pk))
    assert labels == [("benign", "0"), ("response", ""), ("replay_seed", ""), ("replay", "1")]
    assert code == 0


def test_attack_request_not_in_log_is_unmatched_and_fails(labeler, capsys):
    labels, code = labeler([req(2.0, 6000, 5, 6, 1, raw="cc")],
                           manifest([{"kind": "attack", "raw_hex": "bb"}]))
    assert labels == [("unmatched", "")]
    assert code == 1                      # a pipeline must not score this run
    assert "WARNING" in capsys.readouterr().out


def test_unknown_port_left_unscored_and_fails(labeler, capsys):
    labels, code = labeler([req(1.0, 7777, 1, 3, 0)], manifest([]))
    assert labels == [("unknown", "")]
    assert code == 1
    assert "unrecognized source ports" in capsys.readouterr().out


def test_frame_outside_window_fails(labeler, capsys):
    _, code = labeler([req(50.0, 6000, 5, 6, 1, raw="bb")],
                      manifest([{"kind": "attack", "raw_hex": "bb"}], end=10.0))
    assert code == 1
    assert "outside their recorded time window" in capsys.readouterr().out


def test_one_lost_packet_does_not_unmatch_the_rest(labeler):
    """Regression: matching only the head of the queue meant one logged
    packet missing from the capture made every later attack 'unmatched'."""
    pk = [{"kind": "attack", "raw_hex": h} for h in ("b1", "b2", "b3")]
    rows = [req(1.0, 6000, 5, 6, 1, raw="b1"), req(2.0, 6000, 6, 6, 1, raw="b3")]   # b2 lost
    labels, code = labeler(rows, manifest(pk))
    assert labels == [("replay", "1"), ("replay", "1")]
    assert code == 1                      # the lost packet is still reported


def test_unknown_role_is_rejected(labeler):
    with pytest.raises(SystemExit, match="unknown role"):
        labeler([req(1.0, 5000, 1, 3, 0)], manifest([], roles={"5000": "Benign"}))
