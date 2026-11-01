"""GRFICSv2 harder attacks: manifest labeling, the plant rules with sender
identity, and the attack frames."""
import json

import numpy as np
import pandas as pd

import grfics_harder_attack as gha
import grfics_harder_eval as ghe
from grfics_eval import ATTACKER_IP


def test_frames_match_the_plant_format():
    w = gha.fc16(0xd9ec, 1, [638])
    assert w.hex() == "d9ec00000009f7100001000102027e"      # captured PLC write
    assert gha.fc4(0xd9eb, 1, 2).hex() == "d9eb00000006f70400010002"


def test_txid_wraps_to_16_bits():
    assert gha.fc16(0x1_0005, 1, [1])[:2] == b"\x00\x05"


def _df(rows):
    cols = ["src_ip", "function_code", "address", "client_port", "transaction_id", "raw_hex"]
    return pd.DataFrame(rows, columns=cols)


def test_rule_ident_flags_only_unknown_writers():
    df = _df([("192.168.95.2", 16, 1, 1, 1, "a"),
              (ATTACKER_IP, 16, 1, 2, 7, "b"),
              (ATTACKER_IP, 4, 1, 2, 8, "c")])          # a read is not a write
    assert ghe.rule_plant(df, None).tolist() == [0, 0, 0]
    assert ghe.rule_plant(df, {"192.168.95.2"}).tolist() == [0, 1, 0]


def test_rule_plant_still_flags_unused_register_and_reused_txid():
    df = _df([("192.168.95.2", 16, 40, 1, 1, "a"),
              ("192.168.95.2", 16, 1, 1, 2, "b"),
              ("192.168.95.2", 16, 1, 1, 2, "b")])
    assert ghe.rule_plant(df, None).tolist() == [1, 0, 1]


def test_label_session_uses_manifest_bytes(tmp_path, monkeypatch):
    csv = tmp_path / "attack_01.csv"
    csv.write_text("x\n")
    (tmp_path / "attack_01.json").write_text(json.dumps({"packets": [
        {"kind": "attack", "raw_hex": "aa"}, {"kind": "replay", "raw_hex": "bb"},
        {"kind": "cover", "raw_hex": "cc"}, {"kind": "seed", "raw_hex": "dd"}]}))
    frame = pd.DataFrame({"src_ip": ["192.168.95.2", ATTACKER_IP, ATTACKER_IP, ATTACKER_IP,
                                     ATTACKER_IP, ATTACKER_IP],
                          "raw_hex": ["aa", "aa", "bb", "cc", "dd", "ee"]})
    monkeypatch.setattr(ghe, "load_requests", lambda _: frame.copy())
    df = ghe.label_session(csv)
    assert df["label"].tolist() == ["benign", "injection", "replay", "cover", "seed", "unmatched"]
    assert df["is_attack"].tolist() == [0, 1, 1, 0, 0, 0]
    assert df["scored"].tolist() == [True, True, True, False, False, False]
