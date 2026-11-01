"""Authenticated Modbus envelope: tag, anti-replay counter, and the
auth_eval attacker models."""
import pandas as pd
import pytest

import auth_eval
import secure_modbus as sm

KEY = b"k" * 32
FRAME = bytes.fromhex("000100000006010600010050")


def test_valid_envelope_roundtrips():
    v = sm.Verifier(KEY)
    verdict, frame = v.verify(sm.Signer(KEY).seal(FRAME))
    assert (verdict, frame) == (sm.OK, FRAME)


def test_wrong_key_is_rejected():
    verdict, frame = sm.Verifier(KEY).verify(sm.Signer(b"x" * 32).seal(FRAME))
    assert (verdict, frame) == (sm.BAD_TAG, None)


@pytest.mark.parametrize("pos", [0, 8, 12, -1])
def test_any_flipped_byte_is_rejected(pos):
    env = bytearray(sm.Signer(KEY).seal(FRAME))
    env[pos] ^= 0x01
    assert sm.Verifier(KEY).verify(bytes(env))[0] == sm.BAD_TAG


def test_verbatim_resend_is_stale():
    signer, v = sm.Signer(KEY), sm.Verifier(KEY)
    env = signer.seal(FRAME)
    assert v.verify(env)[0] == sm.OK
    assert v.verify(env)[0] == sm.STALE_COUNTER


def test_older_counter_rejected_after_newer_accepted():
    signer, v = sm.Signer(KEY), sm.Verifier(KEY)
    first, second = signer.seal(FRAME), signer.seal(FRAME)
    assert v.verify(second)[0] == sm.OK
    assert v.verify(first)[0] == sm.STALE_COUNTER


def test_bad_envelopes_do_not_move_the_counter():
    v = sm.Verifier(KEY)
    forged = sm.seal(b"x" * 32, 1000, FRAME)
    assert v.verify(forged)[0] == sm.BAD_TAG
    assert v.high_water == 0
    assert v.verify(sm.seal(KEY, 1, FRAME))[0] == sm.OK


def test_short_input_is_malformed():
    assert sm.Verifier(KEY).verify(b"\x00" * 10)[0] == sm.MALFORMED


def test_rewritten_txid_with_sniffed_tag_is_rejected():
    env = sm.Signer(KEY).seal(FRAME)
    changed = bytearray(FRAME)
    changed[1] = 0x09                                  # new transaction ID
    forged = env[:sm.COUNTER_BYTES] + bytes(changed) + env[-sm.TAG_BYTES:]
    assert sm.Verifier(KEY).verify(forged)[0] == sm.BAD_TAG


def _session():
    rows = []
    for i in range(6):
        label = "injection" if i in (2, 4) else "benign"
        rows.append(dict(wall_time=1.0 + i, direction="req", label=label,
                         raw_hex=f"{i + 1:04x}00000006010600010050"))
    rows.append(dict(wall_time=9.0, direction="resp", label="response", raw_hex="aa" * 12))
    return pd.DataFrame(rows)


@pytest.mark.parametrize("cap", ["no-key", "resend", "rewrite"])
def test_keyless_attackers_blocked_and_operator_unaffected(cap):
    c = auth_eval.run_session(_session(), cap)
    assert c["injection"] == 2 and c["injection_blocked"] == 2
    assert c["benign"] == 4 and c["benign_blocked"] == 0


def test_key_holder_is_not_blocked_and_does_not_lock_out_operator():
    c = auth_eval.run_session(_session(), "key-theft")
    assert c["injection_blocked"] == 0 and c["benign_blocked"] == 0
