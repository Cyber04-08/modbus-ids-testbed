"""Varied attack plans (limitation 3) and the label-free threshold."""
import numpy as np
import pandas as pd
import pytest

import command_injection
import replay_attack
import run_scenario
from ml_anomaly import normal_quantile_threshold
from modbus_frames import write_single_register


def test_replay_default_plan_is_the_original_frame():
    p = replay_attack.plan()
    assert replay_attack.captured_frame(p) == write_single_register(0x2A11, 1, 55)
    assert (p["count"], p["spacing"]) == (8, 0.4)


def test_injection_default_plan_is_the_original_sequence():
    p = command_injection.plan()
    frames = [command_injection.frame_for(c, p["txid"] + i) for i, c in enumerate(p["commands"])]
    assert frames[0] == write_single_register(0x7000, 1, 100)
    assert frames[4] == write_single_register(0x7004, 1, 60000)
    assert len(frames) == 6 and p["spacing"] == [0.5] * 6


@pytest.mark.parametrize("seed", range(50))
def test_varied_plans_are_seeded_and_in_range(seed):
    r = replay_attack.plan(seed)
    assert r == replay_attack.plan(seed)
    assert 3 <= r["count"] <= 12 and 0.3 <= r["spacing"] <= 1.5
    assert 0 <= r["txid"] <= 0xFFFF
    if r["target"] == "setpoint":
        assert 20 <= r["value"] <= 90 and r["value"] % 5 == 0
    else:
        assert r["address"] in (0, 1) and r["value"] in (0, 1)

    i = command_injection.plan(seed)
    assert i == command_injection.plan(seed)
    assert 3 <= len(i["commands"]) <= 8
    assert len(i["spacing"]) == len(i["commands"])
    assert i["txid"] + len(i["commands"]) - 1 <= 0xFFFF   # txids never wrap
    for c in i["commands"]:
        command_injection.frame_for(c, i["txid"])           # every command encodes
        if c["kind"] == "setpoint_in_band":
            assert 20 <= c["value"] <= 90
        if c["kind"] == "setpoint_out_of_range":
            assert c["value"] > 100


def test_varied_plans_differ_between_seeds():
    assert len({str(replay_attack.plan(s)) for s in range(20)}) == 20
    assert len({str(command_injection.plan(s)) for s in range(20)}) == 20


def test_session_plan_fixed_unless_varied():
    fixed = run_scenario.session_plan(quick=False, vary=False, seed=None)
    assert fixed["order"] == ["replay", "injection"] and fixed["seed"] is None
    assert (fixed["pre"], fixed["gap"], fixed["post"]) == (15, 10, 12)
    quick = run_scenario.session_plan(quick=True, vary=False, seed=None)
    assert (quick["pre"], quick["gap"], quick["post"]) == (7, 5, 6)
    v = run_scenario.session_plan(quick=False, vary=True, seed=3)
    assert v == run_scenario.session_plan(quick=False, vary=True, seed=3)
    assert sorted(v["order"]) == ["injection", "replay"]
    assert all(s is not None for s in v["attack_seeds"].values())


class _FixedScores:
    """Stand-in detector whose score is a column of the frame."""
    def score(self, df):
        return df["s"].to_numpy(dtype=float)


@pytest.mark.parametrize("target", [0.0, 0.005, 0.01, 0.1, 0.25])
def test_label_free_threshold_never_exceeds_target(target):
    rng = np.random.default_rng(0)
    df = pd.DataFrame({"s": rng.normal(size=1000)})
    t = normal_quantile_threshold(_FixedScores(), df, target)
    realized = float((df["s"] >= t).mean())
    assert realized <= target
    assert realized == pytest.approx(target, abs=1 / len(df))


def test_label_free_threshold_with_ties_stays_under_target():
    df = pd.DataFrame({"s": [0.0] * 990 + [5.0] * 10})
    t = normal_quantile_threshold(_FixedScores(), df, 0.005)  # 5 allowed, 10 tied
    assert float((df["s"] >= t).mean()) == 0.0


def test_label_free_threshold_ignores_labeled_attacks():
    df = pd.DataFrame({"s": [0.0] * 99 + [100.0], "is_attack": [0] * 99 + [1],
                       "scored": [True] * 100})
    t = normal_quantile_threshold(_FixedScores(), df, 0.0)
    assert t <= 1.0   # the attack's 100 did not set the threshold
