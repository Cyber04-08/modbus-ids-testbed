"""Metrics, session separation, the ML detectors' input checks, and the
multi-run statistics."""
import math

import numpy as np
import pytest

from conftest import req
from evaluate import check_separate_sessions, quality_metrics, ratio
from features import load_requests
from ml_anomaly import best_f1_threshold, median_real_gap, normal_training_rows
from multi_run import wilson
from ocsvm import OneClassSVMDetector


def test_undefined_metrics_are_nan_not_zero():
    """Regression: a detector that never alerts reported precision 0.000,
    the same as one that is always wrong."""
    q = quality_metrics(np.array([1, 0, 0]), np.array([0, 0, 0]))
    assert math.isnan(q["precision"])
    assert q["recall"] == 0.0 and q["f1"] == 0.0 and q["fpr"] == 0.0


def test_metrics_match_hand_count():
    q = quality_metrics(np.array([1, 1, 0, 0]), np.array([1, 0, 1, 0]))
    assert (q["TP"], q["FP"], q["FN"], q["TN"]) == (1, 1, 1, 1)
    assert q["precision"] == q["recall"] == q["f1"] == q["fpr"] == 0.5


def test_ratio():
    assert ratio(1, 4) == 0.25
    assert math.isnan(ratio(0, 0))


def test_same_session_as_tune_and_test_is_refused(write_capture):
    """Regression: capture_tuning.py copies labeled.csv to the tuning file,
    so the evaluate.py defaults scored the tuning session against itself."""
    df = load_requests(str(write_capture([req(1.0, 5000, 1, 3, 0)])))
    with pytest.raises(SystemExit, match="share"):
        check_separate_sessions(train=df.iloc[0:0], tune=df, test=df.copy())


def test_separate_sessions_pass(write_capture):
    a = load_requests(str(write_capture([req(1.0, 5000, 1, 3, 0)], name="a.csv")))
    b = load_requests(str(write_capture([req(2.0, 5000, 1, 3, 0)], name="b.csv")))
    check_separate_sessions(tune=a, test=b)


def test_training_rows_exclude_unscored(write_capture):
    """The replay seed has a blank is_attack (read as 0) but is not benign."""
    path = write_capture([req(1.0, 5000, 1, 3, 0, is_attack=0),
                          req(1.1, 6000, 5, 6, 1, values="50", is_attack=""),
                          req(1.2, 6000, 5, 6, 1, values="50", is_attack=1)],
                         extra_cols=["is_attack"])
    rows = normal_training_rows(load_requests(str(path)))
    assert rows["transaction_id"].tolist() == [1]


def test_no_real_gap_is_a_clear_error(write_capture):
    df = load_requests(str(write_capture([req(1.0, 5000, 1, 3, 0), req(1.0, 5001, 1, 3, 0)])))
    with pytest.raises(ValueError, match="inter-arrival"):
        median_real_gap(df)


def test_tuning_without_attacks_is_refused(write_capture):
    rows = [req(1.0 + i, 5000, i + 1, 6, 1, values=str(40 + i), is_attack=0) for i in range(8)]
    df = load_requests(str(write_capture(rows, extra_cols=["is_attack"])))
    det = OneClassSVMDetector().fit(df)
    with pytest.raises(ValueError, match="both attacks and benign"):
        best_f1_threshold(det, df)


def test_wilson_interval():
    lo, hi = wilson(0, 600)                    # 0 false alarms in 600 benign requests
    assert lo == 0.0 and 0.005 < hi < 0.007
    lo, hi = wilson(130, 140)                  # 13/14 recall pooled over 10 runs
    assert lo < 130 / 140 < hi
    assert all(math.isnan(v) for v in wilson(0, 0))
