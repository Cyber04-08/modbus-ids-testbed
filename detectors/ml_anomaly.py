"""
Machine-learning anomaly detector (Isolation Forest).

An unsupervised detector trained on *normal traffic only* - it never sees an
attack during training. It learns what benign Modbus/TCP requests look like
(function code, register address/value, request size, per-connection timing)
and flags requests that don't fit that profile as anomalies. This is the
learned counterpart to the rule-based detector, and the head-to-head between
the two - on the same traffic, same metrics - is the project's core question.

How Isolation Forest finds unusual traffic (Liu et al., 2008):
  1. Build 200 random trees from the normal traffic. Each tree repeatedly
     picks a random feature (e.g. register value) and a random cut point
     between that feature's min and max, splitting the requests in two,
     until every request sits alone in its own leaf.
  2. A typical request looks like many others, so it takes many cuts to
     separate it from its neighbours: it ends up deep in the tree. An odd
     request (a write to an unusual address, an extreme value, odd timing)
     sits apart from the crowd and is cut off after only a few splits.
  3. A request's anomaly score comes from its average depth across all 200
     trees: short average path = easy to isolate = anomalous.

How its sensitivity is chosen: the score is continuous, so a cut-off turns it
into yes/no alerts. `contamination` sets that cut-off: scikit-learn places
the threshold so that exactly that share of the *training* requests would be
flagged. We do not leave it at a default or read it from the test data:
evaluate.contamination_from() sets it to the attack share measured in a
separate tuning session (0.177), so the test answers never influence it.
Higher contamination = more alerts (higher recall, more false alarms); lower
= fewer alerts.

Consequence worth knowing: the training data is all normal, so a 0.177
setting tells the model to treat the most unusual ~18% of *normal* traffic
as anomalous. That is why its false-positive rate (~0.18) tracks the
contamination value, and why lowering it trades recall for fewer false
alarms.

Second-half change - choosing the cut-off from labeled tuning traffic
instead (calibrate(), the "tuned" detector in evaluate.py): the forest is
still trained on normal traffic only, but the alert threshold is then placed
where it gives the best F1 on the separate tuning session, which contains
both normal requests and attacks. The threshold is a point on the score
scale, not a share of training traffic, so the false-alarm rate no longer
equals whatever percentage was asked for. The tuned detector also replaces
the placeholder 0 s inter-arrival of each connection's first request with
the median gap seen in training (fill_first_gap). The original
contamination detector is kept unchanged for comparison.

Chosen over one-class SVM as the primary model for speed and its native
handling of the benign/attack imbalance via `contamination`.

Features are standardized (StandardScaler) so no single wide-range column
(e.g. a 0-60000 register value) dominates the split geometry.

Usage (normally driven by detectors/evaluate.py):
    python detectors/ml_anomaly.py            # train on baseline, score labeled
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import (ML_FEATURE_COLUMNS, build_feature_matrix,  # noqa: E402
                      load_requests)

DEFAULT_CONTAMINATION = 0.1   # expected outlier fraction; tune to the data
RANDOM_STATE = 42


def best_f1_threshold(detector, tune_df) -> float:
    """The anomaly score, among those seen in the labeled tuning session,
    that gives the best F1 when used as the alert threshold (ties -> fewer
    false alarms). Shared by every ML detector with a score() method."""
    if "scored" in tune_df.columns:
        tune_df = tune_df[tune_df["scored"]]
    scores = detector.score(tune_df)
    y = tune_df["is_attack"].to_numpy()
    best = None
    for t in np.unique(scores):
        pred = scores >= t
        tp = int((pred & (y == 1)).sum())
        fp = int((pred & (y == 0)).sum())
        fn = int((~pred & (y == 1)).sum())
        f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
        key = (f1, -fp)
        if best is None or key > best[0]:
            best = (key, float(t))
    return best[1]


class MLAnomalyDetector:
    def __init__(self, contamination: float = DEFAULT_CONTAMINATION,
                 random_state: int = RANDOM_STATE, fill_first_gap: bool = False):
        self.contamination = contamination
        self.fill_first_gap = fill_first_gap
        self.gap_fill_ = 0.0       # learned in fit() when fill_first_gap is on
        self.threshold_ = None     # set by calibrate(); None = use contamination
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
        )

    def _features(self, df) -> np.ndarray:
        X = build_feature_matrix(df)
        if self.fill_first_gap and "first_on_connection" in df.columns:
            col = ML_FEATURE_COLUMNS.index("inter_arrival")
            X[df["first_on_connection"].to_numpy(), col] = self.gap_fill_
        return X

    def fit(self, benign_df) -> "MLAnomalyDetector":
        """Fit on benign-only traffic. Any attack rows present are ignored, so
        this stays true to 'trained on normal traffic only' even if a labeled
        file is passed in."""
        if "is_attack" in benign_df.columns:
            benign_df = benign_df[benign_df["is_attack"] == 0]
        if self.fill_first_gap:
            real_gaps = benign_df.loc[~benign_df["first_on_connection"], "inter_arrival"]
            self.gap_fill_ = float(real_gaps.median())
        X = self.scaler.fit_transform(self._features(benign_df))
        self.model.fit(X)
        return self

    def score(self, df) -> np.ndarray:
        """Anomaly score per request: higher = easier to isolate = more unusual."""
        return -self.model.score_samples(self.scaler.transform(self._features(df)))

    def calibrate(self, tune_df) -> "MLAnomalyDetector":
        """Place the alert threshold at the score that gives the best F1 on the
        labeled TUNING session. Only that session's labels are used; test
        labels never are."""
        self.threshold_ = best_f1_threshold(self, tune_df)
        return self

    def predict(self, df) -> np.ndarray:
        """Return 1 for anomaly (attack), 0 for normal."""
        if self.threshold_ is not None:
            return (self.score(df) >= self.threshold_).astype(int)
        X = self.scaler.transform(self._features(df))
        # IsolationForest: -1 = outlier, 1 = inlier -> map to 1/0.
        return (self.model.predict(X) == -1).astype(int)


def main() -> None:
    train_csv = sys.argv[1] if len(sys.argv) > 1 else "data/baseline_capture.csv"
    test_csv = sys.argv[2] if len(sys.argv) > 2 else "data/labeled.csv"

    train_df = load_requests(train_csv)
    test_df = load_requests(test_csv)

    det = MLAnomalyDetector().fit(train_df)
    preds = det.predict(test_df)
    print(f"ML anomaly detector trained on {len(train_df)} benign requests "
          f"({train_csv})")
    print(f"  scored {len(test_df)} requests from {test_csv}; "
          f"anomalies flagged: {int(preds.sum())}")
    if "is_attack" in test_df.columns:
        # Grade scored requests only (responses / replay seed are not graded).
        keep = test_df["scored"].to_numpy() if "scored" in test_df.columns else slice(None)
        y, preds = test_df["is_attack"].to_numpy()[keep], preds[keep]
        tp = int(((preds == 1) & (y == 1)).sum())
        fp = int(((preds == 1) & (y == 0)).sum())
        fn = int(((preds == 0) & (y == 1)).sum())
        tn = int(((preds == 0) & (y == 0)).sum())
        print(f"  vs ground truth: TP={tp} FP={fp} FN={fn} TN={tn}")


if __name__ == "__main__":
    main()
