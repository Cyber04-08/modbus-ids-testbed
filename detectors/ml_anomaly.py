"""
Machine-learning anomaly detector (Isolation Forest).

An unsupervised detector trained on *normal traffic only* - it never sees an
attack during training. It learns what benign Modbus/TCP requests look like
(function code, register address/value, request size, per-connection timing)
and flags requests that don't fit that profile as anomalies. This is the
learned counterpart to the rule-based detector, and the head-to-head between
the two - on the same traffic, same metrics - is the project's core question.

Isolation Forest (Liu et al.) isolates points with random splits; anomalies
need fewer splits to isolate, so they score as outliers. Chosen over one-class
SVM as the primary model for speed and its native handling of the benign/attack
imbalance via the `contamination` parameter, which we set to the expected
attack fraction rather than leaving at the default (per the proposal).

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
from features import build_feature_matrix, load_requests  # noqa: E402

DEFAULT_CONTAMINATION = 0.1   # expected outlier fraction; tune to the data
RANDOM_STATE = 42


class MLAnomalyDetector:
    def __init__(self, contamination: float = DEFAULT_CONTAMINATION):
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=RANDOM_STATE,
        )

    def fit(self, benign_df) -> "MLAnomalyDetector":
        """Fit on benign-only traffic. Any attack rows present are ignored, so
        this stays true to 'trained on normal traffic only' even if a labeled
        file is passed in."""
        if "is_attack" in benign_df.columns:
            benign_df = benign_df[benign_df["is_attack"] == 0]
        X = self.scaler.fit_transform(build_feature_matrix(benign_df))
        self.model.fit(X)
        return self

    def predict(self, df) -> np.ndarray:
        """Return 1 for anomaly (attack), 0 for normal."""
        X = self.scaler.transform(build_feature_matrix(df))
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
        y = test_df["is_attack"].to_numpy()
        tp = int(((preds == 1) & (y == 1)).sum())
        fp = int(((preds == 1) & (y == 0)).sum())
        fn = int(((preds == 0) & (y == 1)).sum())
        tn = int(((preds == 0) & (y == 0)).sum())
        print(f"  vs ground truth: TP={tp} FP={fp} FN={fn} TN={tn}")


if __name__ == "__main__":
    main()
