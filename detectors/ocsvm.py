"""
Machine-learning anomaly detector #2: one-class SVM.

Like the Isolation Forest, it is trained on *normal traffic only* and flags
requests that don't fit. It differs in how it decides what "doesn't fit":

How a one-class SVM finds unusual traffic (Schoelkopf et al., 2001):
  1. Each request is a point in feature space (function code, address, value,
     size, timing, change in transaction ID), standardized so every feature
     has a comparable scale.
  2. The RBF kernel measures how close two requests are: near-identical
     requests have similarity ~1, very different ones ~0.
  3. Training draws a boundary around the region where normal requests live,
     described by a few of them (the "support vectors").
  4. A request's anomaly score is how far it falls outside that region: low
     similarity to every support vector = unusual.

Why it is tested next to the Isolation Forest: a forest only ever cuts a
feature between the smallest and largest value it saw in training. The change
in transaction ID is always +1 in normal traffic, so the forest has nothing
to cut and ignores it, and a replay (change 0) looks normal. The SVM compares
distances instead: a request whose ID change is 0 sits away from every normal
request, so it scores as unusual. That is the replay signature the rule-based
detector also uses, learned here from normal traffic rather than written as a
rule.

How its sensitivity is chosen: `nu` bounds the share of training requests
treated as outside the boundary (like the forest's contamination). As with the
tuned forest, the alert threshold is then set at the best F1 on the separate
labeled tuning session (calibrate()), so `nu` barely matters (0.01, 0.05 and
0.177 gave the same tuned result); 0.05 is used. Each connection's first
inter-arrival (a placeholder 0) is replaced by the median training gap, as in
the tuned forest.

Usage (normally driven by detectors/evaluate.py):
    python detectors/ocsvm.py [train_csv] [test_csv] [tune_csv]
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import (OCSVM_FEATURE_COLUMNS, build_feature_matrix,  # noqa: E402
                      load_requests)
from ml_anomaly import best_f1_threshold                              # noqa: E402

DEFAULT_NU = 0.05


class OneClassSVMDetector:
    def __init__(self, nu: float = DEFAULT_NU):
        self.nu = nu
        self.gap_fill_ = 0.0
        self.threshold_ = None     # set by calibrate(); None = use nu boundary
        self.scaler = StandardScaler()
        self.model = OneClassSVM(kernel="rbf", gamma="scale", nu=nu)

    def _features(self, df) -> np.ndarray:
        X = build_feature_matrix(df, OCSVM_FEATURE_COLUMNS)
        col = OCSVM_FEATURE_COLUMNS.index("inter_arrival")
        X[df["first_on_connection"].to_numpy(), col] = self.gap_fill_
        return X

    def fit(self, benign_df) -> "OneClassSVMDetector":
        """Fit on benign-only traffic (attack rows, if any, are dropped)."""
        if "is_attack" in benign_df.columns:
            benign_df = benign_df[benign_df["is_attack"] == 0]
        real_gaps = benign_df.loc[~benign_df["first_on_connection"], "inter_arrival"]
        self.gap_fill_ = float(real_gaps.median())
        self.model.fit(self.scaler.fit_transform(self._features(benign_df)))
        return self

    def score(self, df) -> np.ndarray:
        """Anomaly score per request: higher = further outside normal."""
        return -self.model.score_samples(self.scaler.transform(self._features(df)))

    def calibrate(self, tune_df) -> "OneClassSVMDetector":
        """Alert threshold = best F1 on the labeled tuning session."""
        self.threshold_ = best_f1_threshold(self, tune_df)
        return self

    def predict(self, df) -> np.ndarray:
        """Return 1 for anomaly (attack), 0 for normal."""
        if self.threshold_ is not None:
            return (self.score(df) >= self.threshold_).astype(int)
        X = self.scaler.transform(self._features(df))
        return (self.model.predict(X) == -1).astype(int)


def main() -> None:
    train_csv = sys.argv[1] if len(sys.argv) > 1 else "data/baseline_capture.csv"
    test_csv = sys.argv[2] if len(sys.argv) > 2 else "data/labeled.csv"
    tune_csv = sys.argv[3] if len(sys.argv) > 3 else "data/tuning_labeled.csv"

    train_df = load_requests(train_csv)
    test_df = load_requests(test_csv)
    det = OneClassSVMDetector().fit(train_df).calibrate(load_requests(tune_csv))
    preds = det.predict(test_df)
    print(f"One-class SVM trained on {len(train_df)} benign requests ({train_csv}); "
          f"{len(det.model.support_)} support vectors")
    print(f"  scored {len(test_df)} requests from {test_csv}; "
          f"anomalies flagged: {int(preds.sum())}")
    if "is_attack" in test_df.columns:
        keep = test_df["scored"].to_numpy()
        y, preds = test_df["is_attack"].to_numpy()[keep], preds[keep]
        tp = int(((preds == 1) & (y == 1)).sum())
        fp = int(((preds == 1) & (y == 0)).sum())
        fn = int(((preds == 0) & (y == 1)).sum())
        tn = int(((preds == 0) & (y == 0)).sum())
        print(f"  vs ground truth: TP={tp} FP={fp} FN={fn} TN={tn}")


if __name__ == "__main__":
    main()
