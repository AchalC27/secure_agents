"""
Arbiter - Calibration Utilities

Provides simple, dependency-light calibration for confidence scores.

Platt scaling is implemented as a logistic regression trained on
model scores vs binary labels.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

import numpy as np

try:
    from sklearn.linear_model import LogisticRegression

    SKLEARN_AVAILABLE = True
except Exception:  # pragma: no cover
    SKLEARN_AVAILABLE = False


@dataclass
class PlattCalibrator:
    """
    Platt scaling: map a real-valued score to a calibrated probability.

    If scikit-learn is unavailable, this falls back to an identity-ish
    mapping that clamps scores to [0, 1].
    """

    model: Optional["LogisticRegression"] = None
    fitted: bool = False

    def fit(self, scores: Iterable[float], labels: Iterable[int]) -> "PlattCalibrator":
        s = np.asarray(list(scores), dtype=np.float64).reshape(-1, 1)
        y = np.asarray(list(labels), dtype=np.int64)

        if s.size == 0:
            self.fitted = False
            return self

        # Need at least one positive and one negative
        if len(np.unique(y)) < 2:
            self.fitted = False
            return self

        if not SKLEARN_AVAILABLE:
            self.fitted = False
            return self

        lr = LogisticRegression(solver="lbfgs")
        lr.fit(s, y)
        self.model = lr
        self.fitted = True
        return self

    def predict_proba(self, score: float) -> float:
        """
        Returns probability in [0, 1] that label==1.
        """
        if self.fitted and self.model is not None:
            p = float(self.model.predict_proba(np.array([[float(score)]], dtype=np.float64))[0, 1])
            return float(max(0.0, min(p, 1.0)))

        # Fallback: clamp score into [0, 1] (assumes score already resembles similarity)
        return float(max(0.0, min(float(score), 1.0)))

