from __future__ import annotations
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import HashingVectorizer

# NOTE: a real CodeBERT/UniXcoder embedding (transformers) is the intended
# production embedding for R2 and is a drop-in swap of `_embed` below --
# tonight this uses a hashing bag-of-tokens vectorizer instead, so the
# ranker is fully functional and testable offline with zero model download.
# Swapping `_embed` to call a transformers pipeline changes nothing about
# this class's public interface or any downstream consumer.
_VECTORIZER = HashingVectorizer(n_features=512, alternate_sign=False, token_pattern=r"(?u)\b\w+\b")


def _embed(code_series: pd.Series) -> np.ndarray:
    return _VECTORIZER.transform(code_series).toarray()


class R2Ranker:
    # Identifies this ranker's fit/score contract to a persisted calibration
    # (research/artifacts.py) -- bump if that contract ever changes
    # incompatibly, so a stale calibration.json is rejected instead of
    # silently paired with a model it wasn't calibrated against.
    RANKER_ID = "R2"

    def __init__(self, random_seed: int = 0):
        self._random_seed = random_seed
        self._model: LogisticRegression | None = None

    def fit(self, train_df: pd.DataFrame, labels: pd.Series) -> "R2Ranker":
        X = _embed(train_df["code"])
        y = labels.loc[train_df.index].to_numpy()
        self._model = LogisticRegression(max_iter=1000, random_state=self._random_seed)
        self._model.fit(X, y)
        return self

    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        if self._model is None:
            raise RuntimeError("R2Ranker.score called before fit()")
        X = _embed(df["code"])
        # predict_proba[:, 0] = P(class 0 = safe) -> higher = safer, matches convention
        safety_scores = self._model.predict_proba(X)[:, 0]
        return pd.DataFrame({
            "sample_id": df["sample_id"].values,
            "ranker_id": "R2",
            "score": safety_scores,
        })
