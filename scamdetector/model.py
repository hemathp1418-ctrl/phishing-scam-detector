"""Text model: TF-IDF features + Logistic Regression."""

import re
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from .rules import URL_RE

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "scam_model.joblib"


def preprocess(text: str) -> str:
    """Replace URLs and numbers with tokens so the model learns wording, not specific values."""
    text = URL_RE.sub(" urltoken ", text)
    text = re.sub(r"\d+", " 0 ", text)
    return re.sub(r"\s+", " ", text).strip().lower()


def build_pipeline() -> Pipeline:
    features = FeatureUnion([
        ("words", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2)),
        # character n-grams survive spelling tricks like "verlfy" or "k y c"
        ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=3)),
    ])
    clf = LogisticRegression(C=2.0, max_iter=1000, class_weight="balanced")
    return Pipeline([("features", features), ("clf", clf)])


def save_model(pipeline: Pipeline) -> None:
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)


def load_model() -> Pipeline:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "Model not found. Train it first:  python data/generate_data.py && python train.py")
    return joblib.load(MODEL_PATH)


def scam_probability(pipeline: Pipeline, text: str) -> float:
    return float(pipeline.predict_proba([preprocess(text)])[0][1])
