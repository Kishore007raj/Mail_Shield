import os
import logging
import joblib
from typing import Optional

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "models", "phishing_model.joblib")
VECTORIZER_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "models", "tfidf_vectorizer.joblib")

_model = None
_vectorizer = None


def load_model() -> bool:
    """Load the trained ML model and TF-IDF vectorizer from disk."""
    global _model, _vectorizer

    if not os.path.exists(MODEL_PATH):
        logger.warning(f"Model file not found at {MODEL_PATH}. ML predictions will be unavailable.")
        return False

    if not os.path.exists(VECTORIZER_PATH):
        logger.warning(f"Vectorizer file not found at {VECTORIZER_PATH}. ML predictions will be unavailable.")
        return False

    try:
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)
        logger.info("ML model and vectorizer loaded successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        _model = None
        _vectorizer = None
        return False


def predict(text: str) -> dict:
    """
    Predict whether the given text is phishing or legitimate.
    Returns prediction label, confidence score, and probabilities.
    """
    if _model is None or _vectorizer is None:
        logger.warning("ML model not loaded, returning default prediction")
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "probabilities": {"legitimate": 0.0, "phishing": 0.0},
            "available": False
        }

    try:
        text_vectorized = _vectorizer.transform([text])
        prediction = _model.predict(text_vectorized)[0]
        probabilities = _model.predict_proba(text_vectorized)[0]

        class_labels = _model.classes_.tolist()
        prob_dict = {}
        for label, prob in zip(class_labels, probabilities):
            prob_dict[label] = round(float(prob), 4)

        confidence = round(float(max(probabilities)), 4)

        result = {
            "prediction": str(prediction),
            "confidence": confidence,
            "probabilities": prob_dict,
            "available": True
        }

        logger.info(f"ML prediction: {prediction} (confidence: {confidence})")
        return result

    except Exception as e:
        logger.error(f"ML prediction failed: {e}")
        return {
            "prediction": "error",
            "confidence": 0.0,
            "probabilities": {},
            "available": False
        }


def is_model_loaded() -> bool:
    """Check if the ML model is currently loaded."""
    return _model is not None and _vectorizer is not None
