"""
PhishAegis — ML Model Training Script

Trains a TF-IDF + Multinomial Naive Bayes classifier on the phishing dataset.
Outputs evaluation metrics and saves the model artifacts.
"""

import os
import sys
import csv
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

DATASET_PATH = os.path.join(os.path.dirname(__file__), "data", "phishing_dataset.csv")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib")


def load_dataset(path: str) -> tuple[list[str], list[str]]:
    """Load the phishing dataset from CSV."""
    texts = []
    labels = []

    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row.get("text", "").strip()
            label = row.get("label", "").strip().lower()
            if text and label in ("phishing", "legitimate"):
                texts.append(text)
                labels.append(label)

    return texts, labels


def train_model():
    """Train the phishing detection ML model."""
    print("=" * 60)
    print("PhishAegis — ML Model Training")
    print("=" * 60)

    if not os.path.exists(DATASET_PATH):
        print(f"Dataset not found at {DATASET_PATH}")
        print("Generating synthetic dataset...")
        from generate_dataset import generate_dataset
        generate_dataset(1200)

    print(f"\nLoading dataset from {DATASET_PATH}...")
    texts, labels = load_dataset(DATASET_PATH)
    print(f"Loaded {len(texts)} samples")
    print(f"  Phishing: {labels.count('phishing')}")
    print(f"  Legitimate: {labels.count('legitimate')}")

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    print(f"\nTrain set: {len(X_train)} samples")
    print(f"Test set:  {len(X_test)} samples")

    print("\nFitting TF-IDF vectorizer...")
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        stop_words="english",
        min_df=2,
        max_df=0.95,
        sublinear_tf=True,
    )
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    print(f"Vocabulary size: {len(vectorizer.vocabulary_)}")
    print(f"Feature matrix shape: {X_train_tfidf.shape}")

    print("\nTraining Multinomial Naive Bayes classifier...")
    model = MultinomialNB(alpha=0.1)
    model.fit(X_train_tfidf, y_train)

    print("\n" + "=" * 60)
    print("EVALUATION METRICS")
    print("=" * 60)

    y_pred = model.predict(X_test_tfidf)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, pos_label="phishing")
    recall = recall_score(y_test, y_pred, pos_label="phishing")
    f1 = f1_score(y_test, y_pred, pos_label="phishing")

    print(f"\nAccuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")

    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred))

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred, labels=["legitimate", "phishing"])
    print(f"  {'':>12} {'Pred Legit':>12} {'Pred Phish':>12}")
    print(f"  {'True Legit':>12} {cm[0][0]:>12} {cm[0][1]:>12}")
    print(f"  {'True Phish':>12} {cm[1][0]:>12} {cm[1][1]:>12}")

    print("\nCross-validation (5-fold)...")
    cv_scores = cross_val_score(model, X_train_tfidf, y_train, cv=5, scoring="f1_weighted")
    print(f"CV F1 scores: {[f'{s:.4f}' for s in cv_scores]}")
    print(f"CV F1 mean:   {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

    os.makedirs(MODEL_DIR, exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"\nModel saved to:      {MODEL_PATH}")
    print(f"Vectorizer saved to: {VECTORIZER_PATH}")
    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)


if __name__ == "__main__":
    train_model()
