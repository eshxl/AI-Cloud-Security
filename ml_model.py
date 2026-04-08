"""
ml_model.py  — v4 (Gradient Boosting, F1 = 94.9%)
====================================================
Trains and evaluates four classifiers for contextual sensitive-text
detection. Uses 5-fold stratified cross-validation on 122 deduplicated texts.

Best model: Gradient Boosting (95.1% accuracy, 96.6% precision, 93.3% recall, 94.9% F1)

Dataset improvement over v3:
  v3: 69 unique samples → LR F1 = 89.9%
  v4: 122 unique samples → GB F1 = 94.9%
  Expanded categories: credentials, financial, identity, medical,
  security codes, organisational confidential, network/system secrets.

Usage:
    python ml_model.py      # train, evaluate, save model.pkl + metrics.json
"""

import json
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import (accuracy_score, precision_score,
                              recall_score, f1_score, confusion_matrix)


def train_model():
    df = (pd.read_csv("dataset/data.csv")
            .drop_duplicates(subset="text")
            .reset_index(drop=True))
    X, y = df["text"], df["label"]
    n_sens = (y == "sensitive").sum()
    n_safe = (y == "safe").sum()

    candidates = {
        "Logistic Regression": Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2), max_features=10000, sublinear_tf=True)),
            ("clf", LogisticRegression(
                C=0.5, max_iter=2000, random_state=42))
        ]),
        "Linear SVM": Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2), max_features=10000, sublinear_tf=True)),
            ("clf", LinearSVC(
                C=0.5, max_iter=3000, random_state=42))
        ]),
        "Random Forest": Pipeline([
            ("tfidf", TfidfVectorizer(
                max_features=8000, sublinear_tf=True)),
            ("clf", RandomForestClassifier(
                n_estimators=200, random_state=42))
        ]),
        "Gradient Boosting": Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2), max_features=10000, sublinear_tf=True)),
            ("clf", GradientBoostingClassifier(
                n_estimators=200, random_state=42))
        ]),
    }

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    all_results = {}
    best_f1, best_name, best_model = -1.0, "", None

    print("\n" + "=" * 57)
    print("  5-Fold Cross-Validated Model Evaluation")
    print(f"  {len(df)} unique samples  —  "
          f"Sensitive: {n_sens}  |  Safe: {n_safe}")
    print("=" * 57)

    for name, model in candidates.items():
        preds = cross_val_predict(model, X, y, cv=cv)
        acc  = accuracy_score(y, preds)
        prec = precision_score(y, preds, pos_label="sensitive", zero_division=0)
        rec  = recall_score(y,  preds,   pos_label="sensitive", zero_division=0)
        f1   = f1_score(y,      preds,   pos_label="sensitive", zero_division=0)
        cm   = confusion_matrix(y, preds, labels=["safe", "sensitive"]).tolist()

        all_results[name] = {
            "accuracy":         round(float(acc),  4),
            "precision":        round(float(prec), 4),
            "recall":           round(float(rec),  4),
            "f1_score":         round(float(f1),   4),
            "confusion_matrix": cm,
            "unique_samples":   int(len(df)),
            "cv_folds":         5,
        }

        print(f"\n  {name}")
        print(f"    Accuracy  : {acc * 100:.1f}%")
        print(f"    Precision : {prec * 100:.1f}%")
        print(f"    Recall    : {rec  * 100:.1f}%")
        print(f"    F1 Score  : {f1   * 100:.1f}%")
        print(f"    Confusion Matrix (rows=actual, cols=predicted):")
        print(f"                  Safe  Sensitive")
        print(f"      Safe       {cm[0][0]:>4}    {cm[0][1]:>4}")
        print(f"      Sensitive  {cm[1][0]:>4}    {cm[1][1]:>4}")

        if f1 > best_f1:
            best_f1, best_name, best_model = f1, name, model

    print(f"\n  Best Model: {best_name}  (F1 = {best_f1 * 100:.1f}%)")
    print("=" * 57)

    best_model.fit(X, y)
    joblib.dump(best_model, "model.pkl")
    with open("metrics.json", "w") as f:
        json.dump({"best_model": best_name, "all_results": all_results}, f, indent=2)
    print("\n  Saved: model.pkl  |  metrics.json")
    return all_results


def load_model():
    return joblib.load("model.pkl")


def predict_text(text: str) -> str:
    """Returns 'sensitive' or 'safe'."""
    return load_model().predict([text])[0]


def get_keywords(text: str) -> list:
    """Returns sensitive keywords found in text (for UI display)."""
    watch_list = [
        "password", "bank", "account", "salary", "confidential",
        "secret", "private", "credit card", "aadhaar", "ssn",
        "pan card", "passport", "otp", "token", "api key",
        "pin", "credentials", "access key", "private key", "cvv",
        "bearer", "jwt", "ssh", "aws", "insurance", "medical",
        "diagnosis", "prescription", "ctc", "payroll", "audit",
        "merger", "acquisition", "trade secret", "nda",
    ]
    tl = text.lower()
    return [w for w in watch_list if w in tl]


if __name__ == "__main__":
    train_model()