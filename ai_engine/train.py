import os
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
import joblib

from .features import FEATURE_NAMES
from .dataset import load_dataset

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
CLASSIFIER_PATH = os.path.join(MODELS_DIR, "traffic_classifier.joblib")
ANOMALY_MODEL_PATH = os.path.join(MODELS_DIR, "anomaly_detector.joblib")
METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")

def train_models():
    os.makedirs(MODELS_DIR, exist_ok=True)
    df = load_dataset()

    X = df[FEATURE_NAMES]
    y = df["label"].values

    # Train/Test Split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 1. Train Random Forest Classifier
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # Evaluate on Unseen Test Set
    y_pred = clf.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    prec, rec, f1_macro, _ = precision_recall_fscore_support(y_test, y_pred, average="macro")
    _, _, f1_weighted, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted")

    # Feature Importance
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [
        {"feature": FEATURE_NAMES[i], "importance": round(float(importances[i]), 4)}
        for i in sorted_idx[:8]
    ]

    # 2. Train Isolation Forest Anomaly Detector
    # Train anomaly model on normal traffic profile samples
    normal_mask = df["is_anomaly"] == 0
    X_normal = df.loc[normal_mask, FEATURE_NAMES]
    
    anomaly_model = IsolationForest(
        n_estimators=100,
        contamination=0.08,
        random_state=42,
        n_jobs=-1
    )
    anomaly_model.fit(X_normal)

    # Save Models
    joblib.dump(clf, CLASSIFIER_PATH)
    joblib.dump(anomaly_model, ANOMALY_MODEL_PATH)

    metadata = {
        "model_name": "Random Forest Classifier (scikit-learn)",
        "model_version": "1.0.0",
        "dataset_version": "VPNGuard-Testbed-Dataset-v1",
        "classes": list(clf.classes_),
        "feature_names": FEATURE_NAMES,
        "test_samples": len(X_test),
        "accuracy": round(acc, 4),
        "macro_f1": round(float(f1_macro), 4),
        "weighted_f1": round(float(f1_weighted), 4),
        "top_features": top_features,
        "anomaly_model_name": "Isolation Forest (scikit-learn)",
        "anomaly_contamination": 0.08
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Models trained and saved successfully.")
    print(f"Test Accuracy: {acc*100:.2f}%, Macro F1: {f1_macro:.4f}")
    return metadata

if __name__ == "__main__":
    train_models()
