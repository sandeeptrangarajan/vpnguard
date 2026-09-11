import os
import sys
import json
import traceback
import numpy as np
import pandas as pd
import joblib

BASE_DIR = os.path.dirname(__file__)
MODELS_DIR = os.path.join(BASE_DIR, 'models')
CLASSIFIER_PATH = os.path.join(MODELS_DIR, 'traffic_classifier.joblib')
ANOMALY_MODEL_PATH = os.path.join(MODELS_DIR, 'anomaly_detector.joblib')
METADATA_PATH = os.path.join(MODELS_DIR, 'model_metadata.json')

# Import feature names and extractor from sibling module
from .features import FEATURE_NAMES, extract_features_from_packets


def load_models():
    classifier = joblib.load(CLASSIFIER_PATH)
    anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
    metadata = {}
    if os.path.exists(METADATA_PATH):
        with open(METADATA_PATH, 'r') as f:
            metadata = json.load(f)
    return classifier, anomaly_model, metadata


def run_inference(packets):
    # Extract features - returns a dict, not DataFrame
    feature_dict = extract_features_from_packets(packets)

    # Convert to DataFrame for model input
    df_features = pd.DataFrame([feature_dict], columns=FEATURE_NAMES)

    classifier, anomaly_model, metadata = load_models()

    # Classification
    pred_label = str(classifier.predict(df_features)[0])
    proba = classifier.predict_proba(df_features)[0]
    confidence = float(max(proba))

    # Anomaly detection (-1 = outlier)
    anomaly_pred = anomaly_model.predict(df_features)[0]
    is_anomaly = int(anomaly_pred) == -1

    # Feature importance from metadata
    top_features = metadata.get('top_features', [])

    # Build explanation
    explanation_parts = [f'AI-Inferred Traffic Type: {pred_label} (Confidence: {confidence*100:.1f}%)']
    if top_features:
        explanation_parts.append('Top contributing features:')
        for feat in top_features[:5]:
            explanation_parts.append(f'  - {feat["feature"]}: importance {feat["importance"]:.4f}')
    if is_anomaly:
        explanation_parts.append('Potentially unusual traffic pattern detected.')
    explanation = '\n'.join(explanation_parts)

    result = {
        'IsModelConnected': True,
        'Protocol': None,
        'TrafficType': pred_label,
        'Prediction': 'Potentially unusual traffic pattern' if is_anomaly else 'Normal',
        'Confidence': confidence,
        'Features': {col: str(val) for col, val in feature_dict.items()},
        'Anomalies': ['Potentially unusual traffic pattern'] if is_anomaly else [],
        'Explanation': explanation,
        'TopFeatures': [{'Name': f['feature'], 'Importance': f['importance']} for f in top_features[:5]]
    }
    return result


def main():
    try:
        raw_input = sys.stdin.read()
        data = json.loads(raw_input) if raw_input.strip() else {}
        packets = data.get('packets', [])
        result = run_inference(packets)
        json.dump(result, sys.stdout)
    except Exception as e:
        error_info = {
            'IsModelConnected': False,
            'Protocol': None,
            'TrafficType': None,
            'Prediction': None,
            'Confidence': None,
            'Features': {},
            'Anomalies': [],
            'Explanation': None,
            'TopFeatures': [],
            'ErrorMessage': str(e)
        }
        json.dump(error_info, sys.stdout)
        sys.exit(1)


if __name__ == '__main__':
    main()
