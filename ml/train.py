"""Unsupervised Model Training Pipeline (Normal Behavior Only).

Trains Isolation Forest and Local Outlier Factor (LOF in novelty mode)
exclusively on legitimate voting/system telemetry.
No synthetic or attack data is included in training.

Pipeline:
1. Temporal split (60% Train, 20% Validation, 20% Held-Out Normal Test).
2. Train Isolation Forest (contamination='auto', random_state=42).
3. Train Local Outlier Factor (novelty=True, contamination='auto').
4. Compute baseline alert thresholds (5th percentile of decision_function).
5. Persist models to ml/models/ and report to evidence/training_report.json.
"""

import os
import sys
import json
from datetime import datetime, timezone
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.feature_builder import FEATURE_COLUMNS_CORE, FEATURE_COLUMNS_FULL


def train_models(
    normal_windows_path: str = "data/processed/normal_windows.csv",
    models_dir: str = "ml/models",
    evidence_dir: str = "evidence",
    percentile_cutoff: float = 5.0  # Lowest 5% of normal decision scores
):
    """Train Isolation Forest and LOF exclusively on normal windows."""
    if not os.path.exists(normal_windows_path):
        raise FileNotFoundError(f"Processed normal windows not found at {normal_windows_path}")

    df = pd.read_csv(normal_windows_path)
    if df.empty:
        raise ValueError("Processed normal windows dataset is empty!")

    # Verify normal behavior only
    assert (df["ground_truth_label"] == "normal").all(), "Found non-normal data in training set!"

    # Sort strictly temporally (no random shuffle)
    df["window_start"] = pd.to_datetime(df["window_start"], utc=True)
    df = df.sort_values("window_start").reset_index(drop=True)

    n_samples = len(df)
    train_end = int(0.6 * n_samples)
    val_end = int(0.8 * n_samples)

    train_df = df.iloc[:train_end]
    val_df = df.iloc[train_end:val_end]
    test_df = df.iloc[val_end:]

    print(f"Dataset split temporally: Train={len(train_df)}, Val={len(val_df)}, Test={len(test_df)}")

    # Feature selection: use core behavioral features common across all datasets
    features = FEATURE_COLUMNS_CORE
    X_train = train_df[features].fillna(0.0)
    X_val = val_df[features].fillna(0.0)
    X_test = test_df[features].fillna(0.0)

    # 1. Isolation Forest
    print("Fitting Isolation Forest on normal data...")
    iso = IsolationForest(contamination="auto", random_state=42)
    iso.fit(X_train)

    # 2. Local Outlier Factor (novelty=True to enable scoring new observations)
    print("Fitting Local Outlier Factor (novelty=True) on normal data...")
    # Adjust n_neighbors if training set is small
    n_neighbors = min(20, max(2, len(X_train) - 1))
    lof = LocalOutlierFactor(n_neighbors=n_neighbors, novelty=True, contamination="auto")
    lof.fit(X_train)

    # Decision functions: lower score = more abnormal
    iso_train_scores = iso.decision_function(X_train)
    lof_train_scores = lof.decision_function(X_train)

    iso_val_scores = iso.decision_function(X_val) if not X_val.empty else np.array([])
    lof_val_scores = lof.decision_function(X_val) if not X_val.empty else np.array([])

    iso_test_scores = iso.decision_function(X_test) if not X_test.empty else np.array([])
    lof_test_scores = lof.decision_function(X_test) if not X_test.empty else np.array([])

    # Compute baseline alert thresholds at the percentile cutoff of the normal training distribution
    # Anything below this threshold is flagged as an anomaly
    iso_threshold = float(np.percentile(iso_train_scores, percentile_cutoff))
    lof_threshold = float(np.percentile(lof_train_scores, percentile_cutoff))

    # Save models and thresholds
    os.makedirs(models_dir, exist_ok=True)
    iso_path = os.path.join(models_dir, "isolation_forest.joblib")
    lof_path = os.path.join(models_dir, "lof.joblib")
    thresh_path = os.path.join(models_dir, "thresholds.json")

    joblib.dump(iso, iso_path)
    joblib.dump(lof, lof_path)

    threshold_meta = {
        "features": features,
        "percentile_cutoff": percentile_cutoff,
        "iso_threshold": iso_threshold,
        "lof_threshold": lof_threshold,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "train_samples": len(train_df),
        "val_samples": len(val_df),
        "test_samples": len(test_df)
    }

    with open(thresh_path, "w", encoding="utf-8") as f:
        json.dump(threshold_meta, f, indent=2)

    # Save detailed training report
    os.makedirs(evidence_dir, exist_ok=True)
    report_path = os.path.join(evidence_dir, "training_report.json")
    training_report = {
        "status": "success",
        "philosophy": "Train on normal behaviour only — zero attack data in training",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "features": features,
        "samples": {
            "total_normal_windows": n_samples,
            "train": len(train_df),
            "val": len(val_df),
            "test": len(test_df)
        },
        "isolation_forest": {
            "threshold": iso_threshold,
            "train_score_stats": {
                "mean": float(np.mean(iso_train_scores)),
                "std": float(np.std(iso_train_scores)),
                "min": float(np.min(iso_train_scores)),
                "max": float(np.max(iso_train_scores)),
                "p05": float(np.percentile(iso_train_scores, 5)),
                "p50": float(np.median(iso_train_scores)),
                "p95": float(np.percentile(iso_train_scores, 95))
            },
            "held_out_normal_test_flag_rate": float(np.mean(iso_test_scores < iso_threshold)) if len(iso_test_scores) > 0 else 0.0
        },
        "local_outlier_factor": {
            "threshold": lof_threshold,
            "train_score_stats": {
                "mean": float(np.mean(lof_train_scores)),
                "std": float(np.std(lof_train_scores)),
                "min": float(np.min(lof_train_scores)),
                "max": float(np.max(lof_train_scores)),
                "p05": float(np.percentile(lof_train_scores, 5)),
                "p50": float(np.median(lof_train_scores)),
                "p95": float(np.percentile(lof_train_scores, 95))
            },
            "held_out_normal_test_flag_rate": float(np.mean(lof_test_scores < lof_threshold)) if len(lof_test_scores) > 0 else 0.0
        }
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(training_report, f, indent=2)

    print(f"Models successfully trained and saved to {models_dir}")
    print(f"Training report saved to {report_path}")
    print(f"Thresholds: Isolation Forest={iso_threshold:.4f}, LOF={lof_threshold:.4f}")
    return training_report


if __name__ == "__main__":
    train_models()
