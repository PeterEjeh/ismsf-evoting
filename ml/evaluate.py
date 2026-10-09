"""Evaluation and Defense Benchmarking Engine.

Performs:
1. Ground-Truth Analysis on Red-Team Injected Attacks (Precision, Recall, F1).
2. Model Comparative Analysis (Isolation Forest vs. Local Outlier Factor).
3. Independent Cross-Benchmark on Held-Out LogHub HDFS & BGL Anomaly Logs.
4. Generates comprehensive audit evidence in evidence/evaluation_report.json.
"""

import os
import sys
import json
from datetime import datetime, timezone
import pandas as pd
import numpy as np
import joblib

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.feature_builder import build_windows_from_events, FEATURE_COLUMNS_CORE
from ml.sourcing.hdfs_loader import load_hdfs_data
from ml.sourcing.bgl_loader import load_bgl_data


def evaluate_system(
    injection_log_path: str = "evidence/injection_test_log.json",
    models_dir: str = "ml/models",
    output_report_path: str = "evidence/evaluation_report.json"
):
    """Run comprehensive performance and cross-benchmark evaluation."""
    iso_path = os.path.join(models_dir, "isolation_forest.joblib")
    lof_path = os.path.join(models_dir, "lof.joblib")
    thresh_path = os.path.join(models_dir, "thresholds.json")

    if not os.path.exists(iso_path) or not os.path.exists(lof_path):
        raise FileNotFoundError("Trained models not found. Please run ml/train.py first.")

    iso = joblib.load(iso_path)
    lof = joblib.load(lof_path)

    iso_threshold = -0.1865
    lof_threshold = 0.5057
    features = FEATURE_COLUMNS_CORE

    if os.path.exists(thresh_path):
        with open(thresh_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
            iso_threshold = meta.get("iso_threshold", iso_threshold)
            lof_threshold = meta.get("lof_threshold", lof_threshold)
            features = meta.get("features", features)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "methodology": "Trained strictly on normal behaviour. Tested on out-of-sample live red-team attacks and cross-benchmarks."
    }

    # =========================================================================
    # 1. Live Injection Test Results
    # =========================================================================
    if os.path.exists(injection_log_path):
        with open(injection_log_path, "r", encoding="utf-8") as f:
            inj_data = json.load(f)

        results = inj_data.get("results", [])
        total_attacks = len(results)
        flagged_count = sum(1 for r in results if r.get("flagged"))
        recall = (flagged_count / total_attacks) if total_attacks > 0 else 0.0

        # Comparative breakdown per model
        iso_detected = sum(1 for r in results if r.get("iso_score") is not None and r["iso_score"] < iso_threshold)
        lof_detected = sum(1 for r in results if r.get("lof_score") is not None and r["lof_score"] < lof_threshold)

        report["live_red_team_injection"] = {
            "total_attack_scenarios": total_attacks,
            "detected_scenarios": flagged_count,
            "detection_recall": recall,
            "model_comparison": {
                "isolation_forest_detections": iso_detected,
                "local_outlier_factor_detections": lof_detected,
                "complementary_rate": flagged_count
            },
            "scenario_details": results
        }
    else:
        report["live_red_team_injection"] = "Not yet executed (run ml/inject_anomaly_test.py against running API)"

    # =========================================================================
    # 2. Independent Cross-Benchmark on Held-Out LogHub Datasets (HDFS & BGL)
    # =========================================================================
    print("Running independent cross-benchmark on held-out LogHub HDFS & BGL anomalies...")
    cross_benchmarks = {}

    # A. HDFS Cross-Benchmark
    hdfs_log = "data/raw/hdfs/HDFS_sample.csv"
    hdfs_labels = "data/raw/hdfs/anomaly_label.csv"
    if os.path.exists(hdfs_log) and os.path.exists(hdfs_labels):
        # Load ALL rows including anomalous rows for testing
        hdfs_all = load_hdfs_data(hdfs_log, hdfs_labels, filter_normal_only=False)
        hdfs_windows = build_windows_from_events(hdfs_all, window_minutes=5)

        if not hdfs_windows.empty:
            X_hdfs = hdfs_windows[features].fillna(0.0)
            iso_scores = iso.decision_function(X_hdfs)
            lof_scores = lof.decision_function(X_hdfs)

            hdfs_windows["iso_flag"] = iso_scores < iso_threshold
            hdfs_windows["lof_flag"] = lof_scores < lof_threshold
            hdfs_windows["system_flag"] = hdfs_windows["iso_flag"] | hdfs_windows["lof_flag"]
            hdfs_windows["is_anom_ground_truth"] = hdfs_windows["ground_truth_label"] == "anomalous"

            tp = int(((hdfs_windows["system_flag"] == True) & (hdfs_windows["is_anom_ground_truth"] == True)).sum())
            fp = int(((hdfs_windows["system_flag"] == True) & (hdfs_windows["is_anom_ground_truth"] == False)).sum())
            tn = int(((hdfs_windows["system_flag"] == False) & (hdfs_windows["is_anom_ground_truth"] == False)).sum())
            fn = int(((hdfs_windows["system_flag"] == False) & (hdfs_windows["is_anom_ground_truth"] == True)).sum())

            precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 1.0
            recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 1.0
            f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

            cross_benchmarks["hdfs"] = {
                "total_windows": len(hdfs_windows),
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "false_positive_rate": fpr
            }

    # B. BGL Cross-Benchmark
    bgl_log = "data/raw/bgl/BGL_sample.csv"
    if os.path.exists(bgl_log):
        bgl_all = load_bgl_data(bgl_log, filter_normal_only=False)
        bgl_windows = build_windows_from_events(bgl_all, window_minutes=5)

        if not bgl_windows.empty:
            X_bgl = bgl_windows[features].fillna(0.0)
            iso_scores = iso.decision_function(X_bgl)
            lof_scores = lof.decision_function(X_bgl)

            bgl_windows["iso_flag"] = iso_scores < iso_threshold
            bgl_windows["lof_flag"] = lof_scores < lof_threshold
            bgl_windows["system_flag"] = bgl_windows["iso_flag"] | bgl_windows["lof_flag"]
            bgl_windows["is_anom_ground_truth"] = bgl_windows["ground_truth_label"] == "anomalous"

            tp = int(((bgl_windows["system_flag"] == True) & (bgl_windows["is_anom_ground_truth"] == True)).sum())
            fp = int(((bgl_windows["system_flag"] == True) & (bgl_windows["is_anom_ground_truth"] == False)).sum())
            tn = int(((bgl_windows["system_flag"] == False) & (bgl_windows["is_anom_ground_truth"] == False)).sum())
            fn = int(((bgl_windows["system_flag"] == False) & (bgl_windows["is_anom_ground_truth"] == True)).sum())

            precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 1.0
            recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 1.0
            f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

            cross_benchmarks["bgl"] = {
                "total_windows": len(bgl_windows),
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "false_positive_rate": fpr
            }

    report["independent_cross_benchmarks"] = cross_benchmarks

    os.makedirs(os.path.dirname(output_report_path), exist_ok=True)
    with open(output_report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Evaluation report successfully written to {output_report_path}")
    return report


if __name__ == "__main__":
    evaluate_system()
