
from pathlib import Path
import json

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "random_forest_model.joblib"
TEST_PATH = BASE_DIR / "archive" / "UNSW_NB15_testing-set.csv"
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

print("Loading model...")
model = joblib.load(MODEL_PATH)

print("Loading UNSW-NB15 test dataset...")
df = pd.read_csv(TEST_PATH)

# Use the exact feature names and order expected by the trained model.
if not hasattr(model, "feature_names_in_"):
    raise ValueError(
        "The model does not expose feature_names_in_. "
        "Check the model's expected feature order before evaluating."
    )

features = list(model.feature_names_in_)

missing = [column for column in features if column not in df.columns]
if missing:
    raise ValueError(f"Missing required model features: {missing}")

if "label" not in df.columns:
    raise ValueError("The dataset does not contain the true 'label' column.")

X_test = df[features]
y_true = df["label"].astype(int)

if set(y_true.unique()) - {0, 1}:
    raise ValueError("Unexpected labels. Expected 0=Normal and 1=Attack.")

print(f"Test records: {len(df):,}")
print(f"Features used: {len(features)}")
print("Running predictions...")

y_pred = model.predict(X_test).astype(int)

accuracy = accuracy_score(y_true, y_pred)
precision = precision_score(y_true, y_pred, pos_label=1, zero_division=0)
recall = recall_score(y_true, y_pred, pos_label=1, zero_division=0)
f1 = f1_score(y_true, y_pred, pos_label=1, zero_division=0)

# Matrix order: [[TN, FP], [FN, TP]]
matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
tn, fp, fn, tp = matrix.ravel()

report = classification_report(
    y_true,
    y_pred,
    labels=[0, 1],
    target_names=["Normal", "Attack"],
    output_dict=True,
    zero_division=0,
)

results = {
    "dataset": "UNSW-NB15 official testing set",
    "test_samples": int(len(df)),
    "features": int(len(features)),
    "accuracy": float(accuracy),
    "attack_precision": float(precision),
    "attack_recall": float(recall),
    "attack_f1": float(f1),
    "confusion_matrix": {
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    },
    "classification_report": report,
}

output_path = REPORT_DIR / "unsw_test_metrics.json"
with output_path.open("w", encoding="utf-8") as file:
    json.dump(results, file, indent=2)

print("\n========== UNSW-NB15 TEST RESULTS ==========")
print(f"Accuracy:        {accuracy:.4%}")
print(f"Attack precision:{precision:.4%}")
print(f"Attack recall:   {recall:.4%}")
print(f"Attack F1-score: {f1:.4%}")

print("\nConfusion Matrix:")
print("                 Predicted Normal | Predicted Attack")
print(f"Actual Normal    {tn:>15,} | {fp:>15,}")
print(f"Actual Attack    {fn:>15,} | {tp:>15,}")

print("\nClassification Report:")
print(classification_report(
    y_true,
    y_pred,
    labels=[0, 1],
    target_names=["Normal", "Attack"],
    zero_division=0,
))

print(f"Full report saved to: {output_path}")
