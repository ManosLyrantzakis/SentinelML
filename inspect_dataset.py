
from pathlib import Path
import joblib
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent

model = joblib.load(BASE_DIR / "models" / "random_forest_model.joblib")
csv_path = BASE_DIR / "archive" / "UNSW_NB15_testing-set.csv"

print("\n--- MODEL ---")
print("Model type:", type(model).__name__)
print("Expected features:", getattr(model, "n_features_in_", "Not available"))

if hasattr(model, "feature_names_in_"):
    print("Model feature names:")
    print(list(model.feature_names_in_))
elif hasattr(model, "steps"):
    for name, step in model.steps:
        if hasattr(step, "feature_names_in_"):
            print(f"Feature names from {name}:")
            print(list(step.feature_names_in_))

print("\n--- TEST DATASET ---")
df = pd.read_csv(csv_path, nrows=5)
print("Columns:", len(df.columns))
print("Column names:")
print(list(df.columns))
print("\nFirst 5 rows:")
print(df.head().to_string(index=False))

print("\n--- LABELS ---")
if "label" in df.columns:
    print("Sample label values:", df["label"].tolist())

print("\nInspection complete.")
