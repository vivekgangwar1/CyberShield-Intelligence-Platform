
import joblib
from pathlib import Path

from utils.pe_feature_extractor import extract_basic_pe_info

BASE_DIR = Path(__file__).resolve().parent.parent

# Load trained malware model
bundle = joblib.load(
    BASE_DIR / "models" / "malware_classification_model.pkl"
)

expected_features = bundle["feature_columns"]

file_path = input("Enter EXE file path: ").strip().strip('"')

try:
    extracted = extract_basic_pe_info(file_path)

    extracted_features = list(extracted.keys())

    missing = [
        name for name in expected_features
        if name not in extracted
    ]

    extra = [
        name for name in extracted_features
        if name not in expected_features
    ]

    print("\nFEATURE VERIFICATION")
    print("=" * 40)

    print("Expected features:", len(expected_features))
    print("Extracted features:", len(extracted_features))
    print("Missing features:", missing)
    print("Extra features:", extra)

    print(
        "Exact feature order:",
        expected_features == extracted_features
    )

    if not missing and not extra:
        print("\nSUCCESS: All feature names match!")

except Exception as error:
    print("Error:", error)
