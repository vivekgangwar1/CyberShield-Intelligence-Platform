
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_PATH = BASE_DIR / "datasets" / "malware_dataset.csv"

df = pd.read_csv(DATASET_PATH)

print("\nSECTION FEATURES VERIFICATION")
print("=" * 40)

for column in ["sus_sections", "non_sus_sections"]:

    print(f"\n{column}")
    print("-" * 30)

    print("Minimum:", df[column].min())
    print("Maximum:", df[column].max())
    print("Unique values:", df[column].nunique())

    print("\nValue counts:")
    print(df[column].value_counts().sort_index().to_string())

print("\nFIRST 10 DATASET RECORDS")
print("=" * 40)

print(df[["sus_sections", "non_sus_sections", "class"]].head(10))

print("\nDATASET CHECK COMPLETED")
