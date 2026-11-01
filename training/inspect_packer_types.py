
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

df = pd.read_csv(
    BASE_DIR / "datasets" / "malware_dataset.csv"
)

print("Total unique packer types:",
      df["packer_type"].nunique())

print("\nPacker type distribution:")
print(df["packer_type"].value_counts().to_string())

print("\nPacker flag distribution:")
print(df.groupby(["packer", "packer_type"]).size().to_string())
