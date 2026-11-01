
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

df = pd.read_csv(
    BASE_DIR / "datasets" / "malware_dataset.csv"
)

for index, column in enumerate(df.columns):
    print(index + 1, column)

print("\nTotal columns:", len(df.columns))
print("Total features:", len(df.columns) - 1)
