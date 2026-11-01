
import re
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Load dataset
df = pd.read_csv(
    BASE_DIR / "datasets" / "malware_dataset.csv"
)

dataset_names = set(
    df.loc[df["packer"] == 1, "packer_type"].dropna().unique()
)

# Load YARA rule names
rule_file = BASE_DIR / "utils" / "peid.yara"

source = rule_file.read_text(
    encoding="utf-8",
    errors="ignore"
)

yara_names = set(
    re.findall(
        r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)",
        source
    )
)

# Exact matching
matched = sorted(dataset_names.intersection(yara_names))
unmatched = sorted(dataset_names - yara_names)

print("Total dataset packer types:", len(dataset_names))
print("Total YARA rule names:", len(yara_names))

print("\nEXACT MATCHES:", len(matched))
for name in matched:
    print(name)

print("\nDATASET NAMES NOT MATCHED:", len(unmatched))
for name in unmatched:
    print(name)
