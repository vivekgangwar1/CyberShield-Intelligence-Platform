
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
df = pd.read_csv(BASE_DIR / "datasets" / "malware_dataset.csv")

columns = [
    "CreationYear",
    "ImageBase",
    "SectionAlignment",
    "FileAlignment",
    "SizeOfImage",
    "SizeOfHeaders",
    "LoaderFlags",
    "e_lfanew",
    "NumberOfSections",
    "sus_sections",
    "non_sus_sections",
    "packer",
    "E_text",
    "E_data",
    "filesize",
    "E_file",
    "fileinfo"
]

for col in columns:
    print("\n" + "=" * 50)
    print("FEATURE:", col)
    print("Unique values:", df[col].nunique())
    print("Minimum:", df[col].min() if pd.api.types.is_numeric_dtype(df[col]) else "N/A")
    print("Maximum:", df[col].max() if pd.api.types.is_numeric_dtype(df[col]) else "N/A")
    print("Most common values:")
    print(df[col].value_counts().head(10).to_string())
