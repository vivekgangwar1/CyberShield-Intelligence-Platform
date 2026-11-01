
import pandas as pd
from pathlib import Path

# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Dataset path
TRAIN_PATH = BASE_DIR / "datasets" / "KDDTrain+.txt"

# NSL-KDD column names
columns = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty_level"
]

# Read dataset
df = pd.read_csv(
    TRAIN_PATH,
    header=None,
    names=columns
)

print("\n========== NSL-KDD DATASET INFORMATION ==========")

# Dataset shape
print("\nDataset Shape:")
print(df.shape)

# Column names
print("\nTotal Columns:")
print(len(df.columns))

print("\nColumn Names:")
print(df.columns.tolist())

# First five rows
print("\nFirst 5 Records:")
print(df.head())

# Dataset information
print("\nDataset Information:")
df.info()

# Missing values
print("\nMissing Values:")
print(df.isnull().sum().sum())

# Attack labels
print("\nAttack Label Distribution:")
print(df["label"].value_counts())

print("\n========== INSPECTION COMPLETED ==========")
