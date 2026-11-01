
import pandas as pd

# Dataset का path
file_path = "datasets/PhiUSIIL_Phishing_URL_Dataset.csv"

# CSV file पढ़ें
df = pd.read_csv(file_path)

# Dataset की जानकारी दिखाएँ
print("\n--- Dataset Shape ---")
print(df.shape)

print("\n--- First 5 Rows ---")
print(df.head())

print("\n--- Column Names ---")
print(df.columns.tolist())

print("\n--- Missing Values ---")
print(df.isnull().sum())

print("\n--- Label Distribution ---")
print(df["label"].value_counts())
