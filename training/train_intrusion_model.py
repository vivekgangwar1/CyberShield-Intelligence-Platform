
import pandas as pd
import joblib

from pathlib import Path
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


# Project folder path
BASE_DIR = Path(__file__).resolve().parent.parent

# Dataset paths
TRAIN_PATH = BASE_DIR / "datasets" / "KDDTrain+.txt"
TEST_PATH = BASE_DIR / "datasets" / "KDDTest+.txt"

# Model save path
MODEL_PATH = BASE_DIR / "models" / "intrusion_detection_model.pkl"


# Dataset column names
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


# Load datasets
print("Loading datasets...")

train_df = pd.read_csv(
    TRAIN_PATH,
    names=columns
)

test_df = pd.read_csv(
    TEST_PATH,
    names=columns
)

print("Training data shape:", train_df.shape)
print("Testing data shape:", test_df.shape)


# Convert labels into binary values
# 0 = Normal
# 1 = Attack

train_df["target"] = (
    train_df["label"] != "normal"
).astype(int)

test_df["target"] = (
    test_df["label"] != "normal"
).astype(int)


# Separate features and target
X_train = train_df.drop(
    columns=["label", "difficulty_level", "target"]
)

y_train = train_df["target"]

X_test = test_df.drop(
    columns=["label", "difficulty_level", "target"]
)

y_test = test_df["target"]


# Categorical and numerical columns
categorical_features = [
    "protocol_type",
    "service",
    "flag"
]

numerical_features = [
    col for col in X_train.columns
    if col not in categorical_features
]


# Preprocessing
preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(handle_unknown="ignore"),
            categorical_features
        ),
        (
            "numerical",
            "passthrough",
            numerical_features
        )
    ]
)


# Random Forest model
rf_model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)


# Create complete pipeline
model = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("classifier", rf_model)
    ]
)


# Train model
print("\nTraining Intrusion Detection Model...")

model.fit(X_train, y_train)

print("Model training completed!")


# Initial prediction and accuracy
initial_predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    initial_predictions
)

print("\nInitial Model Accuracy:")
print(f"{accuracy * 100:.2f}%")


# Get prediction probabilities
print("\nTesting different thresholds...")

probabilities = model.predict_proba(X_test)


# Test different thresholds
for threshold in [0.50, 0.40, 0.30, 0.20]:

    predictions = (
        probabilities[:, 1] >= threshold
    ).astype(int)

    print("\n" + "=" * 50)
    print(f"THRESHOLD: {threshold}")
    print("=" * 50)

    print(
        classification_report(
            y_test,
            predictions,
            target_names=["Normal", "Attack"],
            zero_division=0
        )
    )

    print("Confusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )


# Save trained model
MODEL_PATH.parent.mkdir(
    parents=True,
    exist_ok=True
)

joblib.dump(model, MODEL_PATH)

print("\nModel saved successfully!")
print("Saved location:", MODEL_PATH)
