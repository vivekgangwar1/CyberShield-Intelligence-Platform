
import pandas as pd
import numpy as np
import tensorflow as tf
import joblib
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "datasets" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

# Load only URL and label columns
df = pd.read_csv(
    DATASET_PATH,
    usecols=["URL", "label"],
    dtype={"URL": "string", "label": "int8"}
).dropna()

# Label mapping: dataset label 0 = phishing, 1 = legitimate
X = df["URL"].astype(str).values
y = df["label"].values

# Character vocabulary
MAX_LEN = 200
chars = sorted(set("".join(X)))
char_to_id = {char: i + 1 for i, char in enumerate(chars)}
VOCAB_SIZE = len(char_to_id) + 1

def encode_url(url):
    sequence = [char_to_id.get(char, 0) for char in url[:MAX_LEN]]
    sequence += [0] * (MAX_LEN - len(sequence))
    return sequence

print("Encoding URLs...")
X_encoded = np.array([encode_url(url) for url in X], dtype=np.int32)

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X_encoded,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# CNN model
model = tf.keras.Sequential([
    tf.keras.layers.Input(shape=(MAX_LEN,)),
    tf.keras.layers.Embedding(VOCAB_SIZE, 32),
    tf.keras.layers.Conv1D(64, 5, activation="relu"),
    tf.keras.layers.GlobalMaxPooling1D(),
    tf.keras.layers.Dense(64, activation="relu"),
    tf.keras.layers.Dropout(0.3),
    tf.keras.layers.Dense(1, activation="sigmoid")
])

model.compile(
    optimizer="adam",
    loss="binary_crossentropy",
    metrics=["accuracy"]
)

model.summary()

# Train
early_stop = tf.keras.callbacks.EarlyStopping(
    monitor="val_loss",
    patience=2,
    restore_best_weights=True
)

print("Training CNN model...")
model.fit(
    X_train,
    y_train,
    validation_split=0.1,
    epochs=10,
    batch_size=128,
    callbacks=[early_stop]
)

# Evaluate
probabilities = model.predict(X_test).ravel()
predictions = (probabilities >= 0.5).astype(int)

print("\nClassification Report:")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate"]
))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

# Save model and URL encoder
model.save(MODEL_DIR / "phishing_cnn.keras")
joblib.dump(
    {"char_to_id": char_to_id, "max_len": MAX_LEN},
    MODEL_DIR / "phishing_cnn_encoder.pkl"
)

print("\nCNN model and encoder saved successfully!")
