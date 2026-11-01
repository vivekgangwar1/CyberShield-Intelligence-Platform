
import os
import tempfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.database import initialize_database, save_scan, get_connection
from utils.pe_feature_extractor import extract_basic_pe_info


# --------------------------------------------------
# Project paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"

PHISHING_MODEL_PATH = MODELS_DIR / "phishing_cnn.keras"
PHISHING_ENCODER_PATH = MODELS_DIR / "phishing_cnn_encoder.pkl"

INTRUSION_MODEL_PATH = MODELS_DIR / "intrusion_detection_model.pkl"
MALWARE_MODEL_PATH = MODELS_DIR / "malware_classification_model.pkl"

INTRUSION_THRESHOLD = 0.20
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB


# --------------------------------------------------
# Model variables
# --------------------------------------------------

phishing_model = None
char_to_id = {}
MAX_LEN = 200

intrusion_model = None
malware_model = None
malware_feature_columns = []

malware_label_mapping = {
    0: "Benign",
    1: "Malware",
}


# --------------------------------------------------
# Load trained models
# --------------------------------------------------

def load_models():
    global phishing_model, char_to_id, MAX_LEN
    global intrusion_model, malware_model
    global malware_feature_columns, malware_label_mapping

    if PHISHING_MODEL_PATH.exists() and PHISHING_ENCODER_PATH.exists():
        phishing_model = tf.keras.models.load_model(
            PHISHING_MODEL_PATH
        )

        encoder_data = joblib.load(PHISHING_ENCODER_PATH)
        char_to_id = encoder_data["char_to_id"]
        MAX_LEN = encoder_data["max_len"]

        print("CNN phishing model loaded successfully.")
    else:
        print("CNN phishing model or encoder not found.")

    if INTRUSION_MODEL_PATH.exists():
        intrusion_model = joblib.load(INTRUSION_MODEL_PATH)
        print("Intrusion detection model loaded.")

    if MALWARE_MODEL_PATH.exists():
        malware_bundle = joblib.load(MALWARE_MODEL_PATH)

        if isinstance(malware_bundle, dict):
            malware_model = malware_bundle["model"]
            malware_feature_columns = malware_bundle["feature_columns"]
            malware_label_mapping = malware_bundle.get(
                "label_mapping",
                {0: "Benign", 1: "Malware"},
            )
        else:
            malware_model = malware_bundle

        print("Malware classification model loaded.")


load_models()


# --------------------------------------------------
# FastAPI application
# --------------------------------------------------

app = FastAPI(
    title="CyberShield Intelligence Platform",
    description="Cybersecurity detection APIs",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "https://cybershield-intelligence-platform.netlify.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# Database startup
# --------------------------------------------------

@app.on_event("startup")
def startup_event():
    initialize_database()


# --------------------------------------------------
# Request schemas
# --------------------------------------------------

class URLRequest(BaseModel):
    url: str


class IntrusionRequest(BaseModel):
    features: dict


class MalwareRequest(BaseModel):
    features: dict


# --------------------------------------------------
# Helper functions
# --------------------------------------------------

def ensure_model_loaded(model, model_name):
    if model is None:
        raise HTTPException(
            status_code=503,
            detail=f"{model_name} model is not loaded.",
        )


def encode_url(url: str) -> np.ndarray:
    sequence = [
        char_to_id.get(char, 0)
        for char in url[:MAX_LEN]
    ]

    sequence += [0] * (MAX_LEN - len(sequence))

    return np.array([sequence], dtype=np.int32)


# --------------------------------------------------
# Home and health endpoints
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "message": "CyberShield Intelligence Platform API is running."
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "running",
        "phishing_model_loaded": phishing_model is not None,
        "intrusion_model_loaded": intrusion_model is not None,
        "malware_model_loaded": malware_model is not None,
    }


# --------------------------------------------------
# Phishing URL Detection — CNN Deep Learning
# --------------------------------------------------

@app.post("/api/phishing-detection")
def phishing_detection(request: URLRequest):
    ensure_model_loaded(phishing_model, "Phishing detection")

    url = request.url.strip()

    if not url:
        raise HTTPException(
            status_code=400,
            detail="URL is required.",
        )

    encoded_url = encode_url(url)

    # CNN sigmoid output: probability of label 1 (Legitimate)
    legitimate_probability = float(
        phishing_model.predict(
            encoded_url,
            verbose=0,
        )[0][0]
    )

    phishing_probability = 1.0 - legitimate_probability

    if phishing_probability >= 0.5:
        result = "Phishing"
        confidence = phishing_probability
        message = (
            "The CNN model classified this URL as phishing. "
            "Do not enter sensitive information on this website."
        )
        label = 0
    else:
        result = "Legitimate"
        confidence = legitimate_probability
        message = (
            "The CNN model classified this URL as legitimate. "
            "This does not guarantee that the website is safe."
        )
        label = 1

    save_scan(
        scan_type="Phishing",
        target=url,
        prediction=result,
        confidence=confidence,
        details=message,
    )

    return {
        "url": url,
        "prediction": result,
        "label": label,
        "confidence": round(confidence, 4),
        "phishing_probability": round(phishing_probability, 4),
        "legitimate_probability": round(legitimate_probability, 4),
        "message": message,
        "model": "CNN Deep Learning",
    }


# --------------------------------------------------
# Network Intrusion Detection
# --------------------------------------------------

@app.post("/api/intrusion-detection")
def intrusion_detection(request: IntrusionRequest):
    ensure_model_loaded(intrusion_model, "Intrusion detection")

    try:
        input_df = pd.DataFrame([request.features])
        probabilities = intrusion_model.predict_proba(input_df)[0]

        attack_probability = float(probabilities[1])

        prediction = (
            "Attack"
            if attack_probability >= INTRUSION_THRESHOLD
            else "Normal"
        )

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid intrusion features: {str(error)}",
        )

    message = (
        "Potential network attack detected."
        if prediction == "Attack"
        else "No attack detected in the supplied features."
    )

    save_scan(
        scan_type="Intrusion",
        target="Supplied network traffic features",
        prediction=prediction,
        confidence=attack_probability,
        details=message,
    )

    return {
        "prediction": prediction,
        "attack_probability": round(attack_probability, 4),
        "threshold": INTRUSION_THRESHOLD,
        "message": message,
    }


# --------------------------------------------------
# Malware Classification — JSON features
# --------------------------------------------------

@app.post("/api/malware-classification")
def malware_classification(request: MalwareRequest):
    ensure_model_loaded(malware_model, "Malware classification")

    try:
        missing_features = [
            column
            for column in malware_feature_columns
            if column not in request.features
        ]

        if missing_features:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Missing required malware features.",
                    "missing_features": missing_features,
                },
            )

        input_df = pd.DataFrame(
            [[request.features[column]
              for column in malware_feature_columns]],
            columns=malware_feature_columns,
        )

        probabilities = malware_model.predict_proba(input_df)[0]
        label = int(malware_model.predict(input_df)[0])
        prediction = malware_label_mapping.get(label, str(label))

        confidence = float(max(probabilities))
        malware_probability = float(probabilities[1])

    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid malware features: {str(error)}",
        )

    message = (
        "The model classified this sample as malware."
        if prediction == "Malware"
        else (
            "The model classified this sample as benign. "
            "This does not guarantee that the file is safe."
        )
    )

    save_scan(
        scan_type="Malware",
        target="JSON feature input",
        prediction=prediction,
        confidence=confidence,
        details=message,
    )

    return {
        "prediction": prediction,
        "label": label,
        "confidence": round(confidence, 4),
        "malware_probability": round(malware_probability, 4),
        "message": message,
    }


# --------------------------------------------------
# Malware EXE Static Scanner
# --------------------------------------------------

@app.post("/api/malware-scan-exe")
async def malware_scan_exe(file: UploadFile = File(...)):
    ensure_model_loaded(malware_model, "Malware classification")

    filename = file.filename or "uploaded_file"

    if not filename.lower().endswith(".exe"):
        raise HTTPException(
            status_code=400,
            detail="Only .exe files are supported.",
        )

    temp_path = None
    file_size = 0

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".exe",
        ) as temp_file:
            temp_path = temp_file.name

            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                file_size += len(chunk)

                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File size must not exceed 100 MB.",
                    )

                temp_file.write(chunk)

        extracted_features = extract_basic_pe_info(temp_path)

        missing_features = [
            column
            for column in malware_feature_columns
            if column not in extracted_features
        ]

        if missing_features:
            raise HTTPException(
                status_code=500,
                detail={
                    "message": (
                        "PE feature extractor is missing model features."
                    ),
                    "missing_features": missing_features,
                },
            )

        input_df = pd.DataFrame(
            [[extracted_features[column]
              for column in malware_feature_columns]],
            columns=malware_feature_columns,
        )

        probabilities = malware_model.predict_proba(input_df)[0]
        label = int(malware_model.predict(input_df)[0])
        prediction = malware_label_mapping.get(label, str(label))

        confidence = float(max(probabilities))
        malware_probability = float(probabilities[1])

        message = (
            "The model classified this EXE as malware."
            if prediction == "Malware"
            else (
                "The model classified this EXE as benign. "
                "This does not guarantee that the file is safe."
            )
        )

        save_scan(
            scan_type="Malware",
            target=filename,
            prediction=prediction,
            confidence=confidence,
            details=message,
        )

        return {
            "filename": filename,
            "file_size": file_size,
            "prediction": prediction,
            "label": label,
            "confidence": round(confidence, 4),
            "malware_probability": round(malware_probability, 4),
            "message": message,
        }

    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to analyze EXE file: {str(error)}",
        )
    finally:
        await file.close()

        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


# --------------------------------------------------
# Threat Classification
# --------------------------------------------------

@app.post("/api/threat-classification")
def threat_classification(request: MalwareRequest):
    return malware_classification(request)


# --------------------------------------------------
# Scan History API
# --------------------------------------------------

@app.get("/api/scan-history")
def get_scan_history(limit: int = 100):
    if limit < 1 or limit > 500:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 500.",
        )

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

        scans = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) FROM scan_history")
        total_scans = cursor.fetchone()[0]

        return {
            "total_scans": total_scans,
            "showing": len(scans),
            "scans": [dict(scan) for scan in scans],
        }

    finally:
        connection.close()
