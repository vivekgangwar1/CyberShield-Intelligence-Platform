
import json
import os
import tempfile
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from backend.database import initialize_database, save_scan, get_connection
from utils.pe_feature_extractor import extract_basic_pe_info


# ---------------- PROJECT PATHS ----------------

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"

PHISHING_MODEL_PATH = MODELS_DIR / "phishing_url_text_model.pkl"
INTRUSION_MODEL_PATH = MODELS_DIR / "intrusion_detection_model.pkl"
MALWARE_MODEL_PATH = MODELS_DIR / "malware_classification_model.pkl"

INTRUSION_THRESHOLD = 0.20
MAX_FILE_SIZE = 100 * 1024 * 1024


# ---------------- PAGE CONFIGURATION ----------------

st.set_page_config(
    page_title="CyberShield Intelligence Platform",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CyberShield Intelligence Platform")
st.caption("AI-Based Cybersecurity Detection Dashboard")

initialize_database()


# ---------------- LOAD MODELS ----------------

@st.cache_resource
def load_models():

    phishing = joblib.load(PHISHING_MODEL_PATH)
    intrusion = joblib.load(INTRUSION_MODEL_PATH)

    malware_bundle = joblib.load(MALWARE_MODEL_PATH)

    if isinstance(malware_bundle, dict):
        malware = malware_bundle["model"]
        malware_columns = malware_bundle["feature_columns"]
        malware_labels = malware_bundle.get(
            "label_mapping",
            {0: "Benign", 1: "Malware"}
        )
    else:
        malware = malware_bundle
        malware_columns = []
        malware_labels = {0: "Benign", 1: "Malware"}

    return phishing, intrusion, malware, malware_columns, malware_labels


try:
    phishing_model, intrusion_model, malware_model, malware_columns, malware_labels = load_models()
except Exception as error:
    st.error(f"Unable to load models: {error}")
    st.stop()


# ---------------- SIDEBAR ----------------

st.sidebar.title("Navigation")

page = st.sidebar.radio(
    "Select Module",
    [
        "Dashboard",
        "Phishing Detection",
        "Network Intrusion",
        "Malware Scanner",
        "Scan History"
    ]
)


# ---------------- DASHBOARD ----------------

if page == "Dashboard":

    st.subheader("Dashboard Overview")

    connection = get_connection()

    total_scans = connection.execute(
        "SELECT COUNT(*) FROM scan_history"
    ).fetchone()[0]

    phishing_scans = connection.execute(
        "SELECT COUNT(*) FROM scan_history WHERE scan_type='Phishing'"
    ).fetchone()[0]

    intrusion_scans = connection.execute(
        "SELECT COUNT(*) FROM scan_history WHERE scan_type='Intrusion'"
    ).fetchone()[0]

    malware_scans = connection.execute(
        "SELECT COUNT(*) FROM scan_history WHERE scan_type='Malware'"
    ).fetchone()[0]

    connection.close()

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Scans", total_scans)
    col2.metric("Phishing Scans", phishing_scans)
    col3.metric("Intrusion Scans", intrusion_scans)
    col4.metric("Malware Scans", malware_scans)

    st.divider()

    st.info(
        "Use the navigation menu to access the cybersecurity detection modules."
    )

    st.warning(
        "These models provide predictions, not guarantees of safety. "
        "Network intrusion detection analyzes supplied features, not live traffic."
    )


# ---------------- PHISHING DETECTION ----------------

elif page == "Phishing Detection":

    st.subheader("🌐 Phishing URL Detection")

    url = st.text_input(
        "Enter Website URL",
        placeholder="https://example.com"
    )

    if st.button("Analyze URL", type="primary"):

        if not url.strip():
            st.warning("Please enter a URL.")

        else:
            prediction = int(phishing_model.predict([url.strip()])[0])

            probabilities = phishing_model.predict_proba([url.strip()])[0]
            confidence = float(max(probabilities))

            if prediction == 0:
                result = "Phishing"
                st.error("⚠️ Phishing URL Detected!")
            else:
                result = "Legitimate"
                st.success("URL Classified as Legitimate")

            st.write(f"**Prediction:** {result}")
            st.write(f"**Confidence:** {confidence:.2%}")

            message = (
                "The model classified this URL as phishing."
                if prediction == 0
                else "The model classified this URL as legitimate. "
                     "This does not guarantee that the website is safe."
            )

            save_scan(
                scan_type="Phishing",
                target=url.strip(),
                prediction=result,
                confidence=confidence,
                details=message
            )


# ---------------- NETWORK INTRUSION ----------------

elif page == "Network Intrusion":

    st.subheader("🔍 Network Intrusion Detection")

    st.write(
        "Enter the network features as JSON. "
        "Use the same feature names and format used during model training."
    )

    example = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 181,
        "dst_bytes": 5450
    }

    features_text = st.text_area(
        "Network Features (JSON)",
        value=json.dumps(example, indent=4),
        height=250
    )

    if st.button("Analyze Network Features", type="primary"):

        try:
            features = json.loads(features_text)

            if not isinstance(features, dict):
                raise ValueError("JSON must contain an object of features.")

            input_df = pd.DataFrame([features])

            probabilities = intrusion_model.predict_proba(input_df)[0]
            attack_probability = float(probabilities[1])

            prediction = (
                "Attack"
                if attack_probability >= INTRUSION_THRESHOLD
                else "Normal"
            )

            if prediction == "Attack":
                st.error("⚠️ Potential Network Attack Detected!")
            else:
                st.success("Normal Traffic Classification")

            st.write(f"**Prediction:** {prediction}")
            st.write(f"**Attack Probability:** {attack_probability:.2%}")

            message = (
                "Potential network attack detected."
                if prediction == "Attack"
                else "No attack detected in supplied features."
            )

            save_scan(
                scan_type="Intrusion",
                target="Supplied network traffic features",
                prediction=prediction,
                confidence=attack_probability,
                details=message
            )

        except Exception as error:
            st.error(f"Invalid features: {error}")


# ---------------- MALWARE SCANNER ----------------

elif page == "Malware Scanner":

    st.subheader("🦠 Malware EXE Static Scanner")

    st.warning(
        "Only upload EXE files you are authorized to analyze. "
        "Uploaded files are analyzed statically and are never executed."
    )

    uploaded_file = st.file_uploader(
        "Upload EXE File",
        type=["exe"]
    )

    if uploaded_file is not None:

        st.write(f"**File:** {uploaded_file.name}")
        st.write(f"**Size:** {uploaded_file.size / (1024 * 1024):.2f} MB")

        if st.button("Scan EXE", type="primary"):

            if uploaded_file.size > MAX_FILE_SIZE:
                st.error("File size must not exceed 100 MB.")

            else:

                temp_path = None

                try:
                    with tempfile.NamedTemporaryFile(
                        delete=False,
                        suffix=".exe"
                    ) as temp_file:

                        temp_path = temp_file.name
                        temp_file.write(uploaded_file.getvalue())

                    extracted_features = extract_basic_pe_info(temp_path)

                    missing_features = [
                        column for column in malware_columns
                        if column not in extracted_features
                    ]

                    if missing_features:
                        raise ValueError(
                            f"Missing model features: {missing_features}"
                        )

                    input_df = pd.DataFrame(
                        [[extracted_features[column] for column in malware_columns]],
                        columns=malware_columns
                    )

                    probabilities = malware_model.predict_proba(input_df)[0]
                    label = int(malware_model.predict(input_df)[0])

                    prediction = malware_labels.get(label, str(label))
                    confidence = float(max(probabilities))

                    if prediction == "Malware":
                        st.error("⚠️ Malware Classification!")
                    else:
                        st.success("File Classified as Benign")

                    st.write(f"**Prediction:** {prediction}")
                    st.write(f"**Confidence:** {confidence:.2%}")

                    save_scan(
                        scan_type="Malware",
                        target=uploaded_file.name,
                        prediction=prediction,
                        confidence=confidence,
                        details="Static PE feature analysis completed."
                    )

                except Exception as error:
                    st.error(f"Unable to analyze file: {error}")

                finally:
                    if temp_path and os.path.exists(temp_path):
                        os.remove(temp_path)


# ---------------- SCAN HISTORY ----------------

elif page == "Scan History":

    st.subheader("📋 Scan History")

    connection = get_connection()

    scans = connection.execute(
        """
        SELECT *
        FROM scan_history
        ORDER BY id DESC
        LIMIT 500
        """
    ).fetchall()

    connection.close()

    if scans:

        df = pd.DataFrame([dict(scan) for scan in scans])

        search = st.text_input("Search by target, type or prediction")

        if search:
            mask = df.astype(str).apply(
                lambda column: column.str.contains(
                    search,
                    case=False,
                    na=False
                )
            ).any(axis=1)

            df = df[mask]

        st.dataframe(df, use_container_width=True)

        st.write(f"**Records displayed:** {len(df)}")

    else:
        st.info("No scan history available yet.")


# ---------------- FOOTER ----------------

st.divider()

st.caption(
    "CyberShield Intelligence Platform | AI-Based Cybersecurity Project"
)
