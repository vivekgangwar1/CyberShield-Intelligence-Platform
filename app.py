
import json
import os
import tempfile
import traceback
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from backend.database import (
    initialize_database,
    save_scan,
    get_connection
)

from utils.pe_feature_extractor import extract_basic_pe_info


# ==================================================
# 1. PROJECT PATHS
# ==================================================

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"

PHISHING_MODEL_PATH = MODELS_DIR / "phishing_url_text_model.pkl"
INTRUSION_MODEL_PATH = MODELS_DIR / "intrusion_detection_model.pkl"
MALWARE_MODEL_PATH = MODELS_DIR / "malware_classification_model.pkl"

INTRUSION_THRESHOLD = 0.20
MAX_FILE_SIZE = 100 * 1024 * 1024


# ==================================================
# 2. PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="CyberShield Intelligence Platform",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CyberShield Intelligence Platform")
st.caption("AI-Based Cybersecurity Detection Dashboard")


# ==================================================
# 3. DATABASE INITIALIZATION
# ==================================================

try:
    initialize_database()

except Exception as error:
    st.error(f"Database initialization failed: {error}")
    st.code(traceback.format_exc())
    st.stop()


# ==================================================
# 4. LOAD AI MODELS
# ==================================================

@st.cache_resource
def load_models():

    # Check model files

    required_files = [
        PHISHING_MODEL_PATH,
        INTRUSION_MODEL_PATH,
        MALWARE_MODEL_PATH
    ]

    for file_path in required_files:

        if not file_path.is_file():

            raise FileNotFoundError(
                f"Model file not found: {file_path}"
            )

    # Load phishing model

    phishing = joblib.load(
        PHISHING_MODEL_PATH
    )

    # Load intrusion model

    intrusion = joblib.load(
        INTRUSION_MODEL_PATH
    )

    # Load malware model bundle

    malware_bundle = joblib.load(
        MALWARE_MODEL_PATH
    )

    if not isinstance(malware_bundle, dict):

        raise ValueError(
            "Malware model bundle must be a dictionary."
        )

    required_keys = [
        "model",
        "feature_columns",
        "label_mapping"
    ]

    for key in required_keys:

        if key not in malware_bundle:

            raise ValueError(
                f"Missing malware bundle key: {key}"
            )

    malware = malware_bundle["model"]

    malware_columns = malware_bundle["feature_columns"]

    malware_labels = malware_bundle["label_mapping"]

    return (
        phishing,
        intrusion,
        malware,
        malware_columns,
        malware_labels
    )


try:

    (
        phishing_model,
        intrusion_model,
        malware_model,
        malware_columns,
        malware_labels
    ) = load_models()

    st.sidebar.success("All AI models loaded successfully")

except Exception as error:

    st.error(f"Unable to load models: {error}")

    st.subheader("Detailed Error Information")

    st.code(traceback.format_exc())

    st.stop()


# ==================================================
# 5. SIDEBAR NAVIGATION
# ==================================================

st.sidebar.title("🛡️ CyberShield")

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


# ==================================================
# 6. DASHBOARD
# ==================================================

if page == "Dashboard":

    st.subheader("📊 Dashboard Overview")

    connection = get_connection()

    try:

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

    finally:

        connection.close()

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Scans", total_scans)
    col2.metric("Phishing Scans", phishing_scans)
    col3.metric("Intrusion Scans", intrusion_scans)
    col4.metric("Malware Scans", malware_scans)

    st.divider()

    st.subheader("Available Security Modules")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.info("🌐 Phishing Detection")

        st.write(
            "Detect potentially malicious and phishing URLs."
        )

    with col2:

        st.info("🔍 Network Intrusion")

        st.write(
            "Classify supplied network connection features."
        )

    with col3:

        st.info("🦠 Malware Scanner")

        st.write(
            "Analyze Windows EXE files using static PE features."
        )

    st.divider()

    st.warning(
        "AI predictions are not guarantees of safety. "
        "Network detection analyzes supplied features, not live traffic."
    )


# ==================================================
# 7. PHISHING URL DETECTION
# ==================================================

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

            try:

                clean_url = url.strip()

                prediction = int(
                    phishing_model.predict([clean_url])[0]
                )

                probabilities = phishing_model.predict_proba(
                    [clean_url]
                )[0]

                classes = list(
                    phishing_model.classes_
                )

                prediction_index = classes.index(prediction)

                confidence = float(
                    probabilities[prediction_index]
                )

                if prediction == 0:

                    result = "Phishing"

                    st.error(
                        "⚠️ Phishing URL Detected!"
                    )

                else:

                    result = "Legitimate"

                    st.success(
                        "URL Classified as Legitimate"
                    )

                st.write(f"**Prediction:** {result}")

                st.write(
                    f"**Confidence:** {confidence:.2%}"
                )

                message = (
                    "The model classified this URL as phishing."
                    if prediction == 0
                    else
                    "The model classified this URL as legitimate. "
                    "This does not guarantee that the website is safe."
                )

                save_scan(
                    scan_type="Phishing",
                    target=clean_url,
                    prediction=result,
                    confidence=confidence,
                    details=message
                )

            except Exception as error:

                st.error(
                    f"Phishing analysis failed: {error}"
                )


# ==================================================
# 8. NETWORK INTRUSION DETECTION
# ==================================================

elif page == "Network Intrusion":

    st.subheader("🔍 Network Intrusion Detection")

    st.write(
        "Enter all 41 NSL-KDD network features in JSON format."
    )

    example = {

        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 181,
        "dst_bytes": 5450,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 1,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 1,
        "srv_count": 1,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 1,
        "dst_host_srv_count": 1,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0

    }

    features_text = st.text_area(
        "Network Features (JSON)",
        value=json.dumps(example, indent=4),
        height=500
    )

    if st.button(
        "Analyze Network Features",
        type="primary"
    ):

        try:

            features = json.loads(features_text)

            if not isinstance(features, dict):

                raise ValueError(
                    "JSON must contain an object."
                )

            if not hasattr(
                intrusion_model,
                "feature_names_in_"
            ):

                raise ValueError(
                    "Model does not contain training feature names."
                )

            expected_features = list(
                intrusion_model.feature_names_in_
            )

            missing_features = [
                feature
                for feature in expected_features
                if feature not in features
            ]

            extra_features = [
                feature
                for feature in features
                if feature not in expected_features
            ]

            if missing_features:

                raise ValueError(
                    f"Missing features: {missing_features}"
                )

            if extra_features:

                raise ValueError(
                    f"Unexpected features: {extra_features}"
                )

            input_df = pd.DataFrame(
                [[
                    features[column]
                    for column in expected_features
                ]],
                columns=expected_features
            )

            probabilities = intrusion_model.predict_proba(
                input_df
            )[0]

            classes = list(
                intrusion_model.classes_
            )

            if 1 not in classes:

                raise ValueError(
                    "Attack class 1 not found in model classes."
                )

            attack_index = classes.index(1)

            attack_probability = float(
                probabilities[attack_index]
            )

            prediction = (
                "Attack"
                if attack_probability >= INTRUSION_THRESHOLD
                else
                "Normal"
            )

            if prediction == "Attack":

                st.error(
                    "⚠️ Potential Network Attack Detected!"
                )

            else:

                st.success(
                    "Normal Traffic Classification"
                )

            st.write(
                f"**Prediction:** {prediction}"
            )

            st.write(
                f"**Attack Probability:** {attack_probability:.2%}"
            )

            save_scan(
                scan_type="Intrusion",
                target="Supplied network traffic features",
                prediction=prediction,
                confidence=attack_probability,
                details="Network feature classification completed."
            )

        except Exception as error:

            st.error(
                f"Network analysis failed: {error}"
            )


# ==================================================
# 9. MALWARE STATIC SCANNER
# ==================================================

elif page == "Malware Scanner":

    st.subheader("🦠 Malware EXE Static Scanner")

    st.warning(
        "Uploaded EXE files are analyzed statically. "
        "They are never executed."
    )

    uploaded_file = st.file_uploader(
        "Upload EXE File",
        type=["exe"]
    )

    if uploaded_file is not None:

        st.write(
            f"**File:** {uploaded_file.name}"
        )

        st.write(
            f"**Size:** {uploaded_file.size / (1024 * 1024):.2f} MB"
        )

        if st.button(
            "Scan EXE",
            type="primary"
        ):

            if uploaded_file.size > MAX_FILE_SIZE:

                st.error(
                    "File size must not exceed 100 MB."
                )

            else:

                temp_path = None

                try:

                    with tempfile.NamedTemporaryFile(
                        delete=False,
                        suffix=".exe"
                    ) as temp_file:

                        temp_path = temp_file.name

                        temp_file.write(
                            uploaded_file.getvalue()
                        )

                    # Extract static PE features

                    extracted_features = extract_basic_pe_info(
                        temp_path
                    )

                    missing_features = [
                        column
                        for column in malware_columns
                        if column not in extracted_features
                    ]

                    if missing_features:

                        raise ValueError(
                            f"Missing model features: {missing_features}"
                        )

                    input_df = pd.DataFrame(
                        [[
                            extracted_features[column]
                            for column in malware_columns
                        ]],
                        columns=malware_columns
                    )

                    probabilities = malware_model.predict_proba(
                        input_df
                    )[0]

                    label = malware_model.predict(
                        input_df
                    )[0]

                    prediction = malware_labels.get(
                        label,
                        malware_labels.get(
                            str(label),
                            str(label)
                        )
                    )

                    prediction = str(prediction)

                    classes = list(
                        malware_model.classes_
                    )

                    prediction_index = classes.index(label)

                    confidence = float(
                        probabilities[prediction_index]
                    )

                    if prediction.lower() == "malware":

                        st.error(
                            "⚠️ Malware Classification!"
                        )

                    else:

                        st.success(
                            "File Classified as Benign"
                        )

                    st.write(
                        f"**Prediction:** {prediction}"
                    )

                    st.write(
                        f"**Confidence:** {confidence:.2%}"
                    )

                    save_scan(
                        scan_type="Malware",
                        target=uploaded_file.name,
                        prediction=prediction,
                        confidence=confidence,
                        details="Static PE feature analysis completed."
                    )

                except Exception as error:

                    st.error(
                        f"Unable to analyze file: {error}"
                    )

                finally:

                    if temp_path and os.path.exists(temp_path):

                        os.remove(temp_path)


# ==================================================
# 10. SCAN HISTORY
# ==================================================

elif page == "Scan History":

    st.subheader("📋 Scan History")

    connection = get_connection()

    try:

        scans = connection.execute(
            """
            SELECT *
            FROM scan_history
            ORDER BY id DESC
            LIMIT 500
            """
        ).fetchall()

    finally:

        connection.close()

    if scans:

        df = pd.DataFrame(
            [dict(scan) for scan in scans]
        )

        search = st.text_input(
            "Search by target, type or prediction"
        )

        if search:

            mask = df.astype(str).apply(
                lambda column: column.str.contains(
                    search,
                    case=False,
                    na=False
                )
            ).any(axis=1)

            df = df[mask]

        st.dataframe(
            df,
            use_container_width=True
        )

        st.write(
            f"**Records displayed:** {len(df)}"
        )

    else:

        st.info(
            "No scan history available yet."
        )


# ==================================================
# 11. FOOTER
# ==================================================

st.divider()

st.caption(
    "🛡️ CyberShield Intelligence Platform | "
    "AI-Based Cybersecurity Detection Dashboard"
)
