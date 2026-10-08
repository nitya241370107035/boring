"""
SentinelLog Dashboard: Machine Learning Performance & Live Inference Tester.
Displays classifier evaluation metrics and provides an interactive inference sandbox.
"""

from pathlib import Path
import joblib
import pandas as pd
import streamlit as st

from models.evaluate import predict_event
from pipeline.cleaner import clean, deep_decode
from pipeline.features import add_request_features
from pipeline.parser import parse_line

st.title("🧠 Machine Learning Models & Explainability")
st.markdown("Model artifacts, comparative evaluation metrics, and real-time inference sandbox.")

bundle_path = Path("models/artifacts/rf_v1.joblib")
metrics_path = Path("reports/metrics.csv")
cat_path = Path("data/processed/feature_catalogue.csv")

col1, col2 = st.columns(2)
with col1:
    st.subheader("Active Model Bundle Metadata")
    if bundle_path.exists():
        bundle = joblib.load(bundle_path)
        st.markdown(f"• **Primary Estimator:** `{bundle.get('model_name', 'RandomForestClassifier')}`")
        st.markdown(f"• **Model Version:** `{bundle.get('version', '1.0')}`")
        st.markdown(f"• **Trained At:** `{bundle.get('trained_at')}`")
        st.markdown(f"• **Engineered Feature Dimensions:** `{len(bundle.get('features', []))}`")
    else:
        st.warning("Model bundle `rf_v1.joblib` not found. Run Practical 9 to train artifacts.")

with col2:
    st.subheader("Model Evaluation Benchmark")
    if metrics_path.exists():
        m_df = pd.read_csv(metrics_path)
        st.dataframe(m_df, use_container_width=True)
    else:
        st.info("Run `python -m pytest tests/test_models.py` or Notebook 09 to generate `metrics.csv`.")

st.divider()

# Live Inference Sandbox
st.subheader("🧪 Live Request Prediction Sandbox")
st.markdown("Test how the trained ML model rates arbitrary HTTP requests.")

test_url = st.text_input(
    "Test HTTP URL / Query",
    value="/products.php?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--",
)
test_method = st.selectbox("HTTP Method", ["GET", "POST", "HEAD", "PUT"], index=0)
test_status = st.number_input("HTTP Status Code", value=200, min_value=100, max_value=599)
test_ua = st.text_input("User-Agent", value="sqlmap/1.7")

if st.button("⚡ Run ML Inference"):
    # Synthesize sample log line
    sample_line = f'203.0.113.10 - - [10/Oct/2026:14:00:00 +0000] "{test_method} {test_url} HTTP/1.1" {test_status} 512 "-" "{test_ua}"'
    parsed = parse_line(sample_line)
    if parsed:
        df_single = pd.DataFrame([parsed])
        df_single["ts"] = pd.to_datetime(df_single["ts"], format="%d/%b/%Y:%H:%M:%S %z", utc=True)
        df_single["status"] = int(test_status)
        df_single["bytes"] = 512
        cleaned = clean(df_single)
        features_df = add_request_features(cleaned)

        probs, anomalies = predict_event(features_df)
        prob = float(probs[0])
        ano = float(anomalies[0])

        res_col1, res_col2 = st.columns(2)
        with res_col1:
            st.metric("ML Attack Probability", f"{prob*100:.1f}%")
            if prob >= 0.70:
                st.error("🚨 High Attack Confidence (Supervised Model)")
            else:
                st.success("✅ Benign Confidence")

        with res_col2:
            st.metric("Unsupervised Anomaly Score", f"{ano*100:.1f}%")
            if ano >= 0.60:
                st.warning("⚠️ High Anomaly Outlier (Isolation Forest)")
            else:
                st.info("ℹ️ Typical Profile")

st.divider()

# Feature Catalogue View
if cat_path.exists():
    with st.expander("📖 Inspect Master Feature Catalogue"):
        cat_df = pd.read_csv(cat_path)
        st.dataframe(cat_df, use_container_width=True)
