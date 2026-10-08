"""
SentinelLog Dashboard: Exploratory Data Analysis & Threat Visualizations (GTU Practical 8).
Interactive Plotly charts, filters, and analytical security deductions.
"""

from pathlib import Path
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from pipeline.cleaner import clean
from pipeline.features import add_request_features, add_window_features
from pipeline.labeler import label_requests, load_rules
from pipeline.parser import parse_file
from pipeline.wrangle import create_pivots, enrich_geoip, ip_summary, resample_traffic


@st.cache_data(ttl=300)
def load_and_process_data(log_path: str = "tests/fixtures/sample_access.log") -> pd.DataFrame:
    """Cached loader for parsed, labeled, and feature-engineered log telemetry."""
    raw_df, _ = parse_file(log_path)
    cleaned = clean(raw_df)
    rules = load_rules("rules/web_rules.yaml")
    labeled = label_requests(cleaned, rules)
    req_feat = add_request_features(labeled)
    win_feat = add_window_features(req_feat)
    enriched = enrich_geoip(win_feat)
    return enriched


def render_eda_page():
    st.title("🛡️ Practical 8: Exploratory Data Analysis & Threat Visualizations")
    st.markdown(
        "Interactive analysis of ingested HTTP access logs: temporal bursts, "
        "attack origin clusters, and behavioral feature separations."
    )

    df = load_and_process_data()
    if df.empty:
        st.warning("No log telemetry available for EDA.")
        return

    # Sidebar Interactive Filters
    st.sidebar.header("🔍 Telemetry Filters")
    all_labels = sorted(df["label"].unique().tolist())
    selected_labels = st.sidebar.multiselect("Filter Attack Labels", all_labels, default=all_labels)

    all_countries = sorted(df["geo_country"].dropna().unique().tolist())
    selected_countries = st.sidebar.multiselect("Filter Countries", all_countries, default=all_countries)

    filtered_df = df[
        df["label"].isin(selected_labels) & df["geo_country"].isin(selected_countries)
    ].copy()

    st.sidebar.markdown(f"**Filtered Events:** {len(filtered_df)} / {len(df)}")

    # 1. KPI Cards Row
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    attack_count = (filtered_df["label"] != "benign").sum()
    kpi1.metric("Total Events", len(filtered_df))
    kpi2.metric("Detected Attacks", attack_count, delta=f"{(attack_count/len(filtered_df)*100 if len(filtered_df) else 0):.1f}%")
    kpi3.metric("Unique Client IPs", filtered_df["ip"].nunique())
    kpi4.metric("HTTP Status 4xx/5xx", (filtered_df["status"] >= 400).sum())

    st.divider()

    # 2. Requests Over Time & Attack Campaigns
    st.subheader("1. Temporal Attack Campaigns Over Time")
    col_t1, col_t2 = st.columns(2)

    with col_t1:
        resampled = resample_traffic(filtered_df, freq="1min")
        if not resampled.empty:
            fig_time = px.line(
                resampled,
                title="Requests per Minute (Traffic Rhythm)",
                labels={"value": "Requests", "ts": "Timestamp"},
                template="plotly_dark",
            )
            st.plotly_chart(fig_time, use_container_width=True)
            st.caption("Insight: High-frequency bursts within 1-minute windows highlight automated tooling vs human browsing.")

    with col_t2:
        fig_cat = px.histogram(
            filtered_df,
            x="ts",
            color="label",
            title="Attack Category Volume Over Time",
            template="plotly_dark",
        )
        st.plotly_chart(fig_cat, use_container_width=True)
        st.caption("Insight: Reconnaissance scanning (Nikto/404s) precedes credential brute-force and SQL injection attempts.")

    # 3. Attacker IPs & Status Code Distributions
    st.subheader("2. Attacker Attribution & Status Anomalies")
    col_a1, col_a2 = st.columns(2)

    with col_a1:
        summary_ip = ip_summary(filtered_df)
        if not summary_ip.empty:
            top10 = summary_ip.head(10)
            fig_ips = px.bar(
                top10,
                x="attacks",
                y="ip",
                orientation="h",
                color="attack_ratio",
                title="Top 10 Source IPs by Attack Volume",
                labels={"attacks": "Attack Count", "ip": "Client IP", "attack_ratio": "Attack Ratio"},
                template="plotly_dark",
            )
            st.plotly_chart(fig_ips, use_container_width=True)
            st.caption("Insight: A small cluster of adversarial IPs generates the vast majority of threats (Pareto 80/20 rule).")

    with col_a2:
        status_counts = filtered_df["status"].value_counts().reset_index()
        status_counts.columns = ["status", "count"]
        fig_status = px.pie(
            status_counts,
            names="status",
            values="count",
            title="HTTP Status Code Distribution",
            hole=0.4,
            template="plotly_dark",
        )
        st.plotly_chart(fig_status, use_container_width=True)
        st.caption("Insight: Elevated 401/403/404 proportions clearly indicate scanning probes and failed authentication bursts.")

    # 4. Heatmap: IP vs Attack Label
    st.subheader("3. Behavioral Signature Heatmap (IP vs Attack Category)")
    ct = pd.crosstab(filtered_df["ip"], filtered_df["label"])
    fig_heat = px.imshow(
        ct,
        labels=dict(x="Attack Category", y="Client IP", color="Count"),
        title="Cross-Tabulation: Attacker Activity Profile",
        template="plotly_dark",
        aspect="auto",
    )
    st.plotly_chart(fig_heat, use_container_width=True)
    st.caption("Insight: Visualizes attacker specialization (e.g. 192.0.2.44 exclusively targeting brute-force, 198.51.100.7 targeting SQLi).")

    # 5. Feature Distribution Separation
    st.subheader("4. Feature Separation (URL Entropy by Attack Class)")
    fig_box = px.box(
        filtered_df,
        x="label",
        y="url_entropy",
        color="label",
        title="Shannon Entropy Distributions Across Attack Categories",
        template="plotly_dark",
    )
    st.plotly_chart(fig_box, use_container_width=True)
    st.caption("Insight: SQL injection and obfuscated commands display statistically higher entropy than standard benign endpoints.")


if __name__ == "__main__":
    st.set_page_config(page_title="SentinelLog - EDA", layout="wide")
    render_eda_page()
