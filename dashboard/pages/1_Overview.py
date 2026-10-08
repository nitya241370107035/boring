"""
SentinelLog Dashboard: Executive Overview & Severity Breakdown.
"""

import json
import pandas as pd
import plotly.express as px
import streamlit as st
from sqlalchemy.orm import Session

from api.db import AlertModel, EventModel, SessionLocal, init_db

st.title("📊 Executive SOC Overview")

init_db()
db: Session = SessionLocal()

alerts = db.query(AlertModel).all()
events = db.query(EventModel).order_by(EventModel.id.desc()).limit(500).all()
db.close()

if not alerts:
    st.info("No security alerts currently recorded. Ingest telemetry or run test attacks to populate alerts.")
else:
    alert_rows = [
        {
            "alert_id": a.alert_id,
            "ts": a.ts,
            "host": a.host,
            "rule_id": a.rule_id,
            "severity": a.severity,
            "score": a.score,
            "status": a.status,
            "count": a.count,
        }
        for a in alerts
    ]
    alert_df = pd.DataFrame(alert_rows)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Severity Distribution")
        sev_counts = alert_df["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        color_map = {
            "CRITICAL": "#da3633",
            "HIGH": "#bc4c00",
            "MEDIUM": "#d29922",
            "LOW": "#388bfd",
            "INFO": "#8b949e",
        }
        fig_donut = px.pie(
            sev_counts,
            names="severity",
            values="count",
            hole=0.45,
            color="severity",
            color_discrete_map=color_map,
            template="plotly_dark",
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    with col2:
        st.subheader("Alerts Over Time")
        alert_df["ts"] = pd.to_datetime(alert_df["ts"])
        fig_hist = px.histogram(
            alert_df,
            x="ts",
            color="severity",
            color_discrete_map=color_map,
            template="plotly_dark",
            nbins=20,
        )
        st.plotly_chart(fig_hist, use_container_width=True)

    st.subheader("Recent Alert Feed")
    st.dataframe(
        alert_df[["alert_id", "ts", "severity", "score", "rule_id", "host", "status", "count"]].tail(10),
        use_container_width=True,
    )
