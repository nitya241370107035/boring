"""
SentinelLog Dashboard: Interactive Security Alerts Management Feed.
Analyst triage interface with buttons to acknowledge alerts or flag false positives.
"""

from datetime import datetime, timezone
import json
import pandas as pd
import streamlit as st
from sqlalchemy.orm import Session

from api.db import AlertModel, FeedbackModel, SessionLocal, init_db

st.title("🚨 Security Alert Triage Feed")
st.markdown("Review and investigate security detections raised by rule signatures and machine learning.")

init_db()
db: Session = SessionLocal()

# Filters
col_f1, col_f2 = st.columns(2)
with col_f1:
    status_filter = st.selectbox("Filter Alert Status", ["all", "open", "acknowledged", "false_positive"], index=1)
with col_f2:
    sev_filter = st.multiselect(
        "Filter Severities",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=["CRITICAL", "HIGH", "MEDIUM"],
    )

query = db.query(AlertModel)
if status_filter != "all":
    query = query.filter(AlertModel.status == status_filter)
if sev_filter:
    query = query.filter(AlertModel.severity.in_(sev_filter))

alerts = query.order_by(AlertModel.id.desc()).limit(100).all()

if not alerts:
    st.info("No alerts match the selected criteria.")
else:
    for a in alerts:
        sev_color = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪",
        }.get(a.severity, "⚪")

        with st.expander(f"{sev_color} [{a.severity}] {a.rule_id} on {a.host} (Score: {a.score:.1f} | Hits: {a.count})"):
            c1, c2 = st.columns([3, 1])

            with c1:
                st.markdown(f"**Alert ID:** `{a.alert_id}` | **Detected at:** `{a.ts}`")
                reasons = json.loads(a.reasons_json)
                st.markdown("**Explainability Triggers:**")
                for r in reasons:
                    st.markdown(f"- {r}")

                st.markdown("**Raw Telemetry Evidence:**")
                try:
                    evidence = json.loads(a.evidence_json)
                    st.json(evidence)
                except Exception:
                    st.text(a.evidence_json)

            with c2:
                st.markdown(f"**Current Status:** `{a.status}`")
                if a.status == "open":
                    if st.button("✅ Acknowledge", key=f"ack_{a.alert_id}"):
                        a.status = "acknowledged"
                        fb = FeedbackModel(
                            alert_id=a.alert_id,
                            action="acknowledged",
                            comment="Triage analyst acknowledged",
                            ts=datetime.now(timezone.utc),
                        )
                        db.add(fb)
                        db.commit()
                        st.success("Alert acknowledged!")
                        st.experimental_rerun()

                    if st.button("❌ False Positive", key=f"fp_{a.alert_id}"):
                        a.status = "false_positive"
                        fb = FeedbackModel(
                            alert_id=a.alert_id,
                            action="false_positive",
                            comment="Marked as false positive by analyst",
                            ts=datetime.now(timezone.utc),
                        )
                        db.add(fb)
                        db.commit()
                        st.warning("Marked as False Positive!")
                        st.experimental_rerun()

db.close()
