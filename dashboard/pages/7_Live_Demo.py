"""
SentinelLog Dashboard: Real-Time Threat Stream & Live Demo Simulator.
Provides real-time event streaming and one-click attack simulations for live demonstrations.
"""

from datetime import datetime, timezone
import json
import os
import time
import pandas as pd
import requests
import streamlit as st
from sqlalchemy.orm import Session

from api.db import AlertModel, EventModel, SessionLocal, init_db

st.title("⚡ Live Threat Stream & Attack Simulator")
st.markdown("Live operational stream of ingested security telemetry with one-click attack triggers.")

API_URL = os.environ.get("DASHBOARD_API_URL", "http://127.0.0.1:8000")
API_KEY = "sentinel-secret-key-1"

# Simulation Controls
st.subheader("🎯 Live Attack Simulation Triggers (Harmless)")
st.caption("Click to fire simulated threats into the platform and observe real-time detection & scoring.")

c1, c2, c3 = st.columns(3)

with c1:
    if st.button("💉 Simulate SQLi Web Attack", use_container_width=True):
        payload = {
            "events": [
                {
                    "ip": "198.51.100.99",
                    "method": "GET",
                    "url": "/login.php?user=admin%27%20OR%201%3D1--",
                    "raw_url": "/login.php?user=admin%27%20OR%201%3D1--",
                    "decoded_url": "/login.php?user=admin' OR 1=1--",
                    "status": 200,
                    "ua": "sqlmap/1.7",
                    "rule_ids": ["WEB-SQLI-001"],
                    "label": "sqli",
                    "url_length": 35,
                    "query_length": 25,
                    "num_params": 1,
                    "special_chars": 7,
                    "special_ratio": 0.2,
                    "digit_ratio": 0.05,
                    "upper_ratio": 0.15,
                    "url_entropy": 4.5,
                    "has_sql_kw": 1,
                    "has_script_tag": 0,
                    "has_traversal": 0,
                    "has_cmd_kw": 0,
                    "method_is_post": 0,
                    "is_rare_method": 0,
                    "is_404": 0,
                }
            ]
        }
        try:
            r = requests.post(
                f"{API_URL}/ingest/weblog",
                json=payload,
                headers={"X-API-Key": API_KEY},
                timeout=3,
            )
            st.success(f"Injected SQLi attack! (API Response: HTTP {r.status_code})")
        except Exception as e:
            st.warning(f"Failed to post to API (is server running?): {e}")

with c2:
    if st.button("🐚 Simulate Encoded PowerShell", use_container_width=True):
        payload = {
            "events": [
                {
                    "action": "process_start",
                    "host": "demo-workstation",
                    "name": "powershell.exe",
                    "parent_name": "winword.exe",
                    "target": "powershell.exe -enc ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==",
                    "cmdline": "powershell.exe -enc ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==",
                    "rule_hits": [
                        {"id": "EP-PROC-001", "name": "Office spawning shell", "severity": 85},
                        {"id": "EP-PROC-002", "name": "Encoded PowerShell command", "severity": 80},
                    ],
                }
            ]
        }
        try:
            r = requests.post(
                f"{API_URL}/ingest/agent",
                json=payload,
                headers={"X-API-Key": API_KEY},
                timeout=3,
            )
            st.success(f"Injected Encoded PowerShell event! (HTTP {r.status_code})")
        except Exception as e:
            st.warning(f"Failed to post to API: {e}")

with c3:
    if st.button("📁 Simulate File Churn Burst", use_container_width=True):
        payload = {
            "events": [
                {
                    "action": "file_churn",
                    "host": "demo-workstation",
                    "target": "C:\\Users\\Public\\Desktop\\data.crypt",
                    "rule_hits": [
                        {"id": "EP-FILE-001", "name": "Mass file modification (ransomware)", "severity": 90}
                    ],
                    "attrs": {"count": 120, "window_seconds": 10},
                }
            ]
        }
        try:
            r = requests.post(
                f"{API_URL}/ingest/agent",
                json=payload,
                headers={"X-API-Key": API_KEY},
                timeout=3,
            )
            st.success(f"Injected File Churn burst! (HTTP {r.status_code})")
        except Exception as e:
            st.warning(f"Failed to post to API: {e}")

st.divider()

# Live Event Stream Table
st.subheader("🔴 Live Event Feed (Last 50 Records)")
auto_refresh = st.checkbox("Auto-refresh stream (every 3 seconds)", value=False)

init_db()
db: Session = SessionLocal()
latest_events = db.query(EventModel).order_by(EventModel.id.desc()).limit(50).all()
db.close()

if not latest_events:
    st.info("No events in stream yet.")
else:
    rows = []
    for ev in latest_events:
        sev_badge = "🔴 High" if ev.score >= 60 else ("🟡 Med" if ev.score >= 40 else "🟢 Low")
        rows.append({
            "ID": ev.id,
            "Timestamp": ev.ts.strftime("%H:%M:%S") if ev.ts else "",
            "Source": ev.source,
            "Host": ev.host,
            "Action": ev.action,
            "Target": ev.target[:60] if ev.target else "",
            "Severity Score": f"{ev.score:.1f}",
            "Risk": sev_badge,
            "Label": ev.label,
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True)

if auto_refresh:
    time.sleep(3)
    st.experimental_rerun()
