"""
SentinelLog Dashboard: Endpoint Telemetry & Process Tree Explorer.
Visualizes host process lifecycles, active TCP sockets, and ransomware file churn.
"""

import json
import pandas as pd
import plotly.express as px
import streamlit as st
from sqlalchemy.orm import Session

from api.db import EventModel, SessionLocal, init_db

st.title("💻 Windows Endpoint Telemetry Explorer")
st.markdown("Detailed investigation of host processes, network sockets, and file churn events.")

init_db()
db: Session = SessionLocal()

events = db.query(EventModel).filter(EventModel.source.startswith("agent_")).order_by(EventModel.id.desc()).limit(200).all()
db.close()

if not events:
    st.info("No host agent telemetry recorded yet. Start the agent with `python -m agent.main` to stream live events.")
else:
    rows = []
    for e in events:
        try:
            attrs = json.loads(e.attrs_json)
        except Exception:
            attrs = {}
        rows.append({
            "id": e.id,
            "ts": e.ts,
            "source": e.source,
            "action": e.action,
            "actor": e.actor,
            "target": e.target,
            "score": e.score,
            "attrs": attrs,
        })
    df = pd.DataFrame(rows)

    tab1, tab2, tab3 = st.tabs(["🚀 Process Trees & Starts", "🌐 Network Sockets", "📁 File Churn & Ransomware"])

    with tab1:
        st.subheader("Process Creation Telemetry")
        proc_df = df[df["action"] == "process_start"]
        if proc_df.empty:
            st.info("No process execution events recorded.")
        else:
            proc_table = []
            for _, r in proc_df.iterrows():
                attrs = r["attrs"]
                proc_table.append({
                    "Timestamp": r["ts"],
                    "Process Name": attrs.get("name", "unknown"),
                    "Parent Process": attrs.get("parent_name", "unknown"),
                    "PID": attrs.get("pid"),
                    "PPID": attrs.get("ppid"),
                    "User": attrs.get("user"),
                    "Command Line": attrs.get("cmdline"),
                    "Severity Score": r["score"],
                })
            st.dataframe(pd.DataFrame(proc_table), use_container_width=True)

    with tab2:
        st.subheader("Active TCP Network Sockets")
        net_df = df[df["action"] == "conn_open"]
        if net_df.empty:
            st.info("No network connection events recorded.")
        else:
            net_table = []
            for _, r in net_df.iterrows():
                attrs = r["attrs"]
                net_table.append({
                    "Timestamp": r["ts"],
                    "Process": r["actor"],
                    "Remote IP": attrs.get("remote_ip"),
                    "Remote Port": attrs.get("remote_port"),
                    "Local Socket": attrs.get("laddr"),
                })
            st.dataframe(pd.DataFrame(net_table), use_container_width=True)

    with tab3:
        st.subheader("File Modification Churn (Ransomware Flags)")
        churn_df = df[df["action"] == "file_churn"]
        if churn_df.empty:
            st.info("No high-frequency file churn detected.")
        else:
            churn_table = []
            for _, r in churn_df.iterrows():
                attrs = r["attrs"]
                churn_table.append({
                    "Timestamp": r["ts"],
                    "Sample File": r["target"],
                    "Modifications in Window": attrs.get("count"),
                    "Window Duration (s)": attrs.get("window_seconds"),
                    "Event Breakdown": str(attrs.get("event_breakdown")),
                })
            st.dataframe(pd.DataFrame(churn_table), use_container_width=True)
