"""
SentinelLog Dashboard: Monitored Windows Endpoints & Fleet Health.
Tracks agent heartbeats, CPU/RAM resource bounds, and offline alerts.
"""

from datetime import datetime, timezone
import pandas as pd
import streamlit as st
from sqlalchemy.orm import Session

from api.db import HostModel, SessionLocal, init_db

st.title("🖥️ Monitored Endpoint Fleet")
st.markdown("Real-time telemetry and resource usage tracking across monitored Windows hosts.")

init_db()
db: Session = SessionLocal()
hosts = db.query(HostModel).all()
db.close()

if not hosts:
    st.info("No endpoint agents currently registered. Start an agent using `python -m agent.main`.")
else:
    rows = []
    now = datetime.now(timezone.utc)
    for h in hosts:
        # Determine online vs offline based on last heartbeat within 180 seconds
        is_online = True
        if h.last_heartbeat:
            delta = (now - h.last_heartbeat.replace(tzinfo=timezone.utc)).total_seconds()
            if delta > 180:
                is_online = False

        rows.append({
            "Hostname": h.host,
            "Agent ID": h.agent_id,
            "Status": "🟢 Online" if is_online else "🔴 Offline (>3m silent)",
            "Last Heartbeat (UTC)": h.last_heartbeat.strftime("%Y-%m-%d %H:%M:%S") if h.last_heartbeat else "Never",
            "Agent CPU (%)": f"{h.cpu_percent:.2f}%",
            "Agent RAM (MB)": f"{h.ram_mb:.1f} MB",
            "Operating System": h.os,
        })

    fleet_df = pd.DataFrame(rows)
    st.dataframe(fleet_df, use_container_width=True)

    st.subheader("Agent Safety & Performance Standards")
    st.markdown(
        """
        - **CPU Guardrail**: Agent throttles polling to remain $< 2\%$ CPU utilization.
        - **RAM Guardrail**: Footprint capped $< 100\text{ MB}$.
        - **Heartbeat Cadence**: Periodic ping every 60 seconds; flagged offline if silent for $> 3$ minutes.
        """
    )
