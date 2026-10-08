"""
SentinelLog: Real-World Log Analysis & Endpoint Threat Detection Platform.
Main Streamlit Portal & Central Navigation Shell.
"""

from datetime import datetime
import os
from pathlib import Path
import requests
import streamlit as st
from sqlalchemy.orm import Session

from api.db import AlertModel, EventModel, HostModel, SessionLocal, init_db

st.set_page_config(
    page_title="SentinelLog Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark Glassmorphic Styling
st.markdown(
    """
    <style>
    .main {
        background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
        color: #e6edf3;
    }
    .kpi-card {
        background: rgba(22, 27, 34, 0.7);
        border: 1px solid rgba(48, 54, 61, 0.8);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
        backdrop-filter: blur(10px);
        margin-bottom: 16px;
    }
    .kpi-title {
        color: #8b949e;
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .kpi-val {
        color: #58a6ff;
        font-size: 2rem;
        font-weight: 700;
        margin-top: 4px;
    }
    .badge-critical {
        background-color: #da3633;
        color: white;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: bold;
    }
    .badge-high {
        background-color: #bc4c00;
        color: white;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: bold;
    }
    .badge-online {
        color: #3fb950;
        font-weight: bold;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def get_api_status() -> tuple[bool, str]:
    api_url = os.environ.get("DASHBOARD_API_URL", "http://127.0.0.1:8000")
    try:
        r = requests.get(f"{api_url}/health", timeout=1.5)
        if r.status_code == 200:
            return True, "API Connected (Live Server)"
    except Exception:
        pass
    return False, "Local Database Mode (SQLite Direct)"


def get_system_counts() -> dict[str, int]:
    try:
        init_db()
        db: Session = SessionLocal()
        total_events = db.query(EventModel).count()
        open_alerts = db.query(AlertModel).filter(AlertModel.status == "open").count()
        total_hosts = db.query(HostModel).count()
        critical_alerts = db.query(AlertModel).filter(AlertModel.severity == "CRITICAL").count()
        db.close()
        return {
            "events": total_events,
            "open_alerts": open_alerts,
            "hosts": max(1, total_hosts),
            "critical_alerts": critical_alerts,
        }
    except Exception:
        return {"events": 0, "open_alerts": 0, "hosts": 1, "critical_alerts": 0}


def main():
    # Sidebar
    st.sidebar.image("https://raw.githubusercontent.com/tandpfun/skill-icons/main/icons/Python-Dark.svg", width=50)
    st.sidebar.title("SentinelLog")
    st.sidebar.caption("GTU PDS Final Platform | Sem V")

    api_online, api_status_text = get_api_status()
    if api_online:
        st.sidebar.success(f"🟢 {api_status_text}")
    else:
        st.sidebar.info(f"💾 {api_status_text}")

    st.sidebar.divider()
    st.sidebar.markdown(
        """
        ### 📌 Navigation
        Use the sidebar pages to navigate:
        - **1. Overview**: System KPIs & severity donuts
        - **2. Alerts**: Real-time SOC triage feed
        - **3. Web Traffic**: Practical 8 visual analytics
        - **4. Endpoint**: Process trees & telemetry
        - **5. Model**: ML benchmarks & live tester
        - **6. Agents**: Monitored PC fleet health
        - **7. Live Demo**: Real-time event stream
        """
    )

    # Main Page
    st.title("🛡️ SentinelLog Security Operations Center")
    st.markdown(
        "**Hybrid Web Log Analysis & Windows Endpoint Threat Detection Platform**  \n"
        "*Combines signature detection (YAML/MITRE), statistical host baselines, and machine learning into explainable alerts.*"
    )

    counts = get_system_counts()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-title">Total Telemetry Events</div>
                <div class="kpi-val">{counts['events']:,}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-title">Open Security Alerts</div>
                <div class="kpi-val" style="color: #f85149;">{counts['open_alerts']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-title">Critical Threats</div>
                <div class="kpi-val" style="color: #ff7b72;">{counts['critical_alerts']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-title">Active Monitored Hosts</div>
                <div class="kpi-val" style="color: #3fb950;">{counts['hosts']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    # Architecture Breakdown
    c_arch1, c_arch2 = st.columns(2)
    with c_arch1:
        st.subheader("🌐 Telemetry Pipeline (Practicals 1–10)")
        st.markdown(
            """
            - **Ingestion & Streaming**: Raw Apache/Nginx combined logs streamed with reservoir sampling.
            - **Deep Sanitization**: Multi-pass URL decoding defeats `%2527` evasion techniques.
            - **Dual-Level Features**: URL Shannon entropy, special character density, and 5-min IP rolling rates.
            - **Balanced Classification**: Random Forest & XGBoost models evaluated with zero data leakage.
            - **Explainability**: Every alert maps back to rule IDs, OWASP Top 10, and MITRE ATT&CK techniques.
            """
        )
    with c_arch2:
        st.subheader("💻 Live Windows Host Agent (Bonus Extension)")
        st.markdown(
            """
            - **Process Trees**: Snapshot diffing catches Office launching shells (`winword` → `powershell`).
            - **Ransomware Churn**: Watchdog observer flags mass file modifications in seconds.
            - **Network Sockets**: Maps established TCP connections to owning process binaries.
            - **Offline Resilience**: Local SQLite queue (`agent_buffer.db`) ensures zero event loss during network outages.
            """
        )


if __name__ == "__main__":
    main()
