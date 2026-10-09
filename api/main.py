"""
SentinelLog API: Central Ingestion Service & Security Alerting Backend.
Exposes RESTful endpoints for agent telemetry, web logs, event exploration,
alert lifecycle management, and host health monitoring.
"""

from datetime import datetime, timezone
import json
import logging
import os
from typing import Any
import uuid
from pathlib import Path
import pandas as pd
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from api.auth import verify_api_key
from api.db import AlertModel, EventModel, FeedbackModel, HostModel, get_db, init_db
from api.schemas import (
    AgentBatchRequest,
    AlertResponse,
    AlertUpdateRequest,
    HealthResponse,
    HostStatusResponse,
    WebLogBatchRequest,
)
from api.scoring import AlertSuppressionEngine, BaselineStore, calculate_severity
from api.notifier import dispatch_alert
from models.evaluate import predict_event

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
)
logger = logging.getLogger("sentinellog.api")

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("SentinelLog API database initialized.")
    yield

app = FastAPI(
    title="SentinelLog Threat Detection API",
    description="Real-world log analysis and endpoint threat detection platform",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for interactive frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global engines
suppression_engine = AlertSuppressionEngine(suppression_window_seconds=600.0)
baseline_store = BaselineStore()


@app.get("/health", response_model=HealthResponse)
def health():
    """Liveness probe for Docker container orchestrators."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "db_connected": True,
    }


@app.post("/ingest/agent", dependencies=[Depends(verify_api_key)])
def ingest_agent(batch: AgentBatchRequest, db: Session = Depends(get_db)):
    """
    Ingests batched host telemetry from endpoint agents.
    Evaluates scoring, baseline novelty, suppresses alert storms, and persists events.
    """
    received_count = len(batch.events)
    alerts_raised = 0

    for ev in batch.events:
        # Register or update host record for any event originating from this host
        host_rec = db.query(HostModel).filter(HostModel.host == ev.host).first()
        if not host_rec:
            host_rec = HostModel(
                host=ev.host,
                agent_id=ev.agent_id or batch.agent_id or "agent-win",
                status="active",
                last_heartbeat=datetime.now(timezone.utc),
                cpu_percent=0.8,
                ram_mb=42.5,
                os="Windows 11",
            )
            db.add(host_rec)
        else:
            host_rec.last_heartbeat = datetime.now(timezone.utc)
            host_rec.status = "active"

        # Check heartbeat actions
        if ev.action == "heartbeat":
            host_rec.agent_id = ev.agent_id or batch.agent_id or host_rec.agent_id or "agent-win"
            attrs = ev.attrs or {}
            host_rec.cpu_percent = float(attrs.get("cpu_percent", host_rec.cpu_percent or 0.8))
            host_rec.ram_mb = float(attrs.get("ram_mb", host_rec.ram_mb or 42.5))
            host_rec.os = str(attrs.get("os", host_rec.os or "Windows 11"))
            db.commit()
            continue

        # Baseline novelty check
        is_novel = False
        if ev.action == "process_start" and ev.name:
            is_novel = baseline_store.check_and_record_novelty(ev.host, "process", ev.name)
        elif ev.action == "conn_open" and ev.remote_ip:
            is_novel = baseline_store.check_and_record_novelty(ev.host, "remote_ip", ev.remote_ip)

        # Multi-layer score calculation
        score, severity, reasons = calculate_severity(
            rule_hits=ev.rule_hits,
            baseline_novelty=is_novel,
        )

        event_id = f"evt-{uuid.uuid4().hex[:12]}"
        db_event = EventModel(
            event_id=event_id,
            source=ev.source,
            host=ev.host,
            actor=ev.actor or "unknown",
            action=ev.action,
            target=ev.target or "",
            attrs_json=json.dumps(ev.attrs or {}),
            label="attack" if score >= 60 else "benign",
            score=score,
            reasons_json=json.dumps(reasons),
        )
        db.add(db_event)

        # Raise alert if severity is MEDIUM, HIGH, or CRITICAL (score >= 40)
        if score >= 40 and ev.rule_hits:
            top_rule = ev.rule_hits[0]["id"]
            target_entity = ev.target or ev.action
            is_suppressed, alert_id, count = suppression_engine.process_alert(
                host=ev.host,
                rule_id=top_rule,
                target=target_entity,
            )

            if is_suppressed:
                # Update existing alert count
                existing = db.query(AlertModel).filter(AlertModel.alert_id == alert_id).first()
                if existing:
                    existing.count = count
                    existing.ts = datetime.now(timezone.utc)
            else:
                new_alert = AlertModel(
                    alert_id=alert_id,
                    host=ev.host,
                    rule_id=top_rule,
                    severity=severity,
                    score=score,
                    status="open",
                    reasons_json=json.dumps(reasons),
                    evidence_json=json.dumps(ev.model_dump()),
                    count=1,
                )
                db.add(new_alert)
                alerts_raised += 1
                dispatch_alert(severity, score, ev.host, top_rule, target_entity, reasons)

    db.commit()
    return {"received": received_count, "new_alerts": alerts_raised}


@app.post("/ingest/weblog", dependencies=[Depends(verify_api_key)])
def ingest_weblog(batch: WebLogBatchRequest, db: Session = Depends(get_db)):
    """Ingests processed web access log records with ML inference."""
    import pandas as pd
    received = len(batch.events)
    if received == 0:
        return {"received": 0, "new_alerts": 0}

    df = pd.DataFrame(batch.events)
    # Run ML prediction
    probs, anomalies = predict_event(df)

    alerts_raised = 0
    for idx, row in df.iterrows():
        ml_p = float(probs[idx])
        ano_s = float(anomalies[idx])
        rule_hits = [{"id": rid, "name": rid, "severity": 70} for rid in row.get("rule_ids", [])]

        score, severity, reasons = calculate_severity(
            rule_hits=rule_hits,
            ml_prob=ml_p,
            anomaly=ano_s,
        )

        db_event = EventModel(
            event_id=f"web-{uuid.uuid4().hex[:12]}",
            source="weblog",
            host=row.get("host", "web-server"),
            actor=str(row.get("ip", "unknown")),
            action=f"{row.get('method', 'GET')} {row.get('path', '/')}",
            target=str(row.get("raw_url", "")),
            attrs_json=json.dumps({"status": row.get("status"), "ua": row.get("ua")}),
            label=row.get("label", "benign"),
            score=score,
            reasons_json=json.dumps(reasons),
        )
        db.add(db_event)

        if score >= 60 and rule_hits:
            top_rule = rule_hits[0]["id"]
            is_suppressed, alert_id, count = suppression_engine.process_alert(
                host="web-server",
                rule_id=top_rule,
                target=str(row.get("ip", "")),
            )
            if not is_suppressed:
                new_alert = AlertModel(
                    alert_id=alert_id,
                    host="web-server",
                    rule_id=top_rule,
                    severity=severity,
                    score=score,
                    status="open",
                    reasons_json=json.dumps(reasons),
                    evidence_json=json.dumps(row.to_dict()),
                    count=1,
                )
                db.add(new_alert)
                alerts_raised += 1

    db.commit()
    return {"received": received, "new_alerts": alerts_raised}


@app.get("/events")
def list_events(
    limit: int = Query(50, le=500),
    host: str | None = None,
    min_score: float = 0.0,
    db: Session = Depends(get_db),
):
    """Retrieves paginated events with optional host and score filters."""
    query = db.query(EventModel).filter(EventModel.score >= min_score)
    if host:
        query = query.filter(EventModel.host == host)

    records = query.order_by(EventModel.id.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "event_id": r.event_id,
            "ts": r.ts.isoformat(),
            "source": r.source,
            "host": r.host,
            "actor": r.actor,
            "action": r.action,
            "target": r.target,
            "label": r.label,
            "score": r.score,
            "reasons": json.loads(r.reasons_json),
        }
        for r in records
    ]


@app.get("/alerts")
def list_alerts(
    status: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Lists security alerts filtered by status (open, acknowledged, false_positive)."""
    query = db.query(AlertModel)
    if status:
        query = query.filter(AlertModel.status == status)

    records = query.order_by(AlertModel.id.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "alert_id": r.alert_id,
            "ts": r.ts.isoformat(),
            "host": r.host,
            "rule_id": r.rule_id,
            "severity": r.severity,
            "score": r.score,
            "status": r.status,
            "count": r.count,
            "reasons": json.loads(r.reasons_json),
            "evidence": json.loads(r.evidence_json),
        }
        for r in records
    ]


@app.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: str,
    update: AlertUpdateRequest,
    db: Session = Depends(get_db),
):
    """Updates an alert status (e.g. acknowledge or flag as false positive)."""
    alert = db.query(AlertModel).filter(AlertModel.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = update.status
    # Record analyst feedback
    feedback = FeedbackModel(
        alert_id=alert_id,
        action=update.status,
        comment=update.comment or "",
    )
    db.add(feedback)
    db.commit()
    return {"status": "updated", "alert_id": alert_id, "new_status": alert.status}


@app.get("/hosts")
def list_hosts(db: Session = Depends(get_db)):
    """Returns the fleet of monitored Windows endpoints and their status."""
    hosts = db.query(HostModel).all()
    return [
        {
            "host": h.host,
            "agent_id": h.agent_id,
            "last_heartbeat": h.last_heartbeat.isoformat() if h.last_heartbeat else None,
            "status": h.status,
            "cpu_percent": h.cpu_percent,
            "ram_mb": h.ram_mb,
            "os": h.os,
        }
        for h in hosts
    ]


@app.get("/metrics")
def get_metrics(db: Session = Depends(get_db)):
    """Returns operational KPIs and platform counters."""
    total_events = db.query(EventModel).count()
    open_alerts = db.query(AlertModel).filter(AlertModel.status == "open").count()
    total_hosts = db.query(HostModel).count()
    return {
        "total_events_ingested": total_events,
        "open_security_alerts": open_alerts,
        "active_endpoints": total_hosts,
    }


@app.post("/api/analyze")
def analyze_url_endpoint(payload: dict[str, Any]):
    """Analyzes any HTTP URL through full feature engineering, ML models, and hybrid scoring."""
    raw_url = payload.get("url", "")
    from pipeline.cleaner import deep_decode
    from pipeline.features import add_request_features
    from pipeline.labeler import load_rules, label_requests

    decoded = deep_decode(raw_url)
    query_str = decoded.split("?", 1)[1] if "?" in decoded else ""

    df = pd.DataFrame([{
        "url": raw_url,
        "decoded_url": decoded,
        "query": query_str,
        "method": payload.get("method", "GET"),
        "status": 200,
        "ua": payload.get("ua", "Mozilla/5.0"),
    }])
    df = add_request_features(df)
    try:
        rules = load_rules()
        df = label_requests(df, rules=rules)
    except Exception:
        df["rule_ids"] = [[]]
        df["label"] = ["benign"]

    probs, anomalies = predict_event(df)
    ml_prob = float(probs[0])
    iso_score = float(anomalies[0])
    rule_ids = list(df["rule_ids"].iloc[0]) if "rule_ids" in df.columns and len(df["rule_ids"].iloc[0]) > 0 else []
    rule_hits_list = [{"id": rid, "name": f"Rule {rid}", "severity": 85} for rid in rule_ids] if rule_ids else []
    threat_score, severity_level, reasons = calculate_severity(
        rule_hits=rule_hits_list,
        ml_prob=ml_prob,
        anomaly=iso_score,
        baseline_novelty=False,
    )

    return {
        "raw_url": raw_url,
        "decoded_url": decoded,
        "threat_score": threat_score,
        "severity_level": severity_level,
        "reasons": reasons,
        "ml_probability": round(ml_prob, 4),
        "anomaly_score": round(iso_score, 4),
        "rule_ids": rule_ids,
        "features": {
            "url_length": int(df["url_length"].iloc[0]),
            "query_length": int(df["query_length"].iloc[0]),
            "url_entropy": round(float(df["url_entropy"].iloc[0]), 3),
            "special_chars": int(df["special_chars"].iloc[0]),
            "special_ratio": round(float(df["special_ratio"].iloc[0]), 3),
            "has_sql_kw": int(df["has_sql_kw"].iloc[0]),
            "has_script_tag": int(df["has_script_tag"].iloc[0]),
            "has_traversal": int(df["has_traversal"].iloc[0]),
        },
    }



# ══════════════════════════════════════════════════════════════
# Real-World Log Ingestion & Analytics Endpoints
# ══════════════════════════════════════════════════════════════
from pipeline.log_analyzer import analyze_log_content

SAMPLE_LOGS_MAP: dict[str, dict[str, Any]] = {
    "apache_web_attacks": {
        "id": "apache_web_attacks",
        "name": "Apache Cyber Attacks Sample",
        "description": "Real-world Apache Combined log with SQLi, XSS, Path Traversal, Scanners & Benign traffic",
        "path": Path("data/samples/apache_web_attacks.log"),
    },
    "nginx_production_traffic": {
        "id": "nginx_production_traffic",
        "name": "Nginx Production Traffic Sample",
        "description": "E-commerce platform access logs with mixed customer requests and sneaky exploits",
        "path": Path("data/samples/nginx_production_traffic.log"),
    },
    "bruteforce_and_recon": {
        "id": "bruteforce_and_recon",
        "name": "Brute Force & Reconnaissance Sample",
        "description": "Credential brute-force bursts against authentication APIs and directory discovery fuzzing",
        "path": Path("data/samples/bruteforce_and_recon.log"),
    },
    "sample_access": {
        "id": "sample_access",
        "name": "GTU Lab Baseline Sample",
        "description": "Complete test fixture log used for GTU Practical 1-10 verification",
        "path": Path("tests/fixtures/sample_access.log"),
    },
}


@app.get("/api/sample-logs")
def list_sample_logs():
    """Lists available pre-packaged real-world access log samples."""
    return [
        {
            "id": k,
            "name": v["name"],
            "description": v["description"],
            "available": v["path"].exists(),
        }
        for k, v in SAMPLE_LOGS_MAP.items()
    ]


@app.get("/api/sample-logs/{sample_id}/raw")
def get_sample_log_raw(sample_id: str):
    """Retrieves raw content of a sample log file."""
    sample = SAMPLE_LOGS_MAP.get(sample_id)
    if not sample or not sample["path"].exists():
        raise HTTPException(status_code=404, detail="Sample log not found")
    return PlainTextResponse(sample["path"].read_text(encoding="utf-8", errors="replace"))


@app.post("/api/sample-logs/{sample_id}/analyze")
def analyze_sample_log(
    sample_id: str,
    ingest_to_db: bool = Query(False),
    db: Session = Depends(get_db),
):
    """Analyzes a pre-packaged sample log directly."""
    sample = SAMPLE_LOGS_MAP.get(sample_id)
    if not sample or not sample["path"].exists():
        raise HTTPException(status_code=404, detail="Sample log not found")
    content = sample["path"].read_text(encoding="utf-8", errors="replace")
    result = analyze_log_content(
        content=content,
        filename=sample["path"].name,
        ingest_to_db=ingest_to_db,
        db=db,
    )
    return result


@app.post("/api/upload-log")
async def upload_log_file(
    file: UploadFile | None = File(None),
    content: str | None = Form(None),
    ingest_to_db: bool = Form(False),
    db: Session = Depends(get_db),
):
    """
    Ingests and analyzes a real-world log file (via file upload or raw form text).
    Extracts features, runs ML models, calculates threat scores, and optionally persists into live SOC.
    """
    log_content = ""
    filename = "uploaded_log.log"

    if file is not None and file.filename:
        filename = file.filename
        raw_bytes = await file.read()
        log_content = raw_bytes.decode("utf-8", errors="replace")
    elif content is not None:
        log_content = content
    else:
        raise HTTPException(status_code=400, detail="Either 'file' or 'content' must be provided")

    if not log_content.strip():
        raise HTTPException(status_code=400, detail="Uploaded log file is empty")

    result = analyze_log_content(
        content=log_content,
        filename=filename,
        ingest_to_db=ingest_to_db,
        db=db,
    )
    return result


@app.post("/api/upload-log-raw")
def upload_log_raw(payload: dict[str, Any], db: Session = Depends(get_db)):
    """JSON API endpoint for uploading and analyzing log content directly."""
    content = payload.get("content", "")
    filename = payload.get("filename", "pasted_log.log")
    ingest_to_db = bool(payload.get("ingest_to_db", False))

    if not content.strip():
        raise HTTPException(status_code=400, detail="Log content cannot be empty")

    result = analyze_log_content(
        content=content,
        filename=filename,
        ingest_to_db=ingest_to_db,
        db=db,
    )
    return result


@app.post("/api/report/markdown")
def download_markdown_report(payload: dict[str, Any]):
    """Generates and returns an executive Markdown SOC Incident Audit Report."""
    from pipeline.log_analyzer import generate_markdown_report
    md_content = generate_markdown_report(payload)
    return PlainTextResponse(
        content=md_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=SentinelLog_Audit_Report_{int(time.time())}.md"}
    )



# Static Web Frontend Mount
frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def serve_frontend_root():
        return FileResponse(frontend_dir / "index.html")


