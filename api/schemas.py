"""
SentinelLog API: Pydantic Validation Schemas.
Validates ingestion payloads, query parameters, alert lifecycle updates, and responses.
"""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class TelemetryEvent(BaseModel):
    ts: Optional[str] = None
    source: str = Field(default="agent_unknown", description="Telemetry source name")
    host: str = Field(default="localhost", description="Originating host name")
    actor: Optional[str] = None
    action: str = Field(..., description="Action name e.g. process_start, conn_open")
    target: Optional[str] = None
    name: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    parent_name: Optional[str] = None
    exe: Optional[str] = None
    cmdline: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    attrs: Optional[dict[str, Any]] = None
    rule_hits: Optional[list[dict[str, Any]]] = None
    local_severity: Optional[int] = 0
    agent_id: Optional[str] = None


class AgentBatchRequest(BaseModel):
    agent_id: Optional[str] = None
    events: list[TelemetryEvent] = Field(..., max_length=1000, description="Batched telemetry events")


class WebLogBatchRequest(BaseModel):
    events: list[dict[str, Any]] = Field(..., max_length=2000, description="Processed web log records")


class AlertUpdateRequest(BaseModel):
    status: str = Field(..., description="open | acknowledged | false_positive")
    comment: Optional[str] = None


class AlertResponse(BaseModel):
    id: int
    alert_id: str
    ts: str
    host: str
    rule_id: str
    severity: str
    score: float
    status: str
    reasons: list[str]
    evidence: dict[str, Any]
    count: int


class HostStatusResponse(BaseModel):
    host: str
    agent_id: str
    last_heartbeat: str
    status: str
    cpu_percent: float
    ram_mb: float
    os: str


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    db_connected: bool
