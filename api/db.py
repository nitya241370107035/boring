"""
SentinelLog API: Database Models & Persistence Engine.
Supports PostgreSQL for containerized deployments and SQLite for local development.
Defines schemas for Events, Alerts, Hosts, and Feedback with optimized compound indexes.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./sentinellog.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class EventModel(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id = Column(String(64), index=True)
    ts = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source = Column(String(32), index=True)
    host = Column(String(64), index=True)
    actor = Column(String(128))
    action = Column(String(64), index=True)
    target = Column(Text)
    attrs_json = Column(Text, default="{}")
    label = Column(String(32), index=True, default="benign")
    score = Column(Float, index=True, default=0.0)
    reasons_json = Column(Text, default="[]")

    __table_args__ = (
        Index("idx_host_ts", "host", "ts"),
        Index("idx_label_score", "label", "score"),
    )


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    alert_id = Column(String(64), unique=True, index=True)
    ts = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    host = Column(String(64), index=True)
    rule_id = Column(String(64), index=True)
    severity = Column(String(16), index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    score = Column(Float, index=True)
    status = Column(String(24), index=True, default="open")  # open, acknowledged, false_positive
    reasons_json = Column(Text, default="[]")
    evidence_json = Column(Text, default="{}")
    count = Column(Integer, default=1)

    __table_args__ = (
        Index("idx_alert_status_ts", "status", "ts"),
    )


class HostModel(Base):
    __tablename__ = "hosts"

    host = Column(String(64), primary_key=True, index=True)
    agent_id = Column(String(64), index=True)
    last_heartbeat = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String(16), default="online")
    cpu_percent = Column(Float, default=0.0)
    ram_mb = Column(Float, default=0.0)
    os = Column(String(128), default="Windows")


class FeedbackModel(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), index=True)
    action = Column(String(32))
    comment = Column(Text, default="")
    ts = Column(DateTime, default=lambda: datetime.now(timezone.utc))


def init_db():
    """Initializes tables in database."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
