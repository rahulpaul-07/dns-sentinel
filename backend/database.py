"""SQLAlchemy models and session factory (SQLite by default).

The database file defaults to backend/dnsentinel.db and can be relocated with
the DNSENTINEL_DB_PATH environment variable (the test suite points it at a
temporary file so tests never touch a developer's data).
"""
import os
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("DNSENTINEL_DB_PATH", os.path.join(BASE_DIR, "dnsentinel.db"))

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def utcnow() -> datetime:
    """Naive UTC timestamp (SQLite has no timezone type; everything stored is UTC)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso_utc(value: datetime) -> str:
    """ISO-8601 with an explicit Z so browsers don't parse it as local time."""
    return value.isoformat() + "Z" if value else ""


class DNSAuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    source_ip = Column(String, index=True)
    query = Column(String)
    qtype = Column(String)
    risk_score = Column(Float)
    risk_level = Column(String, index=True)
    prediction = Column(String)
    priority = Column(String, default="LOW")
    priority_score = Column(Float, default=0.0)
    is_blocked = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)
    mitre_data = Column(JSON)
    features = Column(JSON)
    explanation = Column(String)

    def to_dict(self) -> dict:
        return {
            "db_id": self.id,
            "timestamp": iso_utc(self.timestamp),
            "source_ip": self.source_ip,
            "query": self.query,
            "qtype": self.qtype,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "priority": self.priority,
            "priority_score": self.priority_score,
            "prediction": self.prediction,
            "is_blocked": bool(self.is_blocked),
            "is_false_positive": bool(self.is_false_positive),
            "mitre": self.mitre_data,
            "features": self.features,
            "explanation": self.explanation,
        }


class SecurityRule(Base):
    """SOAR rule store. One row per target; re-blocking reactivates the row."""
    __tablename__ = "security_rules"
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, unique=True, index=True)  # IP or domain
    rule_type = Column(String)  # 'IP_BLOCK' | 'DOMAIN_SINKHOLE'
    action = Column(String)     # 'BLOCK'
    reason = Column(String)
    risk_score = Column(Float)
    is_active = Column(Boolean, default=True)
    added_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=True)  # auto-expiry

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "rule_type": self.rule_type,
            "action": self.action,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "is_active": bool(self.is_active),
            "added_at": iso_utc(self.added_at),
            "expires_at": iso_utc(self.expires_at),
        }


class Whitelist(Base):
    __tablename__ = "whitelist"
    id = Column(Integer, primary_key=True, index=True)
    entity = Column(String, unique=True, index=True)
    reason = Column(String)
    added_at = Column(DateTime, default=utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
