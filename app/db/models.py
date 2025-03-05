from sqlalchemy import Boolean, Integer, String, DateTime, ForeignKey, JSON, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Optional, List
from datetime import datetime
from app.db.base import Base

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    full_name: Mapped[str] = mapped_column(String, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    resolved_threats: Mapped[List["ThreatEvent"]] = relationship("ThreatEvent", back_populates="resolver")
    response_actions: Mapped[List["ResponseAction"]] = relationship("ResponseAction", back_populates="performer")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.created_at is None:
            self.created_at = datetime.utcnow()

class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    severity: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String)
    indicators: Mapped[dict] = mapped_column(JSON)
    confidence_score: Mapped[float] = mapped_column(Float)
    source_ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    target_systems: Mapped[dict] = mapped_column(JSON)
    mitre_techniques: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String, default="OPEN")
    resolved_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    resolver: Mapped[Optional["User"]] = relationship("User", back_populates="resolved_threats")

class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    threat_id: Mapped[str] = mapped_column(String, ForeignKey("threat_events.id"))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    action_type: Mapped[str] = mapped_column(String)
    action_details: Mapped[dict] = mapped_column(JSON)
    performer_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    performer: Mapped[Optional["User"]] = relationship("User", back_populates="response_actions")
