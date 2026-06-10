"""Core domain models shared across connectors, the engine, and the API."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().lower()
        aliases = {
            "informational": cls.INFO,
            "warning": cls.MEDIUM,
            "warn": cls.MEDIUM,
            "error": cls.HIGH,
            "severe": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "1": cls.LOW,
            "2": cls.MEDIUM,
            "3": cls.HIGH,
            "4": cls.CRITICAL,
        }
        if text in cls._value2member_map_:
            return cls(text)
        return aliases.get(text, cls.MEDIUM)


class IncidentStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IntegrationStatus(str, Enum):
    DRAFT = "draft"
    TESTING = "testing"
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"


@dataclass
class Event:
    """Normalized security event. Every connector maps raw payloads to this."""

    source: str
    title: str
    severity: Severity = Severity.MEDIUM
    category: str = "alert"
    entity: str = ""
    raw: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: _id("evt"))
    received_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "entity": self.entity,
            "received_at": self.received_at,
            "raw": self.raw,
        }


@dataclass
class Incident:
    title: str
    severity: Severity = Severity.MEDIUM
    status: IncidentStatus = IncidentStatus.NEW
    source: str = ""
    entity: str = ""
    event_ids: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    assignee: str = ""
    id: str = field(default_factory=lambda: _id("inc"))
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def add_timeline(self, kind: str, message: str) -> None:
        self.timeline.append({"at": _now(), "kind": kind, "message": message})
        self.updated_at = _now()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "source": self.source,
            "entity": self.entity,
            "assignee": self.assignee,
            "event_ids": self.event_ids,
            "timeline": self.timeline,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class Integration:
    """A configured instance of a connector, built via its integration steps."""

    connector_type: str
    name: str
    config: dict = field(default_factory=dict)
    status: IntegrationStatus = IntegrationStatus.DRAFT
    completed_steps: list = field(default_factory=list)
    last_test: dict | None = None
    events_ingested: int = 0
    id: str = field(default_factory=lambda: _id("int"))
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "connector_type": self.connector_type,
            "name": self.name,
            "config": self.config,
            "status": self.status.value,
            "completed_steps": self.completed_steps,
            "last_test": self.last_test,
            "events_ingested": self.events_ingested,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
