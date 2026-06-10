"""Playbook engine.

A playbook is a trigger plus an ordered list of actions. When a normalized
event arrives from any integration, every enabled playbook whose trigger
matches runs its actions against the event/incident.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .models import Event, Incident, IncidentStatus, Severity

SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                  Severity.HIGH, Severity.CRITICAL]

ACTION_CATALOG = {
    "create_incident": "Open an incident from the event",
    "enrich_entity": "Look up the entity in threat intel",
    "notify_channel": "Notify the on-call channel",
    "block_entity": "Push a block for the entity to enforcement points",
    "assign_analyst": "Assign the incident to an analyst",
    "auto_contain": "Mark the incident contained",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Playbook:
    name: str
    description: str = ""
    enabled: bool = True
    min_severity: Severity = Severity.HIGH
    source_contains: str = ""
    category_contains: str = ""
    actions: list = field(default_factory=lambda: ["create_incident"])
    runs: int = 0
    id: str = field(default_factory=lambda: f"pb-{uuid.uuid4().hex[:10]}")

    def matches(self, event: Event) -> bool:
        if not self.enabled:
            return False
        if SEVERITY_ORDER.index(event.severity) < SEVERITY_ORDER.index(self.min_severity):
            return False
        if self.source_contains and self.source_contains.lower() not in event.source.lower():
            return False
        if self.category_contains and self.category_contains.lower() not in event.category.lower():
            return False
        return True

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "min_severity": self.min_severity.value,
            "source_contains": self.source_contains,
            "category_contains": self.category_contains,
            "actions": self.actions,
            "runs": self.runs,
        }


def run_playbook(playbook: Playbook, event: Event, store) -> dict:
    """Execute a playbook's actions for one event. Returns a run record."""
    playbook.runs += 1
    incident: Incident | None = None
    steps = []

    for action in playbook.actions:
        if action == "create_incident":
            incident = store.find_open_incident(event.entity, event.source) if event.entity else None
            if incident:
                incident.event_ids.append(event.id)
                if SEVERITY_ORDER.index(event.severity) > SEVERITY_ORDER.index(incident.severity):
                    incident.severity = event.severity
                incident.add_timeline("correlation",
                                      f"Correlated event '{event.title}' from {event.source}")
                steps.append({"action": action, "result":
                              f"Correlated into existing incident {incident.id}"})
            else:
                incident = Incident(title=event.title, severity=event.severity,
                                    source=event.source, entity=event.entity,
                                    event_ids=[event.id])
                incident.add_timeline("created",
                                      f"Opened by playbook '{playbook.name}'")
                store.add_incident(incident)
                steps.append({"action": action, "result":
                              f"Opened incident {incident.id}"})
        elif action == "enrich_entity":
            verdict = "no prior sightings" if not event.entity else \
                "known-internal asset" if event.entity.endswith(".internal") \
                else "no threat-intel matches"
            if incident:
                incident.add_timeline("enrichment",
                                      f"Threat intel on '{event.entity or 'event'}': {verdict}")
            steps.append({"action": action, "result": f"Enriched: {verdict}"})
        elif action == "notify_channel":
            if incident:
                incident.add_timeline("notification",
                                      "On-call channel notified (#sec-incidents)")
            steps.append({"action": action,
                          "result": "Notified #sec-incidents"})
        elif action == "block_entity":
            target = event.entity or "unknown entity"
            if incident:
                incident.add_timeline("containment",
                                      f"Block pushed for {target} to enforcement points")
            steps.append({"action": action, "result": f"Blocked {target}"})
        elif action == "assign_analyst":
            if incident:
                incident.assignee = "on-call-analyst"
                incident.add_timeline("assignment", "Assigned to on-call analyst")
            steps.append({"action": action, "result": "Assigned on-call analyst"})
        elif action == "auto_contain":
            if incident:
                incident.status = IncidentStatus.CONTAINED
                incident.add_timeline("containment", "Auto-contained by playbook")
            steps.append({"action": action, "result": "Incident contained"})
        else:
            steps.append({"action": action, "result": "Unknown action — skipped"})

    return {
        "playbook_id": playbook.id,
        "playbook_name": playbook.name,
        "event_id": event.id,
        "incident_id": incident.id if incident else None,
        "at": _now(),
        "steps": steps,
    }
