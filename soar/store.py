"""Thread-safe in-memory store.

Deliberately a single swap-in point for persistence: replace this class
with a database-backed implementation without touching the API, the
connectors, or the playbook engine.
"""

from __future__ import annotations

import threading

from .models import (
    Event,
    Incident,
    IncidentStatus,
    Integration,
    IntegrationStatus,
    Severity,
)
from .playbooks import Playbook

MAX_EVENTS = 2000
MAX_RUNS = 500


class Store:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.integrations: dict = {}
        self.events: list = []
        self.incidents: dict = {}
        self.playbooks: dict = {}
        self.playbook_runs: list = []

    # -- integrations --------------------------------------------------------

    def add_integration(self, integration: Integration) -> None:
        with self._lock:
            self.integrations[integration.id] = integration

    def get_integration(self, integration_id: str) -> Integration | None:
        return self.integrations.get(integration_id)

    def delete_integration(self, integration_id: str) -> bool:
        with self._lock:
            return self.integrations.pop(integration_id, None) is not None

    # -- events & incidents ---------------------------------------------------

    def add_event(self, event: Event) -> None:
        with self._lock:
            self.events.append(event)
            del self.events[:-MAX_EVENTS]

    def add_incident(self, incident: Incident) -> None:
        with self._lock:
            self.incidents[incident.id] = incident

    def find_open_incident(self, entity: str, source: str) -> Incident | None:
        """Correlation: an open incident for the same entity and source."""
        with self._lock:
            for inc in reversed(list(self.incidents.values())):
                if (inc.entity == entity and inc.source == source
                        and inc.status not in (IncidentStatus.RESOLVED,
                                               IncidentStatus.CLOSED)):
                    return inc
        return None

    # -- playbooks -------------------------------------------------------------

    def add_playbook(self, playbook: Playbook) -> None:
        with self._lock:
            self.playbooks[playbook.id] = playbook

    def add_run(self, run: dict) -> None:
        with self._lock:
            self.playbook_runs.append(run)
            del self.playbook_runs[:-MAX_RUNS]

    # -- metrics ----------------------------------------------------------------

    def metrics(self) -> dict:
        with self._lock:
            open_incidents = [i for i in self.incidents.values()
                              if i.status not in (IncidentStatus.RESOLVED,
                                                  IncidentStatus.CLOSED)]
            by_severity = {s.value: 0 for s in Severity}
            for inc in open_incidents:
                by_severity[inc.severity.value] += 1
            return {
                "integrations_total": len(self.integrations),
                "integrations_active": sum(
                    1 for i in self.integrations.values()
                    if i.status == IntegrationStatus.ACTIVE),
                "events_total": len(self.events),
                "incidents_open": len(open_incidents),
                "incidents_total": len(self.incidents),
                "open_by_severity": by_severity,
                "playbooks_enabled": sum(
                    1 for p in self.playbooks.values() if p.enabled),
                "playbook_runs": len(self.playbook_runs),
            }

    # -- demo seed ----------------------------------------------------------------

    def seed_demo_data(self) -> None:
        """A working out-of-the-box demo: two active integrations, three
        playbooks, and a stream of sample events run through the pipeline."""
        from .pipeline import ingest_event

        siem = Integration(
            connector_type="rest_api", name="Acme SIEM",
            status=IntegrationStatus.ACTIVE,
            completed_steps=["details", "connection", "auth", "mapping",
                             "test", "review"],
            config={"name": "Acme SIEM",
                    "base_url": "https://siem.acme.example/api/v2/alerts",
                    "poll_interval": 60, "auth_type": "api_key",
                    "map_title": "alert.name",
                    "map_severity": "alert.severity",
                    "map_entity": "host.name",
                    "map_category": "alert.type"},
        )
        edr = Integration(
            connector_type="webhook", name="CrowdStrike EDR",
            status=IntegrationStatus.ACTIVE,
            completed_steps=["details", "connection", "mapping", "test",
                             "review"],
            config={"name": "CrowdStrike EDR",
                    "shared_secret": "********",
                    "map_title": "detection.description",
                    "map_severity": "detection.severity",
                    "map_entity": "device.hostname",
                    "map_category": "detection.tactic"},
        )
        self.add_integration(siem)
        self.add_integration(edr)

        self.add_playbook(Playbook(
            name="Critical alert → incident + page",
            description="Open an incident, enrich, and page on-call for any "
                        "critical event from any source.",
            min_severity=Severity.CRITICAL,
            actions=["create_incident", "enrich_entity", "notify_channel",
                     "assign_analyst"],
        ))
        self.add_playbook(Playbook(
            name="High severity triage",
            description="Open and enrich an incident for high-severity events.",
            min_severity=Severity.HIGH,
            actions=["create_incident", "enrich_entity"],
        ))
        self.add_playbook(Playbook(
            name="EDR malware auto-containment",
            description="Contain malware detections from EDR sources "
                        "automatically.",
            min_severity=Severity.HIGH, source_contains="EDR",
            category_contains="malware",
            actions=["create_incident", "block_entity", "auto_contain",
                     "notify_channel"],
        ))

        samples = [
            (siem, {"alert": {"name": "Impossible travel sign-in",
                              "severity": "high", "type": "identity"},
                    "host": {"name": "okta-tenant"}}),
            (siem, {"alert": {"name": "Brute force against VPN gateway",
                              "severity": "critical", "type": "network"},
                    "host": {"name": "vpn-edge-01.internal"}}),
            (edr, {"detection": {"description": "Ransomware behavior: mass "
                                                "file encryption",
                                 "severity": "critical",
                                 "tactic": "malware"},
                   "device": {"hostname": "fin-ws-114.internal"}}),
            (edr, {"detection": {"description": "Credential dumping via "
                                                "LSASS access",
                                 "severity": "high",
                                 "tactic": "credential-access"},
                   "device": {"hostname": "hr-lt-022.internal"}}),
            (siem, {"alert": {"name": "Anomalous S3 data egress",
                              "severity": "medium", "type": "cloud"},
                    "host": {"name": "data-lake-prod"}}),
        ]
        for integration, payload in samples:
            ingest_event(self, integration, payload)
