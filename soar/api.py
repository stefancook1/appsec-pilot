"""REST API for the SOAR platform.

Everything the UI does goes through these endpoints, so the platform is
fully scriptable: connectors are discoverable, integrations are built by
submitting their declared steps one at a time, and events are pushed via
the ingest endpoint.
"""

from __future__ import annotations

import hmac
import random

from flask import Blueprint, current_app, jsonify, request

from .connectors import all_connectors, get_connector
from .models import Integration, IntegrationStatus, IncidentStatus, Severity
from .pipeline import ingest_event
from .playbooks import ACTION_CATALOG, Playbook

api_bp = Blueprint("api", __name__)


def _store():
    return current_app.extensions["soar_store"]


def _secret_keys(connector) -> set:
    return {f.key for step in connector.steps() for f in step.fields if f.secret}


def _redacted(integration: Integration) -> dict:
    """Integration dict with secret config values masked."""
    data = integration.to_dict()
    connector = get_connector(integration.connector_type)
    if connector:
        secrets = _secret_keys(connector)
        data["config"] = {k: ("••••••••" if k in secrets and v else v)
                          for k, v in data["config"].items()}
    return data


def _error(message, status=400, details=None):
    body = {"error": message}
    if details:
        body["details"] = details
    return jsonify(body), status


# -- connectors ---------------------------------------------------------------


@api_bp.get("/connectors")
def list_connectors():
    return jsonify([c.meta() for c in all_connectors()])


# -- integrations ---------------------------------------------------------------


@api_bp.get("/integrations")
def list_integrations():
    return jsonify([_redacted(i) for i in _store().integrations.values()])


@api_bp.post("/integrations")
def create_integration():
    body = request.get_json(silent=True) or {}
    connector = get_connector(body.get("connector_type", ""))
    if connector is None:
        return _error("Unknown or missing connector_type")
    integration = Integration(connector_type=connector.type_id,
                              name=body.get("name") or f"New {connector.label}")
    _store().add_integration(integration)
    return jsonify(_redacted(integration)), 201


@api_bp.get("/integrations/<integration_id>")
def get_integration(integration_id):
    integration = _store().get_integration(integration_id)
    if integration is None:
        return _error("Integration not found", 404)
    return jsonify(_redacted(integration))


@api_bp.post("/integrations/<integration_id>/steps/<step_id>")
def submit_step(integration_id, step_id):
    """Submit the values for one integration step of the setup wizard."""
    store = _store()
    integration = store.get_integration(integration_id)
    if integration is None:
        return _error("Integration not found", 404)
    connector = get_connector(integration.connector_type)
    values = request.get_json(silent=True) or {}

    step = next((s for s in connector.steps() if s.id == step_id), None)
    if step is None:
        return _error(f"Connector '{connector.type_id}' has no step '{step_id}'", 404)

    if step.kind == "form":
        errors = connector.validate_step(step_id, values)
        if errors:
            return _error("Step validation failed", details=errors)
        allowed = {f.key for f in step.fields}
        integration.config.update(
            {k: v for k, v in values.items() if k in allowed})
        if step_id == "details" and values.get("name"):
            integration.name = values["name"]
    elif step.kind == "test":
        result = connector.test_connection(integration.config)
        integration.last_test = result
        integration.status = (IntegrationStatus.TESTING if result.get("ok")
                              else IntegrationStatus.ERROR)
        if not result.get("ok"):
            return jsonify({"integration": _redacted(integration),
                            "test": result}), 422
    elif step.kind == "review":
        ordered = [s.id for s in connector.steps()]
        missing = [s for s in ordered[:-1]
                   if s not in integration.completed_steps]
        if missing:
            return _error("Cannot activate: incomplete steps",
                          details=missing)
        integration.status = IntegrationStatus.ACTIVE

    if step_id not in integration.completed_steps:
        integration.completed_steps.append(step_id)
    return jsonify({"integration": _redacted(integration),
                    "test": integration.last_test if step.kind == "test" else None})


@api_bp.post("/integrations/<integration_id>/pause")
def pause_integration(integration_id):
    integration = _store().get_integration(integration_id)
    if integration is None:
        return _error("Integration not found", 404)
    if integration.status == IntegrationStatus.ACTIVE:
        integration.status = IntegrationStatus.PAUSED
    elif integration.status == IntegrationStatus.PAUSED:
        integration.status = IntegrationStatus.ACTIVE
    return jsonify(_redacted(integration))


@api_bp.delete("/integrations/<integration_id>")
def delete_integration(integration_id):
    if not _store().delete_integration(integration_id):
        return _error("Integration not found", 404)
    return jsonify({"deleted": integration_id})


# -- ingestion ---------------------------------------------------------------


@api_bp.post("/ingest/<integration_id>")
def ingest(integration_id):
    """Push one raw event into an integration (webhook-style ingestion)."""
    store = _store()
    integration = store.get_integration(integration_id)
    if integration is None:
        return _error("Integration not found", 404)
    if integration.status != IntegrationStatus.ACTIVE:
        return _error("Integration is not active", 409)

    expected = str(integration.config.get("shared_secret", ""))
    if expected and expected != "********":
        provided = request.headers.get("X-SOAR-Secret", "")
        if not hmac.compare_digest(expected, provided):
            return _error("Invalid or missing X-SOAR-Secret header", 401)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("Body must be a JSON object")
    return jsonify(ingest_event(store, integration, payload)), 201


_SIM_EVENTS = [
    {"title": "Suspicious PowerShell with encoded command",
     "severity": "high", "category": "execution", "entity": "ws-{n}.internal"},
    {"title": "Outbound beaconing to rare domain",
     "severity": "critical", "category": "c2", "entity": "srv-{n}.internal"},
    {"title": "New admin account created outside change window",
     "severity": "high", "category": "persistence", "entity": "dc-0{n}"},
    {"title": "Malware quarantined by endpoint agent",
     "severity": "medium", "category": "malware", "entity": "lt-{n}.internal"},
    {"title": "Excessive failed logins from single IP",
     "severity": "medium", "category": "identity", "entity": "auth-gw"},
]


@api_bp.post("/integrations/<integration_id>/simulate")
def simulate(integration_id):
    """Generate a realistic sample event for demos and pipeline testing."""
    store = _store()
    integration = store.get_integration(integration_id)
    if integration is None:
        return _error("Integration not found", 404)
    template = dict(random.choice(_SIM_EVENTS))
    template["entity"] = template["entity"].format(n=random.randint(10, 99))
    payload = {"title": template["title"], "severity": template["severity"],
               "category": template["category"], "entity": template["entity"],
               "simulated": True}
    config_backup = integration.config
    # Simulated payloads are already in normalized shape; use direct paths.
    integration.config = {**config_backup, "map_title": "title",
                          "map_severity": "severity",
                          "map_entity": "entity", "map_category": "category"}
    try:
        result = ingest_event(store, integration, payload)
    finally:
        integration.config = config_backup
    return jsonify(result), 201


# -- events & incidents ---------------------------------------------------------


@api_bp.get("/events")
def list_events():
    limit = min(int(request.args.get("limit", 50)), 500)
    return jsonify([e.to_dict() for e in reversed(_store().events[-limit:])])


@api_bp.get("/incidents")
def list_incidents():
    incidents = sorted(_store().incidents.values(),
                       key=lambda i: i.created_at, reverse=True)
    return jsonify([i.to_dict() for i in incidents])


@api_bp.get("/incidents/<incident_id>")
def get_incident(incident_id):
    incident = _store().incidents.get(incident_id)
    if incident is None:
        return _error("Incident not found", 404)
    return jsonify(incident.to_dict())


@api_bp.patch("/incidents/<incident_id>")
def update_incident(incident_id):
    incident = _store().incidents.get(incident_id)
    if incident is None:
        return _error("Incident not found", 404)
    body = request.get_json(silent=True) or {}
    if "status" in body:
        try:
            new_status = IncidentStatus(body["status"])
        except ValueError:
            return _error(f"Invalid status '{body['status']}'")
        incident.status = new_status
        incident.add_timeline("status", f"Status changed to {new_status.value}")
    if "assignee" in body:
        incident.assignee = body["assignee"]
        incident.add_timeline("assignment",
                              f"Assigned to {body['assignee'] or 'nobody'}")
    return jsonify(incident.to_dict())


# -- playbooks ----------------------------------------------------------------


@api_bp.get("/playbooks")
def list_playbooks():
    return jsonify({
        "playbooks": [p.to_dict() for p in _store().playbooks.values()],
        "action_catalog": ACTION_CATALOG,
    })


@api_bp.post("/playbooks")
def create_playbook():
    body = request.get_json(silent=True) or {}
    if not body.get("name"):
        return _error("'name' is required")
    actions = body.get("actions") or ["create_incident"]
    unknown = [a for a in actions if a not in ACTION_CATALOG]
    if unknown:
        return _error("Unknown actions", details=unknown)
    playbook = Playbook(
        name=body["name"],
        description=body.get("description", ""),
        min_severity=Severity.parse(body.get("min_severity", "high")),
        source_contains=body.get("source_contains", ""),
        category_contains=body.get("category_contains", ""),
        actions=actions,
        enabled=bool(body.get("enabled", True)),
    )
    _store().add_playbook(playbook)
    return jsonify(playbook.to_dict()), 201


@api_bp.patch("/playbooks/<playbook_id>")
def update_playbook(playbook_id):
    playbook = _store().playbooks.get(playbook_id)
    if playbook is None:
        return _error("Playbook not found", 404)
    body = request.get_json(silent=True) or {}
    if "enabled" in body:
        playbook.enabled = bool(body["enabled"])
    return jsonify(playbook.to_dict())


@api_bp.get("/playbook-runs")
def list_runs():
    return jsonify(list(reversed(_store().playbook_runs[-100:])))


# -- metrics ---------------------------------------------------------------------


@api_bp.get("/metrics")
def metrics():
    return jsonify(_store().metrics())
