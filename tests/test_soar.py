"""End-to-end tests for the SOAR platform: connector discovery, the
step-by-step integration wizard, ingestion, and playbook automation."""

import pytest

from soar import create_app


@pytest.fixture()
def client():
    app = create_app(seed_demo_data=False)
    app.testing = True
    return app.test_client()


@pytest.fixture()
def seeded_client():
    app = create_app(seed_demo_data=True)
    app.testing = True
    return app.test_client()


def test_connectors_expose_integration_steps(client):
    connectors = client.get("/api/v1/connectors").get_json()
    assert len(connectors) >= 6
    for connector in connectors:
        step_ids = [s["id"] for s in connector["steps"]]
        assert step_ids[0] == "details"
        assert "mapping" in step_ids
        assert "test" in step_ids
        assert step_ids[-1] == "review"


def test_full_integration_wizard_flow(client):
    created = client.post("/api/v1/integrations",
                          json={"connector_type": "webhook"})
    assert created.status_code == 201
    integration_id = created.get_json()["id"]

    # Step 1: details
    res = client.post(f"/api/v1/integrations/{integration_id}/steps/details",
                      json={"name": "EDR feed"})
    assert res.status_code == 200
    assert res.get_json()["integration"]["name"] == "EDR feed"

    # Step 2: connection — validation rejects a missing secret
    res = client.post(f"/api/v1/integrations/{integration_id}/steps/connection",
                      json={})
    assert res.status_code == 400

    res = client.post(f"/api/v1/integrations/{integration_id}/steps/connection",
                      json={"shared_secret": "super-secret-value-123"})
    assert res.status_code == 200
    # Secrets come back redacted
    assert res.get_json()["integration"]["config"]["shared_secret"] == "••••••••"

    # Step 3: mapping
    res = client.post(f"/api/v1/integrations/{integration_id}/steps/mapping",
                      json={"map_title": "event.title",
                            "map_severity": "event.level",
                            "map_entity": "target.host"})
    assert res.status_code == 200

    # Cannot activate with the test step incomplete
    res = client.post(f"/api/v1/integrations/{integration_id}/steps/review",
                      json={})
    assert res.status_code == 400

    # Step 4: test connection
    res = client.post(f"/api/v1/integrations/{integration_id}/steps/test",
                      json={})
    assert res.status_code == 200
    assert res.get_json()["test"]["ok"] is True

    # Step 5: activate
    res = client.post(f"/api/v1/integrations/{integration_id}/steps/review",
                      json={})
    assert res.status_code == 200
    assert res.get_json()["integration"]["status"] == "active"


def _activate_webhook(client, secret="super-secret-value-123"):
    integration_id = client.post(
        "/api/v1/integrations",
        json={"connector_type": "webhook"}).get_json()["id"]
    for step, body in [
        ("details", {"name": "Push feed"}),
        ("connection", {"shared_secret": secret}),
        ("mapping", {"map_title": "event.title",
                     "map_severity": "event.level",
                     "map_entity": "target.host",
                     "map_category": "event.kind"}),
        ("test", {}),
        ("review", {}),
    ]:
        res = client.post(
            f"/api/v1/integrations/{integration_id}/steps/{step}", json=body)
        assert res.status_code == 200, res.get_json()
    return integration_id


def test_ingest_requires_secret_and_normalizes(client):
    integration_id = _activate_webhook(client)
    payload = {"event": {"title": "Ransomware detected", "level": "critical",
                         "kind": "malware"},
               "target": {"host": "ws-12.internal"}}

    res = client.post(f"/api/v1/ingest/{integration_id}", json=payload)
    assert res.status_code == 401

    res = client.post(f"/api/v1/ingest/{integration_id}", json=payload,
                      headers={"X-SOAR-Secret": "super-secret-value-123"})
    assert res.status_code == 201
    event = res.get_json()["event"]
    assert event["title"] == "Ransomware detected"
    assert event["severity"] == "critical"
    assert event["entity"] == "ws-12.internal"
    assert event["category"] == "malware"


def test_playbook_triggers_and_creates_incident(client):
    integration_id = _activate_webhook(client)
    client.post("/api/v1/playbooks",
                json={"name": "Critical response", "min_severity": "critical",
                      "actions": ["create_incident", "enrich_entity",
                                  "notify_channel"]})

    res = client.post(
        f"/api/v1/ingest/{integration_id}",
        json={"event": {"title": "C2 beacon", "level": "critical",
                        "kind": "c2"},
              "target": {"host": "srv-9.internal"}},
        headers={"X-SOAR-Secret": "super-secret-value-123"})
    runs = res.get_json()["playbook_runs"]
    assert len(runs) == 1
    assert [s["action"] for s in runs[0]["steps"]] == [
        "create_incident", "enrich_entity", "notify_channel"]

    incidents = client.get("/api/v1/incidents").get_json()
    assert len(incidents) == 1
    assert incidents[0]["severity"] == "critical"
    assert incidents[0]["entity"] == "srv-9.internal"

    # A second event for the same entity correlates instead of duplicating.
    client.post(
        f"/api/v1/ingest/{integration_id}",
        json={"event": {"title": "C2 beacon again", "level": "critical",
                        "kind": "c2"},
              "target": {"host": "srv-9.internal"}},
        headers={"X-SOAR-Secret": "super-secret-value-123"})
    incidents = client.get("/api/v1/incidents").get_json()
    assert len(incidents) == 1
    assert len(incidents[0]["event_ids"]) == 2


def test_severity_normalization_across_sources(client):
    from soar.models import Severity

    assert Severity.parse("crit") is Severity.CRITICAL
    assert Severity.parse("WARN") is Severity.MEDIUM
    assert Severity.parse(3) is Severity.HIGH
    assert Severity.parse("unknown-value") is Severity.MEDIUM


def test_incident_lifecycle(seeded_client):
    incidents = seeded_client.get("/api/v1/incidents").get_json()
    assert incidents, "demo seed should open incidents"
    incident_id = incidents[0]["id"]

    res = seeded_client.patch(f"/api/v1/incidents/{incident_id}",
                              json={"status": "resolved",
                                    "assignee": "alice"})
    body = res.get_json()
    assert body["status"] == "resolved"
    assert body["assignee"] == "alice"
    assert any(t["kind"] == "status" for t in body["timeline"])


def test_metrics_and_demo_seed(seeded_client):
    metrics = seeded_client.get("/api/v1/metrics").get_json()
    assert metrics["integrations_active"] == 2
    assert metrics["events_total"] == 5
    assert metrics["incidents_open"] >= 3
    assert metrics["playbook_runs"] >= 3


def test_console_serves(seeded_client):
    res = seeded_client.get("/")
    assert res.status_code == 200
    assert b"SOAR" in res.data
