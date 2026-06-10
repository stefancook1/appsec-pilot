"""Event pipeline: raw payload → normalized Event → matching playbooks."""

from __future__ import annotations

from .connectors import get_connector
from .models import Event, Integration
from .playbooks import run_playbook


def ingest_event(store, integration: Integration, payload: dict) -> dict:
    """Normalize one raw payload from an integration and run playbooks.

    Returns a summary of what happened (event + playbook runs).
    """
    connector = get_connector(integration.connector_type)
    if connector is None:
        raise ValueError(f"Unknown connector type '{integration.connector_type}'")

    event: Event = connector.normalize(integration.name, payload,
                                       integration.config)
    store.add_event(event)
    integration.events_ingested += 1

    runs = []
    for playbook in list(store.playbooks.values()):
        if playbook.matches(event):
            run = run_playbook(playbook, event, store)
            store.add_run(run)
            runs.append(run)

    return {"event": event.to_dict(), "playbook_runs": runs}
