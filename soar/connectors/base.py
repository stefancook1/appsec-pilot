"""Connector framework.

A connector teaches the platform how to talk to one kind of data source.
Each connector declares:

  * metadata (type id, label, icon, vendor category)
  * a sequence of *integration steps* — the guided wizard a user walks
    through to stand the integration up (connection, auth, field mapping,
    test, activate)
  * how to test connectivity with a candidate config
  * how to normalize a raw payload from that source into an Event

Adding support for a brand-new data source means subclassing BaseConnector
and registering it; the API and UI pick it up automatically.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..models import Event, Severity

SEVERITY_CHOICES = [s.value for s in Severity]


@dataclass
class Field:
    """One input collected from the user during an integration step."""

    key: str
    label: str
    type: str = "text"  # text | password | number | select | textarea | toggle
    required: bool = True
    placeholder: str = ""
    help: str = ""
    choices: list = field(default_factory=list)
    default: object = None
    secret: bool = False

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "type": self.type,
            "required": self.required,
            "placeholder": self.placeholder,
            "help": self.help,
            "choices": self.choices,
            "default": self.default,
            "secret": self.secret,
        }


@dataclass
class IntegrationStep:
    """One step of the guided setup wizard for a connector."""

    id: str
    title: str
    description: str = ""
    fields: list = field(default_factory=list)
    kind: str = "form"  # form | test | review

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "kind": self.kind,
            "fields": [f.to_dict() for f in self.fields],
        }


def mapping_step(sample_fields: str) -> IntegrationStep:
    """Shared field-mapping step: tells the platform how to lift the
    source's raw payload into the normalized Event schema."""
    return IntegrationStep(
        id="mapping",
        title="Field mapping",
        description=(
            "Map fields from the source payload onto the normalized event "
            "schema. Dot paths (e.g. alert.name) traverse nested objects. "
            f"Typical fields from this source: {sample_fields}."
        ),
        fields=[
            Field("map_title", "Title field", placeholder="alert.name",
                  help="Path to the human-readable event title."),
            Field("map_severity", "Severity field", required=False,
                  placeholder="alert.severity",
                  help="Path to severity; values are normalized "
                       "(e.g. warn → medium, crit → critical)."),
            Field("map_entity", "Entity field", required=False,
                  placeholder="host.name",
                  help="Path to the affected asset, user, or resource."),
            Field("map_category", "Category field", required=False,
                  placeholder="alert.type",
                  help="Path to an event category/type label."),
            Field("default_severity", "Default severity", type="select",
                  required=False, choices=SEVERITY_CHOICES, default="medium",
                  help="Used when the severity field is absent."),
        ],
    )


def details_step() -> IntegrationStep:
    return IntegrationStep(
        id="details",
        title="Name your integration",
        description="Give this integration a name your team will recognize.",
        fields=[
            Field("name", "Integration name", placeholder="Production SIEM"),
            Field("description", "Description", type="textarea",
                  required=False, placeholder="What does this feed cover?"),
        ],
    )


def test_step(description: str) -> IntegrationStep:
    return IntegrationStep(id="test", title="Test connection",
                           description=description, kind="test")


def review_step() -> IntegrationStep:
    return IntegrationStep(
        id="review", title="Review & activate", kind="review",
        description="Confirm the configuration and activate the integration. "
                    "Once active, events from this source flow into the "
                    "pipeline and matching playbooks run automatically.",
    )


def dig(payload: dict, path: str, default=None):
    """Resolve a dot path like 'alert.severity' inside a nested dict."""
    current = payload
    for part in (path or "").split("."):
        if not part:
            return default
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


class BaseConnector(ABC):
    """Subclass this to plug a new kind of data source into the platform."""

    type_id: str = ""
    label: str = ""
    category: str = "Generic"
    icon: str = "🔌"
    description: str = ""

    @abstractmethod
    def steps(self) -> list:
        """Ordered integration steps shown in the setup wizard."""

    @abstractmethod
    def test_connection(self, config: dict) -> dict:
        """Validate a candidate config. Returns {ok, message, details}."""

    def normalize(self, integration_name: str, payload: dict, config: dict) -> Event:
        """Lift a raw payload into the normalized Event using the field
        mapping captured during setup. Connectors may override for
        source-specific handling."""
        title = dig(payload, config.get("map_title", ""), None) or \
            payload.get("title") or payload.get("message") or "Untitled event"
        severity_raw = dig(payload, config.get("map_severity", ""), None)
        if severity_raw is None:
            severity_raw = config.get("default_severity", "medium")
        return Event(
            source=integration_name,
            title=str(title),
            severity=Severity.parse(severity_raw),
            category=str(dig(payload, config.get("map_category", ""), "alert")),
            entity=str(dig(payload, config.get("map_entity", ""), "") or ""),
            raw=payload,
        )

    def meta(self) -> dict:
        return {
            "type_id": self.type_id,
            "label": self.label,
            "category": self.category,
            "icon": self.icon,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps()],
        }

    # -- shared config validation -------------------------------------------

    def validate_step(self, step_id: str, values: dict) -> list:
        """Return a list of error strings for missing/invalid step inputs."""
        errors = []
        step = next((s for s in self.steps() if s.id == step_id), None)
        if step is None:
            return [f"Unknown step '{step_id}' for connector {self.type_id}"]
        for f in step.fields:
            value = values.get(f.key)
            if f.required and (value is None or str(value).strip() == ""):
                errors.append(f"'{f.label}' is required")
            if f.type == "number" and value not in (None, ""):
                try:
                    float(value)
                except (TypeError, ValueError):
                    errors.append(f"'{f.label}' must be a number")
            if f.type == "select" and value and f.choices and value not in f.choices:
                errors.append(f"'{f.label}' must be one of: {', '.join(f.choices)}")
        return errors


_REGISTRY: dict = {}


def register(cls):
    """Class decorator: makes a connector discoverable by the API and UI."""
    instance = cls()
    if not instance.type_id:
        raise ValueError(f"{cls.__name__} must define a type_id")
    _REGISTRY[instance.type_id] = instance
    return cls


def get_connector(type_id: str) -> BaseConnector | None:
    return _REGISTRY.get(type_id)


def all_connectors() -> list:
    return sorted(_REGISTRY.values(), key=lambda c: (c.category, c.label))
