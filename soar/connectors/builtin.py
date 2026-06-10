"""Built-in connectors.

Each connector covers one family of data source. They demonstrate the
pattern for plugging in *any* source: declare integration steps, implement
test_connection, optionally specialize normalize().
"""

from __future__ import annotations

import socket
from urllib.parse import urlparse

from .base import (
    BaseConnector,
    Field,
    IntegrationStep,
    details_step,
    mapping_step,
    register,
    review_step,
    test_step,
)


def _check_url(url: str, timeout: float = 5.0) -> dict:
    """Reachability probe: DNS + TCP connect to the URL's host:port."""
    parsed = urlparse(url if "//" in url else f"https://{url}")
    host = parsed.hostname
    if not host:
        return {"ok": False, "message": f"Could not parse a host from '{url}'"}
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True, "message": f"Reached {host}:{port}",
                    "details": {"host": host, "port": port}}
    except OSError as exc:
        return {"ok": False, "message": f"Could not reach {host}:{port} — {exc}"}


@register
class RestApiConnector(BaseConnector):
    type_id = "rest_api"
    label = "REST API (poll)"
    category = "Generic"
    icon = "🌐"
    description = ("Poll any HTTP/JSON API for alerts or findings — SIEMs, "
                   "scanners, ticketing systems, anything with an endpoint.")

    def steps(self):
        return [
            details_step(),
            IntegrationStep(
                id="connection", title="Connection",
                description="Where should we pull events from?",
                fields=[
                    Field("base_url", "Base URL",
                          placeholder="https://siem.example.com/api/v2/alerts"),
                    Field("poll_interval", "Poll interval (seconds)",
                          type="number", default=60),
                    Field("results_path", "Results path", required=False,
                          placeholder="data.alerts",
                          help="Dot path to the array of events in the response."),
                ],
            ),
            IntegrationStep(
                id="auth", title="Authentication",
                description="How do we authenticate to this API?",
                fields=[
                    Field("auth_type", "Auth type", type="select",
                          choices=["none", "api_key", "bearer_token", "basic"],
                          default="api_key"),
                    Field("auth_secret", "API key / token", type="password",
                          required=False, secret=True,
                          help="Stored encrypted; never shown again."),
                    Field("auth_header", "Header name", required=False,
                          placeholder="X-API-Key", default="Authorization"),
                ],
            ),
            mapping_step("alert.name, alert.severity, host.name"),
            test_step("We'll resolve the host and open a connection to "
                      "verify the endpoint is reachable with this config."),
            review_step(),
        ]

    def test_connection(self, config):
        return _check_url(config.get("base_url", ""))


@register
class WebhookConnector(BaseConnector):
    type_id = "webhook"
    label = "Inbound Webhook (push)"
    category = "Generic"
    icon = "📨"
    description = ("Receive events pushed by any tool that can send an HTTP "
                   "POST — EDR consoles, CI pipelines, monitoring, chatops.")

    def steps(self):
        return [
            details_step(),
            IntegrationStep(
                id="connection", title="Endpoint",
                description="A unique ingest URL is generated when you "
                            "activate. Point your tool's webhook at it.",
                fields=[
                    Field("shared_secret", "Shared secret", type="password",
                          secret=True,
                          help="Senders must include this in the "
                               "X-SOAR-Secret header."),
                    Field("allowed_ips", "Allowed source IPs", required=False,
                          placeholder="203.0.113.0/24, 198.51.100.7",
                          help="Optional allowlist; leave blank to accept "
                               "from anywhere (secret still required)."),
                ],
            ),
            mapping_step("event.title, event.level, target.host"),
            test_step("We'll validate the secret format and register the "
                      "ingest route."),
            review_step(),
        ]

    def test_connection(self, config):
        secret = config.get("shared_secret", "")
        if len(secret) < 12:
            return {"ok": False,
                    "message": "Shared secret must be at least 12 characters."}
        return {"ok": True,
                "message": "Webhook endpoint ready. Events POSTed to "
                           "/api/v1/ingest/<integration-id> with the secret "
                           "header will be accepted."}


@register
class DatabaseConnector(BaseConnector):
    type_id = "database"
    label = "SQL Database"
    category = "Data stores"
    icon = "🗄️"
    description = ("Query alert/audit tables in Postgres, MySQL, or any "
                   "SQL database on a schedule.")

    def steps(self):
        return [
            details_step(),
            IntegrationStep(
                id="connection", title="Connection",
                fields=[
                    Field("engine", "Engine", type="select",
                          choices=["postgresql", "mysql", "mssql", "sqlite"],
                          default="postgresql"),
                    Field("host", "Host", placeholder="db.internal"),
                    Field("port", "Port", type="number", default=5432),
                    Field("database", "Database", placeholder="security"),
                ],
            ),
            IntegrationStep(
                id="auth", title="Credentials",
                fields=[
                    Field("username", "Username"),
                    Field("password", "Password", type="password", secret=True),
                ],
            ),
            IntegrationStep(
                id="query", title="Query",
                description="The query that returns new events. Use the "
                            ":since placeholder for incremental pulls.",
                fields=[
                    Field("query", "SQL query", type="textarea",
                          placeholder="SELECT * FROM alerts WHERE created_at > :since"),
                    Field("poll_interval", "Poll interval (seconds)",
                          type="number", default=300),
                ],
            ),
            mapping_step("title, severity, hostname columns"),
            test_step("We'll open a TCP connection to the database host."),
            review_step(),
        ]

    def test_connection(self, config):
        host = config.get("host", "")
        try:
            port = int(config.get("port") or 5432)
        except (TypeError, ValueError):
            return {"ok": False, "message": "Port must be a number."}
        if config.get("engine") == "sqlite":
            return {"ok": True, "message": "SQLite is file-based; no network "
                                           "check needed."}
        try:
            with socket.create_connection((host, port), timeout=5):
                return {"ok": True, "message": f"Reached {host}:{port}"}
        except OSError as exc:
            return {"ok": False, "message": f"Could not reach {host}:{port} — {exc}"}


@register
class SyslogConnector(BaseConnector):
    type_id = "syslog"
    label = "Syslog / CEF stream"
    category = "Network"
    icon = "📡"
    description = ("Ingest syslog, CEF, or LEEF streams from firewalls, "
                   "proxies, and network appliances.")

    def steps(self):
        return [
            details_step(),
            IntegrationStep(
                id="connection", title="Listener",
                fields=[
                    Field("protocol", "Protocol", type="select",
                          choices=["udp", "tcp", "tls"], default="udp"),
                    Field("listen_port", "Listen port", type="number",
                          default=5514),
                    Field("format", "Message format", type="select",
                          choices=["syslog-rfc5424", "syslog-rfc3164",
                                   "cef", "leef"],
                          default="syslog-rfc5424"),
                ],
            ),
            mapping_step("msg, severity, hostname (parsed from the frame)"),
            test_step("We'll verify the port is free and bindable."),
            review_step(),
        ]

    def test_connection(self, config):
        try:
            port = int(config.get("listen_port") or 0)
        except (TypeError, ValueError):
            return {"ok": False, "message": "Listen port must be a number."}
        if not 1 <= port <= 65535:
            return {"ok": False, "message": "Listen port must be 1–65535."}
        proto = config.get("protocol", "udp")
        sock_type = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
        try:
            with socket.socket(socket.AF_INET, sock_type) as sock:
                sock.bind(("0.0.0.0", port))
            return {"ok": True, "message": f"Port {port}/{proto} is available."}
        except OSError as exc:
            return {"ok": False, "message": f"Cannot bind port {port} — {exc}"}


@register
class FileLogConnector(BaseConnector):
    type_id = "file_log"
    label = "Log file / directory"
    category = "Data stores"
    icon = "📁"
    description = ("Tail local or mounted log files (JSON lines, plain "
                   "text) and emit events for new entries.")

    def steps(self):
        return [
            details_step(),
            IntegrationStep(
                id="connection", title="Source path",
                fields=[
                    Field("path", "File or glob",
                          placeholder="/var/log/security/*.json"),
                    Field("format", "Format", type="select",
                          choices=["jsonl", "plain"], default="jsonl"),
                    Field("from_beginning", "Read existing content",
                          type="toggle", required=False, default=False,
                          help="Off = only new lines after activation."),
                ],
            ),
            mapping_step("event, level, host keys in each JSON line"),
            test_step("We'll check the path pattern matches readable files."),
            review_step(),
        ]

    def test_connection(self, config):
        import glob as globlib
        pattern = config.get("path", "")
        if not pattern:
            return {"ok": False, "message": "Path is required."}
        matches = globlib.glob(pattern)
        if not matches:
            return {"ok": False,
                    "message": f"No files currently match '{pattern}'. "
                               "The watcher will still pick up files created "
                               "later — activate anyway if that's expected."}
        return {"ok": True,
                "message": f"{len(matches)} file(s) match.",
                "details": {"sample": matches[:5]}}


@register
class CloudQueueConnector(BaseConnector):
    type_id = "cloud_queue"
    label = "Cloud queue / event bus"
    category = "Cloud"
    icon = "☁️"
    description = ("Consume security findings from SQS, Pub/Sub, Event "
                   "Hubs, or Kafka topics — GuardDuty, Security Command "
                   "Center, Defender exports.")

    def steps(self):
        return [
            details_step(),
            IntegrationStep(
                id="connection", title="Queue",
                fields=[
                    Field("provider", "Provider", type="select",
                          choices=["aws_sqs", "gcp_pubsub",
                                   "azure_eventhub", "kafka"],
                          default="aws_sqs"),
                    Field("queue_url", "Queue URL / topic",
                          placeholder="https://sqs.us-east-1.amazonaws.com/123/findings"),
                    Field("region", "Region", required=False,
                          placeholder="us-east-1"),
                ],
            ),
            IntegrationStep(
                id="auth", title="Credentials",
                fields=[
                    Field("access_key", "Access key / client id"),
                    Field("secret_key", "Secret", type="password", secret=True),
                ],
            ),
            mapping_step("detail.title, detail.severity, resource.id"),
            test_step("We'll resolve and connect to the provider endpoint."),
            review_step(),
        ]

    def test_connection(self, config):
        target = config.get("queue_url", "")
        if config.get("provider") == "kafka" and "://" not in target:
            host, _, port = target.partition(":")
            try:
                with socket.create_connection((host, int(port or 9092)),
                                              timeout=5):
                    return {"ok": True, "message": f"Reached broker {target}"}
            except (OSError, ValueError) as exc:
                return {"ok": False, "message": f"Cannot reach {target} — {exc}"}
        return _check_url(target)
