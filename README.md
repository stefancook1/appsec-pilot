# AppSec Pilot

## SOAR Pilot — Security Orchestration, Automation & Response

A pluggable SOAR platform with a polished web console. **Any data source can
be plugged in** through a connector that declares its own guided
**integration steps** — the platform renders the setup wizard, validates each
step, tests connectivity, and activates the feed. Events from every source
are normalized into one schema, correlated into incidents, and acted on by
automation playbooks.

### Quick start

```bash
pip install -r requirements.txt
python run_soar.py
# open http://127.0.0.1:8800
```

The app boots with demo data — two active integrations, three playbooks, and
a stream of sample events already run through the pipeline — so the console
is alive on first load.

### Built-in connectors

| Connector | Category | How it ingests |
|---|---|---|
| 🌐 REST API | Generic | Polls any HTTP/JSON endpoint |
| 📨 Inbound Webhook | Generic | Tools push events to a secret-protected URL |
| 🗄️ SQL Database | Data stores | Scheduled queries against alert/audit tables |
| 📁 Log file / directory | Data stores | Tails JSONL or plain-text logs |
| 📡 Syslog / CEF | Network | UDP/TCP/TLS listener for appliance streams |
| ☁️ Cloud queue | Cloud | SQS, Pub/Sub, Event Hubs, Kafka topics |

### Integration steps

Every connector walks the user through the same wizard pattern, with
connector-specific steps in between:

1. **Details** — name the integration
2. **Connection / Auth / Query…** — connector-specific configuration
3. **Field mapping** — dot-paths that lift the source's raw payload into the
   normalized event schema (`map_title`, `map_severity`, `map_entity`, …)
4. **Test connection** — live validation of the candidate config
5. **Review & activate** — confirm and go live

### Plugging in a new data source

Subclass `BaseConnector`, declare your steps, and register it — the API and
UI pick it up automatically:

```python
from soar.connectors import BaseConnector, Field, IntegrationStep, register
from soar.connectors.base import details_step, mapping_step, review_step, test_step

@register
class MyToolConnector(BaseConnector):
    type_id = "my_tool"
    label = "My Tool"
    category = "Generic"
    icon = "🛠️"
    description = "Pull findings from My Tool."

    def steps(self):
        return [
            details_step(),
            IntegrationStep(id="connection", title="Connection", fields=[
                Field("tenant_url", "Tenant URL"),
                Field("api_token", "API token", type="password", secret=True),
            ]),
            mapping_step("finding.title, finding.risk, asset.name"),
            test_step("We'll verify the tenant is reachable."),
            review_step(),
        ]

    def test_connection(self, config):
        ...  # return {"ok": bool, "message": str}
```

### REST API

Everything in the UI is scriptable:

```
GET    /api/v1/connectors                          # discover connectors + their steps
POST   /api/v1/integrations                        # create a draft
POST   /api/v1/integrations/<id>/steps/<step_id>   # submit one wizard step
POST   /api/v1/ingest/<id>                         # push a raw event (X-SOAR-Secret)
GET    /api/v1/incidents | /events | /playbooks | /metrics
POST   /api/v1/playbooks                           # automation: triggers + actions
```

### Tests

```bash
pip install pytest && pytest tests/ -v
```
