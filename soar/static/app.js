/* SOAR Pilot console — single-page app over the REST API. */

const API = "/api/v1";
const $ = (sel, el = document) => el.querySelector(sel);

const state = {
  view: "dashboard",
  connectors: [],
  wizard: null, // { connector, integration, stepIndex, values, testResult, testing }
};

/* ── helpers ─────────────────────────────────────────── */

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    err.details = data.details;
    err.payload = data;
    throw err;
  }
  return data;
}

function esc(str) {
  return String(str ?? "").replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function toast(message, kind = "ok") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = message;
  $("#toast-rack").appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

function timeAgo(iso) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

const sev = (value) => `<span class="sev sev-${esc(value)}">${esc(value)}</span>`;
const chip = (value) => `<span class="chip chip-${esc(value)}">${esc(value).replace("_", " ")}</span>`;

const SEV_COLORS = { info: "#60a5fa", low: "#34d399", medium: "#fbbf24", high: "#fb923c", critical: "#f87171" };

/* ── routing ─────────────────────────────────────────── */

const VIEWS = {
  dashboard: { title: "Dashboard", render: renderDashboard },
  integrations: { title: "Integrations", render: renderIntegrations },
  playbooks: { title: "Playbooks", render: renderPlaybooks },
  incidents: { title: "Incidents", render: renderIncidents },
  events: { title: "Event stream", render: renderEvents },
};

function navigate(view) {
  state.view = VIEWS[view] ? view : "dashboard";
  document.querySelectorAll("#nav a").forEach((a) =>
    a.classList.toggle("active", a.dataset.view === state.view));
  $("#view-title").textContent = VIEWS[state.view].title;
  refresh();
}

async function refresh() {
  const target = $("#view");
  try {
    await VIEWS[state.view].render(target);
  } catch (err) {
    target.innerHTML = `<div class="card empty"><div class="empty-ico">⚠</div>${esc(err.message)}</div>`;
  }
}

/* ── dashboard ───────────────────────────────────────── */

async function renderDashboard(el) {
  const [metrics, incidents, events] = await Promise.all([
    api("/metrics"), api("/incidents"), api("/events?limit=8"),
  ]);
  const open = incidents.filter((i) => !["resolved", "closed"].includes(i.status));
  const maxSev = Math.max(1, ...Object.values(metrics.open_by_severity));

  el.innerHTML = `
    <div class="grid-metrics">
      <div class="card metric metric-accent">
        <div class="metric-label">Open incidents</div>
        <div class="metric-value">${metrics.incidents_open}</div>
        <div class="metric-sub">${metrics.incidents_total} total</div>
      </div>
      <div class="card metric">
        <div class="metric-label">Active integrations</div>
        <div class="metric-value">${metrics.integrations_active}</div>
        <div class="metric-sub">of ${metrics.integrations_total} configured</div>
      </div>
      <div class="card metric">
        <div class="metric-label">Events ingested</div>
        <div class="metric-value">${metrics.events_total}</div>
        <div class="metric-sub">all sources</div>
      </div>
      <div class="card metric">
        <div class="metric-label">Playbook runs</div>
        <div class="metric-value">${metrics.playbook_runs}</div>
        <div class="metric-sub">${metrics.playbooks_enabled} playbooks enabled</div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <h3>Recent incidents</h3>
        ${open.length ? `<table class="table"><thead><tr>
            <th>Incident</th><th>Severity</th><th>Status</th><th>Age</th>
          </tr></thead><tbody>
          ${open.slice(0, 6).map((i) => `
            <tr class="clickable" data-incident="${esc(i.id)}">
              <td><div class="cell-title">${esc(i.title)}</div>
                  <div class="cell-dim">${esc(i.source)}${i.entity ? " · " + esc(i.entity) : ""}</div></td>
              <td>${sev(i.severity)}</td>
              <td>${chip(i.status)}</td>
              <td class="cell-dim">${timeAgo(i.created_at)}</td>
            </tr>`).join("")}
          </tbody></table>`
        : `<div class="empty"><div class="empty-ico">✓</div>No open incidents. Quiet day.</div>`}
      </div>
      <div>
        <div class="card">
          <h3>Open by severity</h3>
          <div class="sevbar">
            ${["critical", "high", "medium", "low", "info"].map((s) => `
              <div class="sevbar-row">
                <span class="sevbar-label">${s}</span>
                <div class="sevbar-track"><div class="sevbar-fill"
                  style="width:${(metrics.open_by_severity[s] / maxSev) * 100}%;background:${SEV_COLORS[s]}"></div></div>
                <span class="sevbar-count">${metrics.open_by_severity[s]}</span>
              </div>`).join("")}
          </div>
        </div>
        <div class="card section-gap">
          <h3>Live events</h3>
          ${events.length ? events.map((e) => `
            <div style="padding:8px 0;border-bottom:1px solid var(--border)">
              <div style="display:flex;justify-content:space-between;gap:8px;align-items:center">
                <span style="font-size:13px;font-weight:550">${esc(e.title)}</span>
                ${sev(e.severity)}
              </div>
              <div class="cell-dim">${esc(e.source)} · ${timeAgo(e.received_at)}</div>
            </div>`).join("")
          : `<div class="empty">No events yet.</div>`}
        </div>
      </div>
    </div>`;
  bindIncidentRows(el);
}

/* ── integrations ────────────────────────────────────── */

async function renderIntegrations(el) {
  const integrations = await api("/integrations");
  if (!integrations.length) {
    el.innerHTML = `<div class="card empty">
      <div class="empty-ico">⇄</div>
      <p>No integrations yet. Connect your first data source.</p>
      <p class="section-gap"><button class="btn btn-primary" onclick="openWizard()">+ New integration</button></p>
    </div>`;
    return;
  }
  el.innerHTML = `<div class="int-grid">
    ${integrations.map((i) => {
      const connector = state.connectors.find((c) => c.type_id === i.connector_type) || {};
      const total = (connector.steps || []).length || 1;
      const pct = Math.round((i.completed_steps.length / total) * 100);
      return `<div class="card int-card">
        <div class="int-head">
          <div class="int-icon">${connector.icon || "🔌"}</div>
          <div style="flex:1;min-width:0">
            <div class="int-name">${esc(i.name)}</div>
            <div class="int-type">${esc(connector.label || i.connector_type)}</div>
          </div>
          ${chip(i.status)}
        </div>
        ${i.status === "draft" || i.status === "testing" ? `
          <div class="sevbar-row" style="grid-template-columns:1fr 38px">
            <div class="sevbar-track"><div class="sevbar-fill" style="width:${pct}%;background:var(--accent)"></div></div>
            <span class="sevbar-count">${pct}%</span>
          </div>` : ""}
        <div class="int-stats">
          <span><b>${i.events_ingested}</b> events</span>
          <span>added <b>${timeAgo(i.created_at)}</b></span>
        </div>
        <div class="int-actions">
          ${i.status === "active" || i.status === "paused" ? `
            <button class="btn btn-ghost btn-sm" data-act="simulate" data-id="${esc(i.id)}">⚡ Send test event</button>
            <button class="btn btn-ghost btn-sm" data-act="pause" data-id="${esc(i.id)}">${i.status === "active" ? "⏸ Pause" : "▶ Resume"}</button>`
          : `<button class="btn btn-primary btn-sm" data-act="resume-setup" data-id="${esc(i.id)}" data-type="${esc(i.connector_type)}">Continue setup →</button>`}
          <button class="btn btn-danger btn-sm" data-act="delete" data-id="${esc(i.id)}">Delete</button>
        </div>
      </div>`;
    }).join("")}
  </div>`;

  el.querySelectorAll("[data-act]").forEach((btn) => btn.addEventListener("click", async () => {
    const { act, id, type } = btn.dataset;
    try {
      if (act === "simulate") {
        const result = await api(`/integrations/${id}/simulate`, { method: "POST" });
        const runs = result.playbook_runs.length;
        toast(`Event ingested — ${runs} playbook${runs === 1 ? "" : "s"} triggered`);
        refresh();
      } else if (act === "pause") {
        await api(`/integrations/${id}/pause`, { method: "POST" });
        refresh();
      } else if (act === "delete") {
        if (!confirm("Delete this integration?")) return;
        await api(`/integrations/${id}`, { method: "DELETE" });
        toast("Integration deleted");
        refresh();
      } else if (act === "resume-setup") {
        const integration = await api(`/integrations/${id}`);
        const connector = state.connectors.find((c) => c.type_id === type);
        startWizard(connector, integration);
      }
    } catch (err) { toast(err.message, "err"); }
  }));
}

/* ── playbooks ───────────────────────────────────────── */

async function renderPlaybooks(el) {
  const { playbooks, action_catalog } = await api("/playbooks");
  el.innerHTML = `
    <div class="pb-grid">
      ${playbooks.map((p) => `
        <div class="card pb-card">
          <div class="pb-head">
            <div>
              <div class="pb-name">${esc(p.name)}</div>
              <div class="pb-desc">${esc(p.description)}</div>
            </div>
            <label class="switch" title="Enable/disable">
              <input type="checkbox" data-pb="${esc(p.id)}" ${p.enabled ? "checked" : ""}>
              <span class="track"></span>
            </label>
          </div>
          <div class="pb-actions-list">
            ${p.actions.map((a) => `<span class="pb-action-chip" title="${esc(action_catalog[a] || "")}">${esc(a.replace(/_/g, " "))}</span>`).join("")}
          </div>
          <div class="pb-meta">
            <span>trigger ≥ ${sev(p.min_severity)}</span>
            ${p.source_contains ? `<span>source ~ "${esc(p.source_contains)}"</span>` : ""}
            ${p.category_contains ? `<span>category ~ "${esc(p.category_contains)}"</span>` : ""}
            <span style="margin-left:auto"><b style="color:var(--text)">${p.runs}</b> runs</span>
          </div>
        </div>`).join("")}
    </div>`;
  el.querySelectorAll("[data-pb]").forEach((input) => input.addEventListener("change", async () => {
    try {
      await api(`/playbooks/${input.dataset.pb}`, { method: "PATCH", body: { enabled: input.checked } });
      toast(`Playbook ${input.checked ? "enabled" : "disabled"}`);
    } catch (err) { toast(err.message, "err"); }
  }));
}

/* ── incidents ───────────────────────────────────────── */

async function renderIncidents(el) {
  const incidents = await api("/incidents");
  if (!incidents.length) {
    el.innerHTML = `<div class="card empty"><div class="empty-ico">⚑</div>No incidents recorded.</div>`;
    return;
  }
  el.innerHTML = `<div class="card">
    <table class="table"><thead><tr>
      <th>Incident</th><th>Severity</th><th>Status</th><th>Assignee</th><th>Events</th><th>Age</th>
    </tr></thead><tbody>
    ${incidents.map((i) => `
      <tr class="clickable" data-incident="${esc(i.id)}">
        <td><div class="cell-title">${esc(i.title)}</div>
            <div class="cell-dim">${esc(i.source)}${i.entity ? " · " + esc(i.entity) : ""}</div></td>
        <td>${sev(i.severity)}</td>
        <td>${chip(i.status)}</td>
        <td class="cell-dim">${esc(i.assignee || "—")}</td>
        <td class="cell-dim">${i.event_ids.length}</td>
        <td class="cell-dim">${timeAgo(i.created_at)}</td>
      </tr>`).join("")}
    </tbody></table>
  </div>`;
  bindIncidentRows(el);
}

function bindIncidentRows(el) {
  el.querySelectorAll("[data-incident]").forEach((row) =>
    row.addEventListener("click", () => openIncident(row.dataset.incident)));
}

async function openIncident(id) {
  const incident = await api(`/incidents/${id}`);
  const drawer = $("#drawer");
  const statuses = ["new", "triaged", "in_progress", "contained", "resolved", "closed"];
  drawer.innerHTML = `
    <div class="drawer-head">
      <h2>${esc(incident.title)}</h2>
      <button class="modal-close" id="drawer-close">×</button>
    </div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px">
      ${sev(incident.severity)} ${chip(incident.status)}
      <span class="mono">${esc(incident.id)}</span>
    </div>
    <div class="cell-dim">Source: <b style="color:var(--text)">${esc(incident.source)}</b>
      ${incident.entity ? ` · Entity: <b style="color:var(--text)">${esc(incident.entity)}</b>` : ""}
      · ${incident.event_ids.length} correlated event(s)</div>
    <div class="field section-gap">
      <label>Status</label>
      <select id="drawer-status">
        ${statuses.map((s) => `<option value="${s}" ${s === incident.status ? "selected" : ""}>${s.replace("_", " ")}</option>`).join("")}
      </select>
    </div>
    <h3 style="margin-top:22px;font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:var(--text-dim)">Timeline</h3>
    <div class="timeline">
      ${incident.timeline.slice().reverse().map((t) => `
        <div class="tl-item">
          <div class="tl-kind">${esc(t.kind)}</div>
          <div class="tl-msg">${esc(t.message)}</div>
          <div class="tl-at">${esc(t.at.replace("T", " ").slice(0, 19))} UTC</div>
        </div>`).join("")}
    </div>`;
  drawer.classList.remove("hidden");
  $("#drawer-close").addEventListener("click", () => drawer.classList.add("hidden"));
  $("#drawer-status").addEventListener("change", async (e) => {
    try {
      await api(`/incidents/${id}`, { method: "PATCH", body: { status: e.target.value } });
      toast("Incident updated");
      refresh();
      openIncident(id);
    } catch (err) { toast(err.message, "err"); }
  });
}

/* ── events ──────────────────────────────────────────── */

async function renderEvents(el) {
  const events = await api("/events?limit=100");
  if (!events.length) {
    el.innerHTML = `<div class="card empty"><div class="empty-ico">≋</div>No events ingested yet.</div>`;
    return;
  }
  el.innerHTML = `<div class="card">
    <table class="table"><thead><tr>
      <th>Event</th><th>Severity</th><th>Category</th><th>Entity</th><th>Source</th><th>Received</th>
    </tr></thead><tbody>
    ${events.map((e) => `
      <tr>
        <td class="cell-title">${esc(e.title)}</td>
        <td>${sev(e.severity)}</td>
        <td class="cell-dim">${esc(e.category)}</td>
        <td class="mono">${esc(e.entity || "—")}</td>
        <td class="cell-dim">${esc(e.source)}</td>
        <td class="cell-dim">${timeAgo(e.received_at)}</td>
      </tr>`).join("")}
    </tbody></table>
  </div>`;
}

/* ── integration wizard ──────────────────────────────── */

function openWizard() {
  state.wizard = null;
  const modal = $("#wizard-modal");
  modal.innerHTML = `
    <div class="modal-head">
      <h2>Connect a data source</h2>
      <button class="modal-close" onclick="closeWizard()">×</button>
    </div>
    <div class="modal-body">
      <p class="step-desc">Pick a connector. Every source walks through its own guided
      integration steps — connection, auth, field mapping, a connection test, then activation.</p>
      <div class="conn-grid">
        ${state.connectors.map((c) => `
          <button class="conn-card" data-type="${esc(c.type_id)}">
            <span class="conn-ico">${c.icon}</span>
            <span class="conn-cat">${esc(c.category)}</span>
            <span class="conn-label">${esc(c.label)}</span>
            <span class="conn-desc">${esc(c.description)}</span>
          </button>`).join("")}
      </div>
    </div>`;
  modal.querySelectorAll(".conn-card").forEach((card) => card.addEventListener("click", async () => {
    const connector = state.connectors.find((c) => c.type_id === card.dataset.type);
    try {
      const integration = await api("/integrations", { method: "POST", body: { connector_type: connector.type_id } });
      startWizard(connector, integration);
    } catch (err) { toast(err.message, "err"); }
  }));
  $("#wizard-backdrop").classList.remove("hidden");
}

function closeWizard() {
  $("#wizard-backdrop").classList.add("hidden");
  state.wizard = null;
  refresh();
}

function startWizard(connector, integration) {
  const stepIndex = Math.min(integration.completed_steps.length, connector.steps.length - 1);
  state.wizard = { connector, integration, stepIndex, values: { ...integration.config }, testResult: null, testing: false, errors: null };
  $("#wizard-backdrop").classList.remove("hidden");
  renderWizard();
}

function renderWizard() {
  const w = state.wizard;
  const step = w.connector.steps[w.stepIndex];
  const modal = $("#wizard-modal");

  const stepper = w.connector.steps.map((s, idx) => {
    const cls = idx < w.stepIndex ? "done" : idx === w.stepIndex ? "current" : "";
    return `<div class="step-node ${cls}">
        <div class="step-dot">${idx < w.stepIndex ? "✓" : idx + 1}</div>
        <div class="step-label">${esc(s.title)}</div>
      </div>${idx < w.connector.steps.length - 1 ? `<div class="step-line ${idx < w.stepIndex ? "done" : ""}"></div>` : ""}`;
  }).join("");

  let body = "";
  if (step.kind === "form") {
    body = `<div class="form-grid">
      ${step.fields.map((f) => {
        const value = w.values[f.key] ?? f.default ?? "";
        const full = f.type === "textarea" ? "full" : "";
        let input;
        if (f.type === "select") {
          input = `<select name="${esc(f.key)}">
            ${f.choices.map((c) => `<option value="${esc(c)}" ${c === value ? "selected" : ""}>${esc(c)}</option>`).join("")}
          </select>`;
        } else if (f.type === "textarea") {
          input = `<textarea name="${esc(f.key)}" placeholder="${esc(f.placeholder)}">${esc(value)}</textarea>`;
        } else if (f.type === "toggle") {
          input = `<div class="toggle-row"><input type="checkbox" name="${esc(f.key)}" ${value ? "checked" : ""}>
                   <span class="cell-dim">${esc(f.help || f.label)}</span></div>`;
        } else {
          const type = f.type === "password" ? "password" : f.type === "number" ? "number" : "text";
          input = `<input type="${type}" name="${esc(f.key)}" value="${esc(value)}" placeholder="${esc(f.placeholder)}" autocomplete="off">`;
        }
        return `<div class="field ${full}">
          <label>${esc(f.label)}${f.required ? '<span class="req">*</span>' : ""}</label>
          ${input}
          ${f.help && f.type !== "toggle" ? `<div class="hint">${esc(f.help)}</div>` : ""}
        </div>`;
      }).join("")}
    </div>
    ${w.errors ? `<ul class="form-errors">${w.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : ""}`;
  } else if (step.kind === "test") {
    body = `<div class="test-panel">
      <button class="btn btn-primary" id="run-test" ${w.testing ? "disabled" : ""}>
        ${w.testing ? '<span class="spinner"></span>Testing…' : "Run connection test"}
      </button>
      ${w.testResult ? `<div class="test-result ${w.testResult.ok ? "ok" : "fail"}">
          ${w.testResult.ok ? "✓" : "✕"} ${esc(w.testResult.message)}
        </div>` : ""}
    </div>`;
  } else if (step.kind === "review") {
    const rows = Object.entries(w.integration.config)
      .filter(([k]) => k !== "description")
      .map(([k, v]) => `<tr><td>${esc(k)}</td><td><code>${esc(typeof v === "object" ? JSON.stringify(v) : v)}</code></td></tr>`).join("");
    body = `<table class="review-table">${rows}</table>`;
  }

  const isLast = w.stepIndex === w.connector.steps.length - 1;
  const nextLabel = step.kind === "review" ? "Activate integration ✓"
    : step.kind === "test" ? "Continue →" : "Save & continue →";
  const nextDisabled = step.kind === "test" && !(w.testResult && w.testResult.ok);

  modal.innerHTML = `
    <div class="modal-head">
      <h2>${w.connector.icon} ${esc(w.connector.label)} — ${esc(w.integration.name)}</h2>
      <button class="modal-close" onclick="closeWizard()">×</button>
    </div>
    <div class="modal-body">
      <div class="stepper">${stepper}</div>
      <div class="step-heading">${esc(step.title)}</div>
      <div class="step-desc">${esc(step.description)}</div>
      ${body}
      <div class="wizard-foot">
        <button class="btn btn-ghost" id="wiz-back" ${w.stepIndex === 0 ? "disabled" : ""}>← Back</button>
        <button class="btn btn-primary" id="wiz-next" ${nextDisabled ? "disabled" : ""}>${nextLabel}</button>
      </div>
    </div>`;

  $("#wiz-back").addEventListener("click", () => {
    if (w.stepIndex > 0) { w.stepIndex--; w.errors = null; renderWizard(); }
  });

  const runTest = $("#run-test");
  if (runTest) runTest.addEventListener("click", () => submitTest());

  $("#wiz-next").addEventListener("click", () => submitStep(isLast));
}

async function submitTest() {
  const w = state.wizard;
  w.testing = true;
  renderWizard();
  try {
    const result = await api(`/integrations/${w.integration.id}/steps/test`, { method: "POST", body: {} });
    w.integration = result.integration;
    w.testResult = result.test;
  } catch (err) {
    w.testResult = (err.payload && err.payload.test) || { ok: false, message: err.message };
    if (err.payload && err.payload.integration) w.integration = err.payload.integration;
  }
  w.testing = false;
  renderWizard();
}

async function submitStep(isLast) {
  const w = state.wizard;
  const step = w.connector.steps[w.stepIndex];
  try {
    if (step.kind === "form") {
      const values = {};
      step.fields.forEach((f) => {
        const input = document.querySelector(`#wizard-modal [name="${f.key}"]`);
        if (!input) return;
        values[f.key] = f.type === "toggle" ? input.checked : input.value;
      });
      // Don't overwrite stored secrets with the redacted mask.
      Object.keys(values).forEach((k) => { if (values[k] === "••••••••") delete values[k]; });
      const result = await api(`/integrations/${w.integration.id}/steps/${step.id}`, { method: "POST", body: values });
      w.integration = result.integration;
      Object.assign(w.values, values);
      w.errors = null;
    } else {
      const result = await api(`/integrations/${w.integration.id}/steps/${step.id}`, { method: "POST", body: {} });
      w.integration = result.integration;
    }
    if (isLast) {
      toast(`${w.integration.name} is live — events are flowing ✓`);
      closeWizard();
      navigate("integrations");
    } else {
      w.stepIndex++;
      renderWizard();
    }
  } catch (err) {
    w.errors = err.details || [err.message];
    renderWizard();
  }
}

/* ── boot ────────────────────────────────────────────── */

window.openWizard = openWizard;
window.closeWizard = closeWizard;

document.querySelectorAll("#nav a").forEach((a) =>
  a.addEventListener("click", (e) => { e.preventDefault(); navigate(a.dataset.view); }));
$("#refresh-btn").addEventListener("click", refresh);
$("#add-integration-btn").addEventListener("click", openWizard);
$("#wizard-backdrop").addEventListener("click", (e) => {
  if (e.target.id === "wizard-backdrop") closeWizard();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { closeWizard(); $("#drawer").classList.add("hidden"); }
});

(async function boot() {
  state.connectors = await api("/connectors");
  const initial = location.hash.replace("#", "") || "dashboard";
  navigate(initial);
  setInterval(() => { if (!state.wizard) refresh(); }, 20000);
})();
