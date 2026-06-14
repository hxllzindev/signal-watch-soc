const state = {
  role: localStorage.getItem("signal-watch-role") || "analyst",
  view: "overview",
  alerts: [],
  cases: [],
  rules: []
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const e = (value = "") => String(value).replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character]));
const fmtDate = (value) => new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short" }).format(new Date(value));
const age = (value) => {
  const minutes = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 60_000));
  if (minutes < 1) return "agora";
  if (minutes < 60) return `${minutes} min`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)} h`;
  return `${Math.floor(minutes / 1440)} d`;
};
const label = (value) => ({ critical: "Crítico", high: "Alto", medium: "Médio", low: "Baixo", new: "Novo", investigating: "Investigando", contained: "Contido", closed: "Fechado", open: "Aberto", healthy: "Saudável", delayed: "Atrasado", success: "Sucesso", failure: "Falha", unknown: "Desconhecido" }[value] || value);
const badge = (value) => `<span class="badge ${e(value)}">${e(label(value))}</span>`;

async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", "X-SOC-Role": state.role, ...(options.headers || {}) }
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Erro HTTP ${response.status}`);
  return payload;
}

function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", error);
  element.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => element.classList.remove("show"), 3200);
}

function empty(message) {
  return `<div class="empty-state">${e(message)}</div>`;
}

function alertRows(alerts, compact = false) {
  if (!alerts.length) return empty("Nenhum alerta corresponde aos filtros.");
  return `<table><thead><tr><th>Severidade</th><th>Detecção</th>${compact ? "" : "<th>Entidade</th>"}<th>Status</th><th>Último sinal</th></tr></thead><tbody>${alerts.map((alert) => `<tr data-kind="alert" data-id="${e(alert.id)}"><td>${badge(alert.severity)}</td><td><span class="table-title">${e(alert.title)}</span><span class="table-subtitle">${e(alert.techniqueId)} · ${e(alert.tactic)}</span></td>${compact ? "" : `<td><span class="mono">${e(alert.user || alert.host || alert.sourceIp || "-")}</span><span class="table-subtitle">${e(alert.assignee)}</span></td>`}<td>${badge(alert.status)}</td><td><span title="${e(fmtDate(alert.lastSeen))}">${e(age(alert.lastSeen))}</span></td></tr>`).join("")}</tbody></table>`;
}

async function renderOverview() {
  const [summary, alerts, sources] = await Promise.all([api("/summary"), api("/alerts"), api("/sources")]);
  state.alerts = alerts.alerts;
  $("#nav-alert-count").textContent = summary.activeAlerts;
  $("#source-status").textContent = `${summary.healthySources}/${summary.totalSources} fontes saudáveis`;
  $("#last-refresh").textContent = `Atualizado ${new Intl.DateTimeFormat("pt-BR", { timeStyle: "medium" }).format(new Date())}`;
  const metrics = [
    ["Eventos em 24 h", summary.events24h, ""],
    ["Alertas ativos", summary.activeAlerts, ""],
    ["Alertas críticos", summary.criticalAlerts, "danger"],
    ["Casos abertos", summary.openCases, ""],
    ["Fontes saudáveis", `${summary.healthySources}/${summary.totalSources}`, ""]
  ];
  $("#metrics").innerHTML = metrics.map(([name, value, tone]) => `<div class="metric ${tone}"><span>${e(name)}</span><strong>${e(value)}</strong></div>`).join("");

  const maxTrend = Math.max(1, ...summary.trend.map((item) => item.count));
  $("#alert-trend").innerHTML = summary.trend.map((item) => {
    const height = item.count ? Math.max(1, Math.ceil(item.count / maxTrend * 10)) : 0;
    return `<div class="bar-item"><strong>${item.count}</strong><div class="bar h-${height}" title="${item.count} alertas"></div><span>${e(item.label)}</span></div>`;
  }).join("");

  const maxSeverity = Math.max(1, ...summary.severity.map((item) => item.count));
  $("#severity-list").innerHTML = summary.severity.map((item) => {
    const width = item.count ? Math.max(1, Math.ceil(item.count / maxSeverity * 10)) : 0;
    return `<div class="severity-row"><span>${e(label(item.severity))}</span><div class="severity-track"><div class="severity-fill ${e(item.severity)} w-${width}"></div></div><strong>${item.count}</strong></div>`;
  }).join("");

  $("#recent-alerts").innerHTML = alertRows(alerts.alerts.slice(0, 6), true);
  $("#sources-list").innerHTML = sources.sources.map((source) => `<div class="source-row"><div><strong>${e(source.name)}</strong><small>${source.eventCount} eventos · ${source.eventsPerMinute} epm</small></div>${badge(source.status)}</div>`).join("");
  $("#tactics-list").innerHTML = summary.tactics.length ? summary.tactics.map((item) => `<div class="tactic"><span>${e(item.tactic)}</span><strong>${item.count}</strong></div>`).join("") : empty("Nenhuma tática ativa.");
}

async function syncShell() {
  const summary = await api("/summary");
  $("#nav-alert-count").textContent = summary.activeAlerts;
  $("#source-status").textContent = `${summary.healthySources}/${summary.totalSources} fontes saudáveis`;
}

async function renderAlerts() {
  const params = new URLSearchParams();
  if ($("#alert-severity").value) params.set("severity", $("#alert-severity").value);
  if ($("#alert-status").value) params.set("status", $("#alert-status").value);
  const data = await api(`/alerts?${params}`);
  state.alerts = data.alerts;
  $("#alert-result-count").textContent = `${data.alerts.length} alertas`;
  $("#alerts-table").innerHTML = alertRows(data.alerts);
}

async function renderHunt() {
  const params = new URLSearchParams({ limit: "200" });
  const fields = [["#hunt-query", "q"], ["#hunt-source", "sourceType"], ["#hunt-category", "category"], ["#hunt-outcome", "outcome"]];
  fields.forEach(([selector, key]) => { if ($(selector).value) params.set(key, $(selector).value); });
  const data = await api(`/events?${params}`);
  $("#hunt-count").textContent = `${data.events.length} de ${data.total} eventos`;
  $("#events-table").innerHTML = data.events.length ? `<table><thead><tr><th>Horário</th><th>Fonte</th><th>Evento</th><th>Entidades</th><th>Resultado</th></tr></thead><tbody>${data.events.map((event) => `<tr><td class="mono">${e(fmtDate(event.timestamp))}</td><td>${e(event.sourceType)}<span class="table-subtitle">${e(event.category)}</span></td><td><span class="table-title">${e(event.message)}</span><span class="table-subtitle mono">${e(event.commandLine || event.httpPath || event.action)}</span></td><td><span class="mono">${e(event.user || event.host || event.sourceIp || "-")}</span><span class="table-subtitle">${e(event.sourceIp && event.destinationIp ? `${event.sourceIp} → ${event.destinationIp}:${event.destinationPort || ""}` : event.host || "")}</span></td><td>${badge(event.outcome)}</td></tr>`).join("")}</tbody></table>` : empty("Nenhum evento encontrado.");
}

async function renderCases() {
  const data = await api("/cases");
  state.cases = data.cases;
  $("#cases-list").innerHTML = data.cases.length ? data.cases.map((item) => `<article class="case-card" data-kind="case" data-id="${e(item.id)}" tabindex="0"><div class="case-card-head"><span class="mono">${e(item.id)}</span>${badge(item.status)}</div><div class="case-card-body"><div>${badge(item.severity)}</div><h2>${e(item.title)}</h2><p>${e(item.description)}</p></div><div class="case-card-foot"><span>${item.alertIds.length} alerta(s)</span><span>${e(item.owner)}</span></div></article>`).join("") : empty("Nenhum caso foi criado.");
}

async function renderRules() {
  const data = await api("/rules");
  state.rules = data.rules;
  const lead = state.role === "lead";
  $("#rules-table").innerHTML = `<table><thead><tr><th>Ativa</th><th>Regra</th><th>MITRE ATT&CK</th><th>Tipo</th><th>Severidade</th><th>Limite</th></tr></thead><tbody>${data.rules.map((rule) => `<tr><td><input class="rule-toggle" data-rule-id="${e(rule.id)}" data-field="enabled" type="checkbox" ${rule.enabled ? "checked" : ""} ${lead ? "" : "disabled"} aria-label="Ativar ${e(rule.name)}"></td><td><span class="table-title">${e(rule.name)}</span><span class="table-subtitle">${e(rule.description)}</span></td><td><span class="mono">${e(rule.techniqueId)}</span><span class="table-subtitle">${e(rule.techniqueName)}</span></td><td>${e(rule.type)}</td><td><select data-rule-id="${e(rule.id)}" data-field="severity" ${lead ? "" : "disabled"}><option ${rule.severity === "critical" ? "selected" : ""}>critical</option><option ${rule.severity === "high" ? "selected" : ""}>high</option><option ${rule.severity === "medium" ? "selected" : ""}>medium</option><option ${rule.severity === "low" ? "selected" : ""}>low</option></select></td><td>${rule.threshold ? `<input class="mono" data-rule-id="${e(rule.id)}" data-field="threshold" type="number" min="1" max="1000" value="${rule.threshold}" ${lead ? "" : "disabled"}>` : "-"}</td></tr>`).join("")}</tbody></table>`;
}

async function showAlert(id) {
  const { alert, evidence } = await api(`/alerts/${encodeURIComponent(id)}`);
  const canWrite = state.role !== "viewer";
  $("#drawer-content").innerHTML = `<div class="drawer-head"><div><p class="eyebrow">ALERT / ${e(alert.id.slice(-8))}</p><h2>${e(alert.title)}</h2></div><button id="close-drawer" class="icon-button" type="button" aria-label="Fechar">×</button></div>
    <section class="drawer-section"><div class="detail-grid"><div class="detail-item"><span>Severidade</span><strong>${badge(alert.severity)}</strong></div><div class="detail-item"><span>Status</span><strong>${badge(alert.status)}</strong></div><div class="detail-item"><span>MITRE</span><strong>${e(alert.techniqueId)} · ${e(alert.techniqueName)}</strong></div><div class="detail-item"><span>Risco</span><strong>${alert.riskScore}/100</strong></div><div class="detail-item"><span>Usuário</span><strong>${e(alert.user || "-")}</strong></div><div class="detail-item"><span>Origem / host</span><strong class="mono">${e(alert.sourceIp || alert.host || "-")}</strong></div></div></section>
    <section class="drawer-section"><h3>Resumo da detecção</h3><p>${e(alert.summary)}</p></section>
    <section class="drawer-section"><h3>Evidências (${evidence.length})</h3>${evidence.map((event) => `<div class="evidence"><span class="mono">${e(fmtDate(event.timestamp))} · ${e(event.sourceType)}</span><p>${e(event.message)}</p>${event.commandLine || event.httpPath ? `<code>${e(event.commandLine || event.httpPath)}</code>` : ""}</div>`).join("")}</section>
    <section class="drawer-section"><h3>Notas (${alert.notes.length})</h3>${alert.notes.length ? alert.notes.map((note) => `<div class="evidence"><strong>${e(note.author)}</strong><span class="table-subtitle">${e(fmtDate(note.createdAt))}</span><p>${e(note.text)}</p></div>`).join("") : `<p class="refresh-label">Nenhuma nota registrada.</p>`}</section>
    <section class="drawer-section"><h3>Triagem</h3><form id="alert-update-form" class="drawer-form"><input type="hidden" name="id" value="${e(alert.id)}"><label>Status<select name="status" ${canWrite ? "" : "disabled"}><option value="new" ${alert.status === "new" ? "selected" : ""}>Novo</option><option value="investigating" ${alert.status === "investigating" ? "selected" : ""}>Investigando</option><option value="contained" ${alert.status === "contained" ? "selected" : ""}>Contido</option><option value="closed" ${alert.status === "closed" ? "selected" : ""}>Fechado</option></select></label><label>Responsável<input name="assignee" value="${e(alert.assignee)}" ${canWrite ? "" : "disabled"}></label><label>Nota<textarea name="note" rows="3" ${canWrite ? "" : "disabled"}></textarea></label><button class="primary-button" type="submit" ${canWrite ? "" : "disabled"}>Salvar triagem</button><button class="secondary-button" id="create-case-button" type="button" data-alert-id="${e(alert.id)}" ${canWrite ? "" : "disabled"}>Criar caso</button></form></section>`;
  openDrawer();
}

async function showCase(id) {
  const data = await api(`/cases/${encodeURIComponent(id)}`);
  const item = data.case;
  const canWrite = state.role !== "viewer";
  $("#drawer-content").innerHTML = `<div class="drawer-head"><div><p class="eyebrow">CASE / ${e(item.id)}</p><h2>${e(item.title)}</h2></div><button id="close-drawer" class="icon-button" type="button" aria-label="Fechar">×</button></div>
    <section class="drawer-section"><div class="detail-grid"><div class="detail-item"><span>Severidade</span><strong>${badge(item.severity)}</strong></div><div class="detail-item"><span>Status</span><strong>${badge(item.status)}</strong></div><div class="detail-item"><span>Responsável</span><strong>${e(item.owner)}</strong></div><div class="detail-item"><span>Criado</span><strong>${e(fmtDate(item.createdAt))}</strong></div></div></section>
    <section class="drawer-section"><h3>Escopo</h3><p>${e(item.description)}</p></section>
    <section class="drawer-section"><h3>Alertas vinculados</h3>${data.alerts.map((alert) => `<button class="text-button linked-alert" type="button" data-alert-id="${e(alert.id)}">${e(alert.title)} · ${e(alert.techniqueId)}</button>`).join("")}</section>
    <section class="drawer-section"><h3>Linha do tempo</h3>${item.timeline.map((entry) => `<div class="evidence"><strong>${e(entry.author)}</strong><span class="table-subtitle">${e(fmtDate(entry.createdAt))} · ${e(entry.type)}</span><p>${e(entry.text)}</p></div>`).join("")}</section>
    <section class="drawer-section"><h3>Atualizar investigação</h3><form id="case-update-form" class="drawer-form"><input type="hidden" name="id" value="${e(item.id)}"><label>Status<select name="status" ${canWrite ? "" : "disabled"}><option value="open" ${item.status === "open" ? "selected" : ""}>Aberto</option><option value="investigating" ${item.status === "investigating" ? "selected" : ""}>Investigando</option><option value="contained" ${item.status === "contained" ? "selected" : ""}>Contido</option><option value="closed" ${item.status === "closed" ? "selected" : ""}>Fechado</option></select></label><label>Responsável<input name="owner" value="${e(item.owner)}" ${canWrite ? "" : "disabled"}></label><label>Nota de investigação<textarea name="note" rows="3" ${canWrite ? "" : "disabled"}></textarea></label><button class="primary-button" type="submit" ${canWrite ? "" : "disabled"}>Atualizar caso</button></form></section>`;
  openDrawer();
}

function openDrawer() {
  $("#detail-drawer").classList.add("open");
  $("#detail-drawer").setAttribute("aria-hidden", "false");
  $("#drawer-backdrop").classList.add("open");
}

function closeDrawer() {
  $("#detail-drawer").classList.remove("open");
  $("#detail-drawer").setAttribute("aria-hidden", "true");
  $("#drawer-backdrop").classList.remove("open");
}

async function showView(view) {
  state.view = view;
  $$(".view").forEach((element) => element.classList.toggle("active", element.id === `view-${view}`));
  $$(".nav-item").forEach((element) => element.classList.toggle("active", element.dataset.view === view));
  $(".sidebar").classList.remove("open");
  history.replaceState(null, "", `#${view}`);
  if (view !== "overview") await syncShell();
  if (view === "overview") await renderOverview();
  if (view === "alerts") await renderAlerts();
  if (view === "hunt") await renderHunt();
  if (view === "cases") await renderCases();
  if (view === "rules") await renderRules();
}

async function refreshCurrent() {
  await showView(state.view);
}

document.addEventListener("click", async (event) => {
  const nav = event.target.closest("[data-view]");
  if (nav) return showView(nav.dataset.view).catch((error) => toast(error.message, true));
  const go = event.target.closest("[data-go]");
  if (go) return showView(go.dataset.go).catch((error) => toast(error.message, true));
  const item = event.target.closest("[data-kind][data-id]");
  if (item?.dataset.kind === "alert") return showAlert(item.dataset.id).catch((error) => toast(error.message, true));
  if (item?.dataset.kind === "case") return showCase(item.dataset.id).catch((error) => toast(error.message, true));
  if (event.target.closest("#close-drawer") || event.target === $("#drawer-backdrop")) return closeDrawer();
  const linked = event.target.closest(".linked-alert");
  if (linked) return showAlert(linked.dataset.alertId).catch((error) => toast(error.message, true));
  const createCase = event.target.closest("#create-case-button");
  if (createCase) {
    $("#case-alert-id").value = createCase.dataset.alertId;
    const alert = state.alerts.find((candidate) => candidate.id === createCase.dataset.alertId);
    $("#case-title").value = alert ? `Investigar: ${alert.title}` : "Nova investigação";
    $("#case-severity").value = alert?.severity || "medium";
    return $("#case-dialog").showModal();
  }
  if (event.target.closest(".close-dialog")) return event.target.closest("dialog").close();
});

document.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    if (event.target.id === "hunt-form") return renderHunt();
    if (event.target.id === "alert-update-form") {
      const form = new FormData(event.target);
      await api(`/alerts/${encodeURIComponent(form.get("id"))}`, { method: "PATCH", body: JSON.stringify({ status: form.get("status"), assignee: form.get("assignee"), note: form.get("note"), author: state.role }) });
      toast("Triagem atualizada.");
      await showAlert(form.get("id"));
    }
    if (event.target.id === "case-update-form") {
      const form = new FormData(event.target);
      await api(`/cases/${encodeURIComponent(form.get("id"))}`, { method: "PATCH", body: JSON.stringify({ status: form.get("status"), owner: form.get("owner"), note: form.get("note"), author: state.role }) });
      toast("Caso atualizado.");
      await showCase(form.get("id"));
    }
    if (event.target.id === "ingest-form") {
      const events = JSON.parse($("#ingest-json").value);
      const result = await api("/ingest", { method: "POST", body: JSON.stringify({ source: $("#ingest-source").value, events }) });
      $("#ingest-dialog").close();
      toast(`${result.ingested} eventos ingeridos; ${result.alerts.length} alertas gerados.`);
      await refreshCurrent();
    }
    if (event.target.id === "case-form") {
      const result = await api("/cases", { method: "POST", body: JSON.stringify({ title: $("#case-title").value, description: $("#case-description").value, severity: $("#case-severity").value, owner: $("#case-owner").value, alertIds: [$("#case-alert-id").value] }) });
      $("#case-dialog").close();
      closeDrawer();
      toast(`Caso ${result.case.id} criado.`);
      await showView("cases");
    }
  } catch (error) { toast(error.message, true); }
});

$("#simulate-button").addEventListener("click", async () => {
  const button = $("#simulate-button");
  button.disabled = true; button.textContent = "Executando...";
  try {
    const result = await api("/simulate", { method: "POST", body: "{}" });
    toast(`${result.events} eventos simulados; ${result.alerts.length} alertas correlacionados.`);
    await refreshCurrent();
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; button.textContent = "Simular ataque"; }
});

$("#ingest-button").addEventListener("click", () => {
  const start = new Date(Date.now() - 30_000).toISOString();
  $("#ingest-json").value = JSON.stringify([
    { timestamp: start, username: "portfolio.demo", ip: "198.51.100.77", success: false, application: "vpn-gateway" },
    { username: "portfolio.demo", ip: "198.51.100.77", success: false, application: "vpn-gateway" }
  ], null, 2);
  $("#ingest-dialog").showModal();
});

$("#role-select").value = state.role;
$("#role-select").addEventListener("change", async (event) => {
  state.role = event.target.value;
  localStorage.setItem("signal-watch-role", state.role);
  toast(`Perfil alterado para ${event.target.selectedOptions[0].text}.`);
  closeDrawer();
  await refreshCurrent();
});

$("#alert-severity").addEventListener("change", () => renderAlerts().catch((error) => toast(error.message, true)));
$("#alert-status").addEventListener("change", () => renderAlerts().catch((error) => toast(error.message, true)));
$("#mobile-menu").addEventListener("click", () => $(".sidebar").classList.toggle("open"));
$("#drawer-backdrop").addEventListener("click", closeDrawer);

$("#rules-table").addEventListener("change", async (event) => {
  const control = event.target.closest("[data-rule-id][data-field]");
  if (!control) return;
  const value = control.type === "checkbox" ? control.checked : control.dataset.field === "threshold" ? Number(control.value) : control.value;
  try {
    await api(`/rules/${encodeURIComponent(control.dataset.ruleId)}`, { method: "PATCH", body: JSON.stringify({ [control.dataset.field]: value }) });
    toast("Regra atualizada.");
    await renderRules();
  } catch (error) { toast(error.message, true); await renderRules(); }
});

$$(".case-card").forEach(() => {});
const initialView = ["overview", "alerts", "hunt", "cases", "rules"].includes(location.hash.slice(1)) ? location.hash.slice(1) : "overview";
showView(initialView).catch((error) => toast(error.message, true));
