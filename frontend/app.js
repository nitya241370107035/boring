/**
 * SentinelLog SOC — Premium Frontend Application
 * Real API polling, correct field mapping, agent activity ring-buffer
 */

const API_BASE = window.location.origin;
const API_KEY  = "sentinel-secret-key-1";

let isStreamingPaused = false;
let agentActivityLog  = [];
const MAX_ACTIVITY    = 100;
let _lastEventId      = 0;
let _lastHostSnap     = {};

// ─── Time formatters ──────────────────────────────────────────────────────────
function timeAgo(iso) {
  if (!iso) return "—";
  const d    = new Date(iso);
  if (isNaN(d)) return iso;
  const diff = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diff <  5)    return "just now";
  if (diff <  60)   return `${diff}s ago`;
  if (diff <  3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toLocaleDateString() + " " + d.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"});
}
function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleTimeString([], {hour:"2-digit", minute:"2-digit", second:"2-digit"});
}

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  initLogLab();
  fetchInitialData();
  startPolling();
  pushActivity("system", "SOC Dashboard online — connected to " + API_BASE);
});

// ─── Tab system ───────────────────────────────────────────────────────────────
function setupTabs() {
  document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const id = btn.getAttribute("data-tab");
      document.querySelectorAll(".tab-content").forEach(t => t.classList.remove("active"));
      const el = document.getElementById(`tab-${id}`);
      if (el) el.classList.add("active");
      if (id === "loglab")      initLogLab();
      if (id === "hosts")       fetchHosts();
      if (id === "events")      fetchLiveEvents();
      if (id === "alerts")      fetchAlerts("open");
      if (id === "agent")       renderActivityPanel();
    });
  });
}

// ─── Toast ───────────────────────────────────────────────────────────────────
function showToast(msg, type = "info") {
  const c = document.getElementById("toast-container");
  const t = document.createElement("div");
  t.className = `toast ${type}`;
  const icon = type === "success" ? "✔" : type === "error" ? "✖" : "ℹ";
  t.innerHTML = `<span class="toast-icon">${icon}</span><span>${msg}</span>`;
  c.appendChild(t);
  setTimeout(() => {
    t.style.opacity  = "0";
    t.style.transform = "translateX(110%)";
    setTimeout(() => t.remove(), 320);
  }, 4000);
}

// ─── Agent activity ring-buffer ───────────────────────────────────────────────
function pushActivity(type, msg, host = null) {
  const entry = {ts: new Date().toISOString(), type, msg, host};
  agentActivityLog.unshift(entry);
  if (agentActivityLog.length > MAX_ACTIVITY) agentActivityLog.pop();
  renderActivityPanel();
  updateTicker(entry);
}

function updateTicker(entry) {
  const el = document.getElementById("agent-ticker");
  if (!el) return;
  const color = {alert:"var(--rose)", heartbeat:"var(--emerald)", event:"var(--amber)", system:"var(--cyan)"}[entry.type] || "var(--text-secondary)";
  el.innerHTML = `<span style="color:${color};">[${fmtTime(entry.ts)}]</span>`
    + (entry.host ? ` <span style="color:var(--purple);">&lt;${esc(entry.host)}&gt;</span>` : "")
    + ` <span style="color:${color};">${esc(entry.msg)}</span>`;
}

function renderActivityPanel() {
  const p = document.getElementById("agent-activity-list");
  if (!p) return;
  if (agentActivityLog.length === 0) {
    p.innerHTML = `<div style="color:var(--text-muted);text-align:center;padding:3rem;">
      No activity yet. Start agent: <code style="color:var(--cyan);">python agent/main.py</code></div>`;
    return;
  }
  const colors = {heartbeat:"var(--emerald)", alert:"var(--rose)", event:"var(--amber)", error:"var(--red)", system:"var(--cyan)"};
  const icons  = {heartbeat:"💓", alert:"🚨", event:"📡", error:"❌", system:"ℹ"};
  p.innerHTML = agentActivityLog.map(e => {
    const c = colors[e.type] || "var(--text-secondary)";
    const i = icons[e.type]  || "•";
    return `<div class="console-line" style="border-left:2px solid ${c}; padding-left:8px; margin-bottom:1px;">
      <span class="console-ts">[${fmtTime(e.ts)}]</span>
      <span style="margin:0 4px;">${i}</span>
      ${e.host ? `<span class="console-host">&lt;${esc(e.host)}&gt;</span>` : ""}
      <span style="color:${c}; flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${esc(e.msg)}</span>
    </div>`;
  }).join("");
}

// ─── Polling loop ─────────────────────────────────────────────────────────────
function startPolling() {
  setInterval(async () => {
    await checkHealth();
    await fetchMetrics();
    await fetchAlerts("open");
    if (!isStreamingPaused) await fetchLiveEvents();
    await fetchHosts();
  }, 3000);
}

async function fetchInitialData() {
  await checkHealth();
  await fetchMetrics();
  await fetchAlerts("open");
  await fetchHosts();
  await fetchLiveEvents();
}

// ─── Health ───────────────────────────────────────────────────────────────────
async function checkHealth() {
  const pulseEl  = document.getElementById("api-pulse");
  const statusEl = document.getElementById("api-status-text");
  const clockEl  = document.getElementById("server-clock");
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (res.ok) {
      const d = await res.json();
      statusEl.innerText = "ONLINE";
      statusEl.style.color = "var(--emerald)";
      pulseEl.style.background = "var(--emerald)";
      pulseEl.style.boxShadow  = "0 0 8px var(--emerald)";
      if (clockEl && d.timestamp) clockEl.innerText = fmtTime(d.timestamp);
    } else throw new Error();
  } catch {
    statusEl.innerText = "OFFLINE";
    statusEl.style.color = "var(--rose)";
    pulseEl.style.background = "var(--rose)";
    pulseEl.style.boxShadow  = "0 0 8px var(--rose)";
  }
}

// ─── Metrics ──────────────────────────────────────────────────────────────────
let _prevAlertCount = 0;
async function fetchMetrics() {
  try {
    const res = await fetch(`${API_BASE}/metrics`);
    if (!res.ok) return;
    const d = await res.json();
    animateNum("kpi-events", Number(d.total_events_ingested || 0));
    animateNum("kpi-alerts", d.open_security_alerts || 0);
    animateNum("kpi-hosts",  d.active_endpoints || 0);
    document.getElementById("nav-alert-count").innerText = d.open_security_alerts || 0;
    _prevAlertCount = d.open_security_alerts || 0;
  } catch (e) { console.error("Metrics:", e); }
}

function animateNum(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const current = parseInt(el.innerText.replace(/[^0-9]/g, "")) || 0;
  if (current === target) return;
  el.innerText = target.toLocaleString();
}

let currentAlertFilter = "open";

async function fetchAlerts(statusFilter = "open") {
  try {
    currentAlertFilter = statusFilter;
    ["filter-open", "filter-all", "filter-ack", "filter-fp"].forEach(id => {
      const btn = document.getElementById(id);
      if (btn) btn.classList.remove("primary");
    });
    const map = { open: "filter-open", all: "filter-all", acknowledged: "filter-ack", false_positive: "filter-fp" };
    const activeBtn = document.getElementById(map[statusFilter]);
    if (activeBtn) activeBtn.classList.add("primary");

    const url = statusFilter === "all"
      ? `${API_BASE}/alerts?limit=50`
      : `${API_BASE}/alerts?status=${statusFilter}&limit=50`;
    const res = await fetch(url);
    if (!res.ok) return;
    const raw = await res.json();

    const alerts = raw.map(a => ({
      ...a,
      created_at:   a.ts || a.created_at,
      threat_score: a.score ?? a.threat_score ?? 0,
      host_or_ip:   a.host || a.host_or_ip || "unknown",
      title:        buildTitle(a),
    }));

    // Detect new alerts
    const openNow = alerts.filter(a => a.status === "open").length;
    if (openNow > _prevAlertCount && _prevAlertCount > 0) {
      const n = alerts.find(a => a.status === "open");
      if (n) pushActivity("alert", `New alert: ${n.title}`, n.host_or_ip);
    }

    renderOverviewAlerts(alerts.slice(0, 8));
    renderTriageAlerts(alerts);
  } catch (e) { console.error("Alerts:", e); }
}

const RULE_NAMES = {
  "WEB-SQLI-001": "SQL Injection Attack",
  "WEB-XSS-001": "Cross-Site Scripting (XSS)",
  "WEB-TRAV-001": "Directory Traversal Attack",
  "WEB-CMDI-001": "Command Injection Exploit",
  "WEB-SCAN-001": "Path & Vulnerability Scan",
  "WEB-BRUTE-001": "Credential Brute Force",
  "EP-PROC-001": "Suspicious Process Spawn",
  "EP-PROC-002": "Encoded PowerShell Invocation",
  "EP-FILE-001": "Rapid File Churn (Ransomware)",
  "EP-NET-001": "Unusual C2 Remote Connection",
  "EP-AUTH-001": "Failed Logon Burst Anomaly",
  "EP-PERSIST-001": "Registry Persistence Mechanism",
};

function buildTitle(a) {
  let title = a.title || "";
  title = title.replace(/^(CRITICAL|HIGH|MEDIUM|LOW)\s*—\s*/i, "").trim();
  
  if (!title || title.startsWith("EP-") || title.startsWith("WEB-")) {
    const ruleKey = a.rule_id || (title.split(" ")[0]);
    const friendly = RULE_NAMES[ruleKey] || ruleKey || "Threat Detection";
    const host = a.host_or_ip || a.host || "";
    return host ? `${friendly} on ${host}` : friendly;
  }
  return title;
}

function renderOverviewAlerts(alerts) {
  const c = document.getElementById("overview-alerts-list");
  if (!alerts || alerts.length === 0) {
    c.innerHTML = `<div style="padding:2.5rem;text-align:center;color:var(--text-muted);font-size:0.9rem;">✅ No active threats. Platform running cleanly.</div>`;
    return;
  }
  c.innerHTML = alerts.map(a => alertHTML(a, false)).join("");
}

function renderTriageAlerts(alerts) {
  const c = document.getElementById("triage-alerts-list");
  if (!alerts || alerts.length === 0) {
    c.innerHTML = `<div style="padding:2.5rem;text-align:center;color:var(--text-muted);font-size:0.9rem;">No alerts match this filter.</div>`;
    return;
  }
  c.innerHTML = alerts.map(a => alertHTML(a, true)).join("");
}

function toggleAlertDetails(alertId, e) {
  if (e && e.target && e.target.closest(".alert-actions")) return;
  const drawer = document.getElementById(`alert-drawer-${alertId}`);
  if (drawer) {
    drawer.classList.toggle("open");
  }
}

function alertHTML(a, showActions) {
  const score    = a.threat_score || a.score || 0;
  const cls      = score >= 80 ? "crit" : score >= 60 ? "high" : "med";
  const badge    = score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : "MEDIUM";
  const isAck    = a.status === "acknowledged";
  const isFP     = a.status === "false_positive";
  const timeStr  = a.created_at ? timeAgo(a.created_at) : "—";
  const timeFull = a.created_at ? fmtTime(a.created_at) : "—";

  // Score ring SVG gauge
  const r = 20; 
  const circ = 2 * Math.PI * r;
  const fill = circ - (score / 100) * circ;
  const ringColor = score >= 80 ? "var(--rose)" : score >= 60 ? "var(--amber)" : "var(--blue)";
  const ring = `
  <div class="score-ring" title="Threat Severity Score: ${Math.round(score)}/100">
    <svg width="48" height="48" viewBox="0 0 48 48">
      <circle cx="24" cy="24" r="${r}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="4"/>
      <circle cx="24" cy="24" r="${r}" fill="none" stroke="${ringColor}" stroke-width="4"
        stroke-dasharray="${circ}" stroke-dashoffset="${fill}" stroke-linecap="round"/>
    </svg>
    <div class="score-ring-label" style="color:${ringColor};">${Math.round(score)}</div>
  </div>`;

  const reasonsList = Array.isArray(a.reasons) ? a.reasons : [];
  const reasonsHtml = reasonsList.length > 0 
    ? reasonsList.map(r => `<span class="reason-tag">⚡ ${esc(typeof r === "object" ? (r.rule_name || r.name || r.id || JSON.stringify(r)) : String(r))}</span>`).join("")
    : `<span style="color:var(--text-muted);font-size:0.72rem;">Standard rule signature matched.</span>`;

  let evidenceStr = "";
  if (a.evidence) {
    try {
      evidenceStr = typeof a.evidence === "string" ? a.evidence : JSON.stringify(a.evidence, null, 2);
    } catch(err) { evidenceStr = String(a.evidence); }
  }

  return `
  <div class="alert-item ${isAck ? "ack" : cls}" id="alert-item-${a.alert_id}" onclick="toggleAlertDetails('${a.alert_id}', event)">
    <div class="alert-main-row">
      <div class="alert-left">
        <div class="alert-title">
          <span class="badge ${isAck ? "ack" : cls}">${badge}</span>
          <span class="alert-title-text">${esc(buildTitle(a))}</span>
        </div>
        <div class="alert-meta">
          <span>🖥️ <strong style="color:var(--text-primary);">${esc(a.host_or_ip || a.host || "host")}</strong></span>
          <span>📋 <code>${esc(a.rule_id || "ANOMALY")}</code></span>
          <span title="${timeFull}">⏱️ ${timeStr}</span>
          <span class="status-pill status-${a.status}">${a.status}</span>
          ${a.count > 1 ? `<span class="count-pill">×${a.count} hits</span>` : ""}
          <span class="expand-hint">🔍 Details ▾</span>
        </div>
      </div>
      ${ring}
      ${showActions && a.status === "open" ? `
        <div class="alert-actions" onclick="event.stopPropagation()">
          <button class="action-btn ack-btn" onclick="updateAlert('${a.alert_id}','acknowledged')">✔ Ack</button>
          <button class="action-btn fp fp-btn" onclick="updateAlert('${a.alert_id}','false_positive')">🚫 FP</button>
        </div>` : `
        <div class="alert-resolved-tag">
          ${isAck ? "✔ Acknowledged" : isFP ? "🚫 False Positive" : ""}
        </div>`}
    </div>
    <div class="alert-drawer" id="alert-drawer-${a.alert_id}">
      <div class="drawer-inner">
        <div class="drawer-section">
          <div class="drawer-label">Detection Signals & Contributing Rules</div>
          <div class="drawer-tags">${reasonsHtml}</div>
        </div>
        ${evidenceStr ? `
        <div class="drawer-section" style="margin-top:0.7rem;">
          <div class="drawer-label">Telemetry Evidence Snapshot</div>
          <pre class="drawer-evidence"><code>${esc(evidenceStr.slice(0, 500))}</code></pre>
        </div>` : ""}
      </div>
    </div>
  </div>`;
}

async function updateAlert(alertId, newStatus) {
  try {
    const res = await fetch(`${API_BASE}/alerts/${alertId}`, {
      method: "PATCH",
      headers: {"Content-Type":"application/json","X-API-Key":API_KEY},
      body: JSON.stringify({status:newStatus, comment: newStatus === "false_positive"
        ? "Flagged as FP by SOC analyst" : "Acknowledged by SOC analyst"}),
    });
    if (res.ok) {
      showToast(`Alert → ${newStatus.toUpperCase()}`, "success");
      pushActivity("system", `Alert ${alertId.slice(0,10)}… marked ${newStatus}`);
      await fetchAlerts(currentAlertFilter);
      await fetchMetrics();
    } else showToast("Update failed", "error");
  } catch (e) { showToast(`Error: ${e.message}`, "error"); }
}

// ─── Simulations ──────────────────────────────────────────────────────────────
async function simulateAttack(type) {
  showToast(`Launching ${type.toUpperCase()} simulation…`, "info");
  pushActivity("event", `Simulation: ${type.toUpperCase()} vector`, "demo-host");

  const weblog = (events) => fetch(`${API_BASE}/ingest/weblog`, {
    method:"POST", headers:{"Content-Type":"application/json","X-API-Key":API_KEY},
    body: JSON.stringify({events}),
  });
  const agent = (events) => fetch(`${API_BASE}/ingest/agent`, {
    method:"POST", headers:{"Content-Type":"application/json","X-API-Key":API_KEY},
    body: JSON.stringify({agent_id:"agent-demo-01", events}),
  });

  try {
    if (type === "sqli") {
      await weblog([{ip:"45.33.32.15",method:"GET",
        url:"/products.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
        raw_url:"/products.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
        decoded_url:"/products.php?id=1' UNION SELECT username,password FROM users--",
        status:200, ua:"sqlmap/1.7#stable", rule_ids:["WEB-SQLI-001"], label:"sqli",
        url_length:72, query_length:60, num_params:1, special_chars:14,
        special_ratio:0.22, digit_ratio:0.05, upper_ratio:0.32, url_entropy:4.82,
        has_sql_kw:1, has_script_tag:0, has_traversal:0, has_cmd_kw:0,
        method_is_post:0, is_rare_method:0, is_404:0}]);
    } else if (type === "xss") {
      await weblog([{ip:"185.220.101.42",method:"GET",
        url:"/comment?msg=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
        raw_url:"/comment?msg=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
        decoded_url:"/comment?msg=<script>alert(document.cookie)</script>",
        status:200, ua:"Mozilla/5.0", rule_ids:["WEB-XSS-001"], label:"xss",
        url_length:56, query_length:44, num_params:1, special_chars:10,
        special_ratio:0.2, digit_ratio:0, upper_ratio:0, url_entropy:4.45,
        has_sql_kw:0, has_script_tag:1, has_traversal:0, has_cmd_kw:0,
        method_is_post:0, is_rare_method:0, is_404:0}]);
    } else if (type === "traversal") {
      await weblog([{ip:"194.26.29.11",method:"GET",
        url:"/static/%2e%2e/%2e%2e/windows/win.ini",
        raw_url:"/static/%2e%2e/%2e%2e/windows/win.ini",
        decoded_url:"/static/../../windows/win.ini",
        status:404, ua:"curl/7.88.1", rule_ids:["WEB-TRAV-001"], label:"traversal",
        url_length:32, query_length:0, num_params:0, special_chars:8,
        special_ratio:0.25, digit_ratio:0, upper_ratio:0, url_entropy:3.8,
        has_sql_kw:0, has_script_tag:0, has_traversal:1, has_cmd_kw:0,
        method_is_post:0, is_rare_method:0, is_404:1}]);
    } else if (type === "powershell") {
      await agent([{action:"process_started",host:"WORKSTATION-01",actor:"SYSTEM",
        target:"powershell.exe -NoProfile -EncodedCommand ZQBjAGgAbwAgACIAVABlAHMAdAAiAA==",
        rule_hits:[{id:"EP-PROC-001",name:"Suspicious Encoded PowerShell",severity:85}],
        attrs:{parent:"WINWORD.EXE",pid:8492}}]);
    } else if (type === "brute") {
      await agent(Array.from({length:8},(_,i) => ({
        action:"logon_failed", host:"WORKSTATION-01", actor:`attacker_${i}`,
        target:"LocalSystem",
        rule_hits:[{id:"EP-AUTH-001",name:"Brute Force Burst",severity:75}],
        attrs:{reason:"Bad password"}})));
    } else if (type === "churn") {
      await agent([{action:"file_burst_detected",host:"WORKSTATION-01",actor:"unknown.exe",
        target:"C:\\Users\\Documents\\finance_records.locked",
        rule_hits:[{id:"EP-FILE-001",name:"High Frequency File Churn / Ransomware",severity:90}],
        attrs:{count:85,window_seconds:10}}]);
    }

    showToast("Payload delivered — checking for alerts…", "success");
    setTimeout(async () => {
      await fetchAlerts("open");
      await fetchMetrics();
      await fetchLiveEvents();
    }, 900);
  } catch (e) { showToast(`Simulation error: ${e.message}`, "error"); }
}

// ─── ML Sandbox ───────────────────────────────────────────────────────────────
function fillSandbox(url) {
  document.getElementById("sandbox-url-input").value = url;
  runSandboxAnalysis();
}

async function runSandboxAnalysis() {
  const raw = document.getElementById("sandbox-url-input").value.trim();
  if (!raw) { showToast("Enter a URL first", "error"); return; }
  const btn = document.getElementById("sandbox-btn");
  btn.innerText = "Analyzing…"; btn.disabled = true;
  showToast("Running ML pipeline…", "info");
  pushActivity("event", `Sandbox: ${raw.substring(0,60)}`);

  try {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({url: raw}),
    });
    if (!res.ok) throw new Error("API error " + res.status);
    const d = await res.json();

    document.getElementById("sandbox-result").style.display = "block";
    document.getElementById("sb-decoded").innerText = d.decoded_url;

    // Score
    const score = Math.round(d.threat_score);
    const scoreEl = document.getElementById("sb-score");
    const barEl   = document.getElementById("sb-score-bar");
    scoreEl.innerText = score;
    scoreEl.style.color = score >= 80 ? "var(--rose)" : score >= 60 ? "var(--amber)" : "var(--emerald)";
    barEl.style.width = score + "%";
    barEl.style.background = score >= 80
      ? "linear-gradient(90deg,var(--rose),var(--red))"
      : score >= 60
        ? "linear-gradient(90deg,var(--amber),#e67e22)"
        : "linear-gradient(90deg,var(--emerald),var(--teal))";

    document.getElementById("sb-rf-prob").innerText  = (d.ml_probability * 100).toFixed(1) + "%";
    document.getElementById("sb-iso-score").innerText = (d.anomaly_score * 100).toFixed(1) + "%";
    document.getElementById("sb-entropy").innerText   = d.features.url_entropy + " bits/char";

    const rules = d.rule_ids && d.rule_ids.length ? d.rule_ids.join(", ") : "None (Clean)";
    document.getElementById("sb-rules").innerText = rules;

    // Feature signal bars
    const feats = [
      {label:"SQL Keywords",  val:d.features.has_sql_kw,     max:1, color:"var(--rose)"},
      {label:"Script Tags",   val:d.features.has_script_tag, max:1, color:"var(--purple)"},
      {label:"Path Traversal",val:d.features.has_traversal,  max:1, color:"var(--amber)"},
      {label:"Special Chars", val:d.features.special_chars,  max:30,color:"var(--cyan)"},
      {label:"URL Entropy",   val:d.features.url_entropy,    max:6, color:"var(--blue)"},
      {label:"URL Length",    val:d.features.url_length,     max:200,color:"var(--teal)"},
    ];
    document.getElementById("sb-feature-bars").innerHTML = feats.map(f =>
      `<div class="stat-row">
        <span class="stat-row-label">${f.label}</span>
        <div class="stat-bar-track">
          <div class="stat-bar-fill" style="width:${Math.min(100,(f.val/f.max)*100).toFixed(1)}%; background:${f.color};"></div>
        </div>
        <span class="stat-row-val">${typeof f.val === 'number' && f.val < 10 && f.max === 1 ? (f.val ? "Yes" : "No") : f.val}</span>
      </div>`
    ).join("");

    pushActivity(score >= 60 ? "alert" : "event",
      `Sandbox result: score=${score}, prob=${(d.ml_probability*100).toFixed(1)}%, rules=[${rules}]`);
    showToast(`Score: ${score}/100 — ${score>=80?"CRITICAL":score>=60?"HIGH":"CLEAN"}`, score>=60?"error":"success");
  } catch (e) {
    showToast(`Sandbox error: ${e.message}`, "error");
  } finally {
    btn.innerText = "Analyze →"; btn.disabled = false;
  }
}

// ─── Endpoints ───────────────────────────────────────────────────────────────
async function fetchHosts() {
  try {
    const res = await fetch(`${API_BASE}/hosts`);
    if (!res.ok) return;
    const hosts = await res.json();
    const tbody = document.getElementById("hosts-table-body");

    if (!hosts.length) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:2rem;">
        No endpoints. Launch: <code style="color:var(--cyan);">python agent/main.py</code></td></tr>`;
      return;
    }

    hosts.forEach(h => {
      const prev = _lastHostSnap[h.host];
      if (!prev) {
        pushActivity("heartbeat", `New endpoint registered: ${h.host} (${h.agent_id})`, h.host);
      } else if (prev.last_heartbeat !== h.last_heartbeat) {
        const cpu = h.cpu_percent.toFixed(1);
        const ram = h.ram_mb.toFixed(0);
        pushActivity("heartbeat", `Heartbeat: ${h.host} — CPU:${cpu}% RAM:${ram}MB`, h.host);
      }
      _lastHostSnap[h.host] = h;
    });

    tbody.innerHTML = hosts.map(h => {
      const age   = h.last_heartbeat ? Math.floor((Date.now() - new Date(h.last_heartbeat).getTime())/1000) : 9999;
      const stale = age > 60;
      const cpuHigh = h.cpu_percent > 80;
      return `<tr>
        <td><span class="host-status-dot ${h.status==="active"?"active":"offline"}"></span><strong>${esc(h.host)}</strong></td>
        <td><code>${esc(h.agent_id)}</code></td>
        <td><span class="badge ${h.status==="active"?"ack":"crit"}">${h.status.toUpperCase()}</span></td>
        <td>${esc(h.os || "Windows 11")}</td>
        <td style="color:${cpuHigh?"var(--rose)":"inherit"}">${h.cpu_percent.toFixed(1)}%</td>
        <td>${h.ram_mb.toFixed(1)} MB</td>
        <td style="color:${stale?"var(--amber)":"var(--text-secondary)"}" title="${h.last_heartbeat||"—"}">
          ${h.last_heartbeat ? timeAgo(h.last_heartbeat) : "—"}
        </td>
      </tr>`;
    }).join("");
  } catch (e) { console.error("Hosts:", e); }
}

// ─── Event stream ────────────────────────────────────────────────────────────
async function fetchLiveEvents() {
  try {
    const res = await fetch(`${API_BASE}/events?limit=60`);
    if (!res.ok) return;
    const events = await res.json();
    const box = document.getElementById("console-stream");
    const countEl = document.getElementById("event-count-label");
    if (countEl) countEl.innerText = `${events.length} events`;

    if (!events.length) {
      box.innerHTML = `<div style="color:var(--text-muted);text-align:center;padding:3rem;">No events yet. Run simulations above.</div>`;
      return;
    }

    const maxId = Math.max(...events.map(e => e.id || 0));
    if (maxId > _lastEventId && _lastEventId > 0) {
      events.filter(e => (e.id||0) > _lastEventId).forEach(ev => {
        const threat = ev.label && ev.label !== "benign";
        pushActivity(threat ? "alert" : "event",
          `[${ev.source||"agent"}] ${ev.action} → ${(ev.target||"").substring(0,50)}${threat?" 🔴":""}`,
          ev.host);
      });
    }
    _lastEventId = maxId;

    box.innerHTML = events.map(ev => {
      const threat = ev.label && ev.label !== "benign";
      const ts     = ev.ts || ev.timestamp;
      const score  = ev.score || 0;
      return `<div class="console-line" style="${threat?"border-left:2px solid var(--rose);padding-left:6px;":""}">
        <span class="console-ts">[${ts ? fmtTime(ts) : "—"}]</span>
        <span class="console-host">&lt;${esc(ev.host)}&gt;</span>
        <span class="console-action ${threat?"threat":""}">${esc(ev.action)}</span>
        ${score>0?`<span style="color:${score>=60?"var(--rose)":"var(--amber)"};font-size:0.72rem;font-family:var(--font-mono);">[${Math.round(score)}]</span>`:""}
        <span style="color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;">${esc((ev.target||"").substring(0,70))}</span>
      </div>`;
    }).join("");
  } catch (e) { console.error("Events:", e); }
}

function toggleStream() {
  isStreamingPaused = !isStreamingPaused;
  const btn = document.getElementById("stream-toggle");
  btn.innerText = isStreamingPaused ? "▶ Resume" : "⏸ Pause";
  showToast(isStreamingPaused ? "Stream paused" : "Stream resumed", "info");
}

function clearEventConsole() {
  document.getElementById("console-stream").innerHTML = "";
  showToast("Console cleared", "info");
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function esc(str) {
  if (!str) return "";
  return String(str).replace(/[&<>'"]/g, t =>
    ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[t] || t));
}

// ══════════════════════════════════════════════════════════════
// LOG INGESTION LAB & FORENSIC ANALYZER
// ══════════════════════════════════════════════════════════════

let _selectedFile = null;
let _currentLogAnalysis = null;
let _currentLogFilter = "all";
let _currentLogSearch = "";

function initLogLab() {
  setupDropzone();
}

function setupDropzone() {
  const dropzone = document.getElementById("log-dropzone");
  if (!dropzone || dropzone.dataset.initialized) return;
  dropzone.dataset.initialized = "true";

  ["dragenter", "dragover"].forEach(eventName => {
    dropzone.addEventListener(eventName, e => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add("dragover");
    });
  });

  ["dragleave", "drop"].forEach(eventName => {
    dropzone.addEventListener(eventName, e => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove("dragover");
    });
  });

  dropzone.addEventListener("drop", e => {
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      setUploadedFile(files[0]);
    }
  });
}

function handleFileSelected(event) {
  const file = event.target.files && event.target.files[0];
  if (file) setUploadedFile(file);
}

function setUploadedFile(file) {
  _selectedFile = file;
  const nameEl = document.getElementById("file-display-name");
  const sizeEl = document.getElementById("file-display-size");
  const barEl  = document.getElementById("selected-file-info");
  
  if (nameEl) nameEl.innerText = file.name;
  if (sizeEl) sizeEl.innerText = formatFileSize(file.size);
  if (barEl)  barEl.style.display = "flex";
  
  showToast(`File selected: ${file.name} (${formatFileSize(file.size)})`, "info");
}

function clearSelectedFile() {
  _selectedFile = null;
  const input = document.getElementById("log-file-input");
  if (input) input.value = "";
  const barEl = document.getElementById("selected-file-info");
  if (barEl) barEl.style.display = "none";
}

function formatFileSize(bytes) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function switchUploadMode(mode) {
  const fileView = document.getElementById("upload-mode-file");
  const textView = document.getElementById("upload-mode-text");
  const fileBtn  = document.getElementById("seg-btn-file");
  const textBtn  = document.getElementById("seg-btn-text");

  if (mode === "file") {
    if (fileView) fileView.style.display = "block";
    if (textView) textView.style.display = "none";
    if (fileBtn)  fileBtn.classList.add("active");
    if (textBtn)  textBtn.classList.remove("active");
  } else {
    if (fileView) fileView.style.display = "none";
    if (textView) textView.style.display = "block";
    if (fileBtn)  fileBtn.classList.remove("active");
    if (textBtn)  textBtn.classList.add("active");
  }
}

async function loadPresetSample(sampleId) {
  const idMap = {
    apache_web_attacks: "apache",
    nginx_production_traffic: "nginx",
    bruteforce_and_recon: "brute",
    sample_access: "gtu"
  };
  const btn = document.getElementById(`preset-${idMap[sampleId] || "apache"}`);
  const originalText = btn ? btn.innerHTML : "";
  if (btn) btn.innerHTML = `<span>⏳</span><span>Analyzing…</span>`;

  showToast(`Processing telemetry preset: ${sampleId}…`, "info");
  pushActivity("system", `Loading telemetry preset: ${sampleId}`);

  try {
    const ingestDb = document.getElementById("chk-ingest-db")?.checked || false;
    const res = await fetch(`${API_BASE}/api/sample-logs/${sampleId}/analyze?ingest_to_db=${ingestDb}`, {
      method: "POST"
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.status === "error") throw new Error(data.message || "Parsing failed");

    renderAnalysisDashboard(data);
    showToast(`Parsed ${data.parsed_rows} records · ${data.total_attacks} threats identified!`, "success");

    if (ingestDb) {
      setTimeout(async () => {
        await fetchMetrics();
        await fetchAlerts();
        await fetchLiveEvents();
      }, 500);
    }
  } catch (err) {
    showToast(`Error analyzing sample: ${err.message}`, "error");
  } finally {
    if (btn) btn.innerHTML = originalText;
  }
}

async function submitLogAnalysis() {
  const analyzeBtn = document.getElementById("btn-analyze-log");
  const originalHtml = analyzeBtn.innerHTML;
  analyzeBtn.innerHTML = `<span class="spinner-inline"></span> Analyzing…`;
  analyzeBtn.disabled = true;

  const ingestDb = document.getElementById("chk-ingest-db")?.checked || false;
  const isFileMode = document.getElementById("upload-mode-file").style.display !== "none";

  try {
    let res;
    if (isFileMode) {
      if (!_selectedFile) {
        showToast("Please select a log file or click a preset sample above.", "error");
        analyzeBtn.innerHTML = originalHtml;
        analyzeBtn.disabled = false;
        return;
      }
      showToast(`Uploading and analyzing ${_selectedFile.name}…`, "info");
      const formData = new FormData();
      formData.append("file", _selectedFile);
      formData.append("ingest_to_db", ingestDb ? "true" : "false");

      res = await fetch(`${API_BASE}/api/upload-log`, {
        method: "POST",
        body: formData,
      });
    } else {
      const text = document.getElementById("raw-log-textarea").value.trim();
      if (!text) {
        showToast("Please paste log lines into the text area.", "error");
        analyzeBtn.innerHTML = originalHtml;
        analyzeBtn.disabled = false;
        return;
      }
      showToast("Analyzing pasted log telemetry…", "info");
      res = await fetch(`${API_BASE}/api/upload-log-raw`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: text,
          filename: "pasted_access.log",
          ingest_to_db: ingestDb,
        }),
      });
    }

    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.detail || `Server returned ${res.status}`);
    }

    const data = await res.json();
    if (data.status === "error") throw new Error(data.message || "Failed to parse log lines");

    renderAnalysisDashboard(data);
    showToast(`Analysis complete: ${data.parsed_rows} lines parsed, ${data.total_attacks} threats identified!`, "success");
    pushActivity("event", `Log analysis finished: ${data.parsed_rows} rows, ${data.total_attacks} attacks (${data.detected_format})`);

    if (ingestDb) {
      setTimeout(async () => {
        await fetchMetrics();
        await fetchAlerts();
        await fetchLiveEvents();
      }, 600);
    }
  } catch (err) {
    showToast(`Analysis failed: ${err.message}`, "error");
  } finally {
    analyzeBtn.innerHTML = originalHtml;
    analyzeBtn.disabled = false;
  }
}

function resetLogUpload() {
  clearSelectedFile();
  const textEl = document.getElementById("raw-log-textarea");
  if (textEl) textEl.value = "";
  const resPanel = document.getElementById("log-analysis-results");
  if (resPanel) resPanel.style.display = "none";
  _currentLogAnalysis = null;
  showToast("Upload form reset", "info");
}

function renderAnalysisDashboard(data) {
  _currentLogAnalysis = data;
  const panel = document.getElementById("log-analysis-results");
  if (!panel) return;
  panel.style.display = "block";
  panel.scrollIntoView({ behavior: "smooth", block: "start" });

  // 1. KPIs
  document.getElementById("res-total-lines").innerText = Number(data.total_lines || 0).toLocaleString();
  document.getElementById("res-success-rate").innerText = `${data.success_rate_percent}% Valid (${data.parsed_rows} Rows)`;

  document.getElementById("res-total-attacks").innerText = Number(data.total_attacks || 0).toLocaleString();
  document.getElementById("res-attack-rate").innerText = `${data.attack_rate_percent}% Threat Ratio`;

  const peakScore = data.events && data.events.length > 0 ? Math.max(...data.events.map(e => e.score)) : 0;
  const peakSev = peakScore >= 80 ? "CRITICAL" : peakScore >= 60 ? "HIGH" : peakScore >= 40 ? "MEDIUM" : peakScore >= 20 ? "LOW" : "BENIGN";
  document.getElementById("res-peak-score").innerText = Math.round(peakScore);
  document.getElementById("res-max-severity").innerText = `Severity: ${peakSev}`;

  document.getElementById("res-detected-format").innerText = data.detected_format || "Web Access Log";
  document.getElementById("res-rejected-lines").innerText = `${data.rejected_lines} Rejects / Non-HTTP`;

  document.getElementById("res-throughput").innerText = `${data.throughput_lines_sec.toLocaleString()} /s`;
  document.getElementById("res-latency").innerText = `${data.elapsed_seconds}s Processing Time`;

  // 2. Threat Vector Breakdown Bars
  const catContainer = document.getElementById("res-attack-breakdown-bars");
  if (catContainer) {
    const cats = data.threat_categories || {};
    const catKeys = Object.keys(cats);
    if (catKeys.length === 0) {
      catContainer.innerHTML = `<div style="color:var(--emerald); padding:1rem; font-size:0.82rem;">✅ 100% Benign — Zero attack signatures detected in log.</div>`;
    } else {
      const maxCount = Math.max(...Object.values(cats), 1);
      const colors = {
        sqli: "linear-gradient(90deg,var(--rose),var(--red))",
        xss: "linear-gradient(90deg,var(--purple),var(--indigo))",
        traversal: "linear-gradient(90deg,var(--amber),#e67e22)",
        path_traversal: "linear-gradient(90deg,var(--amber),#e67e22)",
        cmdi: "linear-gradient(90deg,var(--cyan),var(--blue))",
        scan: "linear-gradient(90deg,var(--teal),var(--emerald))",
        brute: "linear-gradient(90deg,#f97316,var(--amber))",
        brute_force: "linear-gradient(90deg,#f97316,var(--amber))",
        anomaly: "linear-gradient(90deg,var(--indigo),var(--purple))",
      };
      catContainer.innerHTML = catKeys.map(k => {
        const count = cats[k];
        const pct = Math.min(100, (count / maxCount) * 100).toFixed(1);
        const grad = colors[k] || "linear-gradient(90deg,var(--blue),var(--cyan))";
        return `
        <div class="stat-row">
          <span class="stat-row-label">${esc(k.toUpperCase())}</span>
          <div class="stat-bar-track">
            <div class="stat-bar-fill" style="width:${pct}%; background:${grad};"></div>
          </div>
          <span class="stat-row-val" style="color:var(--text-primary); font-weight:700;">${count}</span>
        </div>`;
      }).join("");
    }
  }

  // 3. HTTP Status Codes Breakdown Bars
  const stContainer = document.getElementById("res-status-breakdown-bars");
  if (stContainer) {
    const statuses = data.status_distribution || {};
    const stKeys = Object.keys(statuses).sort();
    if (stKeys.length === 0) {
      stContainer.innerHTML = `<div style="color:var(--text-muted); padding:1rem; font-size:0.8rem;">No status codes recorded.</div>`;
    } else {
      const maxSt = Math.max(...Object.values(statuses), 1);
      stContainer.innerHTML = stKeys.map(code => {
        const c = statuses[code];
        const pct = Math.min(100, (c / maxSt) * 100).toFixed(1);
        const num = parseInt(code, 10);
        const color = num < 300 ? "linear-gradient(90deg,var(--emerald),var(--teal))" : num < 400 ? "linear-gradient(90deg,var(--cyan),var(--blue))" : num < 500 ? "linear-gradient(90deg,var(--amber),#e67e22)" : "linear-gradient(90deg,var(--rose),var(--red))";
        return `
        <div class="stat-row">
          <span class="stat-row-label"><span class="st-badge ${num<300?'s2xx':num<400?'s3xx':num<500?'s4xx':'s5xx'}">${code}</span></span>
          <div class="stat-bar-track">
            <div class="stat-bar-fill" style="width:${pct}%; background:${color};"></div>
          </div>
          <span class="stat-row-val" style="color:var(--text-primary); font-weight:700;">${c}</span>
        </div>`;
      }).join("");
    }
  }

  // 4. Top Attacker IPs Leaderboard
  const ipTbody = document.getElementById("res-top-ips-tbody");
  if (ipTbody) {
    const ips = data.top_ips || [];
    if (ips.length === 0) {
      ipTbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:1rem;">No attacker IPs logged.</td></tr>`;
    } else {
      ipTbody.innerHTML = ips.map(item => {
        const isMal = item.attack_count > 0;
        const tags = item.attack_types && item.attack_types.length > 0 
          ? item.attack_types.map(t => `<span class="label-pill ${t}">${esc(t)}</span>`).join(" ")
          : `<span style="color:var(--emerald);font-size:0.72rem;">Clean / Benign</span>`;
        return `
        <tr>
          <td><code style="color:${isMal?'var(--rose)':'var(--cyan)'}; font-weight:700;">${esc(item.ip)}</code></td>
          <td>${item.total_requests}</td>
          <td style="color:${isMal?'var(--rose)':'inherit'}; font-weight:700;">${item.attack_count}</td>
          <td>
            <span class="badge ${item.max_score>=80?'crit':item.max_score>=60?'high':item.max_score>=40?'med':'ack'}">
              ${Math.round(item.max_score)} (${item.highest_severity})
            </span>
          </td>
          <td>${tags}</td>
        </tr>`;
      }).join("");
    }
  }

  // 5. Targeted Paths Leaderboard
  const pathTbody = document.getElementById("res-top-paths-tbody");
  if (pathTbody) {
    const paths = data.top_paths || [];
    if (paths.length === 0) {
      pathTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:1rem;">No endpoints recorded.</td></tr>`;
    } else {
      pathTbody.innerHTML = paths.map(item => {
        const isMal = item.attacks > 0;
        const tags = item.attack_types && item.attack_types.length > 0
          ? item.attack_types.map(t => `<span class="label-pill ${t}">${esc(t)}</span>`).join(" ")
          : `<span style="color:var(--text-muted);font-size:0.72rem;">Legitimate</span>`;
        return `
        <tr>
          <td><code style="color:var(--text-primary); font-size:0.75rem;" title="${esc(item.path)}">${esc(item.path.length>40?item.path.slice(0,38)+'...':item.path)}</code></td>
          <td>${item.hits}</td>
          <td style="color:${isMal?'var(--rose)':'inherit'}; font-weight:700;">${item.attacks}</td>
          <td>${tags}</td>
        </tr>`;
      }).join("");
    }
  }

  // 6. Parsed Telemetry Events Table
  renderLogTable();
}

function renderLogTable() {
  if (!_currentLogAnalysis || !_currentLogAnalysis.events) return;
  const events = _currentLogAnalysis.events;
  const tbody = document.getElementById("log-events-tbody");
  const countLabel = document.getElementById("log-table-count");

  let filtered = events.filter(e => {
    // Label / Severity Filters
    if (_currentLogFilter === "attacks" && e.label === "benign" && e.score < 60) return false;
    if (_currentLogFilter === "critical" && e.score < 80) return false;
    if (_currentLogFilter === "high" && (e.score < 60 || e.score >= 80)) return false;
    if (_currentLogFilter === "sqli" && e.label !== "sqli") return false;
    if (_currentLogFilter === "xss" && e.label !== "xss") return false;
    if (_currentLogFilter === "traversal" && e.label !== "traversal" && e.label !== "path_traversal") return false;
    if (_currentLogFilter === "errors" && e.status < 400) return false;

    // Search filter
    if (_currentLogSearch) {
      const q = _currentLogSearch.toLowerCase();
      const ip = (e.ip || "").toLowerCase();
      const meth = (e.method || "").toLowerCase();
      const url = (e.url || "").toLowerCase();
      const dec = (e.decoded_url || "").toLowerCase();
      if (!ip.includes(q) && !meth.includes(q) && !url.includes(q) && !dec.includes(q)) return false;
    }
    return true;
  });

  if (countLabel) countLabel.innerText = `Showing ${filtered.length} of ${events.length} events`;

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center; color:var(--text-muted); padding:2rem;">No events match current filter.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(e => {
    const isThreat = e.label !== "benign" || e.score >= 60;
    const scoreCls = e.score >= 80 ? "crit" : e.score >= 60 ? "high" : e.score >= 40 ? "med" : "ack";
    const stCode = parseInt(e.status, 10);
    const stCls = stCode < 300 ? "s2xx" : stCode < 400 ? "s3xx" : stCode < 500 ? "s4xx" : "s5xx";

    const labelHtml = `<span class="label-pill ${e.label}">${esc(e.label)}</span>`;
    const scoreHtml = `<span class="badge ${scoreCls}" style="font-family:var(--font-mono);">${Math.round(e.score)} / 100</span>`;

    const displayUrl = e.url && e.url.length > 55 ? e.url.slice(0, 52) + "…" : e.url;

    return `
    <tr style="${isThreat ? 'background:rgba(244,63,94,0.03);' : ''}">
      <td style="font-family:var(--font-mono); color:var(--text-muted);">${e.id}</td>
      <td style="font-family:var(--font-mono); font-size:0.73rem; color:var(--text-secondary);">${esc(e.ts.split(' ')[0] || e.ts)}</td>
      <td><code style="color:${isThreat?'var(--rose)':'var(--cyan)'}; font-weight:600;">${esc(e.ip)}</code></td>
      <td><strong>${esc(e.method)}</strong></td>
      <td><code title="${esc(e.url)}" style="color:var(--text-primary); cursor:help;">${esc(displayUrl)}</code></td>
      <td><span class="st-badge ${stCls}">${e.status}</span></td>
      <td>${labelHtml}</td>
      <td>${scoreHtml}</td>
      <td>
        <button class="action-btn" style="padding:2px 8px; font-size:0.72rem;" onclick="openInspectorModal(${e.id})">
          🔍 Inspect
        </button>
      </td>
    </tr>`;
  }).join("");
}

function filterLogTable(filterKey) {
  _currentLogFilter = filterKey;
  document.querySelectorAll(".filter-pill-btn").forEach(b => b.classList.remove("active"));
  const btn = document.getElementById(`ft-${filterKey === "path_traversal" ? "trav" : filterKey}`);
  if (btn) btn.classList.add("active");
  renderLogTable();
}

function handleLogTableSearch(e) {
  _currentLogSearch = e.target.value.trim();
  renderLogTable();
}

function openInspectorModal(eventId) {
  if (!_currentLogAnalysis || !_currentLogAnalysis.events) return;
  const evt = _currentLogAnalysis.events.find(x => x.id === eventId);
  if (!evt) return;

  const modal = document.getElementById("log-inspector-modal");
  const idEl = document.getElementById("modal-event-id");
  const titleEl = document.getElementById("modal-title");
  const bodyEl = document.getElementById("modal-body-content");

  idEl.innerText = `EVENT #${evt.id} · CLIENT: ${evt.ip} · HTTP ${evt.status}`;
  titleEl.innerText = `${evt.method} ${evt.url}`;

  const isCrit = evt.score >= 80;
  const isHigh = evt.score >= 60 && evt.score < 80;
  const sevColor = isCrit ? "var(--rose)" : isHigh ? "var(--amber)" : "var(--emerald)";

  const reasonsList = Array.isArray(evt.reasons) ? evt.reasons : [];
  const reasonsHtml = reasonsList.length > 0
    ? reasonsList.map(r => `<span class="reason-tag">⚡ ${esc(r)}</span>`).join(" ")
    : `<span style="color:var(--text-muted);font-size:0.76rem;">No signature triggers. Clean baseline request.</span>`;

  // Mitigation advice based on attack label
  const mitigations = {
    sqli: "Implement Prepared Statements / Parameterized Queries (PDO/ORM). Configure Web Application Firewall (WAF) to drop UNION SELECT and comment tokens. Block client IP if repeating.",
    xss: "Sanitize & HTML-encode all dynamic query inputs. Enforce a strict Content-Security-Policy (CSP) header. Enable HttpOnly and SameSite flags on sensitive cookies.",
    traversal: "Sanitize file paths with basename(). Avoid dynamic file inclusions based on user query parameters. Restrict web root directory traversal via web server configuration.",
    path_traversal: "Sanitize file paths with basename(). Avoid dynamic file inclusions based on user query parameters. Restrict web root directory traversal via web server configuration.",
    cmdi: "Never pass unsanitized user inputs to system() or exec() calls. Implement strict allowlist validation for administrative parameters.",
    scan: "Rate-limit client IP at reverse proxy level (Nginx/Cloudflare). Return generic 404s without disclosing server versions or tech stack banners.",
    brute: "Enforce IP rate limiting and account lockouts after consecutive failed authentication attempts. Require Multi-Factor Authentication (MFA).",
    brute_force: "Enforce IP rate limiting and account lockouts after consecutive failed authentication attempts. Require Multi-Factor Authentication (MFA).",
    benign: "No mitigation required. Normal application traffic complying with RFC specifications.",
  };
  const advice = mitigations[evt.label] || "Inspect client behavior and review endpoint access logs.";

  bodyEl.innerHTML = `
    <!-- Top Threat Banner -->
    <div style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.03); border:1px solid var(--border-dim); border-radius:12px; padding:1.1rem 1.4rem;">
      <div>
        <div style="font-size:0.7rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.08em; font-weight:700;">Composite Security Verdict</div>
        <div style="display:flex; align-items:center; gap:0.6rem; margin-top:0.35rem;">
          <span class="badge ${evt.score>=80?'crit':evt.score>=60?'high':evt.score>=40?'med':'ack'}" style="font-size:0.95rem; padding:4px 12px;">
            ${evt.severity}
          </span>
          <span class="label-pill ${evt.label}" style="font-size:0.85rem;">${evt.label.toUpperCase()}</span>
        </div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:0.68rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.08em;">Calibrated Threat Score</div>
        <div style="font-size:2.2rem; font-weight:900; color:${sevColor}; font-family:var(--font-mono); line-height:1.1;">
          ${Math.round(evt.score)}<span style="font-size:1rem; color:var(--text-muted);">/100</span>
        </div>
      </div>
    </div>

    <!-- Decoded URL -->
    <div>
      <div class="modal-sec-title"><span>🔗</span> Multi-Pass Decoded Target URL</div>
      <div class="modal-codebox">
        <button class="copy-btn" onclick="navigator.clipboard.writeText('${esc(evt.decoded_url)}'); showToast('URL copied to clipboard','success');">Copy</button>
        ${esc(evt.decoded_url)}
      </div>
    </div>

    <!-- ML Inference Grid -->
    <div>
      <div class="modal-sec-title"><span>🧠</span> Predictive AI Model Signals</div>
      <div class="result-grid" style="margin-bottom:0.75rem;">
        <div class="result-card">
          <div class="result-card-label">Random Forest Attack Prob</div>
          <div class="result-card-value" style="color:${evt.ml_probability>=0.6?'var(--rose)':'var(--emerald)'};">
            ${(evt.ml_probability * 100).toFixed(1)}%
          </div>
        </div>
        <div class="result-card">
          <div class="result-card-label">Isolation Forest Anomaly</div>
          <div class="result-card-value" style="color:var(--purple);">
            ${(evt.anomaly_score * 100).toFixed(1)}%
          </div>
        </div>
        <div class="result-card">
          <div class="result-card-label">Shannon Entropy H(X)</div>
          <div class="result-card-value" style="color:var(--cyan);">
            ${evt.features ? evt.features.url_entropy : '—'} bits/char
          </div>
        </div>
        <div class="result-card">
          <div class="result-card-label">Special Characters</div>
          <div class="result-card-value" style="color:var(--amber);">
            ${evt.features ? evt.features.special_chars : '—'} chars
          </div>
        </div>
      </div>
    </div>

    <!-- Forensic Evidence Reasons -->
    <div>
      <div class="modal-sec-title"><span>⚡</span> Triggered Rules &amp; Contributing Evidence</div>
      <div style="display:flex; gap:0.4rem; flex-wrap:wrap;">
        ${reasonsHtml}
      </div>
    </div>

    <!-- SOC Remediation Guide -->
    <div style="background:rgba(6,182,212,0.06); border:1px solid rgba(6,182,212,0.25); border-radius:10px; padding:1rem 1.25rem;">
      <div style="font-size:0.75rem; color:var(--cyan); font-weight:700; text-transform:uppercase; letter-spacing:0.07em; margin-bottom:0.35rem;">
        🛡️ Recommended SOC Mitigation Action
      </div>
      <p style="font-size:0.83rem; color:var(--text-primary); margin:0; line-height:1.5;">
        ${esc(advice)}
      </p>
    </div>

    <!-- Raw Entry -->
    <div>
      <div class="modal-sec-title"><span>📜</span> Raw Log Telemetry Record</div>
      <div class="modal-codebox" style="color:var(--text-muted);">
        <button class="copy-btn" onclick="navigator.clipboard.writeText('${esc(evt.ip)} - - [${esc(evt.ts)}] &quot;${esc(evt.method)} ${esc(evt.url)} HTTP/1.1&quot; ${evt.status} ${evt.bytes} &quot;-&quot; &quot;${esc(evt.ua)}&quot;'); showToast('Raw log copied','success');">Copy</button>
        ${esc(evt.ip)} - - [${esc(evt.ts)}] "${esc(evt.method)} ${esc(evt.url)} HTTP/1.1" ${evt.status} ${evt.bytes} "-" "${esc(evt.ua)}"
      </div>
    </div>
  `;

  modal.classList.add("open");
}

function closeInspectorModal(e) {
  if (e && e.target && e.target.closest && e.target.closest(".modal-card") && !e.target.classList.contains("modal-close")) return;
  const modal = document.getElementById("log-inspector-modal");
  if (modal) modal.classList.remove("open");
}

// Keyboard ESC to close modal
document.addEventListener("keydown", e => {
  if (e.key === "Escape") closeInspectorModal();
});

function exportAnalysisReport(format) {
  if (!_currentLogAnalysis) {
    showToast("No analysis available to export", "error");
    return;
  }

  if (format === "json") {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(_currentLogAnalysis, null, 2));
    const dl = document.createElement("a");
    dl.setAttribute("href", dataStr);
    dl.setAttribute("download", `SentinelLog_Forensic_Report_${Date.now()}.json`);
    dl.click();
    showToast("Downloaded JSON report", "success");
  } else if (format === "csv") {
    const events = _currentLogAnalysis.events || [];
    if (events.length === 0) {
      showToast("No events to export", "error");
      return;
    }
    const headers = ["id", "timestamp", "ip", "method", "url", "status", "label", "threat_score", "severity", "ml_prob", "anomaly_score"];
    const rows = events.map(e => [
      e.id,
      `"${e.ts}"`,
      `"${e.ip}"`,
      `"${e.method}"`,
      `"${(e.url||'').replace(/"/g, '""')}"`,
      e.status,
      `"${e.label}"`,
      e.score,
      `"${e.severity}"`,
      e.ml_probability,
      e.anomaly_score
    ]);
    const csvContent = "data:text/csv;charset=utf-8," + encodeURIComponent([headers.join(","), ...rows.map(r => r.join(","))].join("\n"));
    const dl = document.createElement("a");
    dl.setAttribute("href", csvContent);
    dl.setAttribute("download", `SentinelLog_Events_${Date.now()}.csv`);
    dl.click();
    showToast("Downloaded CSV log", "success");
  }
}

async function pushDetectedAttacksToLiveSOC() {
  if (!_currentLogAnalysis || !_currentLogAnalysis.events) {
    showToast("No analysis loaded", "error");
    return;
  }
  const attacks = _currentLogAnalysis.events.filter(e => e.label !== "benign" || e.score >= 60);
  if (attacks.length === 0) {
    showToast("No attack threats in this log to push", "info");
    return;
  }

  showToast(`Pushing ${attacks.length} threats to live SOC database…`, "info");
  try {
    const formatted = attacks.map(a => ({
      ip: a.ip,
      method: a.method,
      url: a.url,
      raw_url: a.url,
      decoded_url: a.decoded_url,
      status: a.status,
      ua: a.ua || "Mozilla/5.0",
      rule_ids: a.rule_ids || [],
      label: a.label,
    }));

    const res = await fetch(`${API_BASE}/ingest/weblog`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
      body: JSON.stringify({ events: formatted }),
    });

    if (res.ok) {
      const d = await res.json();
      showToast(`Successfully pushed! ${d.new_alerts || 0} new alerts generated in live SIEM!`, "success");
      pushActivity("alert", `Batch ingest: ${attacks.length} threats pushed to live SOC feed`);
      setTimeout(async () => {
        await fetchMetrics();
        await fetchAlerts("open");
        await fetchLiveEvents();
      }, 500);
    } else throw new Error();
  } catch {
    showToast("Failed to push threats to live SOC", "error");
  }
}

