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
      if (id === "hosts")      fetchHosts();
      if (id === "events")     fetchLiveEvents();
      if (id === "alerts")     fetchAlerts("open");
      if (id === "agent")      renderActivityPanel();
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
