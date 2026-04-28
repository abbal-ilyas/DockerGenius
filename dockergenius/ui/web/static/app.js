const api = "";
const state = {};

async function jget(url, opts={}) {
  const r = await fetch(api + url, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || ("HTTP " + r.status));
  return data;
}
async function jpost(url, body={}) {
  return jget(url, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body),
  });
}
async function previewThenApply(url, body, outId, refreshFn, confirmMessage, useDryRun=true){
  let promptText = confirmMessage || "Apply these changes?";

  if (useDryRun) {
    const preview = await jpost(`${url}?dry_run=true`, body);
    renderKeyValues(outId, {
      Preview: preview.preview || "Dry-run completed",
      Action: preview.action || body.action || "-",
      Target: preview.name || preview.identifier || preview.reference || body.name || body.identifier || body.reference || "-",
    });
    promptText = preview.preview || promptText;
  }

  if (!confirm(promptText)) return { ok: false, cancelled: true };

  const applied = await jpost(`${url}?dry_run=false`, body);
  renderKeyValues(outId, {
    Result: applied.ok ? "Applied" : "Skipped",
    Action: applied.action || body.action || "-",
    Target: applied.name || applied.identifier || applied.reference || body.name || body.identifier || body.reference || "-",
  });
  if (refreshFn) await refreshFn();
  return applied;
}
const $ = (id) => document.getElementById(id);

function setText(id, value){ $(id).textContent = value; }
function esc(s){ return String(s ?? "").replaceAll("<","&lt;").replaceAll(">","&gt;"); }

function badge(text, cls=""){
  return `<span class="badge ${cls}">${esc(text)}</span>`;
}

function fmtBytes(value){
  const bytes = toBytes(value);
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B","KB","MB","GB","TB","PB"];
  const base = 1024;
  let v = bytes;
  let i = 0;
  while (v >= base && i < units.length - 1){ v /= base; i++; }
  const digits = i === 0 ? 0 : (v >= 10 ? 1 : 2);
  return `${v.toFixed(digits)} ${units[i]}`;
}

function fmtDate(value){
  if (!value) return "-";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function fmtCount(value){
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString() : "0";
}

function toBytes(value){
  if (value == null) return 0;
  if (typeof value === "number") return value;
  const s = String(value).trim();
  if (!s) return 0;
  // docker df may return strings like "12.3MB" or "1.2 GB".
  const m = s.match(/^([0-9]+(?:\.[0-9]+)?)\s*([kmgtp]?b)$/i);
  if (!m) {
    const asNum = Number(s);
    return Number.isFinite(asNum) ? asNum : 0;
  }
  const n = Number(m[1]);
  const u = m[2].toUpperCase();
  const mult = ({B:1,KB:1024,MB:1024**2,GB:1024**3,TB:1024**4,PB:1024**5})[u] || 1;
  return n * mult;
}

function sevClass(sev){
  const s = String(sev||"").toLowerCase();
  if (s === "critical") return "sev sev-critical";
  if (s === "high") return "sev sev-high";
  if (s === "medium") return "sev sev-medium";
  if (s === "low") return "sev sev-low";
  return "sev";
}

function riskClass(risk){
  const r = String(risk||"").toUpperCase();
  if (r === "HIGH") return "sev sev-critical";
  if (r === "MEDIUM") return "sev sev-medium";
  if (r === "LOW") return "sev sev-low";
  return "sev";
}

function renderError(containerId, err){
  const el = $(containerId);
  if (!el) return;
  el.innerHTML = `<div class="callout callout-bad"><strong>Error</strong><div class="sub">${esc(err?.message || err || "Unknown error")}</div></div>`;
}

function renderTable(containerId, rows, columns, opts={}){
  const el = $(containerId);
  if (!el) return;
  const emptyText = opts.emptyText || "No data";
  if (!rows || rows.length === 0){ el.innerHTML = `<div class='kpi'>${esc(emptyText)}</div>`; return; }

  const head = columns.map(c => `<th>${esc(c.label)}</th>`).join("");
  const body = rows.map(r => {
    const tds = columns.map(c => {
      const raw = c.get(r);
      const v = c.html ? raw : esc(raw);
      return `<td>${v}</td>`;
    }).join("");
    return `<tr>${tds}</tr>`;
  }).join("");

  el.innerHTML = `
    <div class="table-wrap">
      <table class="table">
        <thead><tr>${head}</tr></thead>
        <tbody>${body}</tbody>
      </table>
    </div>
  `;
}

function sortByBytesDesc(rows, getter){
  return [...(rows||[])].sort((a,b)=>toBytes(getter(b)) - toBytes(getter(a)));
}

// Cards list
function renderCards(containerId, items, fields){
  const el = $(containerId);
  if (!el) return;
  if (!items || items.length === 0){ el.innerHTML = "<div class='kpi'>No data</div>"; return; }
  el.innerHTML = items.map(it => {
    return `<div class="mini-card">
      ${fields.map(f => `<div class="mini-row"><span>${esc(f.label)}</span><strong>${esc(f.get(it))}</strong></div>`).join("")}
    </div>`;
  }).join("");
}

// Images scan renderer
function renderScan(containerId, data){
  const el = $(containerId);
  if (!data || !data.images){ el.innerHTML = "<div class='kpi'>No data</div>"; return; }

  el.innerHTML = data.images.map(img => {
    const counts = img.counts || {};
    const top = (img.top_vulns || []).slice(0,5);
    return `
      <div class="scan-card">
        <div class="scan-head">
          <div><strong>${esc(img.image)}</strong><div class="sub">tool: ${esc(img.tool || "n/a")}</div></div>
          <div class="scan-badges">
            ${badge("Total "+(img.vuln_count||0))}
            ${badge("Critical "+(counts.CRITICAL||0),"bad")}
            ${badge("High "+(counts.HIGH||0),"warn")}
            ${badge("Medium "+(counts.MEDIUM||0))}
          </div>
        </div>
        <div class="scan-top">
          ${top.length ? top.map(v=>`<div class="vuln">• ${esc(v.id||v.title||"vuln")} (${esc(v.severity||"")})</div>`).join("") : "<div class='sub'>No top vulns</div>"}
        </div>
      </div>
    `;
  }).join("");
}

// Key-value renderer (small)
function renderKeyValues(containerId, obj){
  const el = $(containerId);
  if (!obj){ el.innerHTML = "<div class='kpi'>No data</div>"; return; }
  el.innerHTML = Object.entries(obj).map(([k,v]) =>
    `<div class="mini-row"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`
  ).join("");
}

async function loadSnapshots(selectId){
  const d = await jget("/snapshot/list");
  const sel = $(selectId);
  sel.innerHTML = "";
  d.snapshots.forEach(s => {
    const o = document.createElement("option");
    o.value = s; o.textContent = s;
    sel.appendChild(o);
  });
}
async function loadImages(selectId){
  const d = await jget("/images/list");
  const sel = $(selectId);
  sel.innerHTML = "";
  const all = document.createElement("option");
  all.value = ""; all.textContent = "All images";
  sel.appendChild(all);
  d.images.forEach(s => {
    const o = document.createElement("option");
    o.value = s; o.textContent = s;
    sel.appendChild(o);
  });
}