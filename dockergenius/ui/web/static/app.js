const api = "";
const state = {};

async function jget(url, opts={}) {
  const r = await fetch(api + url, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || ("HTTP " + r.status));
  return data;
}
const $ = (id) => document.getElementById(id);

function setText(id, value){ $(id).textContent = value; }
function esc(s){ return String(s ?? "").replaceAll("<","&lt;").replaceAll(">","&gt;"); }

function badge(text, cls=""){
  return `<span class="badge ${cls}">${esc(text)}</span>`;
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