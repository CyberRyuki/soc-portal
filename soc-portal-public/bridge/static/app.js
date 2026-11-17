/* Portal SOC · ACME — SPA sin dependencias externas (solo marked + DOMPurify locales) */
const $ = id => document.getElementById(id);
const nf = n => (n ?? 0).toLocaleString("es-DO");
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const pct = (a, b) => b ? Math.round(a / b * 100) : 0;

/* ---------------- Traducciones (los valores se guardan en inglés; se muestran en español) ---------------- */
const SEV = {Critical: "Crítica", High: "Alta", Medium: "Media", Low: "Baja"};
const STA = {Open: "Abierto", Investigating: "En investigación", Contained: "Contenido", Closed: "Cerrado"};
const AGS = {active: "Activos", disconnected: "Desconectados", never_connected: "Nunca conectados", pending: "Pendientes"};
const EXS = {FINISHED: "Completada", ABORTED: "Abortada", EXECUTING: "En curso", WAITING: "En espera", FAILURE: "Fallida"};
const THREAT = {"1": ["Alto", "bad"], "2": ["Medio", "warn"], "3": ["Bajo", "info"], "4": ["Indefinido", "gray"]};
const tr = t => String(t ?? "").replace(/\b(Status|Severity|Owner)\b/g, m => ({Status: "Estado", Severity: "Severidad", Owner: "Responsable"}[m]))
  .replace(/\b(Open|Investigating|Contained|Closed|Critical|High|Medium|Low)\b/g, m => STA[m] || SEV[m]);
const sev = v => `<span class="pill sev-${esc(v)}">${esc(SEV[v] || v)}</span>`;
const st = v => `<span class="pill st-${esc(v)}">${esc(STA[v] || v)}</span>`;
const lvc = l => l >= 13 ? "c" : l >= 10 ? "s" : l >= 7 ? "w" : "n";
const lv = l => `<span class="lv ${lvc(l)}" title="Nivel ${l}">${l}</span>`;

/* ---------------- Fechas ---------------- */
const toDate = x => x instanceof Date ? x : typeof x === "number" ? new Date(x > 1e12 ? x : x * 1000) : new Date(String(x).replace(/([+-]\d\d)(\d\d)$/, "$1:$2"));
const fdt = x => { if (!x) return "—"; const d = toDate(x); return isNaN(d) ? esc(x) : d.toLocaleString("es-DO", {day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit"}); };
const dur = m => m == null ? "—" : m < 60 ? `${Math.round(m)} min` : m < 1440 ? `${Math.floor(m / 60)} h` + (Math.round(m % 60) ? ` ${Math.round(m % 60)} min` : "") : `${Math.floor(m / 1440)} d` + (Math.floor(m % 1440 / 60) ? ` ${Math.floor(m % 1440 / 60)} h` : "");
const since = x => { const d = toDate(x); return isNaN(d) ? "—" : dur((Date.now() - d) / 60000); };

/* ---------------- Tema claro / oscuro ---------------- */
function toggleTheme() {
  const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const next = {light: "dark", dark: "xr", xr: "light"}[cur] || "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("soc-theme", next); } catch (e) {}
  redraw(); themeIcon();
}
function themeIcon() {
  const th = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"), dark = th === "dark";
  const b = $("themeBtn"); if (!b) return;
  if (th === "xr") { b.innerHTML = '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>'; b.title = "Tema XR · cambiar a tema claro"; if ($("thName")) $("thName").textContent = "XR"; return; }
  b.innerHTML = dark ? '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>'
    : '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z"/></svg>';
  b.innerHTML = dark ? '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l9 5v10l-9 5-9-5V7z"/><path d="M12 22V12M21 7l-9 5-9-5"/></svg>' : b.innerHTML;
  b.title = dark ? "Cambiar a tema XR (azul marino, estilo Code-XR)" : "Cambiar a tema oscuro";
  if ($("thName")) $("thName").textContent = dark ? "Oscuro" : "Claro";
}
themeIcon();

/* ---------------- Tooltip (cualquier elemento con data-tip) ---------------- */
const TIP = $("tip");
function showTip(e, html) {
  TIP.innerHTML = html; TIP.classList.add("on");
  const w = TIP.offsetWidth, h = TIP.offsetHeight;
  TIP.style.left = Math.max(8, Math.min(e.clientX + 14, innerWidth - w - 8)) + "px";
  TIP.style.top = (e.clientY + 16 + h > innerHeight ? e.clientY - h - 12 : e.clientY + 16) + "px";
}
const hideTip = () => TIP.classList.remove("on");
document.addEventListener("mousemove", e => {
  if (e.target.closest && e.target.closest("[data-hover]")) return;  // gráficos de línea gestionan su propio tooltip
  const t = e.target.closest && e.target.closest("[data-tip]");
  t ? showTip(e, t.dataset.tip) : hideTip();
});

/* ======================================================================
   Gráficos SVG (se dibujan con el ancho real del contenedor y se repintan al redimensionar)
   ====================================================================== */
const CHARTS = {};
function draw(id, fn) { CHARTS[id] = fn; const el = $(id); if (el) fn(el); }
function redraw() { for (const [id, fn] of Object.entries(CHARTS)) { const el = $(id); el ? fn(el) : delete CHARTS[id]; } }
let _rz; addEventListener("resize", () => { clearTimeout(_rz); _rz = setTimeout(redraw, 150); });

function niceMax(v) { if (v <= 4) return Math.max(1, Math.ceil(v)); const p = 10 ** Math.floor(Math.log10(v)); return [1, 2, 2.5, 5, 10].map(m => m * p).find(m => m >= v); }
const short = n => n >= 1e6 ? (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + " M" : n >= 1e4 ? Math.round(n / 1e3) + " k" : nf(n);
function tickFmt(span) {
  return span <= 2 * 864e5 ? d => d.toLocaleTimeString("es-DO", {hour: "2-digit", minute: "2-digit"})
    : span <= 8 * 864e5 ? d => d.toLocaleDateString("es-DO", {weekday: "short", day: "2-digit"})
    : d => d.toLocaleDateString("es-DO", {day: "2-digit", month: "2-digit"});
}
function yAxis(W, H, M, max) {
  return [0, .5, 1].map(f => { const y = M.t + (H - M.t - M.b) * (1 - f);
    return `<line class="gl" x1="${M.l}" x2="${W - M.r}" y1="${y}" y2="${y}"/><text x="${M.l - 6}" y="${y + 3.5}" text-anchor="end">${short(max * f)}</text>`; }).join("");
}
const barTop = (x, y, w, h, r) => { r = Math.min(r, w / 2, h); return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`; };

/* Barras en el tiempo: pts = [[ms|iso, n], ...] */
function timeBars(id, pts, {h = 180, unit = "alertas", color = "var(--s1)"} = {}) {
  draw(id, el => {
    const W = el.clientWidth || 600, H = h, M = {l: 40, r: 6, t: 8, b: 22};
    if (!pts || !pts.length) { el.innerHTML = `<div class="empty">Sin datos en este periodo</div>`; return; }
    const ds = pts.map(p => toDate(p[0])), span = ds[ds.length - 1] - ds[0], f = tickFmt(span);
    const max = niceMax(Math.max(...pts.map(p => p[1]))), n = pts.length, bw = (W - M.l - M.r) / n, ih = H - M.t - M.b;
    const gap = bw > 6 ? 2 : bw > 3 ? 1 : 0, every = Math.ceil(n / Math.max(2, Math.floor((W - M.l) / 90)));
    const tipFmt = span <= 2 * 864e5 ? d => d.toLocaleString("es-DO", {weekday: "short", hour: "2-digit", minute: "2-digit"}) : d => d.toLocaleString("es-DO", {weekday: "short", day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"});
    el.innerHTML = `<svg height="${H}" viewBox="0 0 ${W} ${H}">${yAxis(W, H, M, max)}
      ${pts.map((p, i) => { const bh = p[1] ? Math.max(2, p[1] / max * ih) : 0, x = M.l + i * bw;
        return `<g data-tip="${esc(`<b>${nf(p[1])}</b> ${unit}<br>${tipFmt(ds[i])}`)}"><rect x="${x}" y="${M.t}" width="${bw}" height="${ih}" fill="transparent"/>
          ${bh ? `<path d="${barTop(x + gap / 2, M.t + ih - bh, Math.max(1, bw - gap), bh, 3)}" fill="${color}"/>` : ""}</g>`; }).join("")}
      <line x1="${M.l}" x2="${W - M.r}" y1="${M.t + ih}" y2="${M.t + ih}" stroke="var(--line)"/>
      ${pts.map((p, i) => i % every ? "" : `<text x="${M.l + i * bw + bw / 2}" y="${H - 5}" text-anchor="middle">${f(ds[i])}</text>`).join("")}</svg>`;
  });
}

/* Líneas (una escala): labels = fechas ISO; series = [{name, color, values}] */
function lines(id, labels, series, {h = 200} = {}) {
  draw(id, el => {
    const W = el.clientWidth || 600, H = h, M = {l: 34, r: 12, t: 10, b: 22}, n = labels.length, ih = H - M.t - M.b;
    const max = niceMax(Math.max(1, ...series.flatMap(s => s.values)));
    const X = i => M.l + (n < 2 ? 0 : i / (n - 1)) * (W - M.l - M.r), Y = v => M.t + ih * (1 - v / max);
    const ds = labels.map(l => new Date(l + "T12:00:00")), every = Math.ceil(n / Math.max(2, Math.floor((W - M.l) / 80)));
    el.innerHTML = `<svg height="${H}" viewBox="0 0 ${W} ${H}" data-hover>${yAxis(W, H, M, max)}
      ${series.map(s => `<path d="${s.values.map((v, i) => (i ? "L" : "M") + X(i).toFixed(1) + "," + Y(v).toFixed(1)).join("")}" fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`).join("")}
      ${labels.map((l, i) => i % every ? "" : `<text x="${X(i)}" y="${H - 5}" text-anchor="middle">${ds[i].toLocaleDateString("es-DO", {day: "2-digit", month: "2-digit"})}</text>`).join("")}
      <g class="xh" style="display:none"><line y1="${M.t}" y2="${M.t + ih}" stroke="var(--muted)" stroke-dasharray="3 3"/>
        ${series.map(s => `<circle r="4.5" fill="${s.color}" stroke="var(--card)" stroke-width="2"/>`).join("")}</g>
      <rect x="${M.l}" y="${M.t}" width="${W - M.l - M.r}" height="${ih}" fill="transparent" class="hit"/></svg>
      <div class="legend">${series.map(s => `<span><i style="background:${s.color}"></i>${esc(s.name)} <b>${nf(s.values.reduce((a, b) => a + b, 0))}</b></span>`).join("")}</div>`;
    const svg = el.querySelector("svg"), xh = svg.querySelector(".xh");
    svg.querySelector(".hit").addEventListener("mousemove", e => {
      const r = svg.getBoundingClientRect(), i = Math.max(0, Math.min(n - 1, Math.round((e.clientX - r.left - M.l) / (W - M.l - M.r) * (n - 1))));
      xh.style.display = ""; xh.querySelector("line").setAttribute("x1", X(i)); xh.querySelector("line").setAttribute("x2", X(i));
      xh.querySelectorAll("circle").forEach((c, k) => { c.setAttribute("cx", X(i)); c.setAttribute("cy", Y(series[k].values[i])); });
      showTip(e, `<b>${ds[i].toLocaleDateString("es-DO", {weekday: "long", day: "numeric", month: "long"})}</b><br>` +
        series.map(s => `<span style="color:${s.color}">●</span> ${esc(s.name)}: <b>${nf(s.values[i])}</b>`).join("<br>"));
    });
    svg.querySelector(".hit").addEventListener("mouseleave", () => { xh.style.display = "none"; hideTip(); });
  });
}

/* Anillo: items = [{label, value, color, click?}] */
function donut(id, items, center = "") {
  draw(id, el => {
    const tot = items.reduce((a, b) => a + (b.value || 0), 0), R = 62, w = 18, C = 75;
    let a0 = -Math.PI / 2;
    const arcs = tot ? items.filter(x => x.value).map(x => {
      const a = x.value / tot * Math.PI * 2, gap = items.filter(y => y.value).length > 1 ? 0.025 : 0, s = a0 + gap / 2, e = a0 + a - gap / 2; a0 += a;
      const p = (ang, r) => `${(C + r * Math.cos(ang)).toFixed(2)},${(C + r * Math.sin(ang)).toFixed(2)}`, big = e - s > Math.PI ? 1 : 0;
      const d = x.value === tot ? `M${C},${C - R}A${R},${R} 0 1 1 ${C - .01},${C - R}A${R},${R} 0 1 1 ${C},${C - R}` : `M${p(s, R)}A${R},${R} 0 ${big} 1 ${p(e, R)}`;
      return `<path d="${d}" fill="none" stroke="${x.color}" stroke-width="${w}" ${x.click ? `style="cursor:pointer" onclick="${esc(x.click)}"` : ""} data-tip="${esc(`<b>${esc(x.label)}</b><br>${nf(x.value)} · ${pct(x.value, tot)} %`)}"/>`;
    }).join("") : `<circle cx="${C}" cy="${C}" r="${R}" fill="none" stroke="var(--grid)" stroke-width="${w}"/>`;
    el.innerHTML = `<div class="donut"><svg viewBox="0 0 150 150" width="150" height="150">${arcs}
        <text x="75" y="74" text-anchor="middle" style="font-size:24px;font-weight:700;fill:var(--ink)">${short(tot)}</text>
        <text x="75" y="93" text-anchor="middle" style="font-size:11.5px">${esc(center)}</text></svg>
      <ul>${items.map(x => `<li ${x.click ? `style="cursor:pointer" onclick="${esc(x.click)}"` : ""}><i style="background:${x.color}"></i><span>${esc(x.label)}</span><b>${nf(x.value)} <span class="muted" style="font-weight:400">${pct(x.value, tot)} %</span></b></li>`).join("")}</ul></div>`;
  });
}

/* Barras horizontales (HTML): rows = [{label, value, click?, tip?, color?, pre?}] */
function hbars(rows, empty = "Sin datos", max = 8) {
  if (!rows || !rows.length) return `<div class="empty" style="padding:16px">${empty}</div>`;
  const top = Math.max(...rows.map(r => r.value));
  return `<ul class="hb">${rows.slice(0, max).map(r => `<li class="${r.click ? "click" : ""}" ${r.click ? `onclick="${esc(r.click)}"` : ""} ${r.tip ? `data-tip="${esc(r.tip)}"` : ""}>
    <span class="lb">${r.pre || ""}${esc(r.label)}</span><b>${nf(r.value)}</b>
    <span class="bar"><i style="width:${Math.max(1.5, r.value / top * 100)}%;${r.color ? `background:${r.color}` : ""}"></i></span></li>`).join("")}</ul>`;
}

/* Ranking: rows = [{label, sub?, value, pre?, color?, click?}]; muestra posición, barra y % del total */
function rank(rows, total, empty = "Sin datos", max = 7) {
  if (!rows || !rows.length) return `<div class="empty" style="padding:16px">${empty}</div>`;
  const top = Math.max(...rows.map(r => r.value)), tot = total || rows.reduce((a, r) => a + r.value, 0);
  return `<ol class="rank">${rows.slice(0, max).map((r, i) => `<li class="${r.click ? "click" : ""}" ${r.click ? `onclick="${esc(r.click)}"` : ""}>
    <span class="n">${i + 1}</span>
    <span class="lb"><b title="${esc(r.label)}">${esc(r.label)}</b>${r.sub ? `<small>${r.sub}</small>` : ""}</span>
    <span class="val"><b>${short(r.value)}</b><small>${pct(r.value, tot)} %</small></span>
    <span class="bar"><i style="width:${Math.max(2, r.value / top * 100)}%;${r.color ? `background:${r.color}` : ""}"></i></span></li>`).join("")}</ol>`;
}
const LVCOL = l => l >= 13 ? "var(--st-crit)" : l >= 10 ? "var(--st-serious)" : l >= 7 ? "var(--st-warn)" : "var(--s-neutral)";
const ruleRows = list => list.map(r => ({label: r.desc, value: r.n, color: LVCOL(r.nivel),
  sub: `${lv(r.nivel)} <span class="mono">regla ${esc(r.id)}</span>`, click: `drill('rule.id', ${JSON.stringify(String(r.id))})`}));
const agentRows = list => list.map(([k, v]) => ({label: k, value: v, sub: "🖥 equipo", click: `drill('agent.name', ${JSON.stringify(String(k))})`}));

/* Mapa de calor día × hora (hora local) a partir de [[ms, n], ...] */
function heatmap(id, pts) {
  draw(id, el => {
    const DAYS = ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"], m = DAYS.map(() => Array(24).fill(0));
    (pts || []).forEach(([t, n]) => { const d = toDate(t); m[(d.getDay() + 6) % 7][d.getHours()] += n; });
    const max = Math.max(1, ...m.flat()), Q = ["--q1", "--q2", "--q3", "--q4", "--q5", "--q6", "--q7"];
    const col = v => v ? `var(${Q[Math.min(6, Math.floor(Math.sqrt(v / max) * 6.99))]})` : "var(--grid)";
    el.innerHTML = `<div class="heat"><span></span>${[...Array(24).keys()].map(h => `<span style="text-align:center">${h % 3 ? "" : h}</span>`).join("")}
      ${m.map((row, d) => `<span class="l">${DAYS[d]}</span>` + row.map((v, h) => `<div style="background:${col(v)}" data-tip="${esc(`<b>${nf(v)}</b> alertas<br>${DAYS[d]} · ${h}:00–${h}:59`)}"></div>`).join("")).join("")}</div>
      <div class="legend" style="justify-content:flex-end">Menos ${Q.map(q => `<i style="background:var(${q})"></i>`).join("")} Más</div>`;
  });
}

/* Colores con significado: estado y nivel */
const LV_GROUPS = [["Crítico (13–15)", 13, 15, "var(--st-crit)"], ["Alto (10–12)", 10, 12, "var(--st-serious)"], ["Medio (7–9)", 7, 9, "var(--st-warn)"], ["Bajo (0–6)", 0, 6, "var(--s-neutral)"]];
const levelItems = (niveles, min = 0) => LV_GROUPS.filter(g => g[2] >= min).map(([label, a, b, color]) => ({label, color,
  value: (niveles || []).filter(([l]) => l >= a && l <= b).reduce((t, [, c]) => t + c, 0)}));
const AG_COLORS = {active: "var(--st-good)", disconnected: "var(--st-crit)", never_connected: "var(--s-neutral)", pending: "var(--st-warn)"};
const agentItems = (a, click) => Object.keys(AGS).map(k => ({label: AGS[k], value: (a || {})[k] || 0, color: AG_COLORS[k], click: click ? click(k) : null}));

const ICON = {
  shield: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-3z"/></svg>',
  radar: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12l6-6"/></svg>',
  flow: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="6" height="6" rx="1.5"/><rect x="15" y="14" width="6" height="6" rx="1.5"/><path d="M9 7h4a2 2 0 012 2v5"/></svg>',
  book: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 5a2 2 0 012-2h13v16H6a2 2 0 00-2 2V5z"/><path d="M8 7h7"/></svg>',
};

/* ======================================================================
   API, utilidades de vista y modal
   ====================================================================== */
let META = {user: "", severities: ["Critical", "High", "Medium", "Low"], statuses: ["Open", "Investigating", "Contained", "Closed"], users: [], runbooks: [], links: {}};
const md = t => DOMPurify.sanitize(marked.parse(t || ""));
const route = () => location.hash.replace(/^#\/?/, "").split("?")[0].split("/").map(decodeURIComponent);
const qs = () => new URLSearchParams(location.hash.split("?")[1] || "");
const MOTION = !matchMedia("(prefers-reduced-motion: reduce)").matches;
function enter(root) {
  if (!window.gsap || !MOTION || BG || !root) return;
  const els = [...root.querySelectorAll(":scope > *, :scope > .g > *, :scope > .kpis > *, .kboard > .lane")].slice(0, 40);
  gsap.fromTo(els, {y: 10, opacity: 0}, {y: 0, opacity: 1, duration: .38, stagger: .018, ease: "power2.out", clearProps: "transform,opacity"});
}
const view = html => { $("view").innerHTML = html; enter($("view")); };
let BG = false;  // true en los refrescos automáticos: no cuentan como actividad (cierre por inactividad)
async function api(path, opts = {}) {
  const headers = {"Content-Type": "application/json", "X-SOC": "1", ...(BG ? {"X-Background": "1"} : {})};
  const r = await fetch(path, {cache: "no-store", credentials: "same-origin", ...opts, headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined});
  if (r.status === 401 && !path.startsWith("auth/logout")) { location.href = "/portal/login?next=" + encodeURIComponent(location.hash); throw new Error("Sesión caducada"); }
  if (r.status === 428 && route()[0] !== "account") { location.hash = "#/account"; throw new Error("Completa los pasos de seguridad"); }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
const bg = async fn => { BG = true; try { return await fn(); } finally { BG = false; } };
function toast(msg) { const t = $("toast"); t.textContent = msg; t.classList.add("on"); setTimeout(() => t.classList.remove("on"), 2400); }
const opts = (list, cur, labels = {}) => list.map(x => `<option value="${esc(x)}" ${x === cur ? "selected" : ""}>${esc(labels[x] || x || "—")}</option>`).join("");
function formData(id) { const o = {}; new FormData($(id)).forEach((v, k) => o[k] = v); return o; }
function openModal(html, wide = false) { $("modalBody").innerHTML = html; $("modal").classList.toggle("wide", wide); $("modal").classList.add("on"); }
function closeModal() { $("modal").classList.remove("on"); }
$("modal").addEventListener("click", e => { if (e.target.id === "modal") closeModal(); });
addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });
const kpi = (t, v, h = "", href = "", alert = false) => `<${href ? `a href="${href}"` : "div"} class="card kpi ${alert ? "alert" : ""}"><div class="t">${t}</div><div class="v">${v}</div><div class="h">${h}</div></${href ? "a" : "div"}>`;
const box = (title, body, extra = "", cls = "") => `<section class="card panel ${cls}"><h3>${title}${extra ? `<small>${extra}</small>` : ""}</h3>${body}</section>`;
const unavailable = e => `<div class="empty err">No disponible: ${esc(e)}</div>`;

/* Detalle de alertas al pulsar un elemento */
const FIELD_NAMES = {"rule.id": "Regla", "agent.name": "Agente", "rule.mitre.tactic": "Táctica MITRE", "rule.mitre.id": "Técnica MITRE",
  "data.srcip": "IP de origen", "GeoLocation.country_name": "País", "rule.groups": "Grupo de reglas"};
let TH = {range: "24h", lv: 10};
async function drill(field, value) {
  openModal(`<h2 style="margin:0 0 4px">${esc(FIELD_NAMES[field] || field)}: <span class="mono" style="font-size:16px">${esc(value)}</span></h2>
    <p class="muted" style="margin:0 0 14px">Últimas 25 alertas · rango ${esc(TH.range)} · nivel ≥ ${TH.lv}</p><div id="drill"><div class="skel"></div></div>`, true);
  try {
    const rows = await api(`api/alerts?field=${encodeURIComponent(field)}&value=${encodeURIComponent(value)}&range=${TH.range}&min_level=${TH.lv}`);
    $("drill").innerHTML = (rows.length ? `<div class="scroll"><table class="table"><thead><tr><th>Fecha</th><th>Nivel</th><th>Agente</th><th>Regla</th><th>IP origen</th></tr></thead><tbody>
      ${rows.map(a => `<tr data-tip="${esc(esc((a.full_log || "").slice(0, 400)))}"><td style="white-space:nowrap">${fdt(a.timestamp)}</td><td>${lv((a.rule || {}).level)}</td>
        <td>${esc((a.agent || {}).name)}</td><td>${esc((a.rule || {}).description)} <span class="muted mono">#${esc((a.rule || {}).id)}</span></td>
        <td class="mono">${(a.data || {}).srcip ? `<a class="go" href="#/intel?q=${encodeURIComponent(a.data.srcip)}" onclick="closeModal()">${esc(a.data.srcip)}</a>` : "—"}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="empty">Sin alertas para este filtro.</div>`) +
      `<div class="row" style="margin-top:14px"><span class="muted" style="font-size:12.5px">Pasa el ratón por una fila para ver el log original.</span><span>
        ${field === "data.srcip" ? `<a class="btn sm" href="#/intel?q=${encodeURIComponent(value)}" onclick="closeModal()">Buscar IoC</a>` : ""}
        <button class="btn sm" onclick="openNewIncident({title: ${esc(JSON.stringify((FIELD_NAMES[field] || field) + ": " + value))}, detected_by: 'Wazuh · portal', ${field === "data.srcip" ? `iocs: ${esc(JSON.stringify(value))}` : field === "agent.name" ? `assets: ${esc(JSON.stringify(value))}` : ""}})">＋ Crear incidente</button>
        <a class="btn sm primary" href="${esc(META.links.wazuh || "#")}" target="_blank" rel="noopener">Abrir Wazuh →</a></span></div>`;
  } catch (e) { $("drill").innerHTML = unavailable(e.message); }
}

/* ======================================================================
   RESUMEN
   ====================================================================== */
async function renderHome() {
  view(`<div id="home"><div class="skel" style="height:120px"></div></div>`);
  let d;
  try { d = await api("data"); } catch (e) { view(unavailable(e.message)); return; }
  if (route()[0]) return;
  const s = d.summary, a = s.agentes || {}, al = s.alertas || {}, IS = d.incidents.stats, M = d.metrics, L = d.links;
  const crit = (al.por_nivel || []).filter(([l]) => l >= 13).reduce((t, [, c]) => t + c, 0), hits = s.misp_hits || [];
  const up = k => !s[k];
  const attn = [crit && `${nf(crit)} alertas críticas`, M.vencidos.length && `${nf(M.vencidos.length)} SLA vencidos`,
    d.sites.filter(x => x.enabled && x.state === "down").length && "portales caídos", (s.err_alertas || s.err_misp_eventos || s.err_workflows) && "servicios sin conexión"].filter(Boolean);
  setTimeout(() => enter($("home")), 0);
  $("home").innerHTML = `
  <section class="card hero"><div>
      <h1><span class="ic">${ICON.shield}</span>Centro de Operaciones de Seguridad</h1>
      <div class="sub2">ACME · monitoreo, inteligencia de amenazas y respuesta · datos de ${esc(s.generado)}</div>
      <span class="state ${attn.length ? "bad" : "ok"}">${attn.length ? "⚠ Requiere atención: " + attn.join(" · ") : "✓ Operación normal"}</span></div>
    <div class="badges">${[["Wazuh", up("err_alertas")], ["MISP", up("err_misp_eventos")], ["Shuffle", up("err_workflows")], ["Portal", true]]
      .map(([n, ok]) => `<span class="badge"><span class="dot ${ok ? "ok" : "bad"}"></span>${n} · ${ok ? "en línea" : "sin conexión"}</span>`).join("")}</div></section>
  <div class="kpis home5" style="margin-top:14px">
    ${kpi("Agentes activos", `${nf(a.active)}<span class="muted" style="font-size:15px;font-weight:500"> / ${nf(a.total)}</span>`, `${nf(a.disconnected)} desconectados`, "#/agents", false)}
    ${kpi("Alertas ≥ 10 · 24 h", short(al.total || 0), "Wazuh", "#/threats")}
    ${kpi("Críticas 13–15 · 24 h", nf(crit), crit ? "Revisar ahora" : "Sin críticas", "#/threats?lv=13", crit > 0)}
    ${kpi("Coincidencias MISP", nf(hits.length), "IoC vistos en alertas · 24 h", "#/intel")}
    ${kpi("IoC nuevos · 24 h", nf(s.misp_ioc_24h), "MISP (to_ids)", "#/intel")}
    ${kpi("Incidentes abiertos", nf(IS.open), `${nf(IS.critical_open)} críticos`, "#/incidents", IS.critical_open > 0)}
    ${kpi("SLA vencidos", nf(M.vencidos.length), "Sin primera respuesta a tiempo", "#/incidents", M.vencidos.length > 0)}
    ${(() => { const V = d.vulns, c = (V.por_severidad.find(x => x[0] === "Critical") || [0, 0])[1];
      return kpi("Vulnerabilidades críticas", nf(c), `${nf(V.activas)} abiertas · ${nf(V.vencidas)} vencidas`, "#/vulns?view=track&severity=Critical", c > 0 || V.vencidas > 0); })()}
    ${(() => { const on = d.sites.filter(x => x.enabled), dn = on.filter(x => x.state === "down");
      return kpi("Portales caídos", `${nf(dn.length)}<span class="muted" style="font-size:15px;font-weight:500"> / ${nf(on.length)}</span>`, dn.map(x => esc(x.name)).join(", ").slice(0, 50) || "Todos en línea", "#/sites", dn.length > 0); })()}
    ${kpi("Coincidencias IoC · 24 h", nf(d.iocs.vistos), `${short(d.iocs.activos)} IoC en la base`, "#/iocs?view=coincidencias&days=1", d.iocs.vistos > 0)}
  </div>
  <div class="g g21" style="margin-top:14px">
    ${box("Alertas ≥ 10 por hora", `<div class="viz" id="cHome"></div>`, "últimas 24 h · pasa el ratón por las barras")}
    ${box("Alertas por nivel", `<div class="viz" id="dLv"></div>`, "24 h")}
  </div>
  <div class="g g2" style="margin-top:14px">
    ${box("Reglas que más alertan", `<div id="rkR">${rank((al.top_rules || []).map(([k, v]) => ({label: k, value: v})), al.total, "Sin alertas")}</div>`, `24 h · nivel ≥ 10 · <a class="go" href="#/threats">Ver amenazas →</a>`)}
    ${box("Equipos con más alertas", `<div id="rkA">${rank(agentRows(al.top_agents || []), al.total, "Sin alertas")}</div>`, "24 h · pulsa para ver sus alertas")}
  </div>
  <div class="g g3" style="margin-top:14px">
    ${box("Estado de los agentes", `<div class="viz" id="dAg"></div>`, esc(a.fuente || ""))}
    ${box("Incidentes abiertos por severidad", hbars(M.por_severidad.map(([k, v]) => ({label: SEV[k], value: v, click: `location.hash='#/incidents?severity=${k}'`,
        color: {Critical: "var(--st-crit)", High: "var(--st-serious)", Medium: "var(--st-warn)", Low: "var(--s-neutral)"}[k]})), "Sin incidentes abiertos") +
      (M.vencidos.length ? `<div style="margin-top:10px"><b style="font-size:13px;color:var(--bad)">⚠ SLA vencido</b>${M.vencidos.slice(0, 4).map(v =>
        `<div class="row" style="font-size:13px;padding:4px 0;cursor:pointer" onclick="location.hash='#/incidents/${esc(v.code)}'"><span><b>${esc(v.code)}</b> ${esc(v.title).slice(0, 38)}</span>${sev(v.severity)}</div>`).join("")}</div>` : ""),
      `MTTA ${dur(M.mtta_min)} · MTTR ${dur(M.mttr_min)}`)}
    ${box("Coincidencias con MISP", hits.length ? `<ul class="feed">${hits.slice(0, 6).map(h => { const m = (h.data || {}).misp || {};
        return `<li><span class="pill bad">${esc(m.type)}</span><div><a class="mono go" href="#/intel?q=${encodeURIComponent(m.value || "")}">${esc(m.value)}</a>
          <div class="muted" style="font-size:12px">${esc((h.agent || {}).name)} · ${esc(m.event_info)}</div></div><span class="muted" style="font-size:12px">${fdt(h.timestamp)}</span></li>`; }).join("")}</ul>`
      : `<div class="empty">Sin coincidencias en 24 h. Que no haya coincidencias no garantiza que un indicador sea seguro.</div>`, "24 h")}
  </div>
  <div class="g g21" style="margin-top:14px">
    ${box("Incidentes recientes", d.incidents.recent.length ? `<table class="table"><tbody>${d.incidents.recent.map(x => `<tr class="click" onclick="location.hash='#/incidents/${esc(x.code)}'">
        <td><b>${esc(x.code)}</b></td><td>${esc(x.title)}</td><td>${sev(x.severity)}</td><td>${st(x.status)}</td><td class="muted" style="white-space:nowrap">${esc(x.updated_at)}</td></tr>`).join("")}</tbody></table>`
      : `<div class="empty">Aún no hay incidentes. <a class="go" href="javascript:openNewIncident()">Crear el primero →</a></div>`, `<a class="go" href="#/incidents">Ver todos →</a>`)}
    <section class="card panel"><h3>Accesos</h3><div class="g" style="gap:10px">
      ${[["shield", "Wazuh", "SIEM / XDR", L.wazuh], ["radar", "MISP", "Inteligencia de amenazas", L.misp], ["flow", "Shuffle", `SOAR · ${nf((s.workflows || []).length)} workflows`, L.shuffle], ["book", "Runbooks", `${d.runbooks.length} procedimientos`, "#/runbooks"]]
        .map(([i, t, p, h]) => `<a class="card svc" href="${esc(h)}" ${h.startsWith("#") ? "" : 'target="_blank" rel="noopener"'}><div class="thumb">${ICON[i]}</div><div><h4>${t}</h4><p>${p}</p></div></a>`).join("")}
    </div></section>
  </div>`;
  timeBars("cHome", (al.por_hora || []).map(([k, n]) => [k.length <= 13 ? k + ":00:00Z" : k, n]));
  donut("dLv", levelItems(al.por_nivel, 10), "alertas");
  donut("dAg", agentItems(a, k => `location.hash='#/agents?status=${k}'`), "agentes");
  // detalle con nivel e ID de regla (consulta en caché 2 min)
  api("api/threats?range=24h&min_level=10").then(t => { TH = {range: "24h", lv: 10};
    if ($("rkR")) $("rkR").innerHTML = rank(ruleRows(t.reglas), t.total, "Sin alertas");
    if ($("rkA")) $("rkA").innerHTML = rank(agentRows(t.agentes), t.total, "Sin alertas"); }).catch(() => {});
}

/* ======================================================================
   AMENAZAS
   ====================================================================== */
async function renderThreats() {
  const q = qs(); TH = {range: q.get("range") || "24h", lv: +(q.get("lv") || 10)};
  const go = (k, v) => { const p = qs(); p.set(k, v); location.hash = "#/threats?" + p; };
  window._th = go;
  view(`<div class="toolbar" style="margin-top:6px"><div><h1 class="page" style="margin:0 4px">Amenazas</h1><div class="sub" style="margin:0 4px">Alertas de Wazuh con MITRE ATT&CK, origen y reglas. Pulsa cualquier elemento para ver sus alertas.</div></div>
    <span class="grow"></span>
    <div class="chips">${[["24h", "24 h"], ["7d", "7 días"], ["30d", "30 días"]].map(([v, t]) => `<button class="${v === TH.range ? "on" : ""}" onclick="_th('range','${v}')">${t}</button>`).join("")}</div>
    <div class="chips">${[[7, "Nivel ≥ 7"], [10, "≥ 10"], [12, "≥ 12"], [13, "Críticas"]].map(([v, t]) => `<button class="${v === TH.lv ? "on" : ""}" onclick="_th('lv',${v})">${t}</button>`).join("")}</div>
    <button class="btn sm" onclick="router()">↻</button></div>
    <div id="thr"><div class="skel"></div><p class="muted" style="text-align:center">Consultando el indexer de Wazuh… los rangos largos pueden tardar.</p></div>`);
  let t;
  try { t = await api(`api/threats?range=${TH.range}&min_level=${TH.lv}`); } catch (e) { $("thr") && ($("thr").innerHTML = unavailable(e.message)); return; }
  if (!$("thr")) return;
  const crit = t.niveles.filter(([l]) => l >= 13).reduce((a, [, c]) => a + c, 0);
  const rows = (list, field, opt = {}) => list.map(([k, v]) => ({label: k, value: v, click: `drill('${field}', ${JSON.stringify(String(k))})`, ...opt}));
  $("thr").innerHTML = `
  <div class="kpis">
    ${kpi(`Alertas nivel ≥ ${TH.lv}`, short(t.total), `rango ${TH.range}`)}
    ${kpi("Críticas 13–15", nf(crit), pct(crit, t.total) + " % del total", "", crit > 0)}
    ${kpi("Tácticas MITRE", nf(t.tacticas.length), t.tacticas[0] ? "Principal: " + esc(t.tacticas[0][0]) : "—")}
    ${kpi("IPs de origen", nf(t.ips.length) + (t.ips.length >= 10 ? "+" : ""), t.ips[0] ? "Top: " + esc(t.ips[0][0]) : "—")}
    ${kpi("Países", nf(t.paises.length) + (t.paises.length >= 10 ? "+" : ""), t.paises[0] ? "Top: " + esc(t.paises[0][0]) : "—")}
    ${kpi("Agentes afectados", nf(t.agentes.length) + (t.agentes.length >= 10 ? "+" : ""), t.agentes[0] ? "Top: " + esc(t.agentes[0][0]) : "—")}
  </div>
  <div class="g g21" style="margin-top:14px">
    ${box("Evolución de alertas", `<div class="viz" id="cThr"></div>`, `nivel ≥ ${TH.lv}`)}
    ${box("Por nivel", `<div class="viz" id="dThr"></div>`)}
  </div>
  <div class="g g3" style="margin-top:14px">
    ${box("Tácticas MITRE ATT&CK", hbars(rows(t.tacticas, "rule.mitre.tactic"), "Sin datos MITRE en este rango", 10))}
    ${box("Técnicas MITRE", hbars(t.tecnicas.map(x => ({label: `${x.id} · ${x.nombre}`, value: x.n, click: `drill('rule.mitre.id', ${JSON.stringify(x.id)})`})), "Sin técnicas", 10))}
    ${box("Equipos con más alertas", rank(agentRows(t.agentes), t.total, "Sin alertas", 10))}
  </div>
  <div class="g g3" style="margin-top:14px">
    ${box("IPs de origen", hbars(rows(t.ips, "data.srcip", {pre: ""}), "Sin IPs de origen", 10), "pulsa para ver alertas")}
    ${box("Países de origen", hbars(rows(t.paises, "GeoLocation.country_name"), "Sin geolocalización (GeoIP)", 10))}
    ${box("Grupos de reglas", hbars(rows(t.grupos, "rule.groups"), "Sin datos", 10))}
  </div>
  <div class="g g2" style="margin-top:14px">
    ${box("Reglas más frecuentes", rank(ruleRows(t.reglas), t.total, "Sin alertas", 10), "pulsa para ver sus alertas")}
    ${box("Mapa de calor", `<div class="viz" id="hThr"></div>`, "día y hora local")}
  </div>
  ${box(`Últimas alertas nivel ≥ ${Math.max(TH.lv, 12)}`, t.recientes.length ? `<ul class="feed">${t.recientes.map(a => `<li>${lv((a.rule || {}).level)}
    <div style="cursor:pointer" onclick="drill('rule.id', ${esc(JSON.stringify(String((a.rule || {}).id)))})">${esc((a.rule || {}).description)}<div class="muted" style="font-size:12px">${esc((a.agent || {}).name)}${(a.data || {}).srcip ? " · origen " + esc(a.data.srcip) : ""}</div></div>
    <span class="muted" style="font-size:12px;white-space:nowrap">${fdt(a.timestamp)}</span></li>`).join("")}</ul>` : `<div class="empty">Sin alertas de ese nivel.</div>`, "", "").replace('class="card panel "', 'class="card panel" style="margin-top:14px"')}`;
  timeBars("cThr", t.hist);
  donut("dThr", levelItems(t.niveles, TH.lv).map(x => ({...x, click: null})), "alertas");
  heatmap("hThr", t.calor);
}

/* ======================================================================
   AGENTES
   ====================================================================== */
let AGD = null;
async function renderAgents() {
  view(`<h1 class="page">Agentes</h1><div class="sub">Estado de los agentes de Wazuh según la última foto de <span class="mono">wazuh-monitoring</span> (se renueva cada ~15 min).</div><div id="ag"><div class="skel"></div></div>`);
  try { AGD = await api("api/agents"); } catch (e) { $("ag") && ($("ag").innerHTML = unavailable(e.message)); return; }
  if (!$("ag")) return;
  const S = Object.fromEntries(AGD.estados), q = qs();
  $("ag").innerHTML = `
  <div class="kpis">
    ${kpi("Total", nf(AGD.total), "foto " + fdt(AGD.foto + "Z"))}
    ${kpi("Activos", nf(S.active), pct(S.active || 0, AGD.total) + " %", "javascript:_agf('active')")}
    ${kpi("Desconectados", nf(S.disconnected), "Revisar conectividad", "javascript:_agf('disconnected')", (S.disconnected || 0) > 0)}
    ${kpi("Nunca conectados", nf(S.never_connected), "Registrados sin conexión", "javascript:_agf('never_connected')")}
  </div>
  <div class="g g4" style="margin-top:14px">
    ${box("Estado", `<div class="viz" id="dAg2"></div>`, "", "span2")}
    ${box("Sistema operativo", hbars(AGD.so.map(([k, v]) => ({label: k, value: v}))))}
    ${box("Versión del agente", hbars(AGD.versiones.map(([k, v]) => ({label: k, value: v}))))}
  </div>
  ${box("Grupos", hbars(AGD.grupos.map(([k, v]) => ({label: k, value: v})), "Sin grupos", 12)).replace('class="card panel "', 'class="card panel" style="margin-top:14px"')}
  <h2>Listado <small id="agN"></small></h2>
  <div class="toolbar"><div class="chips" id="agChips">${[["", "Todos"], ...Object.entries(AGS).map(([k, v]) => [k, v])].map(([k, v]) => `<button data-k="${k}" onclick="_agf('${k}')">${v}</button>`).join("")}</div>
    <input id="agQ" style="flex:1;width:auto" placeholder="Buscar por nombre, IP, SO o grupo…" oninput="_agt()"></div>
  <section class="card"><div class="scroll" style="max-height:560px"><table class="table"><thead><tr><th>ID</th><th>Nombre</th><th>IP</th><th>Estado</th><th>SO</th><th>Versión</th><th>Grupo</th><th>Última conexión</th></tr></thead><tbody id="agT"></tbody></table></div></section>`;
  donut("dAg2", agentItems(S, k => `_agf('${k}')`), "agentes");
  window._agStatus = q.get("status") || "";
  window._agf = k => { window._agStatus = k; _agt(); document.getElementById("agT").scrollIntoView({behavior: "smooth", block: "center"}); };
  window._agt = () => {
    const f = ($("agQ").value || "").toLowerCase(), k = window._agStatus;
    document.querySelectorAll("#agChips button").forEach(b => b.classList.toggle("on", b.dataset.k === k));
    const rows = AGD.lista.filter(r => (!k || r.status === k) && (!f || [r.name, r.ip, r.os, r.group, r.id].join(" ").toLowerCase().includes(f)));
    $("agN").textContent = `${nf(rows.length)} agentes`;
    $("agT").innerHTML = rows.slice(0, 300).map(r => `<tr><td class="mono">${esc(r.id)}</td><td><b>${esc(r.name)}</b></td><td class="mono">${esc(r.ip)}</td>
      <td><span class="pill ${r.status === "active" ? "" : r.status === "disconnected" ? "bad" : "gray"}">${esc({active: "Activo", disconnected: "Desconectado", never_connected: "Nunca conectado", pending: "Pendiente"}[r.status] || r.status)}</span></td>
      <td>${esc(r.os)}</td><td class="mono">${esc(r.version)}</td><td>${esc(r.group)}</td>
      <td style="white-space:nowrap">${r.last ? `${fdt(r.last)} <span class="muted">· hace ${since(r.last)}</span>` : "—"}</td></tr>`).join("")
      + (rows.length > 300 ? `<tr><td colspan="8" class="muted">Mostrando 300 de ${nf(rows.length)}. Usa el buscador para acotar.</td></tr>` : "")
      || `<tr><td colspan="8" class="empty">Ningún agente coincide.</td></tr>`;
  };
  _agt();
}

/* ======================================================================
   INTELIGENCIA: buscador de IoC, MISP y Shuffle
   ====================================================================== */
async function renderIntel() {
  const q = qs().get("q") || "";
  view(`<h1 class="page">Inteligencia y automatización</h1><div class="sub">Busca un indicador en MISP, en las alertas de Wazuh (30 días) y en los incidentes del portal.</div>
    <form class="search" onsubmit="location.hash='#/intel?q='+encodeURIComponent(this.q.value.trim());return false">
      <input name="q" value="${esc(q)}" placeholder="IP, dominio, URL o hash (MD5 / SHA1 / SHA256)…" autofocus><button class="btn primary">Buscar</button></form>
    <div id="iocR"></div><div id="intel" style="margin-top:6px"><div class="skel" style="margin-top:14px"></div></div>`);
  if (q) searchIoc(q);
  let d;
  try { d = await api("api/intel"); } catch (e) { $("intel") && ($("intel").innerHTML = unavailable(e.message)); return; }
  if (!$("intel")) return;
  const L = META.links, ev = d.eventos, io = d.iocs, sh = d.shuffle;
  const EXC = {FINISHED: "var(--st-good)", ABORTED: "var(--st-crit)", FAILURE: "var(--st-crit)", EXECUTING: "var(--s1)", WAITING: "var(--st-warn)"};
  $("intel").innerHTML = `
  <div class="g g21" style="margin-top:14px">
    ${box("Eventos recientes de MISP", ev ? (ev.length ? `<div class="scroll"><table class="table"><thead><tr><th>ID</th><th>Fecha</th><th>Evento</th><th>Amenaza</th><th class="n">Atributos</th></tr></thead><tbody>
      ${ev.map(e => { const [t, c] = THREAT[String(e.threat_level_id)] || ["—", "gray"];
        return `<tr class="click" onclick="window.open('${esc(L.misp)}/events/view/${esc(e.id)}','_blank')"><td class="mono">${esc(e.id)}</td><td style="white-space:nowrap">${esc(e.date)}</td><td>${esc(e.info)}</td>
          <td><span class="pill ${c}">${t}</span></td><td class="n">${nf(+e.attribute_count)}</td></tr>`; }).join("")}</tbody></table></div>` : `<div class="empty">Sin eventos nuevos en 30 días.</div>`) : unavailable(d.err_eventos), "30 días")}
    ${box("IoC accionables por tipo", io ? hbars(io.tipos.map(([k, v]) => ({label: k, value: v})), "Sin IoC nuevos", 10) + `<div class="muted" style="font-size:12.5px;margin-top:6px">Total: <b>${nf(io.total)}</b> atributos to_ids</div>` : unavailable(d.err_iocs), "7 días")}
  </div>
  <h2>Automatización · Shuffle <small><a class="go" href="${esc(L.shuffle)}" target="_blank" rel="noopener">Abrir Shuffle →</a></small></h2>
  ${sh ? `<div class="g g12">
    ${box("Resultado de las ejecuciones", `<div class="viz" id="dSh"></div>`, "últimas por workflow")}
    ${box("Ejecuciones recientes", sh.recientes.length ? `<div class="scroll"><table class="table"><thead><tr><th>Workflow</th><th>Estado</th><th>Inicio</th><th class="n">Duración</th></tr></thead><tbody>
      ${sh.recientes.map(r => `<tr class="click" onclick="window.open('${esc(L.shuffle)}/workflows/${esc(r.workflow_id)}?execution_id=${esc(r.id)}','_blank')"><td>${esc(r.workflow)}</td>
        <td><span class="pill ${r.status === "FINISHED" ? "" : r.status === "ABORTED" || r.status === "FAILURE" ? "bad" : "warn"}">${esc(EXS[r.status] || r.status)}</span></td>
        <td style="white-space:nowrap">${r.started ? fdt(+r.started) : "—"}</td><td class="n">${r.completed && r.started ? dur((r.completed - r.started) / 60).replace(/^0 min$/, "< 1 min") : "—"}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="empty">Aún no hay ejecuciones.</div>`)}
  </div>` : unavailable(d.err_shuffle)}`;
  if (sh) donut("dSh", sh.estados.map(([k, v]) => ({label: EXS[k] || k, value: v, color: EXC[k] || "var(--s-neutral)"})), "ejecuciones");
}
async function searchIoc(q) {
  $("iocR").innerHTML = `<div class="skel" style="height:120px;margin-top:14px"></div>`;
  let r;
  try { r = await api("api/ioc?q=" + encodeURIComponent(q)); } catch (e) { $("iocR").innerHTML = `<div style="margin-top:14px">${unavailable(e.message)}</div>`; return; }
  const L = META.links, I = r.intel || {score: 0, fuentes: []}, found = (r.misp || []).length + ((r.wazuh || {}).total || 0) + r.incidentes.length + I.fuentes.length;
  $("iocR").innerHTML = `<div class="card panel" style="margin-top:14px;border-color:${found ? "color-mix(in srgb,var(--bad) 40%,var(--line))" : "var(--line)"}">
    <div class="row"><h3 style="margin:0">Resultado para <span class="mono" style="font-size:14px">${esc(r.q)}</span></h3>
      <span>${found ? `<span class="pill bad">Indicador visto</span>` : `<span class="pill">Sin coincidencias</span>`}
      <button class="btn sm" onclick="openNewIncident({title: ${esc(JSON.stringify("IoC: " + r.q))}, iocs: ${esc(JSON.stringify(r.q))}, detected_by: 'Búsqueda de IoC · portal', runbook: 'misp-ioc-match'})">＋ Crear incidente</button></span></div>
    <div style="margin-top:10px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">${risk(I.score)} <b>Fuentes de inteligencia:</b> ${srcPills(I.fuentes) || '<span class="muted">en ninguna de tus fuentes</span>'}
      <a class="go" href="javascript:iocDetail(${esc(JSON.stringify(r.q))})">Análisis a fondo →</a></div>
    <div class="g g3" style="margin-top:12px">
      <div><b>MISP</b> <span class="muted">· ${r.misp ? nf(r.misp.length) + " atributos" : "no disponible"}</span>
        ${(r.misp || []).slice(0, 6).map(m => `<div style="font-size:13px;padding:6px 0;border-top:1px solid var(--line)"><a class="go" target="_blank" href="${esc(L.misp)}/events/view/${esc(m.event_id)}">#${esc(m.event_id)}</a> ${esc(m.event)}
          <div class="muted" style="font-size:12px">${esc(m.type)} · ${esc(m.category)} ${m.to_ids ? '· <span class="pill bad">to_ids</span>' : ""} ${m.tags.map(t => `<span class="pill gray">${esc(t)}</span>`).join(" ")}</div></div>`).join("") || (r.misp ? `<div class="muted" style="font-size:13px;padding:6px 0">No está en MISP.</div>` : `<div class="err">${esc(r.err_misp)}</div>`)}</div>
      <div><b>Wazuh</b> <span class="muted">· ${r.wazuh ? nf(r.wazuh.total) + " alertas en 30 días" : "no disponible"}</span>
        ${r.wazuh ? (r.wazuh.agentes.length ? `<div style="margin:6px 0">${r.wazuh.agentes.map(([k, v]) => `<span class="pill info" style="margin:2px">${esc(k)} · ${nf(v)}</span>`).join("")}</div>` : "")
          + r.wazuh.alertas.slice(0, 5).map(a => `<div style="font-size:13px;padding:5px 0;border-top:1px solid var(--line)">${lv((a.rule || {}).level)} ${esc((a.rule || {}).description)}<div class="muted" style="font-size:12px">${esc((a.agent || {}).name)} · ${fdt(a.timestamp)}</div></div>`).join("")
          : `<div class="err">${esc(r.err_wazuh)}</div>`}</div>
      <div><b>Incidentes del portal</b> <span class="muted">· ${nf(r.incidentes.length)}</span>
        ${r.incidentes.map(i => `<div style="font-size:13px;padding:6px 0;border-top:1px solid var(--line);cursor:pointer" onclick="location.hash='#/incidents/${esc(i.code)}'"><b>${esc(i.code)}</b> ${esc(i.title)}<div>${sev(i.severity)} ${st(i.status)}</div></div>`).join("") || `<div class="muted" style="font-size:13px;padding:6px 0">Ningún incidente lo menciona.</div>`}</div>
    </div></div>`;
}

/* ======================================================================
   MODO NOC (pantalla de la sala SOC)
   ====================================================================== */
let _nocTimer, _clock, _prevTheme;
async function renderNoc() {
  if (!document.body.classList.contains("noc")) {
    document.body.classList.add("noc"); _prevTheme = document.documentElement.dataset.theme; document.documentElement.dataset.theme = "xr";
  }
  view(`<div class="nocbar"><div><h1>SOC ACME · Operación en vivo</h1><div class="badges" id="nocB" style="margin-top:6px"></div></div>
    <div style="text-align:right"><div class="clock" id="clk"></div><div class="muted" id="nocU" style="font-size:12.5px"></div>
      <div style="margin-top:6px"><button class="btn sm" onclick="document.fullscreenElement?document.exitFullscreen():document.documentElement.requestFullscreen()">⛶ Pantalla completa</button>
      <a class="btn sm" href="#/">Salir</a></div></div></div><div id="noc"><div class="skel" style="height:400px"></div></div>`);
  const tick = () => { const c = $("clk"); if (c) c.textContent = new Date().toLocaleTimeString("es-DO"); };
  clearInterval(_clock); _clock = setInterval(tick, 1000); tick();
  await nocData();
  clearInterval(_nocTimer); _nocTimer = setInterval(() => bg(nocData), 60000);
}
async function nocData() {
  if (route()[0] !== "noc") return;
  let d, t = null;
  try { [d, t] = await Promise.all([api("data"), api("api/threats?range=24h&min_level=10").catch(() => null)]); } catch (e) { $("noc").innerHTML = unavailable(e.message); return; }
  if (!$("noc")) return;
  const s = d.summary, a = s.agentes || {}, al = s.alertas || {}, IS = d.incidents.stats, M = d.metrics, hits = s.misp_hits || [];
  const crit = (al.por_nivel || []).filter(([l]) => l >= 13).reduce((x, [, c]) => x + c, 0);
  $("nocB").innerHTML = [["Wazuh", !s.err_alertas], ["MISP", !s.err_misp_eventos], ["Shuffle", !s.err_workflows]].map(([n, ok]) => `<span class="badge"><span class="dot ${ok ? "ok" : "bad"}"></span>${n}</span>`).join("");
  $("nocU").textContent = "Datos de " + s.generado + " · se actualiza cada minuto";
  $("noc").innerHTML = `<div class="noc-grid">
    <div class="c12 kpis">
      ${kpi("Críticas 13–15 · 24 h", nf(crit), "", "", crit > 0)}${kpi("Alertas ≥ 10 · 24 h", short(al.total || 0))}
      ${kpi("Agentes activos", `${nf(a.active)}<span class="muted" style="font-size:20px"> / ${nf(a.total)}</span>`, `${nf(a.disconnected)} desconectados`, "", false)}
      ${kpi("Coincidencias MISP", nf(hits.length), "24 h", "", hits.length > 0)}${kpi("Incidentes abiertos", nf(IS.open), `${nf(IS.critical_open)} críticos`, "", IS.critical_open > 0)}
      ${kpi("SLA vencidos", nf(M.vencidos.length), "", "", M.vencidos.length > 0)}
      ${(() => { const dn = d.sites.filter(x => x.enabled && x.state === "down"); return kpi("Portales caídos", nf(dn.length), dn.map(x => esc(x.name)).join(", ").slice(0, 40), "", dn.length > 0); })()}
    </div>
    ${box("Alertas ≥ 10 por hora · 24 h", `<div class="viz" id="nH"></div>`, "", "c8")}
    ${box("Por nivel", `<div class="viz" id="nL"></div>`, "", "c4")}
    ${box("Agentes", `<div class="viz" id="nA"></div>`, "", "c4")}
    ${box("Tácticas MITRE · 24 h", t ? hbars(t.tacticas.map(([k, v]) => ({label: k, value: v})), "Sin datos", 6) : unavailable("Wazuh"), "", "c4")}
    ${box("Incidentes abiertos", M.abiertos.length ? `<ul class="feed">${M.abiertos.slice(0, 6).map(i => `<li>${sev(i.severity)}<div><b>${esc(i.code)}</b> ${esc(i.title)}<div class="muted" style="font-size:12px">${esc(i.owner || "sin responsable")} · ${st(i.status)}</div></div>
      <span style="font-size:12.5px;white-space:nowrap;${!i.respondido && i.edad_min > i.sla_min ? "color:var(--bad);font-weight:700" : ""}">${dur(i.edad_min)}</span></li>`).join("")}</ul>` : `<div class="empty">Sin incidentes abiertos</div>`, "", "c4")}
    ${box("Últimas alertas críticas", t && t.recientes.length ? `<ul class="feed">${t.recientes.slice(0, 8).map(x => `<li>${lv((x.rule || {}).level)}<div>${esc((x.rule || {}).description)}<div class="muted" style="font-size:12px">${esc((x.agent || {}).name)}</div></div><span class="muted" style="font-size:12.5px">${fdt(x.timestamp)}</span></li>`).join("")}</ul>` : `<div class="empty">Sin alertas ≥ 12</div>`, "", "c7")}
    ${box("Coincidencias MISP · 24 h", hits.length ? `<ul class="feed">${hits.slice(0, 8).map(h => { const m = (h.data || {}).misp || {}; return `<li><span class="pill bad">${esc(m.type)}</span><div class="mono">${esc(m.value)}<div class="muted" style="font-size:12px;font-family:inherit">${esc((h.agent || {}).name)}</div></div><span class="muted" style="font-size:12.5px">${fdt(h.timestamp)}</span></li>`; }).join("")}</ul>` : `<div class="empty">Sin coincidencias</div>`, "", "c5")}
  </div>`;
  timeBars("nH", (al.por_hora || []).map(([k, n]) => [k.length <= 13 ? k + ":00:00Z" : k, n]), {h: 230});
  donut("nL", levelItems(al.por_nivel, 10), "alertas");
  donut("nA", agentItems(a), "agentes");
}
function leaveNoc() {
  if (!document.body.classList.contains("noc")) return;
  document.body.classList.remove("noc"); clearInterval(_nocTimer); clearInterval(_clock);
  if (_prevTheme) document.documentElement.dataset.theme = _prevTheme; else delete document.documentElement.dataset.theme;
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
}

/* ======================================================================
   INCIDENTES
   ====================================================================== */
const rbOpts = cur => `<option value="">— Ninguno —</option>` + (META.runbooks || []).map(r => `<option value="${esc(r.slug)}" ${r.slug === cur ? "selected" : ""}>${esc(r.title)}</option>`).join("");
function openNewIncident(pre = {}) {
  openModal(`<h2 style="margin:0 0 16px">Nuevo incidente</h2>
  <form id="fNew" class="form" onsubmit="return saveNewIncident(event)">
    <div class="full"><label>Título *</label><input name="title" required value="${esc(pre.title || "")}" placeholder="p. ej. Fuerza bruta contra srv-dc01"></div>
    <div><label>Severidad</label><select name="severity">${opts(META.severities, pre.severity || "High", SEV)}</select></div>
    <div><label>Responsable</label><select name="owner">${opts(["", ...META.users], META.user)}</select></div>
    <div><label>Detectado por</label><input name="detected_by" value="${esc(pre.detected_by || "")}" placeholder="Regla Wazuh 5712 / usuario / CSIRT"></div>
    <div><label>Activos afectados</label><input name="assets" value="${esc(pre.assets || "")}" placeholder="srv-dc01, 10.0.0.5"></div>
    <div class="full"><label>Runbook</label><select name="runbook">${rbOpts(pre.runbook || "")}</select></div>
    <div class="full"><label>Resumen</label><textarea name="summary" placeholder="Qué pasó, impacto, primeras acciones…">${esc(pre.summary || "")}</textarea></div>
    <div class="full"><label>Indicadores de compromiso (IoC)</label><textarea name="iocs" class="mono" placeholder="Uno por línea: IPs, dominios, hashes, URLs">${esc(pre.iocs || "")}</textarea></div>
    <div class="full row"><span class="muted" style="font-size:12.5px">El número se asigna solo (INC-AAAA-NNN)</span>
      <span><button type="button" class="btn" onclick="closeModal()">Cancelar</button> <button class="btn primary">Crear incidente</button></span></div>
  </form>`);
  setTimeout(() => document.querySelector("#fNew [name=title]").focus(), 50);
}
async function saveNewIncident(e) {
  e.preventDefault();
  try { const r = await api("api/incidents", {method: "POST", body: formData("fNew")});
    closeModal(); toast(`${r.code} creado`); location.hash = "#/incidents/" + r.code; }
  catch (err) { toast("Error: " + err.message); }
  return false;
}

const LANES = [["Open", "var(--st-crit)"], ["Investigating", "var(--st-warn)"], ["Contained", "var(--brand)"], ["Closed", "var(--st-good)"]];
function kcard(x, slaMap) {
  const s = slaMap[x.code], late = s && !s.respondido && s.edad_min > s.sla_min;
  return `<div class="kcard" data-code="${esc(x.code)}" data-st="${esc(x.status)}"><div class="kh"><b class="mono">${esc(x.code)}</b>${sev(x.severity)}</div>
    <div class="kt">${esc(x.title)}</div><div class="km"><span class="av">${esc(initials(x.owner || "?"))}</span>${esc(x.owner || "sin responsable")}
    ${late ? `<span class="late" title="SLA de primera respuesta vencido">⚠ ${dur(s.edad_min)}</span>` : `<span class="age">${s ? dur(s.edad_min) : esc((x.updated_at || "").slice(5, 16))}</span>`}</div></div>`;
}
async function incBoard(severity, text, M) {
  const B = $("kb"); if (!B) return;
  const rows = await api(`api/incidents?status=&severity=${encodeURIComponent(severity)}&q=${encodeURIComponent(text)}`);
  const slaMap = Object.fromEntries(M.abiertos.map(a => [a.code, a]));
  B.innerHTML = LANES.map(([k, c]) => { const L = rows.filter(x => x.status === k).slice(0, k === "Closed" ? 20 : 200);
    return `<section class="lane ${k === "Closed" ? "closed" : ""}" data-col="${k}" style="--lc:${c}"><h4><i></i>${esc(STA[k])}<em class="cnt">${rows.filter(x => x.status === k).length}</em></h4>
      <div class="kl">${L.map(x => kcard(x, slaMap)).join("") || `<div class="empty" style="padding:20px 6px;font-size:12.5px">Arrastra aquí</div>`}</div></section>`; }).join("");
  if (window.gsap && MOTION) gsap.fromTo(B.querySelectorAll(".kcard"), {y: 8, opacity: 0}, {y: 0, opacity: 1, duration: .3, stagger: .015, ease: "power2.out", clearProps: "transform,opacity"});
  B.querySelectorAll(".kcard").forEach(c => c.addEventListener("pointerdown", e => kdrag(e, c)));
}
function kdrag(ev, card) {
  if (ev.button !== 0) return;
  const x0 = ev.clientX, y0 = ev.clientY, r0 = card.getBoundingClientRect(), from = card.closest(".lane");
  const ro = ME && ME.role === "viewer";
  let on = false, ghost = null, over = null;
  const lanes = [...document.querySelectorAll(".lane")];
  const move = e => {
    const dx = e.clientX - x0, dy = e.clientY - y0;
    if (!on) {
      if (ro || Math.hypot(dx, dy) < 6) return;
      on = true;
      ghost = card.cloneNode(true); ghost.classList.add("kghost");
      Object.assign(ghost.style, {left: r0.left + "px", top: r0.top + "px", width: r0.width + "px", margin: 0});
      document.body.appendChild(ghost); card.classList.add("kplace");
      if (window.gsap) gsap.fromTo(ghost, {scale: 1, rotation: 0}, {scale: 1.04, rotation: -2, duration: .25, ease: "back.out(2)"});
    }
    if (window.gsap) gsap.set(ghost, {x: dx, y: dy}); else ghost.style.transform = `translate(${dx}px,${dy}px) rotate(-2deg)`;
    const under = document.elementFromPoint(e.clientX, e.clientY)?.closest(".lane") || null;
    if (under !== over) { lanes.forEach(l => l.classList.toggle("hot", l === under)); over = under; }
  };
  const up = async e => {
    removeEventListener("pointermove", move); removeEventListener("pointerup", up);
    lanes.forEach(l => l.classList.remove("hot"));
    if (!on) { if (Math.hypot(e.clientX - x0, e.clientY - y0) < 6) location.hash = "#/incidents/" + card.dataset.code; return; }
    const to = over && over !== from ? over.dataset.col : null;
    const finish = () => { ghost.remove(); card.classList.remove("kplace"); };
    const back = () => window.gsap ? gsap.to(ghost, {x: 0, y: 0, rotation: 0, scale: 1, duration: .3, ease: "power3.out", onComplete: finish}) : finish();
    if (!to || (to === "Closed" && !confirm(`¿Cerrar ${card.dataset.code}?`))) { back(); return; }
    const list = over.querySelector(".kl"); list.querySelector(".empty")?.remove(); list.prepend(card);
    const r1 = card.getBoundingClientRect();
    const land = () => { finish(); if (window.gsap) gsap.fromTo(card, {scale: .96}, {scale: 1, duration: .35, ease: "back.out(2)", clearProps: "transform"}); };
    if (window.gsap) gsap.to(ghost, {x: r1.left - r0.left, y: r1.top - r0.top, rotation: 0, scale: 1, duration: .28, ease: "power3.out", onComplete: land}); else land();
    const cnt = l => { const c = l.querySelector("h4 .cnt"); c.textContent = l.querySelectorAll(".kcard").length; };
    cnt(over); cnt(from);
    try { await api("api/incidents/" + encodeURIComponent(card.dataset.code), {method: "PUT", body: {status: to}}); card.dataset.st = to; toast(`${card.dataset.code} → ${STA[to]}`); incCount(); }
    catch (err) { toast("No se pudo mover: " + err.message); from.querySelector(".kl").prepend(card); cnt(over); cnt(from); }
  };
  addEventListener("pointermove", move); addEventListener("pointerup", up);
}

async function renderIncidents() {
  const q = qs(), status = q.get("status") ?? "active", severity = q.get("severity") || "", text = q.get("q") || "", mode = q.get("view") || (localStorage.getItem("soc-incview") || "list");
  try { localStorage.setItem("soc-incview", mode); } catch (e) {}
  const [rows, M] = await Promise.all([
    api(`api/incidents?status=${encodeURIComponent(status)}&severity=${encodeURIComponent(severity)}&q=${encodeURIComponent(text)}`), api("api/metrics")]);
  window._setF = (k, v) => { q.set(k, v); location.hash = "#/incidents?" + q.toString(); };
  const rbTitle = s => ((META.runbooks || []).find(r => r.slug === s) || {}).title || s;
  view(`<h1 class="page">Incidentes</h1><div class="sub">Registro, métricas de respuesta y SLA. Primera respuesta: Crítica ${M.sla.Critical} min · Alta ${M.sla.High} min · Media ${M.sla.Medium / 60} h · Baja ${M.sla.Low / 60} h.</div>
  <div class="kpis">
    ${kpi("Abiertos", nf(M.por_severidad.reduce((a, [, v]) => a + v, 0)), `${nf(M.total)} en total`)}
    ${kpi("Críticos abiertos", nf((M.por_severidad.find(x => x[0] === "Critical") || [0, 0])[1]), "", "javascript:_setF('severity','Critical')", (M.por_severidad.find(x => x[0] === "Critical") || [0, 0])[1] > 0)}
    ${kpi("MTTA (mediana)", dur(M.mtta_min), `tiempo a primera respuesta · ${M.n_tta} casos`)}
    ${kpi("MTTR (mediana)", dur(M.mttr_min), `tiempo hasta el cierre · ${M.n_ttr} casos`)}
    ${kpi("SLA vencidos", nf(M.vencidos.length), "abiertos sin respuesta a tiempo", "", M.vencidos.length > 0)}
  </div>
  <div class="g g21" style="margin-top:14px">
    ${box("Creados y cerrados por día", `<div class="viz" id="cInc"></div>`, "últimos 30 días")}
    <div class="g">${box("Abiertos por severidad", hbars(M.por_severidad.map(([k, v]) => ({label: SEV[k], value: v, click: `_setF('severity','${k}')`,
        color: {Critical: "var(--st-crit)", High: "var(--st-serious)", Medium: "var(--st-warn)", Low: "var(--s-neutral)"}[k]})), "Sin incidentes abiertos"))}
      ${box("Por runbook", hbars(M.por_runbook.map(([k, v]) => ({label: rbTitle(k), value: v, click: `location.hash='#/runbooks/${esc(k)}'`})), "Ningún incidente vinculado a runbook", 5))}</div>
  </div>
  ${M.vencidos.length ? `<section class="card panel" style="margin-top:14px;border-color:color-mix(in srgb,var(--bad) 45%,var(--line))"><h3 style="color:var(--bad)">⚠ SLA de primera respuesta vencido</h3>
    <table class="table"><tbody>${M.vencidos.map(v => `<tr class="click" onclick="location.hash='#/incidents/${esc(v.code)}'"><td><b>${esc(v.code)}</b></td><td>${esc(v.title)}</td><td>${sev(v.severity)}</td>
      <td>${esc(v.owner || "sin responsable")}</td><td class="n" style="color:var(--bad);font-weight:700">${dur(v.edad_min)} <span class="muted" style="font-weight:400">/ SLA ${dur(v.sla_min)}</span></td></tr>`).join("")}</tbody></table></section>` : ""}
  <h2><span style="display:flex;gap:10px;align-items:center">${mode === "board" ? "Tablero" : "Listado"} <span class="chips">${[["list", "☰ Lista"], ["board", "▦ Tablero"]].map(([k, t]) => `<button class="${k === mode ? "on" : ""}" onclick="_setF('view','${k}')">${t}</button>`).join("")}</span></span>
    <small>${mode === "board" ? "arrastra una tarjeta para cambiar su estado · clic para abrirla" : rows.length + " mostrados"}</small></h2>
  <div class="toolbar">
    <select style="width:auto;${mode === "board" ? "display:none" : ""}" onchange="_setF('status', this.value)">
      ${[["active", "Activos (no cerrados)"], ["", "Todos"], ...META.statuses.map(s => [s, STA[s]])].map(([v, t]) => `<option value="${v}" ${v === status ? "selected" : ""}>${t}</option>`).join("")}
    </select>
    <select style="width:auto" onchange="_setF('severity', this.value)"><option value="">Todas las severidades</option>${opts(META.severities, severity, SEV)}</select>
    <input style="width:auto;flex:1" placeholder="Buscar código, título, activo o IoC… (Enter)" value="${esc(text)}" onkeydown="if(event.key==='Enter')_setF('q', this.value)">
    <button class="btn primary" onclick="openNewIncident()">＋ Nuevo incidente</button>
    <a class="btn" href="api/export">Exportar</a>
  </div>
  ${mode === "board" ? `<div class="kboard" id="kb"><div class="skel"></div></div>` : `<section class="card">${rows.length ? `<table class="table"><thead><tr><th>Código</th><th>Título</th><th>Severidad</th><th>Estado</th><th>Responsable</th><th>Runbook</th><th>Actualizado</th></tr></thead><tbody>
    ${rows.map(x => `<tr class="click" onclick="location.hash='#/incidents/${esc(x.code)}'"><td><b>${esc(x.code)}</b></td><td>${esc(x.title)}</td>
      <td>${sev(x.severity)}</td><td>${st(x.status)}</td><td>${esc(x.owner)}</td><td class="muted">${x.runbook ? "📘 " + esc(rbTitle(x.runbook)) : ""}</td><td class="muted" style="white-space:nowrap">${esc(x.updated_at)}</td></tr>`).join("")}
  </tbody></table>` : `<div class="empty">Ningún incidente coincide con estos filtros.</div>`}</section>`}`);
  if (mode === "board") incBoard(severity, text, M);
  lines("cInc", M.dias, [{name: "Creados", color: "var(--s1)", values: M.creados}, {name: "Cerrados", color: "var(--s2)", values: M.cerrados}], {h: 300});
}

async function renderIncident(code) {
  const x = await api("api/incidents/" + encodeURIComponent(code));
  const rb = ((META.runbooks || []).find(r => r.slug === x.runbook) || {}).title || x.runbook;
  view(`<div class="toolbar" style="margin-top:8px"><a class="btn sm" href="#/incidents">← Incidentes</a><span class="grow"></span>
      <span class="muted" style="font-size:12.5px">Creado por ${esc(x.created_by)} · ${esc(x.created_at)}</span>
      <button class="btn sm primary" onclick='investigate(${esc(JSON.stringify(x.code + " · " + x.title))}, ${esc(JSON.stringify(`Incidente ${x.code}: ${x.title}. Severidad ${x.severity}, estado ${x.status}. Activos: ${x.assets || "—"}. IoC: ${(x.iocs || "").replace(/\s+/g, " ").slice(0, 400)}`))}, ${esc(JSON.stringify(`Investiga el incidente ${x.code}: revisa su cronología, comprueba los IoC y las alertas relacionadas, indica la técnica MITRE y el runbook, y propón los siguientes pasos.`))})'>🤖 Investigar con IA</button></div>
  <h1 class="page">${esc(x.code)} · ${esc(x.title)}</h1>
  <div style="margin:0 4px 16px">${sev(x.severity)} ${st(x.status)} ${x.runbook ? `<a class="pill info" href="#/runbooks/${esc(x.runbook)}">📘 ${esc(rb)}</a>` : ""}</div>
  <div class="detail">
    <section class="card panel">
      <form id="fInc" class="form" onsubmit="return saveIncident(event,'${esc(x.code)}')">
        <div class="full"><label>Título</label><input name="title" value="${esc(x.title)}"></div>
        <div><label>Estado</label><select name="status">${opts(META.statuses, x.status, STA)}</select></div>
        <div><label>Severidad</label><select name="severity">${opts(META.severities, x.severity, SEV)}</select></div>
        <div><label>Responsable</label><select name="owner">${opts([...new Set(["", x.owner, ...META.users])], x.owner)}</select></div>
        <div><label>Detectado</label><input name="detected_at" value="${esc(x.detected_at)}"></div>
        <div><label>Detectado por</label><input name="detected_by" value="${esc(x.detected_by)}"></div>
        <div><label>Activos afectados</label><input name="assets" value="${esc(x.assets)}"></div>
        <div class="full"><label>Runbook</label><div class="row" style="flex-wrap:nowrap"><select name="runbook">${rbOpts(x.runbook)}</select>
          ${x.runbook ? `<a class="btn sm" href="#/runbooks/${esc(x.runbook)}" target="_blank">Abrir runbook →</a>` : ""}</div></div>
        <div class="full"><label>Resumen</label><textarea name="summary">${esc(x.summary)}</textarea></div>
        <div class="full"><label>Indicadores de compromiso (IoC)</label><textarea name="iocs" class="mono">${esc(x.iocs)}</textarea>
          ${(x.iocs || "").trim() ? `<div style="margin-top:6px">${x.iocs.split(/\s+/).filter(Boolean).slice(0, 8).map(i => `<a class="pill info" style="margin:2px" href="#/intel?q=${encodeURIComponent(i)}">🔎 ${esc(i)}</a>`).join("")}</div>` : ""}</div>
        <div class="full"><label>Causa raíz</label><textarea name="root_cause">${esc(x.root_cause)}</textarea></div>
        <div class="full"><label>Lecciones aprendidas</label><textarea name="lessons">${esc(x.lessons)}</textarea></div>
        <div class="full" style="text-align:right"><button class="btn primary">Guardar cambios</button></div>
      </form>
    </section>
    <section class="card panel">
      <h3>Cronología</h3>
      <form id="fNote" onsubmit="return addNote(event,'${esc(x.code)}')" style="margin-bottom:14px">
        <textarea name="text" placeholder="Añade una acción, hallazgo o decisión…" style="min-height:70px"></textarea>
        <div style="text-align:right;margin-top:8px"><button class="btn sm primary">Añadir a la cronología</button></div>
      </form>
      <ul class="timeline">${x.events.map(e => `<li class="${esc(e.kind)}"><div class="meta">${esc(e.at)} · ${esc(e.author)}</div>${esc(tr(e.text)).replace(/\n/g, "<br>")}</li>`).join("")}</ul>
    </section>
  </div>`);
}
async function saveIncident(e, code) {
  e.preventDefault();
  try { await api("api/incidents/" + code, {method: "PUT", body: formData("fInc")}); toast("Guardado"); renderIncident(code); }
  catch (err) { toast("Error: " + err.message); }
  return false;
}
async function addNote(e, code) {
  e.preventDefault();
  try { await api(`api/incidents/${code}/notes`, {method: "POST", body: formData("fNote")}); renderIncident(code); }
  catch (err) { toast("Error: " + err.message); }
  return false;
}

/* ======================================================================
   RUNBOOKS
   ====================================================================== */
async function renderRunbookEdit(slug) {
  const r = slug === "new" ? {title: "", description: "", body: "# Runbook — Título\n\n1. Primer paso\n2. Segundo paso\n"} : await api("api/runbooks/" + encodeURIComponent(slug));
  view(`<div class="toolbar" style="margin-top:8px"><a class="btn sm" href="#/runbooks${slug === "new" ? "" : "/" + esc(slug)}">← Volver</a><span class="grow"></span>
      ${slug === "new" ? "" : `<button class="btn sm" onclick="delRunbook('${esc(slug)}')">Eliminar</button>`}
      <button class="btn sm primary" onclick="saveRunbook('${esc(slug)}')">Guardar</button></div>
    <section class="card panel"><form id="fRb" class="form">
      <div><label>Título</label><input name="title" value="${esc(r.title)}"></div>
      <div><label>Descripción corta</label><input name="description" value="${esc(r.description)}"></div>
      <div><label>Nivel</label><select name="level">${opts(["", "Básico", "Intermedio", "Avanzado", "Referencia"], r.level || "")}</select></div>
      <div><label>Categoría</label><input name="category" value="${esc(r.category || "")}" placeholder="Identidad, Malware, Correo…"></div>
      <div><label>Severidad típica</label><select name="severity">${opts(["", ...META.severities], r.severity || "", SEV)}</select></div>
      <div><label>Técnicas MITRE ATT&CK (separadas por comas)</label><input name="mitre" value="${esc(r.mitre || "")}" placeholder="T1566, T1204.002"></div>
      <div class="full"><label>OWASP Top 10 (opcional)</label><input name="owasp" value="${esc(r.owasp || "")}" placeholder="A05:2025, A01:2025"></div>
      <div class="full editor"><div><label>Contenido (Markdown)</label><textarea name="body" id="rbBody" oninput="$('rbPrev').innerHTML=md(this.value)">${esc(r.body)}</textarea></div>
        <div><label>Vista previa</label><div class="md card panel" id="rbPrev" style="min-height:420px;overflow:auto">${md(r.body)}</div></div></div>
    </form></section>`);
}
async function saveRunbook(slug) {
  try { const r = await api("api/runbooks" + (slug === "new" ? "" : "/" + slug), {method: slug === "new" ? "POST" : "PUT", body: formData("fRb")});
    META = await api("api/meta").catch(() => META);
    toast("Runbook guardado"); location.hash = "#/runbooks/" + r.slug; }
  catch (err) { toast("Error: " + err.message); }
}
async function delRunbook(slug) {
  if (!confirm("¿Eliminar este runbook?")) return;
  await api("api/runbooks/" + slug, {method: "DELETE"}); toast("Eliminado"); location.hash = "#/runbooks";
}

/* ======================================================================
   HERRAMIENTAS: repositorio interno (catálogo, README, archivos, visor de código, GitHub)
   ====================================================================== */
const TSTC = {"Aprobada": "", "En evaluación": "warn", "Obsoleta": "gray"};
const PLAT_ICON = {Kali: "🐉", Windows: "🪟", Linux: "🐧", Multiplataforma: "🌐"};
async function openToolCatalog() {
  const rows = await api("api/tools/catalog"), pend = rows.filter(r => !r.added);
  const by = {}; rows.forEach(r => (by[r.category] = by[r.category] || []).push(r));
  openModal(`<div class="row"><h2 style="margin:0">Catálogo de herramientas</h2><span class="muted">${rows.length} herramientas · ${pend.length} sin añadir</span></div>
    <p class="muted" style="font-size:13px">Selección de GitHub, Kali Linux y Windows (Sysinternals y otras). Las marcadas 🔒 son intrusivas y quedan «En evaluación» con autorización obligatoria.</p>
    <div class="scroll" style="max-height:60vh">${Object.entries(by).map(([c, list]) => `<h3 style="margin:14px 0 6px">${esc(c)}</h3>
      <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:8px">${list.map(r => `<label class="card" style="padding:10px;display:flex;gap:10px;box-shadow:none;margin:0;color:var(--ink);cursor:pointer;${r.added ? "opacity:.5" : ""}">
        <input type="checkbox" class="tck" value="${esc(r.name)}" style="width:auto;margin-top:3px" ${r.added ? "checked disabled" : ""}>
        <span><b style="font-size:13.5px">${esc(r.name)}</b> ${r.auth ? "🔒" : ""}<div class="muted" style="font-size:12px;font-weight:400">${PLAT_ICON[r.platform] || ""} ${esc(r.platform)}${r.added ? " · ya está en el repositorio" : ""}</div>
        <div style="font-size:12px;font-weight:400;margin-top:2px">${esc(r.description)}</div></span></label>`).join("")}</div>`).join("")}</div>
    <div class="row" style="margin-top:14px"><button class="btn sm" onclick="document.querySelectorAll('.tck:not(:disabled)').forEach(x=>x.checked=true)">Marcar todas</button>
      <span><button class="btn" onclick="closeModal()">Cerrar</button> <button class="btn primary" onclick="addToolCatalog()">Añadir seleccionadas</button></span></div>`, true);
}
async function addToolCatalog() {
  const names = [...document.querySelectorAll(".tck:checked:not(:disabled)")].map(x => x.value);
  if (!names.length) { toast("Marca alguna herramienta"); return; }
  const r = await api("api/tools/catalog", {method: "POST", body: {names}}); closeModal(); toast(`${r.añadidas} herramientas añadidas`); router();
}
const LANGC = {Python: "#3572A5", Shell: "#89e051", Bash: "#89e051", PowerShell: "#012456", JavaScript: "#f1e05a", Go: "#00ADD8", "C": "#555555", "C++": "#f34b7d", Rust: "#dea584", YARA: "#220000", Ruby: "#701516", "C#": "#178600", Java: "#b07219"};
const TICON = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14.7 6.3a4 4 0 00-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 005.4-5.4l-2.5 2.5-2.4-.6-.6-2.4z"/></svg>';
const fsize = b => b == null ? "—" : b < 1024 ? b + " B" : b < 1048576 ? (b / 1024).toFixed(1) + " KB" : (b / 1048576).toFixed(1) + " MB";
const langDot = l => l ? `<span style="display:inline-flex;align-items:center;gap:5px"><i style="width:10px;height:10px;border-radius:50%;background:${LANGC[l] || "var(--s-neutral)"};display:inline-block"></i>${esc(l)}</span>` : "";

/* Resaltado de sintaxis sencillo (sin librerías): comentarios, cadenas, palabras clave y números */
const KW = new Set("def class import from return if elif else for while try except finally with as in is not and or None True False async await lambda yield pass break continue raise global nonlocal del assert function const let var new this typeof instanceof switch case default echo fi then do done esac local export param begin process end foreach select where".split(" "));
const Q3 = "'".repeat(3);
function highlight(src, lang) {
  if (lang === "text" || src.length > 1500000) return esc(src);
  const hashC = ["python", "bash", "powershell", "ruby", "yaml"].includes(lang), slashC = !["python", "bash", "yaml", "powershell"].includes(lang);
  const parts = [
    hashC ? "(#[^\\n]*)" : "(\\b\\B)",
    slashC ? "(\\/\\/[^\\n]*|\\/\\*[\\s\\S]*?\\*\\/)" : "(\\b\\B)",
    '("""[\\s\\S]*?"""|' + Q3 + "[\\s\\S]*?" + Q3 + '|"(?:\\\\.|[^"\\\\\\n])*"|' + "'(?:\\\\.|[^'\\\\\\n])*'|`(?:\\\\.|[^`\\\\])*`)",
    "\\b([A-Za-z_][A-Za-z0-9_]*)\\b",
    "\\b(\\d+(?:\\.\\d+)?)\\b"];
  const re = new RegExp(parts.join("|"), "g");
  let out = "", last = 0, m;
  while ((m = re.exec(src))) {
    if (!m[0]) { re.lastIndex++; continue; }
    out += esc(src.slice(last, m.index));
    const t = m[0];
    if (m[1] || m[2]) out += `<span class="tk-c">${esc(t)}</span>`;
    else if (m[3]) out += `<span class="tk-s">${esc(t)}</span>`;
    else if (m[4]) out += KW.has(t) ? `<span class="tk-k">${t}</span>` : /^[A-Z][A-Z0-9_]{2,}$/.test(t) ? `<span class="tk-n">${t}</span>` : t;
    else out += `<span class="tk-n">${t}</span>`;
    last = re.lastIndex;
  }
  return out + esc(src.slice(last));
}

let TOOLS_META = {categorias: [], estados: []};
async function renderTools() {
  const q = qs(), cat = q.get("cat") || "", text = q.get("q") || "", plat = q.get("p") || "";
  const d = await api(`api/tools?cat=${encodeURIComponent(cat)}&q=${encodeURIComponent(text)}&platform=${encodeURIComponent(plat)}`);
  TOOLS_META = d;
  window._tf2 = (k, v) => { const p = qs(); v ? p.set(k, v) : p.delete(k); location.hash = "#/tools?" + p; };
  view(`<div class="toolbar" style="margin-top:6px"><div><h1 class="page" style="margin:0 4px">Herramientas del SOC</h1>
      <div class="sub" style="margin:0 4px">Repositorio interno de scripts y utilidades: documentación, código, versiones y quién autoriza su uso.</div></div>
    <span class="grow"></span><button class="btn" onclick="openToolCatalog()">📚 Catálogo</button><button class="btn" onclick="importGithub()">⬇ Importar de GitHub</button><a class="btn primary" href="#/tools/new/edit">＋ Nueva herramienta</a></div>
  <div class="kpis" style="margin-bottom:14px">
    ${kpi("Herramientas", nf(d.total), `${nf(d.rows.length)} con estos filtros`, "#/tools")}
    ${d.plataformas.map(p => kpi(PLAT_ICON[p] + " " + p, nf(d.por_plataforma[p] || 0), "", `javascript:_tf2('p', ${JSON.stringify(p === plat ? "" : p)})`)).join("")}
  </div>
  <div id="secsum"></div>
  <div class="toolbar"><div class="chips" style="flex-wrap:wrap">${[["", "Todas"], ...d.categorias.map(c => [c, c])].map(([k, t]) => `<button class="${k === cat ? "on" : ""}" onclick="_tf2('cat', ${esc(JSON.stringify(k))})">${esc(t)}${k ? ` <span class="muted" style="font-weight:400">${d.por_categoria[k] || 0}</span>` : ""}</button>`).join("")}</div></div>
  <div class="toolbar"><div class="chips">${[["", "Todas las plataformas"], ...d.plataformas.map(p => [p, PLAT_ICON[p] + " " + p])].map(([k, t]) => `<button class="${k === plat ? "on" : ""}" onclick="_tf2('p', ${esc(JSON.stringify(k))})">${esc(t)}</button>`).join("")}</div>
    <input style="flex:1;min-width:220px;width:auto" placeholder="Buscar por nombre, etiqueta o lenguaje… (Enter)" value="${esc(text)}" onkeydown="if(event.key==='Enter')_tf2('q',this.value)"></div>
  ${d.rows.length ? `<div class="grid">${d.rows.map(t => `<a class="card rb" href="#/tools/${esc(t.slug)}" style="${t.status === "Obsoleta" ? "opacity:.6" : ""}">
      <div class="row" style="flex-wrap:nowrap;margin-bottom:10px"><div class="thumb">${TICON}</div>
        <span>${t.requires_auth ? `<span class="pill bad" title="Requiere autorización antes de usarla">🔒 Autorización</span> ` : ""}<span class="pill ${TSTC[t.status] ?? "gray"}">${esc(t.status)}</span></span></div>
      <h4>${esc(t.name)}</h4><div class="muted" style="font-size:12px;margin:-2px 0 6px">${esc(t.category)}</div>
      <p>${esc(t.description).slice(0, 180)}</p>
      <div style="margin-bottom:10px">${(t.tags || "").split(",").map(x => x.trim()).filter(Boolean).slice(0, 4).map(x => `<span class="pill gray" style="margin:2px 2px 0 0">${esc(x)}</span>`).join("")}</div>
      <div class="row" style="font-size:12.5px"><span class="muted" style="display:flex;gap:12px;align-items:center">${t.platform ? `<span title="Plataforma">${PLAT_ICON[t.platform] || ""} ${esc(t.platform)}</span>` : ""}${langDot(t.language)}${t.files ? `<span>📄 ${t.files}</span>` : ""}${t.stars != null && t.repo_url ? `<span>★ ${t.stars}</span>` : ""}</span>
        <span class="muted">${esc((t.updated_at || "").slice(0, 10))}</span></div></a>`).join("")}</div>`
    : `<div class="card empty">No hay herramientas${cat || text ? " con estos filtros" : ""}. <a class="go" href="#/tools/new/edit">Registra la primera →</a></div>`}`);
  try { const x = await bg(() => api("api/tools/security-summary")); const el = $("secsum"); if (!el) return;
    const tot = x.critical + x.high + x.medium + x.low + x.informational;
    el.innerHTML = `<section class="card panel secsum" style="margin-bottom:14px"><b>🔒 Seguridad del código</b><span class="muted" style="font-size:12.5px">${x.auditadas ? `${x.auditadas} herramienta(s) auditada(s) · última auditoría de cada una` : "Aún no se ha auditado ninguna herramienta: ábrela y usa la pestaña «Auditoría»."}</span>
      <span class="grow"></span>${x.auditadas ? `${Object.keys(FSEV).filter(k => k !== "informational").map(k => `<span>${fsev(k)} <b>${x[k]}</b></span>`).join("")}<span><span class="pill gray">Por validar</span> <b>${x.needs_validation}</b></span>${tot ? "" : '<span class="pill">✔ Sin hallazgos</span>'}` : ""}</section>`; } catch (e) {}
}

async function importGithub() {
  const url = prompt("URL del repositorio de GitHub (https://github.com/usuario/repositorio):"); if (!url) return;
  const m = url.match(/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:\/|$)/); if (!m) { toast("No parece una URL de GitHub"); return; }
  toast("Importando…");
  try { const t = await api("api/tools", {method: "POST", body: {name: m[2], repo_url: `https://github.com/${m[1]}/${m[2]}`, owner: META.user, status: "En evaluación"}});
    location.hash = "#/tools/" + t.slug; }
  catch (e) { toast("Error: " + e.message); }
}

async function renderTool(slug, sub, fid) {
  const t = await api("api/tools/" + encodeURIComponent(slug));
  const tab = sub === "file" ? "files" : (qs().get("tab") || (t.readme ? "readme" : t.files.length ? "files" : "usage"));
  const ghURL = t.repo_url && /github\.com/.test(t.repo_url) ? t.repo_url : "";
  const tabs = [["readme", "📖 README"], ["files", `📁 Archivos <span class="pill gray">${t.files.length}</span>`], ["usage", "⚙ Uso"], ["audit", "🔒 Auditoría"], ["metrics", "📊 Métricas"], ["log", "🕘 Historial"]];
  view(`<div class="toolbar" style="margin-top:8px"><a class="btn sm" href="#/tools">← Herramientas</a><span class="grow"></span>
      ${(t.homepage || (!ghURL && t.repo_url)) ? `<a class="btn sm" href="${esc(t.homepage || t.repo_url)}" target="_blank" rel="noopener">Sitio oficial ↗</a>` : ""}
      ${ghURL ? `<a class="btn sm" href="${esc(ghURL)}" target="_blank" rel="noopener">Ver en GitHub ↗</a><button class="btn sm" onclick="syncTool('${esc(t.slug)}',0,this)" title="Actualiza README y lista de archivos">↻ Sincronizar</button>` : ""}
      <a class="btn sm primary" href="#/tools/${esc(t.slug)}/edit">Editar</a></div>
  <div class="row" style="flex-wrap:nowrap;align-items:flex-start;gap:14px;margin:6px 4px 14px"><div class="thumb" style="width:52px;height:52px">${TICON}</div>
    <div style="flex:1;min-width:0"><h1 class="page" style="margin:0">${esc(t.name)} ${t.version ? `<span class="muted" style="font-size:15px;font-weight:500">v${esc(t.version)}</span>` : ""}</h1>
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:6px;font-size:13px"><span class="pill ${TSTC[t.status] ?? "gray"}">${esc(t.status)}</span>
        <span class="pill info">${esc(t.category || "Sin categoría")}</span>${t.platform ? `<span>${PLAT_ICON[t.platform] || ""} ${esc(t.platform)}</span>` : ""}${langDot(t.language)}${t.license ? `<span class="muted">⚖ ${esc(t.license)}</span>` : ""}
        ${t.stars != null && ghURL ? `<span class="muted">★ ${t.stars}</span>` : ""}${t.gh_synced ? `<span class="muted">sincronizado ${esc(t.gh_synced)}</span>` : ""}</div></div></div>
  ${t.requires_auth ? `<section class="card panel" style="border-color:color-mix(in srgb,var(--bad) 45%,var(--line));background:var(--bad-soft);margin-bottom:14px">
    <b style="color:var(--bad)">🔒 Requiere autorización antes de usarla</b><div style="font-size:13.5px;margin-top:4px">${esc(t.auth_note || "Solicita aprobación del responsable de seguridad.")}</div></section>` : ""}
  <div class="detail">
    <section class="card panel" style="min-width:0">
      <div class="chips" style="margin-bottom:14px">${tabs.map(([k, l]) => `<button class="${k === tab ? "on" : ""}" onclick="location.hash='#/tools/${esc(t.slug)}?tab=${k}'">${l}</button>`).join("")}</div>
      <div id="ttab"></div></section>
    <aside class="g" style="align-content:start">
      <section class="card panel"><h3>Acerca de</h3><p style="margin:0 0 10px;font-size:13.5px">${esc(t.description) || '<span class="muted">Sin descripción.</span>'}</p>
        <div style="margin-bottom:10px">${(t.tags || "").split(",").map(x => x.trim()).filter(Boolean).map(x => `<span class="pill info" style="margin:2px 2px 0 0">${esc(x)}</span>`).join("")}</div>
        <div style="font-size:13px;line-height:1.9">${ghURL ? `<div>🔗 <a class="go" href="${esc(ghURL)}" target="_blank" rel="noopener">${esc(ghURL.replace("https://github.com/", ""))}</a></div>` : ""}
          <div>👤 Responsable: <b>${esc(t.owner || "—")}</b></div><div>📄 ${t.files.length} archivos · ${fsize(t.files.reduce((a, f) => a + (f.size || 0), 0))}</div>
          <div class="muted">Actualizado por ${esc(t.updated_by || "—")} · ${esc(t.updated_at || "")}</div></div></section>
      <section class="card panel"><h3>Subir archivos</h3>
        <input type="file" multiple onchange="uploadToolFiles('${esc(t.slug)}', this.files)" style="font-size:13px">
        <label style="margin-top:8px;font-weight:400">o una carpeta completa:</label><input type="file" webkitdirectory multiple onchange="uploadToolFiles('${esc(t.slug)}', this.files)" style="font-size:13px">
        <div id="upT" class="muted" style="font-size:12.5px;margin-top:6px">Se calcula el SHA256 de cada archivo para verificar su integridad.</div>
        ${ghURL ? `<button class="btn sm" style="margin-top:10px" onclick="syncTool('${esc(t.slug)}',1,this)">⬇ Guardar copia local de GitHub</button>` : ""}</section>
    </aside></div>`);
  const T = $("ttab");
  if (sub === "file") return toolFileView(t, fid);
  if (tab === "readme") T.innerHTML = t.readme ? `<div class="md">${md(t.readme)}</div>` : `<div class="empty">Sin README. ${ghURL ? "Pulsa «Sincronizar» para traerlo de GitHub o " : ""}<a class="go" href="#/tools/${esc(t.slug)}/edit">escríbelo aquí</a>.</div>`;
  else if (tab === "usage") T.innerHTML = t.usage ? `<div class="md">${md(t.usage)}</div>` : `<div class="empty">Sin instrucciones de uso. <a class="go" href="#/tools/${esc(t.slug)}/edit">Añádelas</a>.</div>`;
  else if (tab === "audit") toolAuditTab(t);
  else if (tab === "metrics") toolMetricsTab(t);
  else if (tab === "log") T.innerHTML = t.log.length ? `<ul class="timeline">${t.log.map(e => `<li><div class="meta">${esc(e.at)} · ${esc(e.user)}</div>${esc(e.text)}</li>`).join("")}</ul>` : `<div class="empty">Sin cambios registrados.</div>`;
  else {
    const files = [...t.files].sort((a, b) => (a.path.includes("/") - b.path.includes("/")) || a.path.localeCompare(b.path));
    T.innerHTML = files.length ? `<table class="table"><thead><tr><th>Archivo</th><th class="n">Tamaño</th><th>Origen</th><th></th></tr></thead><tbody>
      ${files.map(f => { const dir = f.path.includes("/") ? f.path.slice(0, f.path.lastIndexOf("/") + 1) : "", name = f.path.slice(dir.length);
        return `<tr class="click" onclick="location.hash='#/tools/${esc(t.slug)}/file/${f.id}'"><td>📄 <span class="muted">${esc(dir)}</span><b>${esc(name)}</b></td><td class="n">${fsize(f.size)}</td>
        <td><span class="pill ${f.source === "github" ? "info" : "gray"}">${f.source === "github" ? "GitHub" : "Subido"}</span>${f.source === "github" && f.cached ? ' <span class="muted" title="Hay copia local en el portal">💾</span>' : ""}</td>
        <td style="text-align:right;white-space:nowrap" onclick="event.stopPropagation()"><a class="btn sm" href="api/tools/${esc(t.slug)}/files/${f.id}/download" title="Descargar">⬇</a>
          <button class="btn sm" onclick="delToolFile('${esc(t.slug)}',${f.id})" title="Quitar">✕</button></td></tr>`; }).join("")}</tbody></table>`
      : `<div class="empty">Sin archivos. Súbelos desde el panel de la derecha${ghURL ? " o sincroniza con GitHub" : ""}.</div>`;
  }
}

async function toolFileView(t, fid) {
  const T = $("ttab"); T.innerHTML = `<div class="skel"></div>`;
  let f;
  try { f = await api(`api/tools/${encodeURIComponent(t.slug)}/files/${fid}`); } catch (e) { T.innerHTML = unavailable(e.message); return; }
  window._codeText = f.text;
  T.innerHTML = `<div class="row" style="margin-bottom:10px"><div style="min-width:0"><a class="go" href="#/tools/${esc(t.slug)}?tab=files">${esc(t.name)}</a> / <b class="mono" style="word-break:break-all">${esc(f.path)}</b>
      <div class="muted" style="font-size:12px;margin-top:3px">${f.lines != null ? nf(f.lines) + " líneas · " : ""}${fsize(f.size)} · ${esc(f.lang)}${f.sha256 ? ` · SHA256 <span class="mono" title="${esc(f.sha256)}">${esc(f.sha256.slice(0, 16))}…</span>` : ""}</div></div>
    <span style="white-space:nowrap">${f.text != null ? `<button class="btn sm" onclick="navigator.clipboard.writeText(_codeText).then(()=>toast('Copiado'))">Copiar</button> ` : ""}
      <a class="btn sm" href="api/tools/${esc(t.slug)}/files/${f.id}/download">⬇ Descargar</a></span></div>
  ${f.text == null ? `<div class="empty">Archivo binario o demasiado grande para mostrarlo (más de 3 MB). Descárgalo para revisarlo.</div>`
    : f.lang === "markdown" ? `<div class="md card panel" style="box-shadow:none">${md(f.text)}</div>`
    : `<div class="code"><pre class="gut">${Array.from({length: f.lines}, (_, i) => i + 1).join("\n")}</pre><pre class="src">${highlight(f.text, f.lang)}</pre></div>`}`;
}

function uploadToolFiles(slug, files) {
  const list = [...files]; if (!list.length) return;
  let done = 0, fail = 0;
  const next = () => {
    if (!list.length) { toast(`${done} archivos subidos${fail ? `, ${fail} con error` : ""}`); router(); return; }
    const f = list.shift(), path = f.webkitRelativePath || f.name;
    $("upT").textContent = `Subiendo ${path}… (${done + fail + 1} de ${done + fail + list.length + 1})`;
    fetch(`api/tools/${encodeURIComponent(slug)}/files?path=${encodeURIComponent(path)}`, {method: "POST", body: f, headers: {"Content-Type": "application/octet-stream", "X-SOC": "1"}})
      .then(r => { r.ok ? done++ : fail++; next(); }).catch(() => { fail++; next(); });
  };
  next();
}
async function syncTool(slug, cache, btn) {
  btn.disabled = true; btn.textContent = "…";
  try { const r = await api(`api/tools/${encodeURIComponent(slug)}/github?cache=${cache}`, {method: "POST"});
    toast(cache ? `Copia local de ${r.copiados} archivos` : `Sincronizado: ${r.archivos} archivos (rama ${r.rama})`); }
  catch (e) { toast("Error: " + e.message); }
  router();
}
async function delToolFile(slug, fid) { if (!confirm("¿Quitar este archivo del repositorio interno?")) return; await api(`api/tools/${encodeURIComponent(slug)}/files/${fid}`, {method: "DELETE"}); router(); }

async function renderToolEdit(slug) {
  if (!TOOLS_META.categorias.length) TOOLS_META = await api("api/tools");
  const t = slug === "new" ? {status: "En evaluación", owner: META.user, category: TOOLS_META.categorias[0]} : await api("api/tools/" + encodeURIComponent(slug));
  view(`<div class="toolbar" style="margin-top:8px"><a class="btn sm" href="#/tools${slug === "new" ? "" : "/" + esc(slug)}">← Volver</a><span class="grow"></span>
      ${slug === "new" ? "" : `<button class="btn sm" onclick="delTool('${esc(slug)}')">Eliminar</button>`}<button class="btn sm primary" onclick="saveTool('${esc(slug)}')">Guardar</button></div>
  <section class="card panel"><form id="fT" class="form" onsubmit="return false">
    <div><label>Nombre *</label><input name="name" value="${esc(t.name || "")}" placeholder="p. ej. Crawler-Scanner"></div>
    <div><label>Repositorio (GitHub u otro)</label><input name="repo_url" value="${esc(t.repo_url || "")}" placeholder="https://github.com/usuario/repositorio"></div>
    <div><label>Categoría</label><select name="category">${opts(TOOLS_META.categorias, t.category)}</select></div>
    <div><label>Estado</label><select name="status">${opts(TOOLS_META.estados, t.status)}</select></div>
    <div><label>Plataforma</label><select name="platform">${opts(["", ...(TOOLS_META.plataformas || [])], t.platform || "")}</select></div>
    <div><label>Sitio oficial</label><input name="homepage" value="${esc(t.homepage || "")}" placeholder="https://…"></div>
    <div><label>Lenguaje</label><input name="language" value="${esc(t.language || "")}" placeholder="Python, PowerShell, Bash…"></div>
    <div><label>Versión</label><input name="version" value="${esc(t.version || "")}" placeholder="1.0"></div>
    <div><label>Licencia</label><input name="license" value="${esc(t.license || "")}" placeholder="MIT, GPL-3.0, interna…"></div>
    <div><label>Responsable</label><select name="owner">${opts([...new Set(["", t.owner || "", ...META.users])], t.owner || "")}</select></div>
    <div class="full"><label>Descripción corta</label><input name="description" value="${esc(t.description || "")}"></div>
    <div class="full"><label>Etiquetas (separadas por comas)</label><input name="tags" value="${esc(t.tags || "")}" placeholder="osint, tor, phishing"></div>
    <div class="full"><label style="display:flex;gap:6px;align-items:center;color:var(--ink)"><input type="checkbox" name="requires_auth" style="width:auto" ${t.requires_auth ? "checked" : ""}> Requiere autorización antes de usarla</label>
      <textarea name="auth_note" style="min-height:60px" placeholder="Quién autoriza, en qué casos se permite, restricciones (máquina aislada, alcance…)">${esc(t.auth_note || "")}</textarea></div>
    <div class="full editor"><div><label>Uso / instalación (Markdown)</label><textarea name="usage" oninput="$('tPrev').innerHTML=md(this.value)">${esc(t.usage || "")}</textarea></div>
      <div><label>Vista previa</label><div class="md card panel" id="tPrev" style="min-height:420px;overflow:auto;box-shadow:none">${md(t.usage || "")}</div></div></div>
    <div class="full"><label>README (Markdown · si está vacío y hay GitHub, se trae al sincronizar)</label><textarea name="readme" class="mono" style="min-height:200px">${esc(t.readme || "")}</textarea></div>
  </form></section>`);
}
async function saveTool(slug) {
  const body = {...formData("fT"), requires_auth: $("fT").requires_auth.checked};
  try { const t = await api("api/tools" + (slug === "new" ? "" : "/" + encodeURIComponent(slug)), {method: slug === "new" ? "POST" : "PUT", body});
    toast("Guardado"); location.hash = "#/tools/" + t.slug; }
  catch (e) { toast("Error: " + e.message); }
}
async function delTool(slug) { if (!confirm("¿Eliminar la herramienta y todos sus archivos del portal?")) return; await api("api/tools/" + encodeURIComponent(slug), {method: "DELETE"}); location.hash = "#/tools"; }

/* ======================================================================
   CONTACTOS
   ====================================================================== */
async function renderContacts() {
  const rows = await api("api/contacts");
  const row = (c = {}) => `<tr>${["role", "name", "phone", "email", "hours"].map(k => `<td><input data-k="${k}" value="${esc(c[k])}"></td>`).join("")}
    <td><button class="btn sm" onclick="this.closest('tr').remove()" title="Quitar fila">✕</button></td></tr>`;
  window._newRow = () => document.querySelector("#tC tbody").insertAdjacentHTML("beforeend", row());
  view(`<div class="toolbar" style="margin-top:6px"><div><h1 class="page" style="margin:0 4px">Contactos y guardias</h1><div class="sub" style="margin:0 4px">A quién llamar y cuándo</div></div>
    <span class="grow"></span><button class="btn" onclick="_newRow()">＋ Añadir fila</button><button class="btn primary" onclick="saveContacts()">Guardar</button></div>
  <section class="card" style="overflow-x:auto"><table class="table" id="tC"><thead><tr><th>Rol</th><th>Nombre</th><th>Teléfono</th><th>Correo</th><th>Horario</th><th></th></tr></thead>
    <tbody>${rows.map(row).join("")}</tbody></table></section>`);
}
async function saveContacts() {
  const rows = [...document.querySelectorAll("#tC tbody tr")].map(tr => { const o = {}; tr.querySelectorAll("input").forEach(i => o[i.dataset.k] = i.value); return o; });
  await api("api/contacts", {method: "PUT", body: rows}); toast("Contactos guardados");
}

/* ======================================================================
   VULNERABILIDADES: Wazuh (detección), seguimiento e importación de escáneres
   ====================================================================== */
const VST = {Open: "Abierta", Remediating: "En remediación", Mitigated: "Mitigada", Accepted: "Riesgo aceptado", Closed: "Cerrada"};
const VSTC = {Open: "bad", Remediating: "warn", Mitigated: "info", Accepted: "gray", Closed: ""};
const SEVC = {Critical: "var(--st-crit)", High: "var(--st-serious)", Medium: "var(--st-warn)", Low: "var(--s-neutral)"};
const normSev = v => ({critical: "Critical", high: "High", medium: "Medium", low: "Low"}[String(v || "").toLowerCase()] || v);
const nvd = c => c ? String(c).split(/,\s*/).map(x => `<a class="go mono" target="_blank" rel="noopener" href="https://nvd.nist.gov/vuln/detail/${esc(x)}">${esc(x)}</a>`).join(" ") : "";
const subnav = (base, cur, items) => `<div class="chips">${items.map(([v, t]) => `<button class="${v === cur ? "on" : ""}" onclick="location.hash='${base}?view=${v}'">${t}</button>`).join("")}</div>`;

async function renderVulns() {
  const q = qs(), v = q.get("view") || "wazuh";
  view(`<div class="toolbar" style="margin-top:6px"><div><h1 class="page" style="margin:0 4px">Vulnerabilidades</h1>
      <div class="sub" style="margin:0 4px">Detección automática de Wazuh, resultados de escáneres y registro manual, con seguimiento hasta su cierre.</div></div>
    <span class="grow"></span>${subnav("#/vulns", v, [["wazuh", "Detectadas por Wazuh"], ["track", "Seguimiento"], ["import", "Importar escáner"]])}
    <button class="btn primary sm" onclick="editVuln()">＋ Registrar</button></div><div id="vv"><div class="skel"></div></div>`);
  if (v === "track") return vulnTrack(q);
  if (v === "import") return vulnImport();
  return vulnWazuh(q);
}

async function vulnWazuh(q) {
  const sevF = q.get("severity") || "", ag = q.get("agent") || "", text = q.get("q") || "";
  let d;
  try { d = await api(`api/vulns/wazuh?severity=${sevF}&agent=${encodeURIComponent(ag)}&q=${encodeURIComponent(text)}`); }
  catch (e) { $("vv") && ($("vv").innerHTML = unavailable(e.message) + `<p class="muted" style="text-align:center;font-size:13px">Si dice 403, el rol <span class="mono">soc_bridge_read</span> del indexer necesita lectura sobre <span class="mono">wazuh-states-vulnerabilities-*</span>.</p>`); return; }
  if (!$("vv")) return;
  const S = Object.fromEntries(d.severidad.map(([k, n]) => [normSev(k), n]));
  window._vf = (k, val) => { const p = qs(); p.set("view", "wazuh"); val ? p.set(k, val) : p.delete(k); location.hash = "#/vulns?" + p; };
  $("vv").innerHTML = `
  <div class="kpis">
    ${kpi("Detecciones", short(d.total), d.fuente === "states" ? "inventario actual de Wazuh" : "alertas de los últimos 30 días")}
    ${kpi("CVE distintos", nf(d.cves_n))}${kpi("Equipos afectados", nf(d.agentes_n))}
    ${kpi("Críticas", nf(S.Critical), "detecciones", "javascript:_vf('severity','Critical')", (S.Critical || 0) > 0)}
    ${kpi("Altas", nf(S.High), "detecciones", "javascript:_vf('severity','High')")}
  </div>
  <div class="toolbar" style="margin-top:14px">
    <div class="chips">${[["", "Todas"], ["Critical", "Críticas"], ["High", "Altas"], ["Medium", "Medias"], ["Low", "Bajas"]].map(([k, t]) => `<button class="${k === sevF ? "on" : ""}" onclick="_vf('severity','${k}')">${t}</button>`).join("")}</div>
    ${ag ? `<span class="pill info">Equipo: ${esc(ag)} <a href="javascript:_vf('agent','')" title="Quitar filtro">✕</a></span>` : ""}
    <input style="flex:1;width:auto" placeholder="Buscar CVE o paquete… (Enter)" value="${esc(text)}" onkeydown="if(event.key==='Enter')_vf('q',this.value)"></div>
  <div class="g g3">
    ${box("Por severidad", `<div class="viz" id="dV"></div>`)}
    ${box("Equipos con más vulnerabilidades", hbars(d.agentes.map(([k, n]) => ({label: k, value: n, click: `_vf('agent', ${JSON.stringify(k)})`})), "Sin datos"), "pulsa para filtrar")}
    ${box("Paquetes más afectados", hbars(d.paquetes.map(([k, n]) => ({label: k, value: n, click: `_vf('q', ${JSON.stringify(k)})`})), "Sin datos"))}
  </div>
  <section class="card" style="margin-top:14px"><div class="scroll" style="max-height:620px"><table class="table"><thead><tr><th>CVE</th><th>Severidad</th><th class="n">CVSS</th><th>Paquete</th><th class="n">Equipos</th><th></th></tr></thead><tbody>
    ${d.cves.map(c => `<tr><td>${nvd(c.cve)}</td><td>${sev(normSev(c.sev))}</td><td class="n">${c.score != null ? (+c.score).toFixed(1) : "—"}</td>
      <td>${esc(c.paquetes.join(", "))}</td><td class="n"><b>${nf(c.agentes)}</b></td>
      <td style="white-space:nowrap;text-align:right"><button class="btn sm" onclick="vulnHosts(${esc(JSON.stringify(c.cve))})">Equipos</button>
        <button class="btn sm primary" onclick="trackCve(${esc(JSON.stringify(c.cve))}, ${esc(JSON.stringify(normSev(c.sev)))})">Seguir</button></td></tr>`).join("")
      || `<tr><td colspan="6" class="empty">Sin vulnerabilidades con estos filtros.</td></tr>`}</tbody></table></div></section>
  <p class="muted" style="font-size:12.5px;margin:8px 4px">Se muestran los 60 CVE con mayor puntuación. <b>Seguir</b> crea un registro en Seguimiento con todos los equipos afectados y fecha límite según la severidad.</p>`;
  donut("dV", ["Critical", "High", "Medium", "Low"].map(k => ({label: SEV[k], value: S[k] || 0, color: SEVC[k], click: `_vf('severity','${k}')`})), "detecciones");
}
async function vulnHosts(cve) {
  openModal(`<h2 style="margin:0 0 12px">${nvd(cve)} · equipos afectados</h2><div id="vh"><div class="skel"></div></div>`, true);
  try { const rows = await api("api/vulns/wazuh/" + encodeURIComponent(cve));
    $("vh").innerHTML = `${rows[0] && rows[0].description ? `<p class="muted" style="margin-top:0">${esc(rows[0].description).slice(0, 600)}</p>` : ""}
    <div class="scroll"><table class="table"><thead><tr><th>Equipo</th><th>Paquete</th><th>Versión</th><th>Severidad</th><th>Detectado</th></tr></thead><tbody>
    ${rows.map(r => `<tr><td><b>${esc(r.agent)}</b> <span class="muted mono">${esc(r.agent_id || "")}</span></td><td>${esc(r.package)}</td><td class="mono">${esc(r.version)}</td><td>${sev(normSev(r.severity))}</td><td>${fdt(r.date)}</td></tr>`).join("")}</tbody></table></div>
    <div style="text-align:right;margin-top:12px"><button class="btn primary" onclick="trackCve(${esc(JSON.stringify(cve))})">Pasar a seguimiento</button></div>`;
  } catch (e) { $("vh").innerHTML = unavailable(e.message); }
}
async function trackCve(cve, severity) {
  try { const r = await api("api/vulns/track", {method: "POST", body: {cve, severity}});
    closeModal(); toast(r.nuevo ? `${cve} en seguimiento` : `${cve} ya estaba en seguimiento; equipos actualizados`); }
  catch (e) { toast("Error: " + e.message); }
}

async function vulnTrack(q) {
  const status = q.get("status") ?? "active", sevF = q.get("severity") || "", src = q.get("source") || "", text = q.get("q") || "";
  const d = await api(`api/vulns?status=${status}&severity=${sevF}&source=${encodeURIComponent(src)}&q=${encodeURIComponent(text)}`);
  if (!$("vv")) return;
  window._VR = d.rows; const S = d.stats, today = d.today;
  window._tf = (k, val) => { const p = qs(); p.set("view", "track"); p.set(k, val); location.hash = "#/vulns?" + p; };
  $("vv").innerHTML = `
  <div class="kpis">
    ${kpi("Abiertas", nf(S.activas), `${nf(S.total)} registradas en total`)}
    ${kpi("Fecha límite vencida", nf(S.vencidas), "sin remediar a tiempo", "", S.vencidas > 0)}
    ${S.por_severidad.map(([k, n]) => kpi(SEV[k] + "s abiertas", nf(n), `plazo ${S.sla_dias[k]} días`, `javascript:_tf('severity','${k}')`, k === "Critical" && n > 0)).join("")}
  </div>
  <div class="g g3" style="margin-top:14px">
    ${box("Por estado", hbars(S.por_estado.map(([k, n]) => ({label: VST[k], value: n, click: `_tf('status','${k}')`}))))}
    ${box("Por origen", hbars(S.por_origen.map(([k, n]) => ({label: k, value: n, click: `_tf('source','${k}')`})), "Aún no hay registros"))}
    ${box("Plazos de remediación", `<ul class="hb">${Object.entries(S.sla_dias).map(([k, n]) => `<li><span class="lb">${sev(k)}</span><b>${n} días</b></li>`).join("")}</ul>
      <p class="muted" style="font-size:12.5px;margin:8px 0 0">Se calculan al registrar. Se cambian en <span class="mono">store.py</span> (VULN_SLA_DAYS).</p>`)}
  </div>
  <div class="toolbar" style="margin-top:14px">
    <select style="width:auto" onchange="_tf('status',this.value)">${[["active", "Activas (abiertas o en remediación)"], ["", "Todas"], ...Object.entries(VST)].map(([k, t]) => `<option value="${k}" ${k === status ? "selected" : ""}>${t}</option>`).join("")}</select>
    <select style="width:auto" onchange="_tf('severity',this.value)"><option value="">Todas las severidades</option>${opts(META.severities, sevF, SEV)}</select>
    <input style="flex:1;width:auto" placeholder="Buscar CVE, título, activo o paquete… (Enter)" value="${esc(text)}" onkeydown="if(event.key==='Enter')_tf('q',this.value)">
    <button class="btn" onclick="csvDownload('vulnerabilidades.csv', _VR, ['cve','title','severity','cvss','asset','package','port','status','owner','due_date','source','first_seen','last_seen'])">Exportar CSV</button></div>
  <section class="card">${d.rows.length ? `<div class="scroll" style="max-height:640px"><table class="table"><thead><tr><th>Vulnerabilidad</th><th>Severidad</th><th>Activo</th><th>Estado</th><th>Responsable</th><th>Fecha límite</th><th>Origen</th></tr></thead><tbody>
    ${d.rows.map(r => { const late = r.due_date && r.due_date < today && ["Open", "Remediating"].includes(r.status);
      return `<tr class="click" onclick="editVuln(${r.id})"><td><b>${esc(r.title)}</b><div>${nvd(r.cve)} ${r.cvss != null ? `<span class="muted">CVSS ${(+r.cvss).toFixed(1)}</span>` : ""}</div></td>
        <td>${sev(r.severity)}</td><td style="max-width:240px" title="${esc(r.asset)}">${esc(r.asset.length > 70 ? r.asset.slice(0, 70) + "…" : r.asset)}${r.port ? ` <span class="muted">:${esc(r.port)}</span>` : ""}</td>
        <td><span class="pill ${VSTC[r.status]}">${VST[r.status] || esc(r.status)}</span></td><td>${esc(r.owner) || '<span class="muted">—</span>'}</td>
        <td style="white-space:nowrap;${late ? "color:var(--bad);font-weight:700" : ""}">${esc(r.due_date || "—")}${late ? " ⚠" : ""}</td><td><span class="pill gray">${esc(r.source)}</span></td></tr>`; }).join("")}
  </tbody></table></div>` : `<div class="empty">No hay vulnerabilidades con estos filtros. Puedes pasarlas desde <a class="go" href="#/vulns?view=wazuh">Wazuh</a>, <a class="go" href="#/vulns?view=import">importar un escáner</a> o <a class="go" href="javascript:editVuln()">registrarlas a mano</a>.</div>`}</section>`;
}

async function editVuln(id) {
  const v = id ? (window._VR || []).find(r => r.id === id) : {severity: "High", status: "Open"};
  if (!v) return;
  openModal(`<h2 style="margin:0 0 16px">${id ? "Editar vulnerabilidad" : "Registrar vulnerabilidad"}</h2>
  <form id="fV" class="form" onsubmit="return saveVuln(event, ${id || 0})">
    <div><label>CVE</label><input name="cve" value="${esc(v.cve || "")}" placeholder="CVE-2024-3400"></div>
    <div><label>CVSS</label><input name="cvss" value="${esc(v.cvss ?? "")}" placeholder="9.8"></div>
    <div class="full"><label>Título *</label><input name="title" required value="${esc(v.title || "")}" placeholder="p. ej. Ejecución remota en PAN-OS GlobalProtect"></div>
    <div><label>Severidad</label><select name="severity">${opts(META.severities, v.severity, SEV)}</select></div>
    <div><label>Estado</label><select name="status">${opts(Object.keys(VST), v.status, VST)}</select></div>
    <div class="full"><label>Activos afectados</label><input name="asset" value="${esc(v.asset || "")}" placeholder="fw-perimetral, 10.0.0.9"></div>
    <div><label>Paquete / producto</label><input name="package" value="${esc(v.package || "")}"></div>
    <div><label>Puerto</label><input name="port" value="${esc(v.port || "")}"></div>
    <div><label>Responsable</label><select name="owner">${opts([...new Set(["", v.owner || "", ...META.users])], v.owner || "")}</select></div>
    <div><label>Fecha límite</label><input type="date" name="due_date" value="${esc(v.due_date || "")}"><div class="muted" style="font-size:12px;margin-top:3px">${id ? "" : "Vacía = según la severidad"}</div></div>
    <div class="full"><label>Solución</label><textarea name="solution" style="min-height:60px">${esc(v.solution || "")}</textarea></div>
    <div class="full"><label>Notas (avance, excepción, aceptación de riesgo…)</label><textarea name="notes" style="min-height:60px">${esc(v.notes || "")}</textarea></div>
    <div class="full row"><span>${id ? `<button type="button" class="btn sm" onclick="delVuln(${id})">Eliminar</button>
        <button type="button" class="btn sm" onclick="openNewIncident({title: ${esc(JSON.stringify("Vulnerabilidad: " + (v.cve || v.title)))}, assets: ${esc(JSON.stringify(v.asset || ""))}, runbook: 'vulnerabilidad-critica', severity: ${esc(JSON.stringify(v.severity))}})">＋ Incidente</button>` : ""}</span>
      <span><button type="button" class="btn" onclick="closeModal()">Cancelar</button> <button class="btn primary">Guardar</button></span></div>
  </form>`);
}
async function saveVuln(e, id) {
  e.preventDefault();
  try { await api("api/vulns" + (id ? "/" + id : ""), {method: id ? "PUT" : "POST", body: formData("fV")});
    closeModal(); toast("Guardado"); if (qs().get("view") === "track") router(); else location.hash = "#/vulns?view=track"; }
  catch (err) { toast("Error: " + err.message); }
  return false;
}
async function delVuln(id) { if (!confirm("¿Eliminar esta vulnerabilidad?")) return; await api("api/vulns/" + id, {method: "DELETE"}); closeModal(); router(); }

function vulnImport() {
  $("vv").innerHTML = `<div class="g g21">
    <section class="card panel"><h3>Importar resultados de un escáner</h3>
      <div class="form">
        <div><label>Escáner</label><select id="scn"><option value="nessus">Nessus / Tenable</option><option value="openvas">OpenVAS / Greenbone</option>
          <option value="qualys">Qualys</option><option value="pentest">Pentest / informe</option><option value="csv">Otro CSV</option></select></div>
        <div><label>Archivo CSV</label><input type="file" accept=".csv,.txt" onchange="readFileTo(this,'scanTxt')"></div>
        <div class="full"><label>…o pega el contenido</label><textarea id="scanTxt" class="mono" style="min-height:220px" placeholder="Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Solution&#10;..."></textarea></div>
        <div class="full row"><span class="muted" style="font-size:12.5px">Se omiten los hallazgos informativos. Reimportar el mismo escaneo actualiza en lugar de duplicar.</span>
          <span><button class="btn" onclick="importScan(true)">Vista previa</button> <button class="btn primary" onclick="importScan(false)">Importar</button></span></div>
      </div><div id="scanR"></div></section>
    ${box("Cómo exportar el CSV", `<div style="font-size:13.5px;line-height:1.6">
      <p style="margin-top:0"><b>Nessus:</b> abre el escaneo → <i>Report</i> → <i>CSV</i> → marca todas las columnas.</p>
      <p><b>OpenVAS / Greenbone:</b> <i>Scans → Reports</i> → abre el informe → descarga con el formato <i>CSV Results</i>.</p>
      <p><b>Qualys:</b> <i>Reports</i> → <i>Scan report</i> → formato CSV.</p>
      <p><b>Otro / pentest:</b> un CSV con cabeceras como <span class="mono">title, cve, severity, cvss, host, port, solution</span> (también en español: <span class="mono">título, severidad, activo, puerto, solución</span>).</p>
      <p class="muted" style="margin-bottom:0">El estado, el responsable y las notas que pongas en el portal se conservan al reimportar.</p></div>`)}
  </div>`;
}
function readFileTo(input, id) {
  const f = input.files[0]; if (!f) return;
  if (f.size > 15e6) { toast("Archivo demasiado grande (máx. 15 MB)"); return; }
  const r = new FileReader(); r.onload = () => { $(id).value = r.result; toast(`${f.name} cargado`); }; r.readAsText(f);
}
async function importScan(preview) {
  const text = $("scanTxt").value; if (!text.trim()) { toast("Pega o selecciona un CSV"); return; }
  $("scanR").innerHTML = `<div class="skel" style="height:80px;margin-top:14px"></div>`;
  try { const r = await api("api/vulns/import", {method: "POST", body: {text, scanner: $("scn").value, preview}});
    $("scanR").innerHTML = preview ? `<div style="margin-top:14px"><b>${nf(r.total)}</b> vulnerabilidades a importar · ${nf(r.omitidos)} omitidas (informativas)
      <div class="muted" style="font-size:12.5px;margin:6px 0">Columnas detectadas: ${Object.entries(r.columnas).map(([k, c]) => `<span class="pill gray">${k} ← ${esc(c)}</span>`).join(" ")}</div>
      <table class="table"><tbody>${r.muestra.map(x => `<tr><td>${sev(x.severity)}</td><td>${esc(x.title)} ${nvd(x.cve)}</td><td>${esc(x.asset)}${x.port ? ":" + esc(x.port) : ""}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="card panel" style="margin-top:14px;background:var(--ok-soft)"><b>Importación completada:</b> ${nf(r.nuevas)} nuevas · ${nf(r.actualizadas)} actualizadas · ${nf(r.omitidos)} omitidas.
         <a class="go" href="#/vulns?view=track">Ver seguimiento →</a></div>`;
  } catch (e) { $("scanR").innerHTML = `<div style="margin-top:14px">${unavailable(e.message)}</div>`; }
}
function csvDownload(name, rows, cols) {
  const q = v => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const blob = new Blob(["﻿" + [cols.join(","), ...rows.map(r => cols.map(c => q(r[c])).join(","))].join("\n")], {type: "text/csv"});
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

/* ======================================================================
   INTELIGENCIA DE AMENAZAS (IoC): fuentes, millones de IoC, correlación con Wazuh y MISP
   ====================================================================== */
const ITYPE = {ip: "IP", cidr: "Red", domain: "Dominio", url: "URL", md5: "MD5", sha1: "SHA1", sha256: "SHA256", email: "Correo"};
const TLPC = {red: "bad", amber: "warn", green: "", clear: "gray", white: "gray"};
const KIND = {feed: "Feed", misp: "MISP", manual: "Carga"};
const riskCls = s => s >= 80 ? "c" : s >= 50 ? "s" : s > 0 ? "w" : "n";
const risk = s => `<span class="lv ${riskCls(s)}" title="Puntuación de riesgo combinando la confianza de las fuentes">${s}</span>`;
const srcPills = f => (f || []).slice(0, 4).map(x => `<span class="pill ${x.weight >= 80 ? "bad" : x.weight >= 60 ? "warn" : "gray"}" title="Confianza ${x.weight}${x.ref ? " · " + esc(x.ref) : ""}${x.via && x.via !== x.value ? " · vía " + esc(x.via) : ""}">${esc(x.name)}</span>`).join(" ") + ((f || []).length > 4 ? ` <span class="muted">+${f.length - 4}</span>` : "");
let _jobTimer;

async function renderIocs() {
  clearTimeout(_jobTimer);
  const v = qs().get("view") || "resumen";
  view(`<div class="toolbar" style="margin-top:6px"><div><h1 class="page" style="margin:0 4px">Inteligencia de amenazas · IoC</h1>
      <div class="sub" style="margin:0 4px">Millones de indicadores de varias fuentes, cruzados automáticamente con las alertas de Wazuh y con MISP.</div></div>
    <span class="grow"></span>${subnav("#/iocs", v, [["resumen", "Resumen"], ["coincidencias", "Coincidencias"], ["comprobar", "Comprobar"], ["fuentes", "Fuentes"], ["cargar", "Cargar"], ["integrar", "Integrar"]])}</div>
    <div id="iv"><div class="skel"></div></div>`);
  try {
    if (v === "coincidencias") return await iocSightings();
    if (v === "comprobar") return iocCheckView();
    if (v === "fuentes") return await iocSources();
    if (v === "cargar") return iocLoadView();
    if (v === "integrar") return await iocIntegrate();
    return await iocOverview();
  } catch (e) { $("iv") && ($("iv").innerHTML = unavailable(e.message)); }
}

function jobsHtml(jobs) {
  if (!jobs.length) return `<div class="empty" style="padding:14px">Sin trabajos todavía.</div>`;
  const K = {feed: "Descarga", misp: "MISP", upload: "Archivo", retro: "Retrobúsqueda", delete: "Borrado"};
  return `<ul class="feed">${jobs.map(j => `<li><span class="pill ${j.status === "ok" ? "" : j.status === "error" ? "bad" : "warn"}">${j.status === "running" ? "⏳ En curso" : j.status === "ok" ? "Listo" : "Error"}</span>
    <div><b>${K[j.kind] || esc(j.kind)}</b> ${esc(j.source || "")}<div class="muted" style="font-size:12px">${j.status === "running" ? `${nf(j.done)} procesados…` : esc(j.msg)}</div></div>
    <span class="muted" style="font-size:12px;white-space:nowrap">${esc((j.finished || j.started || "").slice(5))}</span></li>`).join("")}</ul>`;
}
function watchJobs(el) {
  clearTimeout(_jobTimer);
  const tick = async () => {
    if (!$(el)) return;
    const r = await api("api/intel/jobs").catch(() => null); if (!r || !$(el)) return;
    $(el).innerHTML = jobsHtml(r.jobs.slice(0, 8));
    if (r.jobs.some(j => j.status === "running") || r.cola) _jobTimer = setTimeout(tick, 3000);
  };
  tick();
}

async function iocOverview() {
  const d = await api("api/intel/overview"); if (!$("iv")) return;
  const on = d.fuentes.filter(f => f.enabled), recent = await api("api/intel/sightings?days=7").catch(() => []);
  $("iv").innerHTML = `
  <div class="kpis">
    ${kpi("IoC en la base", short(d.unicos), `${nf(on.length)} fuentes activas`)}
    ${kpi("En varias fuentes", short(d.multi), "más confianza (coinciden ≥ 2)")}
    ${kpi("Coincidencias 24 h", nf(d.coincidencias_24h), "IoC vistos en alertas de Wazuh", "#/iocs?view=coincidencias&days=1", d.coincidencias_24h > 0)}
    ${kpi("IoC vistos · 7 días", nf(d.iocs_vistos_7d), `${nf(d.equipos_7d)} equipos afectados`, "#/iocs?view=coincidencias", d.iocs_vistos_7d > 0)}
    ${kpi("Correlación con Wazuh", d.correlacion ? "Activa" : "—", d.correlacion ? `cada 5 min · última ${esc(d.correlacion.slice(11))}` : "esperando la primera ventana")}
  </div>
  ${!d.fuentes.length ? `<section class="card panel" style="margin-top:14px;background:var(--brand-soft)"><h3>Empieza añadiendo fuentes</h3>
    <p style="margin:0 0 10px">Activa feeds públicos de inteligencia (abuse.ch, Spamhaus, Emerging Threats…) y tu MISP, o carga tus propias listas.</p>
    <a class="btn primary" href="#/iocs?view=fuentes">Añadir fuentes →</a> <a class="btn" href="#/iocs?view=cargar">Cargar una lista</a></section>` : ""}
  <div class="g g3" style="margin-top:14px">
    ${box("IoC por tipo", `<div class="viz" id="dT"></div>`)}
    ${box("IoC por fuente", rank(d.fuentes.filter(f => f.n).map(f => ({label: f.name, value: f.n, sub: `${KIND[f.kind] || f.kind} · confianza ${f.weight}`,
      click: `location.hash='#/iocs?view=fuentes'`})), d.fuentes.reduce((a, f) => a + (f.n || 0), 0), "Sin fuentes con datos", 6))}
    ${box("Trabajos", `<div id="jobs">${jobsHtml(d.jobs)}</div>`, `<a class="go" href="javascript:retro()">Retrobúsqueda →</a>`)}
  </div>
  <div class="g g21" style="margin-top:14px">
    ${box("Últimas coincidencias con Wazuh", recent.length ? `<ul class="feed">${recent.slice(0, 8).map(x => `<li>${risk(x.score)}
      <div style="cursor:pointer" onclick="iocDetail(${esc(JSON.stringify(x.value))})"><span class="mono">${esc(x.value)}</span> ${srcPills(x.fuentes)}
        <div class="muted" style="font-size:12px">${x.agents.slice(0, 3).map(([a, n]) => esc(a) + " (" + nf(n) + ")").join(", ")} · ${esc(x.rule)}</div></div>
      <span class="muted" style="font-size:12px;white-space:nowrap">${esc(x.last_seen.slice(5, 16))}</span></li>`).join("")}</ul>`
      : `<div class="empty">Sin coincidencias en 7 días. ${d.fuentes.length ? "La correlación revisa las alertas nuevas cada 5 minutos." : ""}</div>`, `<a class="go" href="#/iocs?view=coincidencias">Ver todas →</a>`)}
    ${box("Solapamiento entre fuentes", `<div id="ovl"><div class="skel" style="height:140px"></div></div>`, "IoC compartidos")}
  </div>
  <p class="muted" style="font-size:12.5px;margin:10px 4px">${esc(d.correlacion_msg || "")}</p>`;
  donut("dT", d.por_tipo.map(([k, n], i) => ({label: ITYPE[k] || k, value: n, color: ["var(--s1)", "var(--s2)", "#1baf7a", "#eda100", "#e87ba4", "#6250d6", "#008300", "#98a2b3"][i % 8]})), "IoC");
  if (d.jobs.some(j => j.status === "running")) watchJobs("jobs");
  api("api/intel/overlap").then(o => {
    if (!$("ovl")) return;
    if (o.fuentes.length < 2) { $("ovl").innerHTML = `<div class="empty" style="padding:14px">Necesitas al menos dos fuentes con datos.</div>`; return; }
    const M = {}; o.pares.forEach(([x, y, n]) => { M[x + "-" + y] = n; M[y + "-" + x] = n; });
    const mx = Math.max(1, ...o.pares.map(p => p[2])), F = o.fuentes.slice(0, 8);
    const col = n => n ? `var(--q${Math.min(7, 1 + Math.floor(Math.sqrt(n / mx) * 6.99))})` : "var(--grid)";
    $("ovl").innerHTML = `<div class="scroll"><table class="table" style="font-size:12px"><thead><tr><th></th>${F.map((f, i) => `<th title="${esc(f.name)}">${i + 1}</th>`).join("")}</tr></thead><tbody>
      ${F.map((a, i) => `<tr><td style="white-space:nowrap;max-width:190px;overflow:hidden;text-overflow:ellipsis" title="${esc(a.name)}"><b>${i + 1}</b> ${esc(a.name)}</td>${F.map(b => a.id === b.id ? `<td style="background:var(--grid)"></td>`
        : `<td style="background:${col(M[a.id + "-" + b.id])};text-align:center;${(M[a.id + "-" + b.id] || 0) / mx > .25 ? "color:#fff;font-weight:600" : ""}" data-tip="${esc(`<b>${nf(M[a.id + "-" + b.id] || 0)}</b> IoC en común<br>${esc(a.name)}<br>${esc(b.name)}`)}">${M[a.id + "-" + b.id] ? short(M[a.id + "-" + b.id]) : ""}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  }).catch(() => { $("ovl") && ($("ovl").innerHTML = `<div class="empty">No disponible</div>`); });
}

async function retro() {
  const days = prompt("¿Cuántos días hacia atrás revisar en las alertas de Wazuh? (1-90)", "7"); if (!days) return;
  const r = await api("api/intel/retro", {method: "POST", body: {days: +days}}).catch(e => ({error: e.message}));
  toast(r.error ? "Error: " + r.error : r.encolado ? `Retrobúsqueda de ${days} días en marcha` : "Ya hay una retrobúsqueda en curso");
  if ($("jobs")) watchJobs("jobs");
}

async function iocSightings() {
  const q = qs(), days = +(q.get("days") || 7), ms = +(q.get("min") || 0), text = q.get("q") || "";
  const rows = await api(`api/intel/sightings?days=${days}&min_score=${ms}&q=${encodeURIComponent(text)}`); if (!$("iv")) return;
  window._sf = (k, val) => { const p = qs(); p.set("view", "coincidencias"); p.set(k, val); location.hash = "#/iocs?" + p; };
  window._SR = rows;
  $("iv").innerHTML = `<div class="toolbar">
      <div class="chips">${[[1, "24 h"], [7, "7 días"], [30, "30 días"], [90, "90 días"]].map(([k, t]) => `<button class="${k === days ? "on" : ""}" onclick="_sf('days',${k})">${t}</button>`).join("")}</div>
      <div class="chips">${[[0, "Todo riesgo"], [50, "≥ 50"], [80, "Alto ≥ 80"]].map(([k, t]) => `<button class="${k === ms ? "on" : ""}" onclick="_sf('min',${k})">${t}</button>`).join("")}</div>
      <input style="flex:1;width:auto" placeholder="Buscar IoC, equipo o regla… (Enter)" value="${esc(text)}" onkeydown="if(event.key==='Enter')_sf('q',this.value)">
      <button class="btn" onclick="retro()">Retrobúsqueda</button>
      <button class="btn" onclick="csvDownload('coincidencias.csv', _SR.map(x => ({...x, fuentes: x.fuentes.map(f => f.name).join(' | '), agents: x.agents.map(a => a[0]).join(' | ')})), ['value','type','score','fuentes','agents','n','first_seen','last_seen','rule'])">Exportar CSV</button></div>
  <section class="card">${rows.length ? `<div class="scroll" style="max-height:680px"><table class="table"><thead><tr><th>Riesgo</th><th>Indicador visto</th><th>Fuentes</th><th>Equipos</th><th class="n">Alertas</th><th>Última vez</th><th></th></tr></thead><tbody>
    ${rows.map(x => `<tr><td>${risk(x.score)}</td>
      <td><span class="mono" style="word-break:break-all">${esc(x.value)}</span> <span class="pill gray">${ITYPE[x.type] || esc(x.type)}</span>
        <div class="muted" style="font-size:12px">${esc(x.rule)}${x.matched && x.matched !== x.value ? ` · coincide con <span class="mono">${esc(x.matched)}</span>` : ""}</div></td>
      <td>${srcPills(x.fuentes)}</td><td style="font-size:13px">${x.agents.slice(0, 3).map(([a, n]) => `<div>${esc(a)} <span class="muted">${nf(n)}</span></div>`).join("")}${x.agents.length > 3 ? `<span class="muted">+${x.agents.length - 3} más</span>` : ""}</td>
      <td class="n"><b>${nf(x.n)}</b></td><td style="white-space:nowrap;font-size:13px">${esc(x.last_seen.slice(0, 16))}<div class="muted" style="font-size:11.5px">desde ${esc(x.first_seen.slice(5, 16))}</div></td>
      <td style="white-space:nowrap"><button class="btn sm" onclick="iocDetail(${esc(JSON.stringify(x.value))})">Detalle</button>
        ${x.fields.includes("data.srcip") ? `<button class="btn sm" onclick="drill('data.srcip', ${esc(JSON.stringify(x.value))})">Alertas</button>` : ""}
        <button class="btn sm primary" onclick="openNewIncident({title: ${esc(JSON.stringify("IoC visto en Wazuh: " + x.value))}, iocs: ${esc(JSON.stringify(x.value))}, assets: ${esc(JSON.stringify(x.agents.map(a => a[0]).join(", ")))}, detected_by: 'Motor de inteligencia', runbook: 'misp-ioc-match', severity: ${esc(JSON.stringify(x.score >= 90 ? "Critical" : "High"))}})">＋</button></td></tr>`).join("")}
  </tbody></table></div>` : `<div class="empty">Ningún IoC de tus fuentes aparece en las alertas de Wazuh en este periodo. Prueba una <a class="go" href="javascript:retro()">retrobúsqueda</a> tras cargar fuentes nuevas.</div>`}</section>
  <p class="muted" style="font-size:12.5px;margin:8px 4px">Campos revisados: IPs de origen y destino (también Sysmon, AWS y Office 365), consultas DNS, URLs y hashes de FIM y VirusTotal. Un subdominio coincide con su dominio padre; una IP coincide con las redes CIDR (p. ej. Spamhaus).</p>`;
}

function iocCheckView() {
  $("iv").innerHTML = `<div class="g g21">
    <section class="card panel"><h3>Comprobar indicadores <small>hasta 1000 a la vez</small></h3>
      <textarea id="chkTxt" class="mono" style="min-height:160px" placeholder="Pega IPs, dominios, URLs o hashes (también el texto de un aviso)…"></textarea>
      <div class="row" style="margin-top:10px"><span class="muted" style="font-size:12.5px">Se busca en todas tus fuentes, en las alertas de Wazuh (30 días) y en MISP, en una sola consulta.</span>
        <button class="btn primary" onclick="bulkCheck()">Comprobar</button></div><div id="chkR"></div></section>
    <section class="card panel"><h3>Análisis a fondo de un indicador</h3>
      <form class="search" onsubmit="iocDetail(this.v.value.trim());return false"><input name="v" placeholder="185.220.101.1 · malo.xyz · hash…"><button class="btn primary">Analizar</button></form>
      <p class="muted" style="font-size:12.5px">Añade enriquecimiento externo: Shodan InternetDB (gratis) y, si configuras sus claves, AbuseIPDB, VirusTotal, AlienVault OTX y ThreatFox.</p></section>
  </div>`;
}
async function bulkCheck() {
  const t = $("chkTxt").value; if (!t.trim()) return;
  $("chkR").innerHTML = `<div class="skel" style="height:100px;margin-top:12px"></div>`;
  try { const r = await api("api/intel/check", {method: "POST", body: {text: t}}), rows = r.resultados;
    rows.sort((a, b) => b.score - a.score || (b.wazuh || 0) - (a.wazuh || 0)); window._CR = rows;
    const bad = rows.filter(x => x.score || x.wazuh || (x.misp || []).length).length;
    $("chkR").innerHTML = `<div class="row" style="margin:14px 0 8px"><b>${nf(rows.length)} indicadores · <span style="color:${bad ? "var(--bad)" : "var(--ok)"}">${nf(bad)} con coincidencias</span></b>
      <button class="btn sm" onclick="csvDownload('comprobacion.csv', _CR.map(x => ({...x, fuentes: x.fuentes.map(f => f.name).join(' | '), misp: (x.misp || []).join(' ')})), ['value','type','score','fuentes','wazuh','misp','sightings'])">Exportar CSV</button></div>
      <div class="scroll" style="max-height:520px"><table class="table"><thead><tr><th>Riesgo</th><th>Indicador</th><th>Fuentes</th><th class="n">Wazuh 30 d</th><th>MISP</th><th></th></tr></thead><tbody>
      ${rows.map(x => `<tr><td>${risk(x.score)}</td><td class="mono" style="word-break:break-all">${esc(x.value)} <span class="pill gray">${ITYPE[x.type] || x.type}</span></td>
        <td>${srcPills(x.fuentes) || '<span class="muted">—</span>'}</td><td class="n">${x.wazuh == null ? "?" : x.wazuh ? `<b style="color:var(--bad)">${nf(x.wazuh)}</b>` : "0"}</td>
        <td>${x.misp == null ? "?" : x.misp.length ? x.misp.slice(0, 3).map(e => `<a class="go" target="_blank" href="${esc(META.links.misp)}/events/view/${esc(e)}">#${esc(e)}</a>`).join(" ") : "—"}</td>
        <td><button class="btn sm" onclick="iocDetail(${esc(JSON.stringify(x.value))})">Detalle</button></td></tr>`).join("")}</tbody></table></div>`;
  } catch (e) { $("chkR").innerHTML = `<div style="margin-top:12px">${unavailable(e.message)}</div>`; }
}
async function iocDetail(v) {
  if (!v) return;
  openModal(`<h2 style="margin:0 0 4px">Análisis de <span class="mono" style="font-size:16px;word-break:break-all">${esc(v)}</span></h2>
    <p class="muted" style="margin:0 0 12px;display:flex;justify-content:space-between;gap:10px;align-items:center">Fuentes locales, Wazuh, MISP y servicios externos
      <button class="btn sm primary" onclick='closeModal();investigate(${esc(JSON.stringify("IoC " + v))}, "", ${esc(JSON.stringify(`Investiga el indicador ${v}: en qué fuentes aparece, qué hizo en nuestra red, qué equipos tocó y si hay que abrir un incidente.`))})'>🤖 Investigar con IA</button></p><div id="idt"><div class="skel"></div></div>`, true);
  try { const x = await api("api/intel/lookup?deep=1&v=" + encodeURIComponent(v));
    const E = x.enriquecimiento || [], vc = s => ({malicioso: "bad", sospechoso: "warn", vulnerable: "warn", limpio: "", error: "gray"}[s] || "gray");
    $("idt").innerHTML = `<div class="g g4" style="gap:10px">
        ${kpi("Riesgo", `${risk(x.score)}`, x.score >= 80 ? "Alto" : x.score >= 50 ? "Medio" : x.score ? "Bajo" : "Sin datos en tus fuentes")}
        ${kpi("Fuentes", nf(x.fuentes.length), x.fuentes.map(f => esc(f.name)).join(", ").slice(0, 70) || "—")}
        ${kpi("Wazuh · 30 días", x.wazuh == null ? "?" : nf(x.wazuh), "alertas que lo contienen", "", x.wazuh > 0)}
        ${kpi("MISP", nf((x.misp || []).length), "eventos", "", (x.misp || []).length > 0)}</div>
      <div class="g g2" style="margin-top:12px">
        <div><h3>Fuentes</h3>${x.fuentes.length ? `<table class="table"><tbody>${x.fuentes.map(f => `<tr><td><b>${esc(f.name)}</b>${f.ref ? `<div class="muted" style="font-size:12px">${esc(f.ref)}</div>` : ""}${f.via !== x.value ? `<div class="muted" style="font-size:12px">vía ${esc(f.via)}</div>` : ""}</td><td class="n">confianza ${f.weight}</td></tr>`).join("")}</tbody></table>` : `<div class="muted">No está en ninguna fuente.</div>`}
          <h3 style="margin-top:14px">Visto en</h3>${(x.sightings_detalle || []).length ? x.sightings_detalle.map(s => s.agents.map(([a, n]) => `<div style="font-size:13px;padding:4px 0">🖥 <b>${esc(a)}</b> · ${nf(n)} alertas <span class="muted">· ${esc(s.last_seen.slice(0, 16))}</span></div>`).join("")).join("") : `<div class="muted" style="font-size:13px">Sin coincidencias registradas.</div>`}
          ${(x.misp || []).length ? `<h3 style="margin-top:14px">MISP</h3>${x.misp.map(e => `<a class="pill info" target="_blank" href="${esc(META.links.misp)}/events/view/${esc(e)}">Evento #${esc(e)}</a>`).join(" ")}` : ""}</div>
        <div><h3>Servicios externos</h3>${E.length ? E.map(e => `<div class="card" style="padding:10px 12px;margin-bottom:8px;box-shadow:none"><div class="row"><b>${esc(e.provider)}</b><span class="pill ${vc(e.verdict)}">${esc(e.verdict)}${e.score != null ? " · " + e.score : ""}</span></div>
            <div class="muted mono" style="font-size:11.5px;margin-top:4px;word-break:break-word">${Object.entries(e.data || {}).filter(([, val]) => val != null && val !== "" && !(Array.isArray(val) && !val.length)).map(([k, val]) => `${esc(k)}: ${esc(Array.isArray(val) ? val.join(", ") : typeof val === "object" ? JSON.stringify(val) : val)}`).join("<br>")}</div></div>`).join("")
          : `<div class="muted" style="font-size:13px">No hay servicios aplicables a este tipo. Configura claves en <a class="go" href="#/iocs?view=integrar" onclick="closeModal()">Integrar</a>.</div>`}</div></div>
      <div class="row" style="margin-top:14px"><span></span><span><a class="btn sm" href="#/intel?q=${encodeURIComponent(x.value)}" onclick="closeModal()">Buscar en el portal</a>
        <button class="btn sm primary" onclick="openNewIncident({title: ${esc(JSON.stringify("IoC: " + x.value))}, iocs: ${esc(JSON.stringify(x.value))}, detected_by: 'Motor de inteligencia', runbook: 'misp-ioc-match'})">＋ Crear incidente</button></span></div>`;
  } catch (e) { $("idt").innerHTML = unavailable(e.message); }
}

async function iocSources() {
  const [src, cat] = await Promise.all([api("api/intel/sources"), api("api/intel/catalog")]); if (!$("iv")) return;
  window._SRC = src;
  $("iv").innerHTML = `
  <section class="card panel"><div class="row"><h3 style="margin:0">Fuentes configuradas <small>${src.length}</small></h3>
    <span><button class="btn sm" onclick="editSource(0,'misp')">＋ Mi MISP</button> <button class="btn sm primary" onclick="editSource(0,'feed')">＋ Feed por URL</button></span></div>
  ${src.length ? `<div class="scroll" style="margin-top:10px"><table class="table"><thead><tr><th>Fuente</th><th>Tipo</th><th class="n">Confianza</th><th class="n">IoC</th><th>Actualiza</th><th>Última ejecución</th><th></th></tr></thead><tbody>
    ${src.map(s => `<tr style="${s.enabled ? "" : "opacity:.55"}"><td><b>${esc(s.name)}</b>${s.url ? `<div class="muted mono" style="font-size:11px;max-width:330px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(s.url)}</div>` : ""}</td>
      <td><span class="pill ${s.kind === "misp" ? "info" : s.kind === "feed" ? "" : "gray"}">${KIND[s.kind] || esc(s.kind)}</span> <span class="pill ${TLPC[s.tlp] ?? "gray"}">TLP:${esc(String(s.tlp).toUpperCase())}</span></td>
      <td class="n"><b>${s.weight}</b></td><td class="n"><b>${short(s.n || 0)}</b>${s.last_added ? `<div class="muted" style="font-size:11.5px">+${short(s.last_added)}</div>` : ""}</td>
      <td style="font-size:13px">${s.kind === "manual" ? "—" : `cada ${s.interval_h} h`}<div class="muted" style="font-size:11.5px">${s.retention_days ? `caduca a los ${s.retention_days} d` : "no caduca"}</div></td>
      <td style="font-size:12.5px;max-width:260px">${esc(s.last_run || "pendiente")}<div class="${String(s.last_status).startsWith("Error") ? "err" : "muted"}" style="font-size:12px">${esc(s.last_status)}</div></td>
      <td style="white-space:nowrap">${s.kind !== "manual" ? `<button class="btn sm" onclick="runSource(${s.id})" title="Actualizar ahora">↻</button>` : ""}
        <button class="btn sm" onclick="editSource(${s.id})">Editar</button> <button class="btn sm" onclick="delSource(${s.id})" title="Eliminar la fuente y sus IoC">✕</button></td></tr>`).join("")}</tbody></table></div>`
    : `<div class="empty">Aún no hay fuentes. Elige feeds del catálogo de abajo o conecta tu MISP.</div>`}</section>
  <section class="card panel" style="margin-top:14px"><div class="row"><h3 style="margin:0">Catálogo de feeds públicos</h3><button class="btn primary sm" onclick="addCatalog()">Añadir seleccionados</button></div>
    <p class="muted" style="font-size:12.5px;margin:6px 0 10px">Feeds gratuitos y reconocidos. La <b>confianza</b> (1-100) pesa en la puntuación de riesgo: un IoC que está en varias fuentes fiables puntúa alto. Revisa las condiciones de uso de cada proveedor.</p>
    <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px">${cat.map(c => `<label class="card" style="padding:12px;display:flex;gap:10px;align-items:flex-start;box-shadow:none;margin:0;color:var(--ink);cursor:pointer;${c.added ? "opacity:.55" : ""}">
      <input type="checkbox" class="catk" value="${esc(c.key)}" style="width:auto;margin-top:3px" ${c.added ? "disabled checked" : ""}>
      <span><b style="font-size:13.5px">${esc(c.name)}</b><div class="muted" style="font-size:12px;font-weight:400">${ITYPE[c.ioc_type] || "Varios"} · confianza ${c.weight} · cada ${c.interval_h} h${c.added ? " · ya añadida" : ""}</div></span></label>`).join("")}</div></section>
  <section class="card panel" style="margin-top:14px"><h3>Trabajos recientes</h3><div id="jobs"></div></section>`;
  watchJobs("jobs");
}
async function addCatalog() {
  const keys = [...document.querySelectorAll(".catk:checked:not(:disabled)")].map(x => x.value); if (!keys.length) { toast("Marca algún feed"); return; }
  await api("api/intel/catalog", {method: "POST", body: {keys}}); toast(`${keys.length} fuentes añadidas; descargando…`); router();
}
async function runSource(id) { await api(`api/intel/sources/${id}/run`, {method: "POST"}); toast("Actualización en cola"); watchJobs("jobs"); }
async function delSource(id) { if (!confirm("¿Eliminar la fuente y todos sus IoC?")) return; await api("api/intel/sources/" + id, {method: "DELETE"}); toast("Eliminando en segundo plano"); router(); }
function editSource(id, kind) {
  const s = id ? _SRC.find(x => x.id === id) : {kind, weight: kind === "misp" ? 90 : 70, interval_h: kind === "misp" ? 6 : 12, retention_days: kind === "misp" ? 90 : 30, fmt: "lines", ioc_type: "auto", tlp: "amber", enabled: 1, csv_col: 0,
    name: kind === "misp" ? "MISP ACME" : "", url: ""};
  const isMisp = s.kind === "misp";
  openModal(`<h2 style="margin:0 0 16px">${id ? "Editar fuente" : isMisp ? "Conectar mi MISP" : "Nuevo feed por URL"}</h2>
  <form id="fSrc" class="form" onsubmit="return saveSource(event, ${id || 0}, '${s.kind}')">
    <div class="full"><label>Nombre *</label><input name="name" required value="${esc(s.name)}"></div>
    ${s.kind === "feed" ? `<div class="full"><label>URL del feed *</label><input name="url" value="${esc(s.url)}" placeholder="https://…/lista.txt (también .gz)"></div>
      <div><label>Formato</label><select name="fmt"><option value="lines" ${s.fmt === "lines" ? "selected" : ""}>Un IoC por línea</option><option value="csv" ${s.fmt === "csv" ? "selected" : ""}>CSV (elige columna)</option></select></div>
      <div><label>Tipo de IoC</label><select name="ioc_type">${[["auto", "Detectar solo"], ...Object.entries(ITYPE)].map(([k, t]) => `<option value="${k}" ${s.ioc_type === k ? "selected" : ""}>${t}</option>`).join("")}</select></div>
      <div><label>Columna del IoC (CSV, empieza en 0)</label><input name="csv_col" value="${esc(s.csv_col ?? 0)}"></div>
      <div><label>Columna de referencia (opcional)</label><input name="ref_col" value="${esc(s.ref_col ?? "")}" placeholder="p. ej. familia de malware"></div>
      <div class="full"><label>Cabecera de autenticación (opcional)</label><input name="auth_header" value="${esc(s.auth_header || "")}" placeholder="Auth-Key: tu_clave   ·   Authorization: Bearer …"></div>`
    : isMisp ? `<div class="full muted" style="font-size:13px">Descarga los atributos marcados para detección (to_ids) de tu MISP de los últimos días indicados en «Caducidad». Usa la conexión ya configurada en el portal.</div>` : ""}
    <div><label>Confianza (1-100)</label><input name="weight" type="number" min="1" max="100" value="${esc(s.weight)}"></div>
    ${s.kind !== "manual" ? `<div><label>Actualizar cada (horas)</label><input name="interval_h" type="number" step="0.5" min="0.5" value="${esc(s.interval_h)}"></div>` : "<div></div>"}
    <div><label>Caducidad (días sin aparecer${isMisp ? " · ventana de MISP" : ""})</label><input name="retention_days" type="number" min="0" value="${esc(s.retention_days ?? 0)}"><div class="muted" style="font-size:11.5px">0 = no caduca</div></div>
    <div><label>TLP</label><select name="tlp">${["clear", "green", "amber", "red"].map(t => `<option value="${t}" ${s.tlp === t ? "selected" : ""}>TLP:${t.toUpperCase()}</option>`).join("")}</select></div>
    <div class="full"><label style="display:flex;gap:6px;align-items:center;color:var(--ink)"><input type="checkbox" name="enabled" style="width:auto" ${s.enabled ? "checked" : ""}> Activa (se usa para correlacionar)</label></div>
    <div class="full" style="text-align:right"><button type="button" class="btn" onclick="closeModal()">Cancelar</button> <button class="btn primary">${id ? "Guardar" : "Añadir y descargar"}</button></div>
  </form>`);
}
async function saveSource(e, id, kind) {
  e.preventDefault();
  const body = {...formData("fSrc"), enabled: $("fSrc").enabled.checked, kind};
  try { await api("api/intel/sources" + (id ? "/" + id : ""), {method: id ? "PUT" : "POST", body}); closeModal(); toast("Guardado"); router(); }
  catch (err) { toast("Error: " + err.message); }
  return false;
}

function iocLoadView() {
  $("iv").innerHTML = `<div class="g g2">
  <section class="card panel"><h3>Archivo grande <small>TXT, CSV o .gz · hasta millones de IoC</small></h3>
    <form id="fUp" class="form" onsubmit="return uploadIocs(event)">
      <div class="full"><label>Archivo *</label><input type="file" name="file" required accept=".txt,.csv,.gz,.log,.lst"></div>
      <div><label>Nombre de la fuente *</label><input name="name" required placeholder="p. ej. Lista CSIRT nacional 2026"></div>
      <div><label>Confianza (1-100)</label><input name="weight" type="number" min="1" max="100" value="70"></div>
      <div><label>Tipo de IoC</label><select name="ioc_type"><option value="auto">Detectar solo</option>${Object.entries(ITYPE).map(([k, t]) => `<option value="${k}">${t}</option>`).join("")}</select></div>
      <div><label>De cada línea tomar</label><select name="mode"><option value="first">El primer indicador</option><option value="all">Todos los indicadores</option></select></div>
      <div><label>Caduca</label><select name="expires_days"><option value="0">Nunca</option><option value="30">30 días</option><option value="90" selected>90 días</option><option value="365">1 año</option></select></div>
      <div><label>TLP</label><select name="tlp"><option value="clear">CLEAR</option><option value="green">GREEN</option><option value="amber" selected>AMBER</option><option value="red">RED</option></select></div>
      <div class="full"><label>Retrobúsqueda en Wazuh al terminar</label><select name="retro"><option value="0">No</option><option value="1">Último día</option><option value="7" selected>Últimos 7 días</option><option value="30">Últimos 30 días</option></select></div>
      <div class="full"><div class="bar" id="upBar" style="height:8px;border-radius:6px;background:var(--grid);overflow:hidden;display:none"><i style="display:block;height:100%;width:0;background:var(--s1)"></i></div><div id="upMsg" class="muted" style="font-size:12.5px;margin-top:6px"></div></div>
      <div class="full" style="text-align:right"><button class="btn primary">Subir y cargar</button></div></form>
    <p class="muted" style="font-size:12.5px;margin-bottom:0">Ritmo aproximado: 1 millón de IoC cada 30 s. Los IoC repetidos solo actualizan su fecha. Para enviar a MISP listas de este tamaño, usa el feed de la pestaña <a class="go" href="#/iocs?view=integrar">Integrar</a> en vez de crear un evento.</p></section>
  <section class="card panel"><h3>Pegar indicadores <small>hasta 50 000 líneas</small></h3>
    <textarea id="iocTxt" class="mono" style="min-height:140px" placeholder="185.220.101[.]1&#10;hxxp://malo[.]xyz/login.php&#10;…o el texto completo de un aviso" oninput="clearTimeout(window._ip);window._ip=setTimeout(previewIocs,500)"></textarea>
    <div id="iocPrev" class="muted" style="font-size:12.5px;margin:6px 0">Se corrigen los «defanged» (hxxp, [.]) y se ignoran IPs privadas y dominios propios.</div>
    <form id="fIoc" class="form" onsubmit="return loadIocs(event)">
      <div><label>Fuente</label><input name="source" placeholder="CSIRT nacional, análisis propio…"></div>
      <div><label>Confianza</label><input name="weight" type="number" min="1" max="100" value="80"></div>
      <div class="full"><label>Descripción (título del evento en MISP)</label><input name="description"></div>
      <div class="full" style="display:flex;gap:16px;flex-wrap:wrap;font-size:13.5px">
        <label style="display:flex;gap:6px;align-items:center;margin:0;color:var(--ink)"><input type="checkbox" name="misp" style="width:auto"> Enviar a MISP</label>
        <label style="display:flex;gap:6px;align-items:center;margin:0;color:var(--ink)"><input type="checkbox" name="to_ids" style="width:auto" checked> to_ids</label>
        <label style="display:flex;gap:6px;align-items:center;margin:0;color:var(--ink)"><input type="checkbox" name="retro" style="width:auto" checked> Retrobúsqueda 7 días</label></div>
      <div class="full" style="text-align:right"><button class="btn primary">Cargar</button></div></form><div id="iocRes"></div></section></div>
  <section class="card panel" style="margin-top:14px"><h3>Trabajos</h3><div id="jobs"></div></section>`;
  watchJobs("jobs");
}
function uploadIocs(e) {
  e.preventDefault();
  const f = $("fUp"), file = f.file.files[0]; if (!file) return false;
  const p = new URLSearchParams({name: f.name.value, weight: f.weight.value, ioc_type: f.ioc_type.value, mode: f.mode.value, expires_days: f.expires_days.value, tlp: f.tlp.value, retro: f.retro.value});
  const x = new XMLHttpRequest(), bar = $("upBar"); bar.style.display = "block";
  x.upload.onprogress = ev => { if (ev.lengthComputable) { bar.firstElementChild.style.width = (ev.loaded / ev.total * 100) + "%"; $("upMsg").textContent = `Subiendo ${(ev.loaded / 1048576).toFixed(0)} de ${(ev.total / 1048576).toFixed(0)} MB…`; } };
  x.onload = () => { if (x.status < 300) { $("upMsg").innerHTML = `<b style="color:var(--ok)">Archivo recibido.</b> Se está cargando en segundo plano; mira el avance en «Trabajos».`; watchJobs("jobs"); f.reset(); }
    else { let m = x.status; try { m = JSON.parse(x.responseText).detail; } catch (_) {} $("upMsg").innerHTML = `<span class="err">Error: ${esc(m)}</span>`; } };
  x.onerror = () => { $("upMsg").innerHTML = `<span class="err">Error de red al subir el archivo</span>`; };
  x.open("POST", "api/intel/upload?" + p); x.setRequestHeader("Content-Type", "application/octet-stream"); x.setRequestHeader("X-SOC", "1"); x.send(file);
  return false;
}
async function previewIocs() {
  const t = $("iocTxt").value; if (!t.trim()) { $("iocPrev").innerHTML = ""; return; }
  const r = await api("api/iocs/parse", {method: "POST", body: {text: t}}).catch(() => null); if (!r || !$("iocPrev")) return;
  const by = {}; r.iocs.forEach(i => by[i.type] = (by[i.type] || 0) + 1);
  $("iocPrev").innerHTML = `<b style="color:var(--ink)">${nf(r.iocs.length)} válidos:</b> ${Object.entries(by).map(([k, n]) => `<span class="pill info">${esc(k)} · ${n}</span>`).join(" ")}
    ${r.ignorados.length ? ` · se ignoran ${r.ignorados.length}` : ""}`;
}
async function loadIocs(e) {
  e.preventDefault();
  const f = $("fIoc"), body = {...formData("fIoc"), text: $("iocTxt").value, misp: f.misp.checked, to_ids: f.to_ids.checked, retro: f.retro.checked};
  if (!body.text.trim()) { toast("Pega algún indicador"); return false; }
  $("iocRes").innerHTML = `<div class="skel" style="height:50px;margin-top:10px"></div>`;
  try { const r = await api("api/intel/add", {method: "POST", body});
    $("iocTxt").value = "";
    $("iocRes").innerHTML = `<div class="card panel" style="margin-top:12px;background:var(--ok-soft)"><b>${nf(r.leidos)} leídos · ${nf(r.añadidos)} nuevos</b> · ${nf(r.ya_conocidos)} ya estaban en otras fuentes
      ${r.misp_event ? `<div>Evento MISP <a class="go" target="_blank" href="${esc(META.links.misp)}/events/view/${esc(r.misp_event)}">#${esc(r.misp_event)}</a> creado.</div>` : ""}
      ${r.misp_error ? `<div class="err">MISP: ${esc(r.misp_error)}</div>` : ""}</div>`;
    watchJobs("jobs");
  } catch (err) { $("iocRes").innerHTML = `<div style="margin-top:10px">${unavailable(err.message)}</div>`; }
  return false;
}

async function iocIntegrate() {
  const d = await api("api/intel/overview"); if (!$("iv")) return;
  const base = location.origin;
  const code = t => `<pre class="mono" style="background:var(--grid);padding:10px 12px;border-radius:10px;overflow:auto;font-size:12px;margin:6px 0">${esc(t)}</pre>`;
  $("iv").innerHTML = `<div class="g g2">
    ${box("MISP consume tus IoC (feed)", `<p style="font-size:13.5px;margin-top:0">En MISP: <i>Sync Actions → Feeds → Add Feed</i>, tipo <b>Freetext Parsed Feed</b>, «Lookup visible» y cabecera
      <span class="mono">X-API-Key: &lt;BRIDGE_TOKEN&gt;</span>. MISP los correlaciona con sus eventos sin crear millones de atributos.</p>
      ${code(["ip", "domain", "url", "hash"].map(k => `${base}/feeds/misp/${k}.txt?min_weight=60`).join("\n"))}
      <p class="muted" style="font-size:12.5px">Se excluye lo que vino del propio MISP para no crear bucles.</p>`)}
    ${box("Wazuh detecta en tiempo real (listas CDB)", `<p style="font-size:13.5px;margin-top:0">El script <span class="mono">wazuh/actualizar_listas_ioc.sh</span> del proyecto descarga estas listas en el servidor de Wazuh, las compara y reinicia el manager solo si cambiaron. Las reglas están en <span class="mono">wazuh/rules/ioc_portal_rules.xml</span>.</p>
      ${code(["ip", "domain", "hash"].map(k => `${base}/feeds/wazuh/${k}.cdb?min_weight=75`).join("\n"))}
      <p class="muted" style="font-size:12.5px">Solo fuentes con confianza ≥ 75 para que las listas no sean enormes. La correlación del portal (cada 5 min) revisa además todas las fuentes.</p>`)}
  </div>
  <div class="g g2" style="margin-top:14px">
    ${box("Servicios de enriquecimiento", `<table class="table"><tbody>${d.providers.map(p => `<tr><td><b>${esc(p.name)}</b></td><td>${p.on ? '<span class="pill">Activo</span>' : '<span class="pill gray">Sin clave</span>'}</td></tr>`).join("")}</tbody></table>
      <p class="muted" style="font-size:12.5px">Las claves van en el <span class="mono">.env</span>: <span class="mono">ABUSEIPDB_KEY</span>, <span class="mono">VT_API_KEY</span>, <span class="mono">OTX_API_KEY</span>, <span class="mono">ABUSECH_AUTH_KEY</span>. Solo se usan al analizar un indicador (con caché de 24 h), nunca en masa.</p>`)}
    ${box("Shuffle", `<p style="font-size:13.5px;margin-top:0">Shuffle puede cargar IoC y comprobarlos con <span class="mono">X-API-Key: &lt;BRIDGE_TOKEN&gt;</span>:</p>
      ${code(`POST ${base}/portal/api/iocs\n{"text": "1.2.3.4\\nmalo.xyz", "source": "Shuffle", "weight": 80, "misp": false}`)}
      <p class="muted" style="font-size:12.5px">Con <span class="mono">INTEL_AUTO_INCIDENT_SCORE=80</span> en el <span class="mono">.env</span>, cada IoC nuevo visto en Wazuh con riesgo ≥ 80 abre un incidente automáticamente.</p>`)}
  </div>`;
}

/* ======================================================================
   PORTALES: monitoreo de disponibilidad, tiempo de respuesta, SSL y contenido
   ====================================================================== */
let _siteTimer, SITES = [];
const SST = {up: ["En línea", ""], down: ["Caído", "bad"], degraded: ["Inestable", "warn"], pending: ["Comprobando…", "gray"]};
const sslDays = (d, today) => d ? Math.round((new Date(d) - new Date(today)) / 864e5) : null;
async function renderSites() {
  clearTimeout(_siteTimer);
  const d = await api("api/sites"); SITES = d.rows;
  const on = d.rows.filter(s => s.enabled), up = on.filter(s => s.state === "up").length, down = on.filter(s => s.state === "down");
  const ms = on.filter(s => s.avg_ms != null), sslSoon = on.filter(s => { const n = sslDays(s.ssl_expiry, d.today); return n != null && n <= 30; });
  const changed = on.filter(s => s.content_changed && (Date.now() - new Date(s.content_changed.replace(" ", "T"))) < 864e5);
  const strip = h => { if (!h.length) return `<div class="muted" style="font-size:12px;height:30px">Sin historial aún</div>`;
    const mx = Math.max(300, ...h.map(x => x[2] || 0));
    return `<svg viewBox="0 0 ${h.length * 4} 30" preserveAspectRatio="none" style="width:100%;height:30px;display:block">${h.map((x, i) => {
      const hh = x[1] ? Math.max(4, (x[2] || 0) / mx * 30) : 30;
      return `<rect x="${i * 4}" y="${30 - hh}" width="3" height="${hh}" rx="1" fill="${x[1] ? "var(--st-good)" : "var(--st-crit)"}" data-tip="${esc(`${new Date(x[0] * 1000).toLocaleString("es-DO", {hour: "2-digit", minute: "2-digit", day: "2-digit", month: "2-digit"})} · ${x[1] ? (x[2] + " ms") : "fallo"}`)}"/>`; }).join("")}</svg>`; };
  view(`<div class="toolbar" style="margin-top:6px"><div><h1 class="page" style="margin:0 4px">Portales monitoreados</h1>
      <div class="sub" style="margin:0 4px">Disponibilidad, tiempo de respuesta, certificado SSL y cambios de contenido (posible desfiguración) de los sitios web institucionales.</div></div>
    <span class="grow"></span><button class="btn primary" onclick="editSite()">＋ Añadir portal</button></div>
  <div class="kpis">
    ${kpi("En línea", `${nf(up)}<span class="muted" style="font-size:15px;font-weight:500"> / ${nf(on.length)}</span>`, "portales activos")}
    ${kpi("Caídos", nf(down.length), down.map(s => esc(s.name)).join(", ").slice(0, 60) || "Ninguno", "", down.length > 0)}
    ${kpi("Respuesta media", ms.length ? Math.round(ms.reduce((a, s) => a + s.avg_ms, 0) / ms.length) + " ms" : "—", "últimas 24 h")}
    ${kpi("SSL caduca ≤ 30 días", nf(sslSoon.length), sslSoon.map(s => esc(s.name)).join(", ").slice(0, 60) || "Ninguno", "", sslSoon.length > 0)}
    ${kpi("Cambios de contenido", nf(changed.length), "últimas 24 h", "", changed.length > 0)}
  </div>
  ${d.rows.length ? `<div class="grid" style="margin-top:14px;grid-template-columns:repeat(auto-fill,minmax(340px,1fr))">${d.rows.map(s => {
    const [lbl, cls] = SST[s.state] || [s.state, "gray"], sd = sslDays(s.ssl_expiry, d.today);
    return `<section class="card panel" style="${s.state === "down" ? "border-color:color-mix(in srgb,var(--bad) 50%,var(--line))" : ""};${s.enabled ? "" : "opacity:.6"}">
      <div class="row" style="flex-wrap:nowrap"><div style="min-width:0"><h3 style="margin:0;justify-content:flex-start;align-items:center"><span class="dot ${s.state === "up" ? "ok" : s.state === "down" ? "bad" : ""}" style="display:inline-block;margin-right:6px"></span>${esc(s.name)}</h3>
        <a class="muted mono" style="font-size:12px;word-break:break-all" href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.url)}</a></div>
        <span class="pill ${cls}">${s.enabled ? lbl : "Pausado"}</span></div>
      <div class="g g4" style="gap:8px;margin:12px 0 10px;font-size:12px">
        <div><div class="muted">Código</div><b style="font-size:16px">${s.last_code ?? "—"}</b></div>
        <div><div class="muted">Respuesta</div><b style="font-size:16px">${s.last_ms != null ? s.last_ms + " ms" : "—"}</b></div>
        <div><div class="muted">Uptime 24 h</div><b style="font-size:16px;${s.uptime24 != null && s.uptime24 < 99 ? "color:var(--bad)" : ""}">${s.uptime24 != null ? s.uptime24 + " %" : "—"}</b></div>
        <div><div class="muted">SSL</div><b style="font-size:16px;${sd != null && sd <= 30 ? "color:var(--bad)" : ""}" title="${esc(s.ssl_expiry || s.ssl_error || "")}">${s.url.startsWith("https") ? (sd != null ? sd + " días" : s.ssl_error ? "⚠ error" : "—") : "sin HTTPS"}</b></div>
      </div>
      ${strip(s.hist)}
      ${s.last_error ? `<div class="err" style="margin-top:8px">${esc(s.last_error)}</div>` : ""}
      ${s.ssl_error && s.url.startsWith("https") ? `<div class="err" style="margin-top:4px">SSL: ${esc(s.ssl_error)}</div>` : ""}
      ${s.content_changed ? `<div style="margin-top:6px;font-size:12.5px;color:var(--warn)">⚠ Contenido cambiado el ${esc(s.content_changed)}</div>` : ""}
      <div class="row" style="margin-top:10px;font-size:12px"><span class="muted">Cada ${s.interval_min} min · ${s.last_check ? "comprobado " + esc(s.last_check.slice(5, 16)) : "sin comprobar"}${s.keyword ? ` · busca «${esc(s.keyword)}»` : ""}${s.auto_incident ? " · crea incidentes" : ""}</span>
        <span><button class="btn sm" onclick="checkSite(${s.id}, this)">Comprobar</button> <button class="btn sm" onclick="editSite(${s.id})">Editar</button></span></div>
    </section>`; }).join("")}</div>` : `<div class="card empty" style="margin-top:14px">Aún no hay portales. <a class="go" href="javascript:editSite()">Añade el primero →</a></div>`}
  ${box("Últimos cambios de estado", d.events.length ? `<ul class="feed">${d.events.map(e => `<li><span class="pill ${{down: "bad", up: "", degraded: "warn", content: "warn", incident: "info"}[e.kind] || "gray"}">${{down: "Caído", up: "Recuperado", degraded: "Fallo", content: "Contenido", incident: "Incidente"}[e.kind] || esc(e.kind)}</span>
    <div><b>${esc(e.name)}</b> · ${esc(e.text)}</div><span class="muted" style="font-size:12px;white-space:nowrap">${esc(e.at)}</span></li>`).join("")}</ul>` : `<div class="empty">Sin eventos todavía.</div>`).replace('class="card panel "', 'class="card panel" style="margin-top:14px"')}`);
  _siteTimer = setTimeout(() => { if (route()[0] === "sites" && !$("modal").classList.contains("on")) router(); }, 30000);
}
function editSite(id) {
  const s = id ? SITES.find(x => x.id === id) : {interval_min: 5, enabled: 1, auto_incident: 1};
  const ck = (n, v, t) => `<label style="display:flex;gap:6px;align-items:center;margin:0;color:var(--ink);font-size:13.5px"><input type="checkbox" name="${n}" style="width:auto" ${v ? "checked" : ""}> ${t}</label>`;
  openModal(`<h2 style="margin:0 0 16px">${id ? "Editar portal" : "Añadir portal"}</h2>
  <form id="fS" class="form" onsubmit="return saveSite(event, ${id || 0})">
    <div><label>Nombre *</label><input name="name" required value="${esc(s.name || "")}" placeholder="Portal ACME"></div>
    <div><label>URL *</label><input name="url" required value="${esc(s.url || "")}" placeholder="https://acme.example"></div>
    <div><label>Comprobar cada</label><select name="interval_min">${[1, 5, 15, 30, 60].map(n => `<option value="${n}" ${+s.interval_min === n ? "selected" : ""}>${n} min</option>`).join("")}</select></div>
    <div><label>Código HTTP esperado</label><input name="expect_code" value="${esc(s.expect_code ?? "")}" placeholder="vacío = cualquiera menor de 400"></div>
    <div class="full"><label>Texto que debe aparecer en la página</label><input name="keyword" value="${esc(s.keyword || "")}" placeholder="p. ej. Oficina Gubernamental de Tecnologías — si falta, se marca como caído (posible desfiguración)"></div>
    <div><label>Responsable</label><select name="owner">${opts([...new Set(["", s.owner || "", ...META.users])], s.owner || "")}</select></div><div></div>
    <div class="full" style="display:flex;gap:18px;flex-wrap:wrap">${ck("watch_content", s.watch_content, "Vigilar cambios de contenido")}${ck("auto_incident", s.auto_incident, "Crear incidente si cae o cambia")}${ck("enabled", s.enabled, "Activo")}</div>
    <div class="full muted" style="font-size:12.5px">Se declara caído tras 2 fallos seguidos. «Vigilar cambios» compara el HTML (sin números ni scripts): úsalo en páginas estáticas, porque las que cambian a menudo darán avisos.</div>
    <div class="full row"><span>${id ? `<button type="button" class="btn sm" onclick="delSite(${id})">Eliminar</button>` : ""}</span>
      <span><button type="button" class="btn" onclick="closeModal()">Cancelar</button> <button class="btn primary">${id ? "Guardar" : "Añadir y comprobar"}</button></span></div>
  </form>`);
}
async function saveSite(e, id) {
  e.preventDefault();
  const f = $("fS"), body = {...formData("fS"), watch_content: f.watch_content.checked, auto_incident: f.auto_incident.checked, enabled: f.enabled.checked};
  try { await api("api/sites" + (id ? "/" + id : ""), {method: id ? "PUT" : "POST", body}); closeModal(); toast("Guardado"); router(); }
  catch (err) { toast("Error: " + err.message); }
  return false;
}
async function checkSite(id, btn) { btn.textContent = "…"; btn.disabled = true; try { await api(`api/sites/${id}/check`, {method: "POST"}); } catch (e) { toast(e.message); } router(); }
async function delSite(id) { if (!confirm("¿Eliminar este portal y su historial?")) return; await api("api/sites/" + id, {method: "DELETE"}); closeModal(); router(); }

/* ======================================================================
   CUENTA Y ADMINISTRACIÓN DE USUARIOS
   ====================================================================== */
let ME = null;
const ROLEC = {admin: "bad", analyst: "info", viewer: "gray"};
const initials = s => String(s || "?").split(/[\s._-]+/).filter(Boolean).slice(0, 2).map(x => x[0].toUpperCase()).join("");
function userMenu() {
  if (!ME) return;
  $("who").innerHTML = `<button class="umenu" onclick="this.nextElementSibling.classList.toggle('on')" aria-haspopup="true">
      <span class="av">${esc(initials(ME.display || ME.username))}</span><span class="un"><b>${esc(ME.display || ME.username)}</b><small>${esc(ME.role_name)}</small></span> ▾</button>
    <div class="dd" onclick="this.classList.remove('on')">
      <div class="ddh"><b>${esc(ME.username)}</b><small>${ME.source === "ldap" ? "Cuenta del dominio" : "Cuenta local"} · ${esc(ME.role_name)}</small></div>
      <a href="#/account">👤 Mi cuenta y seguridad</a>
      ${ME.role === "admin" ? `<a href="#/admin">🛡 Usuarios y accesos</a>` : ""}
      <a href="javascript:logout()">↩ Cerrar sesión</a></div>`;
  document.body.classList.toggle("role-viewer", ME.role === "viewer");
}
document.addEventListener("click", e => { if (!e.target.closest || !e.target.closest("#who")) document.querySelectorAll("#who .dd.on").forEach(d => d.classList.remove("on")); });
async function logout() { try { await api("auth/logout", {method: "POST"}); } catch (e) {} location.href = "/portal/login"; }

async function renderAccount() {
  ME = await api("auth/me"); userMenu();
  const forced = ME.state !== "ok";
  view(`<h1 class="page">Mi cuenta</h1><div class="sub">Datos de acceso, contraseña, verificación en dos pasos y sesiones abiertas.</div>
  ${forced ? `<section class="card panel" style="border-color:color-mix(in srgb,var(--warn) 50%,var(--line));background:var(--warn-soft);margin-bottom:14px">
    <b>Antes de continuar:</b> ${ME.state === "change_password" ? "cambia la contraseña temporal por una propia." : "tu rol exige la verificación en dos pasos (MFA). Actívala abajo con tu teléfono."}</section>` : ""}
  <section class="card panel" style="display:flex;gap:16px;align-items:center;flex-wrap:wrap">
    <span class="av" style="width:56px;height:56px;font-size:20px">${esc(initials(ME.display || ME.username))}</span>
    <div style="flex:1"><h3 style="margin:0;justify-content:flex-start;gap:8px">${esc(ME.display || ME.username)} <span class="pill ${ROLEC[ME.role]}">${esc(ME.role_name)}</span>
      <span class="pill gray">${ME.source === "ldap" ? "Active Directory" : "Cuenta local"}</span></h3>
      <div class="muted" style="font-size:13px">${esc(ME.username)}${ME.email ? " · " + esc(ME.email) : ""} · último acceso ${esc(ME.last_login || "—")} desde ${esc(ME.last_ip || "—")}</div></div></section>
  <div class="g g2" style="margin-top:14px">
    <section class="card panel"><h3>Contraseña</h3>${ME.source === "ldap" ? `<p class="muted" style="margin:0">Tu cuenta es del dominio: la contraseña se cambia en Windows (Ctrl+Alt+Supr → Cambiar contraseña).</p>` : `
      <form id="fPw" class="form" onsubmit="return changePw(event)" style="grid-template-columns:1fr">
        <div><label>Contraseña actual</label><input type="password" name="current" autocomplete="current-password" required></div>
        <div><label>Nueva contraseña</label><input type="password" name="new" id="pwNew" autocomplete="new-password" required oninput="pwMeter()"></div>
        <div><label>Repite la nueva contraseña</label><input type="password" name="new2" autocomplete="new-password" required></div>
        <ul id="pwRules" style="margin:0;padding-left:18px;font-size:12.5px;line-height:1.7"></ul>
        <div style="text-align:right"><button class="btn primary">Cambiar contraseña</button></div></form>
      <p class="muted" style="font-size:12px;margin-bottom:0">Al cambiarla se cierran tus otras sesiones abiertas. Último cambio: ${esc(ME.pw_changed || "—")}</p>`}</section>
    <section class="card panel"><h3>Verificación en dos pasos (MFA) ${ME.mfa_enabled ? '<span class="pill">Activada</span>' : ME.mfa_required ? '<span class="pill bad">Obligatoria</span>' : '<span class="pill gray">Desactivada</span>'}</h3>
      <div id="mfaBox">${ME.mfa_enabled ? `<p style="margin-top:0">Al entrar se te pide un código de tu app Authenticator. Te quedan <b>${ME.recovery_left}</b> códigos de recuperación.</p>
        ${ME.mfa_required ? `<p class="muted" style="font-size:12.5px">Tu rol exige MFA. Si cambias de teléfono, pide a un administrador que lo restablezca.</p>` :
        `<form class="search" onsubmit="mfaOff(this.c.value);return false"><input name="c" placeholder="Código para desactivar" inputmode="numeric"><button class="btn">Desactivar</button></form>`}`
      : `<p style="margin-top:0">Añade una capa extra: además de la contraseña, un código de 6 dígitos de <b>Google Authenticator</b>, <b>Microsoft Authenticator</b> u otra app TOTP.</p>
        <button class="btn primary" onclick="mfaSetup()">Activar MFA</button>`}</div></section>
  </div>
  <section class="card panel" style="margin-top:14px"><div class="row"><h3 style="margin:0">Sesiones abiertas <small>${ME.sessions.length}</small></h3>
    ${ME.sessions.length > 1 ? `<button class="btn sm" onclick="revokeOthers()">Cerrar las demás sesiones</button>` : ""}</div>
    <table class="table" style="margin-top:8px"><thead><tr><th>Dispositivo</th><th>IP</th><th>Inicio</th><th>Última actividad</th></tr></thead><tbody>
    ${ME.sessions.map(s => `<tr><td style="font-size:12.5px;max-width:420px">${esc(uaShort(s.ua))} ${s.current ? '<span class="pill">Esta sesión</span>' : ""}</td><td class="mono">${esc(s.ip)}</td><td>${esc(s.created)}</td><td>${esc(s.last_seen)}</td></tr>`).join("")}</tbody></table></section>`);
  pwMeter();
}
const uaShort = ua => { ua = ua || ""; const b = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Navegador";
  const o = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : ""; return `${b}${o ? " · " + o : ""}`; };
function pwMeter() {
  const el = $("pwRules"); if (!el) return; const v = ($("pwNew") || {}).value || "";
  const rules = [[v.length >= 12, "Al menos 12 caracteres"], [/[a-z]/.test(v) && /[A-Z]/.test(v), "Mayúsculas y minúsculas"], [/\d/.test(v), "Algún número"], [/[^\w\s]|_/.test(v), "Algún símbolo (!#$%…)"],
    [!ME || !v.toLowerCase().includes(ME.username.toLowerCase()), "Sin tu nombre de usuario"]];
  el.innerHTML = rules.map(([ok, t]) => `<li style="color:${ok && v ? "var(--ok)" : "var(--muted)"}">${ok && v ? "✓" : "○"} ${t}</li>`).join("");
}
async function changePw(e) {
  e.preventDefault(); const d = formData("fPw");
  if (d.new !== d.new2) { toast("Las contraseñas nuevas no coinciden"); return false; }
  try { await api("auth/password", {method: "POST", body: {current: d.current, new: d.new}}); toast("Contraseña cambiada");
    ME = await api("auth/me"); if (ME.state === "ok") { location.hash = "#/"; } else renderAccount(); }
  catch (err) { toast("Error: " + err.message); }
  return false;
}
async function mfaSetup() {
  try { const s = await api("auth/mfa/setup", {method: "POST"});
    $("mfaBox").innerHTML = `<ol style="padding-left:18px;margin-top:0;font-size:13.5px;line-height:1.7"><li>Abre tu app Authenticator y escanea este código.</li><li>Escribe el código de 6 dígitos que aparece.</li></ol>
      <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:center"><div style="background:#fff;padding:8px;border-radius:12px;width:180px;height:180px">${s.qr || ""}</div>
      <div style="flex:1;min-width:200px"><label>¿No puedes escanear? Clave manual</label><div class="mono" style="font-size:14px;background:var(--grid);padding:8px 10px;border-radius:8px;word-break:break-all">${esc(s.secret)}</div>
        <form class="search" style="margin-top:12px" onsubmit="mfaEnable(this.c.value);return false"><input name="c" placeholder="123456" inputmode="numeric" maxlength="6" autofocus><button class="btn primary">Verificar</button></form></div></div>`;
    const svg = $("mfaBox").querySelector("svg"); if (svg) { svg.setAttribute("width", "164"); svg.setAttribute("height", "164"); }
  } catch (e) { toast("Error: " + e.message); }
}
async function mfaEnable(code) {
  try { const r = await api("auth/mfa/enable", {method: "POST", body: {code}});
    window._rec = r.recovery.join("\n");
    $("mfaBox").innerHTML = `<p style="margin-top:0;color:var(--ok)"><b>✓ MFA activado.</b></p><p style="font-size:13.5px">Guarda estos <b>códigos de recuperación</b> en un lugar seguro (gestor de contraseñas). Cada uno sirve una vez si pierdes el teléfono. <b>No se volverán a mostrar.</b></p>
      <div class="mono" style="display:grid;grid-template-columns:1fr 1fr;gap:6px;background:var(--grid);padding:12px;border-radius:10px;font-size:14px">${r.recovery.map(c => `<span>${c}</span>`).join("")}</div>
      <div class="row" style="margin-top:10px"><button class="btn sm" onclick="navigator.clipboard.writeText(_rec).then(()=>toast('Copiados'))">Copiar</button>
        <button class="btn sm" onclick="const a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['Códigos de recuperación · Portal SOC ACME\\n\\n'+_rec]));a.download='codigos-recuperacion-soc.txt';a.click()">Descargar .txt</button>
        <button class="btn sm primary" onclick="location.hash = '#/'; location.reload()">Continuar</button></div>`;
  } catch (e) { toast("Error: " + e.message); }
}
async function mfaOff(code) { try { await api("auth/mfa/disable", {method: "POST", body: {code}}); toast("MFA desactivado"); renderAccount(); } catch (e) { toast("Error: " + e.message); } }
async function revokeOthers() { await api("auth/sessions/revoke", {method: "POST", body: {}}); toast("Otras sesiones cerradas"); renderAccount(); }

/* ---------------- Administración ---------------- */
const EVC = {login: "", logout: "gray", expired: "gray", login_fail: "warn", mfa_fail: "warn", unknown: "warn", locked: "bad", blocked: "bad", ip_block: "bad",
  disabled: "bad", ldap_down: "bad", ldap_nogroup: "warn", pw_change: "info", mfa_on: "info", mfa_off: "warn", recovery: "warn", admin: "info"};
async function renderAdmin() {
  const v = qs().get("view") || "users";
  view(`<div class="toolbar" style="margin-top:6px"><div><h1 class="page" style="margin:0 4px">Usuarios y accesos</h1><div class="sub" style="margin:0 4px">Cuentas del portal, roles, MFA y registro de auditoría de accesos.</div></div>
    <span class="grow"></span>${subnav("#/admin", v, [["users", "Usuarios"], ["log", "Registro de accesos"]])}<button class="btn primary sm" onclick="newUser()">＋ Nuevo usuario</button></div><div id="adm"><div class="skel"></div></div>`);
  const d = await api("api/admin/users"); window._ADM = d; if (!$("adm")) return;
  const S = d.stats, P = S.politica;
  const head = `<div class="kpis">${kpi("Usuarios", nf(S.usuarios), `${nf(S.sesiones)} sesiones abiertas`)}${kpi("Accesos · 24 h", nf(S.logins_24h), "inicios de sesión correctos", "#/admin?view=log")}
    ${kpi("Intentos fallidos · 24 h", nf(S.fallos_24h), "contraseña, MFA o usuario inexistente", "#/admin?view=log&event=login_fail", S.fallos_24h > 20)}
    ${kpi("Cuentas bloqueadas", nf(S.bloqueados), `${P.max_fails} fallos → ${P.lock_min} min`, "", S.bloqueados > 0)}${kpi("Sin MFA", nf(S.sin_mfa), `obligatorio para: ${P.mfa_roles.map(r => d.roles[r]).join(", ") || "nadie"}`, "", S.sin_mfa > 0)}</div>
    <p class="muted" style="font-size:12.5px;margin:8px 4px 14px">Cierre por inactividad: ${P.idle_min} min · sesión máxima ${P.max_hours} h · Active Directory: ${S.ldap ? '<b style="color:var(--ok)">conectado</b>' : "no configurado (LDAP_ENABLED)"}</p>`;
  if (v === "log") return adminLog(head, d);
  $("adm").innerHTML = head + `<section class="card"><div class="scroll" style="max-height:none"><table class="table"><thead><tr><th>Usuario</th><th>Origen</th><th>Rol</th><th>MFA</th><th>Estado</th><th>Último acceso</th><th></th></tr></thead><tbody>
    ${d.rows.map(u => `<tr><td><span style="display:flex;gap:10px;align-items:center"><span class="av">${esc(initials(u.display || u.username))}</span><span><b>${esc(u.username)}</b><div class="muted" style="font-size:12px">${esc(u.display)}${u.email ? " · " + esc(u.email) : ""}</div></span></span></td>
      <td><span class="pill gray">${u.source === "ldap" ? "AD" : "Local"}</span></td><td><span class="pill ${ROLEC[u.role]}">${esc(u.role_name)}</span></td>
      <td>${u.mfa_enabled ? '<span class="pill">✓ Activado</span>' : u.mfa_required ? '<span class="pill bad">Pendiente</span>' : '<span class="muted">—</span>'}</td>
      <td>${!u.enabled ? '<span class="pill gray">Desactivada</span>' : u.locked ? '<span class="pill bad">🔒 Bloqueada</span>' : u.must_change ? '<span class="pill warn">Clave temporal</span>' : '<span class="pill">Activa</span>'}${u.sessions ? ` <span class="muted" style="font-size:12px">${u.sessions} ses.</span>` : ""}</td>
      <td style="font-size:12.5px">${esc(u.last_login || "nunca")}<div class="muted mono" style="font-size:11.5px">${esc(u.last_ip || "")}</div></td>
      <td><button class="btn sm" onclick="editUser(${u.id})">Gestionar</button></td></tr>`).join("")}</tbody></table></div></section>`;
}
async function adminLog(head, d) {
  const q = qs(), days = +(q.get("days") || 7), ev = q.get("event") || "", text = q.get("q") || "";
  const rows = await api(`api/admin/authlog?days=${days}&event=${ev}&q=${encodeURIComponent(text)}`); window._ALOG = rows;
  window._af = (k, val) => { const p = qs(); p.set("view", "log"); val ? p.set(k, val) : p.delete(k); location.hash = "#/admin?" + p; };
  $("adm").innerHTML = head + `<div class="toolbar"><div class="chips">${[[1, "24 h"], [7, "7 días"], [30, "30 días"], [90, "90 días"]].map(([k, t]) => `<button class="${k === days ? "on" : ""}" onclick="_af('days',${k})">${t}</button>`).join("")}</div>
    <select style="width:auto" onchange="_af('event',this.value)"><option value="">Todos los eventos</option>${Object.entries(d.events).map(([k, t]) => `<option value="${k}" ${k === ev ? "selected" : ""}>${t}</option>`).join("")}</select>
    <input style="flex:1;width:auto" placeholder="Usuario o IP… (Enter)" value="${esc(text)}" onkeydown="if(event.key==='Enter')_af('q',this.value)">
    <button class="btn" onclick="csvDownload('registro-accesos.csv', _ALOG, ['at','username','ip','event_name','detail'])">Exportar CSV</button></div>
  <section class="card">${rows.length ? `<div class="scroll" style="max-height:640px"><table class="table"><thead><tr><th>Fecha</th><th>Usuario</th><th>IP</th><th>Evento</th><th>Detalle</th></tr></thead><tbody>
    ${rows.map(r => `<tr><td style="white-space:nowrap">${esc(r.at)}</td><td><b>${esc(r.username)}</b></td><td class="mono">${esc(r.ip)}</td>
      <td><span class="pill ${EVC[r.event] ?? "gray"}">${esc(r.event_name)}</span></td><td class="muted" style="font-size:12.5px">${esc(r.detail)}</td></tr>`).join("")}</tbody></table></div>`
    : `<div class="empty">Sin eventos con estos filtros.</div>`}</section>`;
}
function showSecret(title, user, pw) {
  openModal(`<h2 style="margin:0 0 10px">${title}</h2><p>Entrega esta contraseña temporal a <b>${esc(user)}</b> por un canal seguro. Se le pedirá cambiarla al entrar. <b>No se volverá a mostrar.</b></p>
    <div class="mono" style="font-size:20px;background:var(--grid);padding:14px;border-radius:12px;text-align:center;letter-spacing:1px">${esc(pw)}</div>
    <div class="row" style="margin-top:14px"><button class="btn" onclick="navigator.clipboard.writeText(${esc(JSON.stringify(pw))}).then(()=>toast('Copiada'))">Copiar</button><button class="btn primary" onclick="closeModal();router()">Hecho</button></div>`);
}
function newUser() {
  const R = (window._ADM || {}).roles || {admin: "Administrador", analyst: "Analista", viewer: "Solo lectura"};
  openModal(`<h2 style="margin:0 0 16px">Nuevo usuario</h2><form id="fU" class="form" onsubmit="return createUser(event)">
    <div><label>Usuario *</label><input name="username" required placeholder="nombre.apellido" autocapitalize="off"></div>
    <div><label>Origen</label><select name="source" onchange="$('pwRow').style.display=this.value==='ldap'?'none':''"><option value="local">Cuenta local</option><option value="ldap">Cuenta del dominio (AD)</option></select></div>
    <div><label>Nombre completo</label><input name="display"></div><div><label>Correo</label><input name="email" type="email"></div>
    <div><label>Rol</label><select name="role">${Object.entries(R).map(([k, t]) => `<option value="${k}" ${k === "analyst" ? "selected" : ""}>${t}</option>`).join("")}</select></div>
    <div id="pwRow"><label>Contraseña inicial</label><input name="password" placeholder="vacía = se genera una temporal"></div>
    <div class="full muted" style="font-size:12.5px"><b>Administrador:</b> todo, incluidos usuarios. <b>Analista:</b> incidentes, IoC, vulnerabilidades, herramientas… <b>Solo lectura:</b> consulta y pantalla NOC.
      Las cuentas del dominio también pueden entrar directamente si pertenecen a un grupo del SOC en AD.</div>
    <div class="full" style="text-align:right"><button type="button" class="btn" onclick="closeModal()">Cancelar</button> <button class="btn primary">Crear</button></div></form>`);
}
async function createUser(e) {
  e.preventDefault();
  try { const r = await api("api/admin/users", {method: "POST", body: formData("fU")});
    if (r.password) showSecret("Usuario creado", r.username, r.password); else { closeModal(); toast("Usuario creado"); router(); } }
  catch (err) { toast("Error: " + err.message); }
  return false;
}
function editUser(id) {
  const u = _ADM.rows.find(x => x.id === id), R = _ADM.roles, self = ME && ME.id === id;
  openModal(`<div class="row"><h2 style="margin:0">${esc(u.username)}</h2><span class="pill gray">${u.source === "ldap" ? "Active Directory" : "Cuenta local"}</span></div>
    <form id="fE" class="form" style="margin-top:14px" onsubmit="return saveUser(event, ${id})">
      <div><label>Nombre</label><input name="display" value="${esc(u.display)}"></div><div><label>Correo</label><input name="email" value="${esc(u.email)}"></div>
      <div><label>Rol</label><select name="role" ${self ? "disabled" : ""}>${Object.entries(R).map(([k, t]) => `<option value="${k}" ${k === u.role ? "selected" : ""}>${t}</option>`).join("")}</select>
        ${u.source === "ldap" ? '<div class="muted" style="font-size:11.5px">En cuentas de AD el rol se recalcula con sus grupos en cada inicio.</div>' : ""}</div>
      <div><label>Estado</label><select name="enabled" ${self ? "disabled" : ""}><option value="1" ${u.enabled ? "selected" : ""}>Activa</option><option value="0" ${u.enabled ? "" : "selected"}>Desactivada</option></select></div>
      <div class="full" style="text-align:right"><button class="btn primary">Guardar</button></div></form>
    <h3 style="margin-top:18px">Acciones</h3><div style="display:flex;gap:8px;flex-wrap:wrap">
      ${u.locked ? `<button class="btn sm" onclick="userAct(${id},{unlock:1})">🔓 Desbloquear</button>` : ""}
      ${u.source === "local" ? `<button class="btn sm" onclick="userAct(${id},{reset_password:1},'¿Generar una contraseña temporal nueva y cerrar sus sesiones?')">🔑 Restablecer contraseña</button>` : ""}
      ${u.mfa_enabled ? `<button class="btn sm" onclick="userAct(${id},{reset_mfa:1},'¿Restablecer el MFA? Tendrá que configurarlo de nuevo.')">📱 Restablecer MFA</button>` : ""}
      ${u.sessions ? `<button class="btn sm" onclick="userAct(${id},{logout:1})">⏏ Cerrar sus sesiones (${u.sessions})</button>` : ""}
      ${self ? "" : `<button class="btn sm" style="color:var(--bad)" onclick="delUser(${id})">✕ Eliminar</button>`}
      <a class="btn sm" href="#/admin?view=log&q=${encodeURIComponent(u.username)}" onclick="closeModal()">📜 Ver sus accesos</a></div>
    <p class="muted" style="font-size:12px">Creada ${esc(u.created_at || "—")} · último acceso ${esc(u.last_login || "nunca")} ${u.last_ip ? "desde " + esc(u.last_ip) : ""}</p>`);
}
async function saveUser(e, id) {
  e.preventDefault(); const d = formData("fE"); if ("enabled" in d) d.enabled = d.enabled === "1";
  try { await api("api/admin/users/" + id, {method: "PUT", body: d}); closeModal(); toast("Guardado"); router(); } catch (err) { toast("Error: " + err.message); }
  return false;
}
async function userAct(id, body, ask) {
  if (ask && !confirm(ask)) return;
  try { const r = await api("api/admin/users/" + id, {method: "PUT", body});
    if (r.password) showSecret("Contraseña restablecida", _ADM.rows.find(x => x.id === id).username, r.password); else { closeModal(); toast("Hecho"); router(); } }
  catch (err) { toast("Error: " + err.message); }
}
async function delUser(id) { if (!confirm("¿Eliminar este usuario? Su historial de accesos se conserva.")) return; try { await api("api/admin/users/" + id, {method: "DELETE"}); closeModal(); router(); } catch (e) { toast("Error: " + e.message); } }

/* ======================================================================
   RUNBOOKS (catálogo con niveles) · MITRE ATT&CK · OWASP Top 10
   ====================================================================== */
const LVLC = {"Básico": "", "Intermedio": "warn", "Avanzado": "bad", "Referencia": "gray"};
const mitreChips = (s, max = 4) => (s || "").split(",").map(x => x.trim()).filter(Boolean).slice(0, max)
  .map(t => `<a class="pill info mono" style="font-size:11px" href="#/mitre?t=${esc(t)}" onclick="event.stopPropagation()">${esc(t)}</a>`).join(" ");
async function renderRunbooks() {
  const rows = await api("api/runbooks"), q = qs(), lvl = q.get("level") || "", cat = q.get("cat") || "", text = (q.get("q") || "").toLowerCase();
  window._rf = (k, v) => { const p = qs(); v ? p.set(k, v) : p.delete(k); location.hash = "#/runbooks?" + p; };
  const cats = [...new Set(rows.map(r => r.category).filter(Boolean))].sort();
  const by = l => rows.filter(r => r.level === l).length;
  const list = rows.filter(r => (!lvl || r.level === lvl) && (!cat || r.category === cat) &&
    (!text || [r.title, r.description, r.mitre, r.owasp, r.category].join(" ").toLowerCase().includes(text)));
  view(`<div class="toolbar" style="margin-top:6px"><div><h1 class="page" style="margin:0 4px">Runbooks</h1><div class="sub" style="margin:0 4px">${rows.length} procedimientos de respuesta, mapeados a MITRE ATT&CK y OWASP Top 10</div></div>
    <span class="grow"></span><a class="btn" href="#/mitre">🧭 Matriz ATT&CK</a><a class="btn primary" href="#/runbooks/new/edit">＋ Nuevo runbook</a></div>
  <div class="kpis" style="margin-bottom:14px">
    ${kpi("Todos", nf(rows.length), "procedimientos", "javascript:_rf('level','')")}
    ${["Básico", "Intermedio", "Avanzado"].map(l => kpi(`<span class="pill ${LVLC[l]}">${l}</span>`, nf(by(l)), {"Básico": "nivel 1 · incidentes frecuentes", "Intermedio": "nivel 2 · requiere análisis", "Avanzado": "equipo completo · crisis"}[l], `javascript:_rf('level','${l}')`)).join("")}
  </div>
  <div class="toolbar"><div class="chips">${[["", "Todos los niveles"], ["Básico", "Básico"], ["Intermedio", "Intermedio"], ["Avanzado", "Avanzado"]].map(([k, t]) => `<button class="${k === lvl ? "on" : ""}" onclick="_rf('level','${k}')">${t}</button>`).join("")}</div>
    <select style="width:auto" onchange="_rf('cat',this.value)"><option value="">Todas las categorías</option>${cats.map(c => `<option ${c === cat ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>
    <input style="flex:1;min-width:200px;width:auto" placeholder="Buscar por nombre, técnica (T1486) u OWASP (A05)… (Enter)" value="${esc(q.get("q") || "")}" onkeydown="if(event.key==='Enter')_rf('q',this.value)"></div>
  <div class="grid">${list.map(r => `<a class="card rb" href="#/runbooks/${esc(r.slug)}">
    <div class="row" style="flex-wrap:nowrap;margin-bottom:10px"><div class="thumb">${ICON.book}</div><span>${r.level ? `<span class="pill ${LVLC[r.level] ?? "gray"}">${esc(r.level)}</span>` : ""} ${r.severity ? sev(r.severity) : ""}</span></div>
    <h4>${esc(r.title)}</h4><div class="muted" style="font-size:12px;margin:-2px 0 6px">${esc(r.category || "")}</div><p>${esc(r.description)}</p>
    <div style="margin-bottom:10px;display:flex;gap:4px;flex-wrap:wrap">${mitreChips(r.mitre)}${(r.owasp || "").split(",").filter(x => x.trim()).map(o => `<span class="pill warn" style="font-size:11px">${esc(o.trim().split(":")[0])}</span>`).join("")}</div>
    <div class="row"><span class="muted" style="font-size:12px">${esc(r.updated_by)} · ${esc((r.updated_at || "").slice(0, 10))}</span><span class="go">Leer →</span></div></a>`).join("") || `<div class="card empty">Ningún runbook con estos filtros.</div>`}</div>`);
}
async function renderRunbook(slug) {
  const r = await api("api/runbooks/" + encodeURIComponent(slug));
  view(`<div class="toolbar" style="margin-top:8px"><a class="btn sm" href="#/runbooks">← Runbooks</a><span class="grow"></span>
      <span class="muted" style="font-size:12.5px">Actualizado por ${esc(r.updated_by)} · ${esc(r.updated_at)}</span>
      <button class="btn sm" onclick="openNewIncident({runbook: '${esc(r.slug)}', severity: ${esc(JSON.stringify(r.severity || "High"))}})">＋ Incidente con este runbook</button>
      <a class="btn sm primary" href="#/runbooks/${esc(r.slug)}/edit">Editar</a></div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin:0 4px 12px">${r.level ? `<span class="pill ${LVLC[r.level] ?? "gray"}">${esc(r.level)}</span>` : ""}${r.category ? `<span class="pill gray">${esc(r.category)}</span>` : ""}${mitreChips(r.mitre, 12)}</div>
    <section class="card panel md rbmd" style="padding:26px 30px">${md(r.body)}</section>`);
  // las casillas [ ] del runbook se pueden marcar durante la respuesta (solo en esta vista)
  document.querySelectorAll(".rbmd input[type=checkbox]").forEach(c => { c.disabled = false; });
}

/* ---------------- MITRE ATT&CK ---------------- */
const MARKC = {detectada: "var(--st-good)", parcial: "var(--st-warn)", sin_cobertura: "var(--st-crit)", no_aplica: "var(--s-neutral)"};
let MITRE = null;
const fwNav = cur => subnav("#/" + cur, cur, []).replace('<div class="chips"></div>', `<div class="chips"><button class="${cur === "mitre" ? "on" : ""}" onclick="location.hash='#/mitre'">🧭 MITRE ATT&CK</button><button class="${cur === "owasp" ? "on" : ""}" onclick="location.hash='#/owasp'">🌐 OWASP Top 10</button></div>`);
async function renderMitre() {
  const q = qs(), days = +(q.get("days") || 30), f = q.get("f") || "", text = (q.get("q") || "").toLowerCase();
  view(`<div class="toolbar" style="margin-top:6px"><div><h1 class="page" style="margin:0 4px">MITRE ATT&CK · Enterprise</h1>
      <div class="sub" style="margin:0 4px">Tácticas y técnicas del adversario con las alertas de Wazuh, los runbooks del SOC y la cobertura de detección.</div></div>
    <span class="grow"></span>${fwNav("mitre")}</div><div id="mt"><div class="skel" style="height:420px"></div></div>`);
  MITRE = await api("api/mitre?days=" + days); if (!$("mt")) return;
  const S = MITRE.stats;
  window._mf = (k, v) => { const p = qs(); v ? p.set(k, v) : p.delete(k); p.delete("t"); location.hash = "#/mitre?" + p; };
  const maxA = Math.max(1, ...MITRE.tactics.flatMap(t => t.techniques.map(x => x.alerts)));
  const heat = n => n ? `var(--q${Math.min(7, 1 + Math.floor(Math.sqrt(n / maxA) * 6.99))})` : "var(--card)";
  const keep = x => (!text || (x.id + " " + x.name).toLowerCase().includes(text)) &&
    (!f || (f === "alertas" && x.alerts) || (f === "runbook" && x.runbooks.length) || (f === "sin" && x.mark === "sin_cobertura") || (f === "gap" && x.alerts && !x.runbooks.length));
  $("mt").innerHTML = `
  <div class="kpis">
    ${kpi("Técnicas", nf(S.tecnicas), MITRE.source === "stix" ? `ATT&CK v${esc(MITRE.version)}` : "lista básica (sin conexión)")}
    ${kpi(`Con alertas · ${days} d`, nf(S.con_alertas), `${short(S.alertas)} alertas de Wazuh`, "javascript:_mf('f','alertas')")}
    ${kpi("Con runbook", nf(S.con_runbook), "procedimiento de respuesta", "javascript:_mf('f','runbook')")}
    ${(() => { const g = MITRE.tactics.flatMap(t => t.techniques).filter(x => x.alerts && !x.runbooks.length).length; return kpi("Alertas sin runbook", nf(g), "huecos a documentar", "javascript:_mf('f','gap')", g > 0); })()}
    ${kpi("Cobertura marcada", `${nf(S.detectadas)}<span class="muted" style="font-size:14px;font-weight:500"> detectadas</span>`, `${nf(S.parciales)} parciales · ${nf(S.sin_cobertura)} sin cobertura`, "javascript:_mf('f','sin')")}
  </div>
  <div class="toolbar" style="margin-top:14px">
    <div class="chips">${[["", "Todas"], ["alertas", "Con alertas"], ["runbook", "Con runbook"], ["gap", "Alertas sin runbook"], ["sin", "Sin cobertura"]].map(([k, t]) => `<button class="${k === f ? "on" : ""}" onclick="_mf('f','${k}')">${t}</button>`).join("")}</div>
    <div class="chips">${[[7, "7 d"], [30, "30 d"], [90, "90 d"]].map(([k, t]) => `<button class="${k === days ? "on" : ""}" onclick="_mf('days',${k})">${t}</button>`).join("")}</div>
    <input style="flex:1;min-width:200px;width:auto" placeholder="Buscar técnica (T1059, Phishing…) — Enter" value="${esc(q.get("q") || "")}" onkeydown="if(event.key==='Enter')_mf('q',this.value)">
    ${META.role === "admin" ? `<button class="btn sm" onclick="api('api/mitre/refresh',{method:'POST'}).then(()=>toast('Actualizando ATT&CK en segundo plano'))" title="Descargar la última versión de ATT&CK">↻ ATT&CK</button>` : ""}</div>
  <div class="legend" style="margin:0 4px 10px">Fondo = alertas de Wazuh (${days} d) ${["--q1", "--q3", "--q5", "--q7"].map(v => `<i style="background:var(${v})"></i>`).join("")} · Borde = cobertura:
    ${Object.entries(MITRE.estados).map(([k, t]) => `<span><i style="background:${MARKC[k]}"></i>${t}</span>`).join("")} · 📘 tiene runbook
    ${MITRE.err_wazuh ? ` · <span class="err">Wazuh: ${esc(MITRE.err_wazuh)}</span>` : ""}</div>
  <p class="muted" style="font-size:12px;margin:0 4px 6px">Desliza la matriz hacia la derecha para ver las 15 tácticas →</p>
  <div class="matrix">${MITRE.tactics.map(t => { const items = t.techniques.filter(keep);
    return `<div class="mcol"><div class="mhead" title="${esc(t.id)} · ${esc(t.name)}"><b>${esc(t.name_es)}</b><small>${esc(t.name)} · ${items.length}</small>${t.alerts ? `<span class="pill bad" style="font-size:10.5px">${short(t.alerts)}</span>` : ""}</div>
      ${items.map(x => `<button class="mcell" style="background:${heat(x.alerts)};${x.mark ? `border-left:4px solid ${MARKC[x.mark]}` : ""};${x.alerts / maxA > .35 ? "color:#fff" : ""}" onclick="mitreDetail('${x.id}')"
        data-tip="${esc(`<b>${x.id}</b> ${esc(x.name)}<br>${nf(x.alerts)} alertas · ${x.runbooks.length} runbooks${x.subs ? ` · ${x.subs} subtécnicas` : ""}`)}">
        <span class="mid">${esc(x.id)}${x.runbooks.length ? " 📘" : ""}</span>${esc(x.name)}${x.alerts ? `<span class="mn">${short(x.alerts)}</span>` : ""}</button>`).join("") || `<div class="muted" style="font-size:12px;padding:8px">—</div>`}</div>`; }).join("")}</div>
  <p class="muted" style="font-size:12px;margin:10px 4px">Las reglas de Wazuh con la táctica antigua «Defense Evasion» aparecen en Sigilo y Debilitamiento de defensas. Fuente: <a class="go" href="https://attack.mitre.org/" target="_blank" rel="noopener">attack.mitre.org</a> ${MITRE.status ? "· " + esc(MITRE.status) : ""}</p>`;
  if (q.get("t")) mitreDetail(q.get("t").toUpperCase().split(".")[0], q.get("t").toUpperCase());
}
async function mitreDetail(tid, exact) {
  openModal(`<div id="md"><div class="skel"></div></div>`, true);
  let t; try { t = await api(`api/mitre/${encodeURIComponent(tid)}?days=${qs().get("days") || 30}`); } catch (e) { $("md").innerHTML = unavailable(e.message); return; }
  const W = t.wazuh || {}, mk = t.mark || {};
  $("md").innerHTML = `<div class="row" style="align-items:flex-start"><div><h2 style="margin:0">${esc(t.id)} · ${esc(t.name)}</h2>
      <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">${t.tactics_es.map(x => `<span class="pill info">${esc(x)}</span>`).join("")}${(t.platforms || []).slice(0, 6).map(p => `<span class="pill gray">${esc(p)}</span>`).join("")}</div></div>
    <a class="btn sm" href="${esc(t.url)}" target="_blank" rel="noopener">Ver en attack.mitre.org ↗</a></div>
  ${exact && exact !== tid ? `<p class="muted" style="font-size:13px">Abierto desde la subtécnica <b>${esc(exact)}</b>.</p>` : ""}
  <div class="g g21" style="margin-top:12px">
    <div>${t.desc ? `<div class="md" style="font-size:13.5px">${md(t.desc.replace(/\(Citation:[^)]*\)/g, ""))}</div>` : `<p class="muted">Descripción disponible al descargar ATT&CK (necesita salida a Internet).</p>`}
      ${t.detection ? `<h3 style="margin-top:14px">Detección (MITRE)</h3><div class="md muted" style="font-size:13px">${md(t.detection.replace(/\(Citation:[^)]*\)/g, ""))}</div>` : ""}
      ${t.subtechniques.length ? `<h3 style="margin-top:14px">Subtécnicas</h3><div style="display:flex;gap:6px;flex-wrap:wrap">${t.subtechniques.map(s => `<a class="pill gray" href="https://attack.mitre.org/techniques/${s.id.replace(".", "/")}/" target="_blank" rel="noopener" title="${esc(s.name)}">${esc(s.id)} ${esc(s.name)}</a>`).join("")}</div>` : ""}</div>
    <div class="g" style="align-content:start">
      <section class="card panel" style="box-shadow:none"><h3>Cobertura del SOC</h3>
        <select id="mkS">${opts(["", ...Object.keys(t.estados)], mk.status || "", {"": "Sin evaluar", ...t.estados})}</select>
        <textarea id="mkN" style="min-height:60px;margin-top:8px" placeholder="Cómo se detecta (regla Wazuh, Sysmon…), qué falta">${esc(mk.note || "")}</textarea>
        <div class="row" style="margin-top:8px"><span class="muted" style="font-size:11.5px">${mk.user ? `${esc(mk.user)} · ${esc(mk.at)}` : ""}</span><button class="btn sm primary" onclick="saveMark('mitre','${t.id}')">Guardar</button></div></section>
      <section class="card panel" style="box-shadow:none"><h3>Runbooks <small>${t.runbooks.length}</small></h3>${t.runbooks.length ? t.runbooks.map(r => `<div style="padding:4px 0"><a class="go" href="#/runbooks/${esc(r.slug)}" onclick="closeModal()">📘 ${esc(r.title)}</a> <span class="pill ${LVLC[r.level] ?? "gray"}" style="font-size:10.5px">${esc(r.level || "")}</span></div>`).join("")
        : `<div class="muted" style="font-size:13px">Sin runbook. <a class="go" href="#/runbooks/new/edit" onclick="closeModal()">Crear uno →</a></div>`}</section>
      <section class="card panel" style="box-shadow:none"><h3>Wazuh <small>${qs().get("days") || 30} días</small></h3>${W.error ? unavailable(W.error) : `<div style="font-size:22px;font-weight:700">${nf(W.total)} <span class="muted" style="font-size:13px;font-weight:400">alertas</span></div>
        ${(W.reglas || []).slice(0, 6).map(r => `<div style="font-size:12.5px;padding:3px 0">${lv(r.nivel)} ${esc(r.desc)} <span class="muted">#${esc(r.id)} · ${nf(r.n)}</span></div>`).join("")}
        ${(W.agentes || []).length ? `<div style="margin-top:6px">${W.agentes.map(([a, n]) => `<span class="pill gray" style="margin:2px">${esc(a)} ${nf(n)}</span>`).join("")}</div>` : ""}`}</section>
    </div></div>`;
}
async function saveMark(fw, key) {
  try { await api(`api/frameworks/${fw}/${encodeURIComponent(key)}`, {method: "PUT", body: {status: $("mkS").value, note: $("mkN").value}}); toast("Cobertura guardada"); closeModal(); router(); }
  catch (e) { toast("Error: " + e.message); }
}

/* ---------------- OWASP Top 10 ---------------- */
const OWC = {cumple: "", parcial: "warn", no_cumple: "bad", no_aplica: "gray"};
async function renderOwasp() {
  view(`<div class="toolbar" style="margin-top:6px"><div><h1 class="page" style="margin:0 4px">OWASP Top 10 · 2025</h1>
      <div class="sub" style="margin:0 4px">Los diez riesgos principales de las aplicaciones web, con controles, detección y la autoevaluación de los portales institucionales.</div></div>
    <span class="grow"></span>${fwNav("owasp")}</div><div id="ow"><div class="skel"></div></div>`);
  const d = await api("api/owasp"); if (!$("ow")) return; window._OW = d;
  const cnt = k => d.items.filter(i => (i.mark || {}).status === k).length;
  $("ow").innerHTML = `
  <div class="kpis">${kpi("Riesgos", "10", "edición 2025")}${kpi("Cumple", nf(cnt("cumple")), "controles implantados")}${kpi("Parcial", nf(cnt("parcial")), "con mejoras pendientes")}
    ${kpi("No cumple", nf(cnt("no_cumple")), "prioridad de remediación", "", cnt("no_cumple") > 0)}${kpi("Sin evaluar", nf(d.items.filter(i => !(i.mark || {}).status).length), "pulsa «Evaluar» en cada riesgo")}</div>
  <div class="g g2" style="margin-top:14px">${d.items.map(i => { const m = i.mark || {};
    return `<section class="card panel"><div class="row" style="flex-wrap:nowrap;align-items:flex-start">
        <div style="display:flex;gap:12px;align-items:flex-start"><span class="owid">${esc(i.id.split(":")[0])}</span>
          <div><h3 style="margin:0;display:block">${esc(i.es)}</h3><div class="muted" style="font-size:12px">${esc(i.en)} · ${esc(i.id)}</div></div></div>
        <span>${m.status ? `<span class="pill ${OWC[m.status]}">${esc(d.estados[m.status])}</span>` : '<span class="pill gray">Sin evaluar</span>'}</span></div>
      <p style="font-size:13.5px;margin:10px 0">${esc(i.resumen)}</p>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">${i.alertas ? `<span class="pill bad">${nf(i.alertas)} alertas web · ${d.days} d</span>` : ""}${i.mitre.map(t => `<a class="pill info mono" style="font-size:11px" href="#/mitre?t=${esc(t)}">${esc(t)}</a>`).join("")}
        ${i.runbooks.map(r => `<a class="pill" href="#/runbooks/${esc(r.slug)}">📘 ${esc(r.title)}</a>`).join("")}</div>
      <details><summary>Ejemplos, controles y detección</summary>
        <h4 style="margin:10px 0 4px;font-size:13px">Ejemplos</h4><ul style="margin:0;padding-left:18px;font-size:13px">${i.ejemplos.map(x => `<li>${esc(x)}</li>`).join("")}</ul>
        <h4 style="margin:10px 0 4px;font-size:13px">Controles recomendados</h4><ul style="margin:0;padding-left:18px;font-size:13px">${i.controles.map(x => `<li>${esc(x)}</li>`).join("")}</ul>
        <h4 style="margin:10px 0 4px;font-size:13px">Cómo detectarlo en el SOC</h4><ul style="margin:0;padding-left:18px;font-size:13px">${i.deteccion.map(x => `<li>${md(x).replace(/^<p>|<\/p>\s*$/g, "")}</li>`).join("")}</ul>
        <h4 style="margin:10px 0 4px;font-size:13px">Herramientas</h4><div>${i.herramientas.map(h => `<a class="pill gray" style="margin:2px" href="#/tools?q=${encodeURIComponent(h.split(" (")[0])}">🛠 ${esc(h)}</a>`).join("")}</div>
        <div style="margin-top:8px"><a class="go" href="https://top10.owasp.org/2025/" target="_blank" rel="noopener">Ficha oficial en OWASP ↗</a></div></details>
      <div class="row" style="margin-top:10px"><span class="muted" style="font-size:12px">${m.note ? "📝 " + esc(m.note).slice(0, 90) : ""}${m.user ? ` · ${esc(m.user)} ${esc((m.at || "").slice(0, 10))}` : ""}</span>
        <button class="btn sm" onclick="owaspEval('${i.id}')">Evaluar</button></div></section>`; }).join("")}</div>
  ${box(`Ataques web detectados por Wazuh · ${d.days} días`, d.err_wazuh ? unavailable(d.err_wazuh) : d.web.length ? `<div class="scroll"><table class="table"><thead><tr><th>Regla</th><th>OWASP</th><th class="n">IPs</th><th class="n">Alertas</th></tr></thead><tbody>
    ${d.web.map(w => `<tr><td>${esc(w.desc)}</td><td>${w.owasp ? `<span class="pill warn">${esc(w.owasp.split(":")[0])}</span>` : '<span class="muted">—</span>'}</td><td class="n">${nf(w.ips)}</td><td class="n"><b>${nf(w.n)}</b></td></tr>`).join("")}</tbody></table></div>
    <p class="muted" style="font-size:12px;margin-bottom:0">La categoría OWASP se asigna por palabras clave de la descripción de la regla; es orientativa.</p>` : `<div class="empty">Sin alertas web en el periodo.</div>`).replace('class="card panel "', 'class="card panel" style="margin-top:14px"')}`;
}
function owaspEval(id) {
  const i = _OW.items.find(x => x.id === id), m = i.mark || {};
  openModal(`<h2 style="margin:0 0 6px">${esc(i.id)} · ${esc(i.es)}</h2><p class="muted" style="margin:0 0 14px">Autoevaluación de los portales y aplicaciones de la institución frente a este riesgo.</p>
    <label>Estado</label><select id="mkS">${opts(["", ...Object.keys(_OW.estados)], m.status || "", {"": "Sin evaluar", ..._OW.estados})}</select>
    <label style="margin-top:12px">Notas (qué aplicaciones, qué falta, enlace a hallazgos de Vulnerabilidades)</label><textarea id="mkN" style="min-height:110px">${esc(m.note || "")}</textarea>
    <h4 style="margin:14px 0 4px;font-size:13px">Controles a revisar</h4><ul style="margin:0;padding-left:18px;font-size:13px">${i.controles.map(x => `<li>${esc(x)}</li>`).join("")}</ul>
    <div class="row" style="margin-top:14px"><span></span><span><button class="btn" onclick="closeModal()">Cancelar</button> <button class="btn primary" onclick="saveMark('owasp','${i.id}')">Guardar</button></span></div>`);
}

/* ======================================================================
   ROUTER
   ====================================================================== */
/* ======================================================================
   ASISTENTE DE INVESTIGACIÓN (IA)
   ====================================================================== */
const TOOLN = {resumen_soc: "Resumen del SOC", buscar_alertas: "Alertas Wazuh", amenazas: "Panorama de amenazas", comprobar_ioc: "Comprobar IoC", analizar_ioc: "Análisis de IoC",
  buscar_misp: "Búsqueda MISP", incidentes: "Incidentes", ver_incidente: "Detalle de incidente", buscar_runbooks: "Runbooks", ver_runbook: "Runbook", tecnica_mitre: "Técnica MITRE",
  vulnerabilidades: "Vulnerabilidades", estado_agentes: "Agentes", estado_portales: "Portales", herramientas: "Herramientas", proponer_incidente: "Propuesta de incidente", proponer_nota: "Propuesta de nota"};
const VERD = {verificada: ["✔ Verificada", ""], parcial: ["◐ Verificada en parte", "warn"], no_verificada: ["✕ No verificada", "bad"], sin_verificar: ["Sin verificar", "gray"], error: ["Error", "bad"]};
const STARTERS = [["🌐", "¿Cómo está el SOC ahora? Resume lo más urgente."], ["🔎", "Investiga la IP 185.220.101.1: qué hizo en nuestra red y si es peligrosa."],
  ["🛡", "¿Qué técnicas MITRE se repiten más esta semana y qué runbook aplica a cada una?"], ["🧯", "Revisa los incidentes abiertos con SLA vencido y propón los siguientes pasos."],
  ["🐞", "¿Qué vulnerabilidades críticas siguen abiertas y en qué equipos?"], ["📡", "¿Qué agentes están desconectados y desde cuándo?"]];
let AIS = null, _aiTimer;
const argsTxt = a => Object.entries(a || {}).filter(([, v]) => v !== "" && v != null).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(", ") : v}`).join(" · ");
const cite = h => h.replace(/\[(E\d+)\]/g, `<a class="cite" href="javascript:void 0" onclick="showEv(this,'$1')">$1</a>`);

async function renderAI(cid) {
  clearTimeout(_aiTimer);
  const [status, chats] = await Promise.all([api("api/ai/status"), api("api/ai/chats")]);
  AIS = status;
  const ro = ME && ME.role === "viewer";
  view(`<div class="toolbar" style="margin-top:6px"><div><h1 class="page" style="margin:0 4px">Asistente de investigación</h1>
      <div class="sub" style="margin:0 4px">Pregunta en lenguaje natural: el asistente consulta Wazuh, MISP, IoC, incidentes, runbooks y MITRE, cita cada dato y un verificador independiente revisa la respuesta.</div></div>
    <span class="grow"></span>${ME && ME.role === "admin" ? `<a class="btn sm" href="#/ai/audit">📋 Registro de uso</a>` : ""}<button class="btn primary sm" onclick="newChat()" ${ro || !status.on ? "disabled" : ""}>＋ Nueva investigación</button></div>
  ${status.on ? `<div class="aistat"><span class="dot ${status.local ? "ok" : "warn"}"></span><b>${esc(status.provider)}</b> · ${esc(status.model)}
      <span class="muted">${status.local ? "· modelo local: los datos no salen de la red" : "· proveedor en la nube" + (status.redact ? " · correos enmascarados antes de enviar" : "")} · ${status.tools.length} herramientas de solo lectura · las acciones solo se proponen</span></div>`
    : `<section class="card panel" style="margin-bottom:14px;border-color:color-mix(in srgb,var(--st-warn) 50%,var(--line))"><b>El asistente no está configurado.</b>
      <div style="font-size:13.5px;margin-top:6px">Un administrador debe definir en el <span class="mono">.env</span> del portal: <span class="mono">AI_PROVIDER</span> (<i>ollama</i> u <i>openai</i> para un modelo local o compatible, o <i>anthropic</i>), <span class="mono">AI_MODEL</span> y <span class="mono">AI_BASE_URL</span> o <span class="mono">AI_API_KEY</span>. Para datos del gobierno se recomienda un modelo local (Ollama/vLLM).</div></section>`}
  ${ro ? `<p class="muted" style="margin:0 4px 12px">Tu rol (solo lectura) no puede iniciar investigaciones.</p>` : ""}
  <div class="aiwrap"><aside class="card ailist"><div class="ailh">Investigaciones <span class="muted">${chats.length}</span></div>
      ${chats.length ? chats.map(c => `<a class="${c.id === cid ? "on" : ""}" href="#/ai/${c.id}"><b>${esc(c.title)}</b><small>${esc(c.updated)}</small></a>`).join("") : `<div class="empty" style="padding:18px 12px">Aún no hay investigaciones.</div>`}</aside>
    <section class="card aimain" id="aimain"></section></div>`);
  const M = $("aimain");
  if (!cid) {
    M.innerHTML = `<div class="aihello"><div class="aiicon">🤖</div><h2>¿Qué quieres investigar?</h2><p class="muted">Elige un ejemplo o escribe tu pregunta. Puedes pegar IPs, dominios, hashes o códigos de incidente.</p>
      <div class="starters">${STARTERS.map(([i, t]) => `<button ${ro || !status.on ? "disabled" : ""} onclick='newChat(${esc(JSON.stringify(t))})'><span>${i}</span>${esc(t)}</button>`).join("")}</div></div>`;
    return;
  }
  const c = await api("api/ai/chats/" + cid);
  M.innerHTML = `<div class="aihead"><div style="min-width:0"><b>${esc(c.title)}</b>${c.context ? `<div class="muted" style="font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">Contexto: ${esc(c.context.slice(0, 140))}</div>` : ""}</div>
      <span class="grow"></span><button class="btn sm" onclick="exportChat('${cid}')" title="Descargar como Markdown">⬇</button><button class="btn sm" onclick="delChat('${cid}')" title="Eliminar">✕</button></div>
    <div class="aimsgs" id="aimsgs">${c.messages.map(m => msgHtml(m, cid)).join("") || `<div class="empty">Escribe tu primera pregunta.</div>`}</div>
    <form class="aicompose" onsubmit="return sendAI(event,'${cid}')"><textarea id="aiq" rows="2" placeholder="Pregunta, o pega indicadores… (Enter para enviar, Mayús+Enter para salto de línea)" ${ro || !status.on ? "disabled" : ""}
        onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();this.form.requestSubmit()}"></textarea>
      <div class="row"><label class="chk" title="Un segundo modelo contrasta cada dato con las evidencias (más lento, más fiable)"><input type="checkbox" id="aiv" checked> Verificar respuesta</label>
        <button class="btn primary" id="aisend" ${ro || !status.on ? "disabled" : ""}>Enviar ➤</button></div></form>`;
  window._CHAT = c;
  const box = $("aimsgs"); box.scrollTop = box.scrollHeight;
  const pend = sessionStorage.getItem("ai_pending_" + cid);
  if (pend) { sessionStorage.removeItem("ai_pending_" + cid); $("aiq").value = pend; $("aiq").form.requestSubmit(); }
}

function msgHtml(m, cid) {
  if (m.role === "user") return `<div class="msg u"><div class="bub">${esc(m.content).replace(/\n/g, "<br>")}</div><small>${esc(m.at || "")}</small></div>`;
  const x = m.meta || {}, v = VERD[(x.verdict || {}).veredicto] || VERD.sin_verificar, ev = x.evidence || [];
  const props = (x.proposals || []).map((p, i) => `<div class="prop"><div><b>${p.tipo === "incidente" ? "📝 Propuesta de incidente" : "🗒 Propuesta de nota para " + esc(p.code)}</b>
      <div style="font-size:13px;margin-top:4px">${p.tipo === "incidente" ? `${sev(p.severity)} <b>${esc(p.title)}</b><div class="muted" style="margin-top:4px">${esc(p.summary).slice(0, 300)}</div>` : esc(p.text).slice(0, 400)}</div></div>
      <button class="btn sm primary" ${ME && ME.role === "viewer" ? "disabled" : ""} onclick='applyProposal(${esc(JSON.stringify(p))})'>${p.tipo === "incidente" ? "Revisar y crear…" : "Añadir nota"}</button></div>`).join("");
  return `<div class="msg a" data-ev='${esc(JSON.stringify(ev.map(e => ({ref: e.ref, tool: e.tool, args: e.args, data: e.data}))))}'>
    <div class="bub">${x.error ? `<div class="empty err" style="padding:6px 0;text-align:left">${esc(m.content)}</div>` : `<div class="md">${cite(md(m.content))}</div>`}
      ${props}
      ${x.error ? "" : `<div class="aimeta"><span class="pill ${v[1]}" title="${esc(((x.verdict || {}).problemas || []).join(" · "))}">${v[0]}${(x.verdict || {}).confianza != null ? ` · ${x.verdict.confianza}%` : ""}</span>
        ${ev.length ? `<button class="lnk" onclick="this.closest('.msg').querySelector('.evl').classList.toggle('on')">🔎 ${ev.length} evidencias</button>` : `<span class="muted">sin herramientas</span>`}
        ${x.injections ? `<span class="pill bad" title="Se detectaron posibles instrucciones incrustadas en los datos; se marcaron y no se siguieron">⚠ ${x.injections} posible(s) inyección(es)</span>` : ""}
        <span class="muted">${x.ms ? (x.ms / 1000).toFixed(1) + " s" : ""}${x.tokens ? ` · ${nf(x.tokens.in + x.tokens.out)} tokens` : ""}</span></div>
      ${((x.verdict || {}).problemas || []).length ? `<div class="vprob">Verificador: ${x.verdict.problemas.map(esc).join(" · ")}</div>` : ""}
      <div class="evl">${ev.map(e => `<details id="ev-${esc(e.ref)}"><summary><span class="pill info">${esc(e.ref)}</span> ${esc(TOOLN[e.tool] || e.tool)} <span class="muted">${esc(argsTxt(e.args))}</span></summary><pre>${esc(prettyJson(e.data))}</pre></details>`).join("")}</div>`}
    </div><small>${esc(m.at || "")}</small></div>`;
}
const prettyJson = s => { try { return JSON.stringify(JSON.parse(s), null, 2).slice(0, 6000); } catch (e) { return s; } };
function showEv(a, ref) {
  const m = a.closest(".msg"); m.querySelector(".evl").classList.add("on");
  const d = m.querySelector("#ev-" + ref); if (d) { d.open = true; d.scrollIntoView({block: "nearest", behavior: "smooth"}); d.classList.add("flash"); setTimeout(() => d.classList.remove("flash"), 1200); }
}

async function newChat(text = "", context = "", title = "") {
  const r = await api("api/ai/chats", {method: "POST", body: {title: title || (text ? text.slice(0, 70) : "Nueva investigación"), context}});
  if (text) sessionStorage.setItem("ai_pending_" + r.id, text);
  location.hash = "#/ai/" + r.id;
}
function investigate(title, context, question) { newChat(question, context, title); }
async function delChat(cid) { if (!confirm("¿Eliminar esta investigación?")) return; await api("api/ai/chats/" + cid, {method: "DELETE"}); location.hash = "#/ai"; }
function exportChat(cid) {
  const c = window._CHAT; if (!c) return;
  const txt = `# ${c.title}\n\n${c.context ? "> Contexto: " + c.context + "\n\n" : ""}` + c.messages.map(m => m.role === "user" ? `## 👤 ${m.at}\n\n${m.content}\n` :
    `## 🤖 ${m.at} · ${(VERD[(m.meta.verdict || {}).veredicto] || VERD.sin_verificar)[0]}\n\n${m.content}\n\n${(m.meta.evidence || []).map(e => `- **${e.ref}** ${TOOLN[e.tool] || e.tool} (${argsTxt(e.args)})`).join("\n")}\n`).join("\n");
  const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([txt], {type: "text/markdown"})); a.download = `investigacion-${cid}.md`; a.click();
}

async function sendAI(e, cid) {
  e.preventDefault();
  const q = $("aiq").value.trim(); if (!q) return false;
  $("aiq").value = ""; $("aisend").disabled = true;
  const box = $("aimsgs"); box.querySelector(".empty")?.remove();
  box.insertAdjacentHTML("beforeend", msgHtml({role: "user", content: q, at: "ahora"}) + `<div class="msg a live" id="ailive"><div class="bub"><div class="steps" id="aisteps"><div class="step on">Preparando…</div></div></div></div>`);
  box.scrollTop = box.scrollHeight;
  let rid;
  try { rid = (await api(`api/ai/chats/${cid}/messages`, {method: "POST", body: {text: q, verify: $("aiv").checked}})).run; }
  catch (err) { $("aisteps").innerHTML = `<div class="empty err">${esc(err.message)}</div>`; $("aisend").disabled = false; return false; }
  const poll = async () => {
    let r; try { r = await bg(() => api("api/ai/runs/" + rid)); } catch (err) { _aiTimer = setTimeout(poll, 2000); return; }
    const el = $("aisteps"); if (!el) return;
    el.innerHTML = r.events.map((ev, i) => {
      const last = i === r.events.length - 1 && r.status === "running";
      const t = ev.kind === "tool" ? `<span class="pill info">${esc(ev.ref)}</span> ${esc(TOOLN[ev.name] || ev.name)} <span class="muted">${esc(argsTxt(ev.args))}</span>`
        : ev.kind === "warn" ? `⚠ ${esc(ev.text)}` : ev.kind === "verify" ? `🛡 ${esc(ev.text)}` : esc(ev.text);
      return `<div class="step ${last ? "on" : "ok"} ${ev.kind}">${t}<span class="muted" style="margin-left:auto">${ev.t}s</span></div>`;
    }).join("");
    $("aimsgs").scrollTop = $("aimsgs").scrollHeight;
    if (r.status === "running") { _aiTimer = setTimeout(poll, 800); return; }
    renderAI(cid);
  };
  poll();
  return false;
}

async function applyProposal(p) {
  if (p.tipo === "incidente") { openNewIncident(p); return; }
  if (!confirm(`¿Añadir esta nota a ${p.code}?\n\n${p.text}`)) return;
  try { await api(`api/incidents/${encodeURIComponent(p.code)}/notes`, {method: "POST", body: {text: "[Asistente IA, revisado por " + META.user + "] " + p.text}}); toast("Nota añadida a " + p.code); }
  catch (err) { toast("Error: " + err.message); }
}

async function renderAIAudit() {
  const rows = await api("api/admin/ai-audit");
  const tot = rows.reduce((a, r) => a + (r.tokens_in || 0) + (r.tokens_out || 0), 0);
  view(`<div class="toolbar" style="margin-top:8px"><a class="btn sm" href="#/ai">← Asistente</a></div><h1 class="page">Registro de uso del asistente</h1>
    <div class="kpis" style="margin-bottom:14px">${kpi("Consultas", nf(rows.length))}${kpi("Tokens", short(tot))}${kpi("Verificadas", pct(rows.filter(r => r.verdict === "verificada").length, rows.length) + " %")}
      ${kpi("Inyecciones detectadas", nf(rows.reduce((a, r) => a + (r.injections || 0), 0)), "instrucciones en datos, marcadas", "", rows.some(r => r.injections))}</div>
    <section class="card"><div class="scroll" style="max-height:none"><table class="table"><thead><tr><th>Fecha</th><th>Usuario</th><th>Modelo</th><th>Herramientas</th><th class="n">Tokens</th><th>Verificación</th><th class="n">Tiempo</th></tr></thead><tbody>
    ${rows.map(r => `<tr><td>${esc(r.at)}</td><td>${esc(r.user)}</td><td class="muted">${esc(r.provider)} · ${esc(r.model)}</td><td style="font-size:12px">${esc((r.tools || "").split(",").filter(Boolean).map(t => TOOLN[t] || t).join(", ") || "—")}</td>
      <td class="n">${nf((r.tokens_in || 0) + (r.tokens_out || 0))}</td><td><span class="pill ${(VERD[r.verdict] || VERD.sin_verificar)[1]}">${(VERD[r.verdict] || VERD.sin_verificar)[0]}</span>${r.injections ? ' <span class="pill bad">⚠</span>' : ""}</td><td class="n">${((r.ms || 0) / 1000).toFixed(1)} s</td></tr>`).join("") || `<tr><td colspan="7" class="empty">Sin consultas.</td></tr>`}
    </tbody></table></div></section>`);
}

/* ---------------------------------------------------------- auditoría de seguridad de herramientas */
const FSEV = {critical: ["Crítica", "var(--st-crit)"], high: ["Alta", "var(--st-serious)"], medium: ["Media", "var(--st-warn)"], low: ["Baja", "var(--s-neutral)"], informational: ["Info", "var(--s-neutral)"]};
const fsev = s => s ? `<span class="pill" style="background:color-mix(in srgb,${FSEV[s][1]} 18%,transparent);color:${FSEV[s][1]}">${FSEV[s][0]}</span>` : `<span class="pill gray">Por validar</span>`;
let _audTimer;
async function toolAuditTab(t) {
  clearTimeout(_audTimer);
  const T = $("ttab"); if (!T) return;
  const d = await bg(() => api(`api/tools/${encodeURIComponent(t.slug)}/audits`));
  const aid = Number(qs().get("a")) || (d.rows[0] || {}).id;
  const cur = d.rows.find(r => r.id === aid);
  T.innerHTML = `<div class="row" style="align-items:flex-start;gap:14px;margin-bottom:12px"><div style="flex:1;min-width:240px"><b>Auditoría de seguridad del código</b>
      <div class="muted" style="font-size:12.5px;margin-top:4px;line-height:1.5">Análisis estático asistido por IA, con la metodología del <i>security-audit skill</i> de Cloudflare: reconocimiento → búsqueda por archivo → validación independiente de cada hallazgo → esquema → informe.
      Un hallazgo solo se confirma si describe la <b>frontera de confianza</b> que se cruza; lo que depende del despliegue queda «por validar». El código no se ejecuta.${d.local ? "" : " <b>El código se envía al proveedor de IA en la nube.</b>"}</div></div>
    <span style="display:flex;gap:6px;align-items:center"><select id="audp">${Object.entries(d.profiles).map(([k, p]) => `<option value="${k}" ${k === "standard" ? "selected" : ""}>${p.label} · hasta ${p.files} archivos</option>`).join("")}</select>
      <button class="btn primary sm" ${!d.ai || (cur && cur.status === "running") || (ME && ME.role === "viewer") ? "disabled" : ""} onclick="startAudit('${esc(t.slug)}')">▶ Auditar</button></span></div>
  ${!d.ai ? `<div class="empty">Configura el asistente de IA (AI_PROVIDER, AI_MODEL) para auditar.</div>` : ""}
  ${d.rows.length ? `<div class="chips" style="margin-bottom:12px;flex-wrap:wrap">${d.rows.slice(0, 8).map(r => `<button class="${r.id === aid ? "on" : ""}" onclick="location.hash='#/tools/${esc(t.slug)}?tab=audit&a=${r.id}'">#${r.id} · ${esc(r.started)} ${r.status === "running" ? "⏳" : r.status === "error" ? "⚠" : `· ${r.counts.confirmed}✔ ${r.counts.needs_validation}?`}</button>`).join("")}</div>` : ""}
  <div id="audv">${d.rows.length ? `<div class="skel"></div>` : `<div class="empty">Sin auditorías todavía.</div>`}</div>`;
  if (!cur) return;
  const a = await bg(() => api(`api/tools/${encodeURIComponent(t.slug)}/audits/${cur.id}`));
  const V = $("audv"); if (!V) return;
  if (a.status === "running") {
    const ph = parseInt(a.progress) || 1;
    V.innerHTML = `<div class="phases">${["Reconocimiento", "Búsqueda", "Validación", "Esquema", "Informe"].map((p, i) => `<div class="${i + 1 < ph ? "ok" : i + 1 === ph ? "on" : ""}"><span>${i + 1}</span>${p}</div>`).join("")}</div>
      <p class="muted" style="text-align:center">${esc(a.progress)}</p>`;
    _audTimer = setTimeout(() => toolAuditTab(t), 2000); return;
  }
  if (a.status === "error") { V.innerHTML = `<div class="empty err">La auditoría falló: ${esc(a.error)}</div>`; return; }
  const conf = a.findings.filter(f => f.status === "confirmed"), nv = a.findings.filter(f => f.status === "needs_validation");
  window._AUD = a;
  V.innerHTML = `<div class="g g4" style="gap:10px;margin-bottom:12px">${kpi("Confirmados", nf(conf.length), Object.keys(FSEV).map(s => conf.filter(f => f.severity === s).length ? `${conf.filter(f => f.severity === s).length} ${FSEV[s][0].toLowerCase()}` : "").filter(Boolean).join(" · ") || "ninguno", "", conf.some(f => ["critical", "high"].includes(f.severity)))}
      ${kpi("Por validar", nf(nv.length), "dependen del despliegue")}${kpi("Señales automáticas", nf(a.signals.length), "pistas de patrones, no hallazgos")}${kpi("Llamadas a la IA", nf(a.cost.llamadas || 0), `${short((a.cost.tokens_in || 0) + (a.cost.tokens_out || 0))} tokens · ${a.cost.archivos || 0} archivos`)}</div>
    <div class="row" style="margin-bottom:10px"><span class="muted" style="font-size:12.5px">Por ${esc(a.user)} · ${esc(a.started)} → ${esc(a.finished || "")}</span>
      <span><a class="btn sm" href="api/tools/${esc(t.slug)}/audits/${a.id}/export?fmt=md">⬇ Informe .md</a> <a class="btn sm" href="api/tools/${esc(t.slug)}/audits/${a.id}/export?fmt=json">⬇ findings.json</a></span></div>
    ${a.recon && a.recon.proposito ? `<details class="card panel" style="box-shadow:none;margin-bottom:12px"><summary><b>Reconocimiento</b> — ${esc(a.recon.proposito)}</summary>
      <div style="font-size:13px;margin-top:8px"><b>Puntos de entrada:</b><ul>${(a.recon.puntos_entrada || []).map(x => `<li>${esc(x)}</li>`).join("")}</ul><b>Fronteras de confianza:</b><ul>${(a.recon.fronteras || []).map(x => `<li>${esc(x)}</li>`).join("")}</ul></div></details>` : ""}
    ${a.findings.length ? a.findings.map(f => `<div class="finding ${f.status}"><div class="row" style="flex-wrap:nowrap;align-items:flex-start"><div style="min-width:0">
        <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">${fsev(f.severity)}<b>${esc(f.id)} · ${esc(f.title)}</b></div>
        <div class="muted" style="font-size:12.5px;margin-top:3px"><a class="go mono" href="#/tools/${esc(t.slug)}/file/${f.file_id}">${esc(f.file)}:${f.line_start}</a> · ${esc(f.class)}</div></div>
        ${f.status === "confirmed" ? `<button class="btn sm" ${ME && ME.role === "viewer" ? "disabled" : ""} onclick="findingToVuln('${esc(t.slug)}',${a.id},'${f.id}')" title="Crear una vulnerabilidad en seguimiento">→ Vulnerabilidades</button>` : ""}</div>
      ${f.status === "confirmed" ? `<div class="bnd"><div><small>Quién</small>${esc(f.boundary.principal)}</div><div><small>Entrada</small>${esc(f.boundary.input)}</div><div><small>Control superado</small>${esc(f.boundary.control)}</div><div><small>Resultado</small>${esc(f.boundary.result)}</div></div>
        <div style="font-size:13px"><b>Impacto:</b> ${esc(f.impact)}</div><div style="font-size:13px;margin-top:3px"><b>Corrección:</b> ${esc(f.fix)}</div>`
        : `<div style="font-size:13px;margin-top:6px"><b>Por qué falta validar:</b> ${esc(f.reason)}${f.fix ? `<div style="margin-top:3px"><b>Sugerencia:</b> ${esc(f.fix)}</div>` : ""}</div>`}
      ${f.evidence ? `<pre class="evcode">${esc(f.evidence)}</pre>` : ""}</div>`).join("") : `<div class="empty">✔ Sin hallazgos confirmados ni por validar en los archivos revisados.</div>`}
    ${a.signals.length ? `<details style="margin-top:12px"><summary class="muted">Señales automáticas (${a.signals.length}) — patrones que el cazador revisó</summary><table class="table" style="margin-top:6px"><tbody>
      ${a.signals.slice(0, 100).map(s => `<tr><td><span class="pill gray">${esc(s.type)}</span></td><td class="mono" style="font-size:12px"><a class="go" href="#/tools/${esc(t.slug)}/file/${s.file_id}">${esc(s.file)}:${s.line}</a></td><td class="mono" style="font-size:12px;word-break:break-all">${esc(s.code)}</td></tr>`).join("")}</tbody></table></details>` : ""}`;
}
async function startAudit(slug) {
  try { await api(`api/tools/${encodeURIComponent(slug)}/audits`, {method: "POST", body: {profile: $("audp").value}}); toast("Auditoría iniciada"); location.hash = `#/tools/${slug}?tab=audit&t=${Date.now()}`; }
  catch (err) { toast("Error: " + err.message); }
}
async function findingToVuln(slug, aid, fid) {
  try { const r = await api(`api/tools/${encodeURIComponent(slug)}/audits/${aid}/findings/${fid}/vuln`, {method: "POST"}); toast(r.nuevo ? "Añadida a Vulnerabilidades" : "Ya estaba en seguimiento (actualizada)"); }
  catch (err) { toast("Error: " + err.message); }
}

/* ---------------------------------------------------------- métricas de código (estilo Code-XR) */
const ccnCol = c => c > 25 ? "var(--st-crit)" : c > 15 ? "var(--st-serious)" : c > 10 ? "var(--st-warn)" : c > 5 ? "var(--q4)" : "var(--q2)";
async function toolMetricsTab(t) {
  const T = $("ttab"); T.innerHTML = `<div class="skel"></div>`;
  let m; try { m = await api(`api/tools/${encodeURIComponent(t.slug)}/metrics`); } catch (e) { T.innerHTML = unavailable(e.message); return; }
  if (!m.files.length) { T.innerHTML = `<div class="empty">No hay archivos de código legibles. Súbelos o guarda una copia local de GitHub.</div>`; return; }
  const X = m.totals;
  T.innerHTML = `<div class="g g4" style="gap:10px;margin-bottom:14px">${kpi("Líneas de código", nf(X.nloc), `${X.files} archivos`)}${kpi("Funciones", nf(X.functions))}
      ${kpi("Complejidad media", X.ccn_avg, "ciclomática ponderada por líneas", "", X.ccn_avg > 10)}${kpi("Funciones complejas", nf(X.complejas), "complejidad > 15", "", X.complejas > 0)}</div>
    <div class="row" style="margin-bottom:6px"><b>Ciudad del código</b><span class="muted" style="font-size:12px">Cada edificio es un archivo · altura = líneas · color = complejidad máxima</span></div>
    <div id="city" class="city"></div>
    <div class="legend" style="margin:6px 0 16px">${[["≤ 5", "var(--q2)"], ["6–10", "var(--q4)"], ["11–15", "var(--st-warn)"], ["16–25", "var(--st-serious)"], ["> 25", "var(--st-crit)"]].map(([l, c]) => `<span><i style="background:${c}"></i>${l}</span>`).join("")}</div>
    <div class="g g2"><div><b>Funciones más complejas</b><table class="table" style="margin-top:6px"><thead><tr><th>Función</th><th class="n">Complejidad</th><th class="n">Líneas</th><th class="n">Parám.</th></tr></thead><tbody>
      ${m.top_functions.slice(0, 12).map(f => `<tr><td><b class="mono" style="font-size:12.5px">${esc(f.name)}</b><div class="muted mono" style="font-size:11.5px">${esc(f.path)}:${f.line}</div></td>
        <td class="n"><span class="lv" style="background:${ccnCol(f.ccn)};color:#fff">${f.ccn}</span></td><td class="n">${f.nloc}</td><td class="n">${f.params}</td></tr>`).join("") || `<tr><td colspan="4" class="empty">Sin funciones.</td></tr>`}</tbody></table></div>
      <div><b>Archivos</b><table class="table" style="margin-top:6px"><thead><tr><th>Archivo</th><th class="n">Líneas</th><th class="n">Func.</th><th class="n">Media</th><th class="n">Máx.</th></tr></thead><tbody>
      ${m.files.slice(0, 15).map(f => { const fo = t.files.find(x => x.path === f.path); return `<tr ${fo ? `class="click" onclick="location.hash='#/tools/${esc(t.slug)}/file/${fo.id}'"` : ""}><td class="mono" style="font-size:12px;word-break:break-all">${esc(f.path)}</td><td class="n">${nf(f.nloc)}</td><td class="n">${f.functions}</td><td class="n">${f.ccn_avg}</td><td class="n"><b style="color:${ccnCol(f.ccn_max)}">${f.ccn_max}</b></td></tr>`; }).join("")}</tbody></table></div></div>
    <p class="muted" style="font-size:12px;margin-top:10px">Métricas calculadas con Lizard (las mismas que usa la extensión Code-XR de VS Code). Una complejidad alta no es un fallo de seguridad, pero sí dónde conviene revisar primero.</p>`;
  draw("city", el => cityChart(el, m.files, t));
}
function cityChart(el, files, t) {
  const W = el.clientWidth || 700, H = 300, n = files.length, cols = Math.ceil(Math.sqrt(n)), rows = Math.ceil(n / cols);
  const maxN = Math.max(...files.map(f => f.nloc), 1), cw = Math.min(46, (W - 60) / (cols + rows) * 1.6), ch = cw * .5;
  const ox = W / 2, oy = H - 20 - (rows + cols) * ch / 2 + ch;
  const sorted = files.map((f, i) => ({...f, c: i % cols, r: Math.floor(i / cols)})).sort((a, b) => (a.c + a.r) - (b.c + b.r));
  const g = sorted.map(f => {
    const x = ox + (f.c - f.r) * cw / 2, y = oy + (f.c + f.r) * ch / 2, h = 12 + Math.sqrt(f.nloc / maxN) * 190, w = cw * .42, d = ch * .42, col = ccnCol(f.ccn_max);
    const fo = t.files.find(z => z.path === f.path);
    return `<g class="bld" ${fo ? `onclick="location.hash='#/tools/${esc(t.slug)}/file/${fo.id}'"` : ""} onmousemove='showTip(event, ${esc(JSON.stringify(`<b>${esc(f.path)}</b><br>${nf(f.nloc)} líneas · ${f.functions} funciones<br>complejidad media ${f.ccn_avg} · máx. ${f.ccn_max}`))})' onmouseleave="hideTip()">
      <path d="M${x - w},${y - h} L${x},${y - h + d} L${x},${y + d} L${x - w},${y} Z" fill="${col}" style="filter:brightness(.82)"/>
      <path d="M${x},${y - h + d} L${x + w},${y - h} L${x + w},${y} L${x},${y + d} Z" fill="${col}" style="filter:brightness(.66)"/>
      <path d="M${x - w},${y - h} L${x},${y - h - d} L${x + w},${y - h} L${x},${y - h + d} Z" fill="${col}"/></g>`;
  }).join("");
  el.innerHTML = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">${g}</svg>`;
}

const PAGE = {"": "Resumen", threats: "Amenazas", agents: "Agentes", vulns: "Vulnerabilidades", iocs: "IoC", sites: "Portales", intel: "Inteligencia", ai: "Asistente IA",
  incidents: "Incidentes", runbooks: "Runbooks", mitre: "ATT&CK", owasp: "OWASP Top 10", tools: "Herramientas", contacts: "Contactos", account: "Mi cuenta", admin: "Usuarios y accesos"};
function greet(a) {
  const h = new Date().getHours(), n = ME ? (ME.display || ME.username).split(" ")[0] : "";
  if ($("greet")) $("greet").textContent = `${h < 12 ? "Buenos días" : h < 19 ? "Buenas tardes" : "Buenas noches"}${n ? ", " + n : ""}`;
  if ($("gtxt")) $("gtxt").textContent = `${new Date().toLocaleDateString("es-DO", {weekday: "long", day: "numeric", month: "long"})} · Portal SOC · ${PAGE[a || ""] || ""}`;
}
async function incCount() {
  try { const m = await bg(() => api("api/metrics")); const n = m.abiertos.length, el = $("cntInc"); if (!el) return;
    el.textContent = n || ""; el.classList.toggle("bad", m.vencidos.length > 0); el.title = `${n} abiertos · ${m.vencidos.length} con SLA vencido`; } catch (e) {}
}
document.addEventListener("keydown", e => { if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); $("sq") && $("sq").focus(); } });
async function router() {
  if (ME && ME.state !== "ok" && route()[0] !== "account") { location.hash = "#/account"; return; }
  const [a, b, c] = route();
  if (a !== "noc") leaveNoc();
  hideTip(); closeModal(); clearTimeout(_siteTimer); clearTimeout(_jobTimer); clearTimeout(_aiTimer); clearTimeout(_audTimer);
  document.querySelectorAll("#tabs a").forEach(x => x.classList.toggle("on", x.dataset.r === (a === "owasp" ? "mitre" : a || "")));
  greet(a);
  try {
    if (!a) await renderHome();
    else if (a === "threats") await renderThreats();
    else if (a === "agents") await renderAgents();
    else if (a === "intel") await renderIntel();
    else if (a === "vulns") await renderVulns();
    else if (a === "iocs") await renderIocs();
    else if (a === "sites") await renderSites();
    else if (a === "noc") await renderNoc();
    else if (a === "incidents" && !b) await renderIncidents();
    else if (a === "incidents") await renderIncident(b);
    else if (a === "runbooks" && !b) await renderRunbooks();
    else if (a === "runbooks" && c === "edit") await renderRunbookEdit(b);
    else if (a === "runbooks") await renderRunbook(b);
    else if (a === "contacts") await renderContacts();
    else if (a === "account") await renderAccount();
    else if (a === "mitre") await renderMitre();
    else if (a === "owasp") await renderOwasp();
    else if (a === "admin") await renderAdmin();
    else if (a === "ai" && b === "audit") await renderAIAudit();
    else if (a === "ai") await renderAI(b);
    else if (a === "tools" && !b) await renderTools();
    else if (a === "tools" && c === "edit") await renderToolEdit(b);
    else if (a === "tools") await renderTool(b, c, route()[3]);
    else view(`<div class="empty">Página no encontrada. <a class="go" href="#/">Volver al resumen</a></div>`);
  } catch (err) { view(`<div class="empty">No se pudo cargar: ${esc(err.message)}</div>`); }
}
addEventListener("hashchange", () => { router(); scrollTo(0, 0); });
(async () => {
  try { ME = await api("auth/me"); userMenu(); } catch (e) { return; }
  if (ME.state !== "ok") { location.hash = "#/account"; }
  try { META = await api("api/meta"); } catch (e) {}
  router(); incCount(); setInterval(incCount, 60000);
  setInterval(() => { if (!route()[0] && !document.hidden) bg(renderHomeRefresh); }, 60000);
})();
async function renderHomeRefresh() { const y = scrollY; await renderHome(); scrollTo(0, y); }
