"""
soc-bridge: API interna de solo lectura + sincronización periódica de la página
SOC/Estado en Wiki.js. Las credenciales quedan en el servidor; la Wiki solo
recibe Markdown ya filtrado.
"""
import asyncio
import json
import logging
import os
import pathlib
import re
import secrets
import threading
import time

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

import datetime

import feeds
import requests
from connectors import MISP, Shuffle, Wazuh, WikiJS, now_str
import ai as AI
import code_audit
import owasp as OWASP
from mitre import Mitre
from auth import EVENTS as AUTH_EVENTS, ROLES, Auth, ldap_conf
from intel import CATALOG, TYPE_ES, TYPES, Intel
from tools import SEED as TOOL_SEED, ToolFiles, lang_of
from tools_catalog import CATALOG as TOOL_CATALOG, to_tool
from store import SEVERITIES, STATUSES, VULN_STATUSES, Store
from m365 import KINDS as M365_KINDS, M365, M365Error, friendly as m365_friendly
from sophos import KINDS as SOPHOS_KINDS, SophosCentral, SophosError, friendly as sophos_friendly

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("soc-bridge")
from audit import Audit, AuditMiddleware, RingLog  # noqa: E402
import hashlib  # noqa: E402
import pentera  # noqa: E402
import deface  # noqa: E402
import screens  # noqa: E402
from exposure import Exposure, ScopeError  # noqa: E402
syslog = RingLog()
logging.getLogger().addHandler(syslog)
for _noisy in ("httpx", "httpcore", "urllib3", "multipart"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)  # registro del sistema visible en Auditoría

app = FastAPI(title="SOC Bridge", version="1.0")
TOKEN = os.environ["BRIDGE_TOKEN"]
INTERVAL = int(os.getenv("SYNC_INTERVAL", "300"))
HOST = os.getenv("HOST_IP", "localhost")
WAZUH_DASH = os.getenv("WAZUH_DASHBOARD_URL", f"https://{os.getenv('WAZUH_HOST', 'localhost')}")

wazuh, misp, shuffle = Wazuh(), MISP(), Shuffle()
WIKI_SYNC = os.getenv("WIKI_SYNC", "false").lower() in ("1", "true", "yes")
wiki = WikiJS() if WIKI_SYNC else None
SHUFFLE_UI = os.getenv("SHUFFLE_URL", f"http://{HOST}:3001").rstrip("/")
THREAT = {"1": "Alto", "2": "Medio", "3": "Bajo", "4": "Indefinido"}
THREAT_EN = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}
STATIC = pathlib.Path(__file__).parent / "static"
intel = Intel(os.path.join(os.path.dirname(os.getenv("DB_PATH", "/data/soc.db")), "intel.db"))
store = Store(os.getenv("DB_PATH", "/data/soc.db"), pathlib.Path(__file__).parent / "seed" / "runbooks")
audit = Audit(os.path.join(os.path.dirname(os.getenv("DB_PATH", "/data/soc.db")), "audit.db"))
AUDIT_DAYS = int(os.getenv("AUDIT_DAYS", "730") or 0)  # conservación de la auditoría de cambios (0 = siempre)
exposure = Exposure(os.path.join(os.path.dirname(os.getenv("DB_PATH", "/data/soc.db")), "exposure.db"))
m365 = M365(os.path.join(os.path.dirname(os.getenv("DB_PATH", "/data/soc.db")), "m365.db"))
sophos = SophosCentral(os.path.join(os.path.dirname(os.getenv("DB_PATH", "/data/soc.db")), "sophos.db"))
mitre_db = Mitre(os.path.dirname(os.getenv("DB_PATH", "/data/soc.db")))
toolfs = ToolFiles(os.path.join(os.path.dirname(os.getenv("DB_PATH", "/data/soc.db")), "tools"), store)
if not store._q("SELECT 1 FROM tools LIMIT 1"):
    for _t in TOOL_SEED:
        store.save_tool(None, _t, "system")


def _import_catalog(names=None, user="catálogo"):
    """Añade al repositorio las herramientas del catálogo que aún no existen (por nombre)."""
    have = {r["name"].lower() for r in store._q("SELECT name FROM tools")}
    n = 0
    for e in TOOL_CATALOG:
        if (names is None or e["n"] in names) and e["n"].lower() not in have:
            store.save_tool(None, to_tool(e), user)
            n += 1
    return n


# El catálogo se carga una sola vez; lo que el equipo borre no vuelve a aparecer (se puede re-añadir desde «Catálogo»)
_cat_mark = os.path.join(os.path.dirname(os.getenv("DB_PATH", "/data/soc.db")), "tools", ".catalogo_v1")
if not os.path.exists(_cat_mark):
    _import_catalog()
    open(_cat_mark, "w").write("ok")
_cat_mark2 = _cat_mark.replace(".catalogo_v1", ".catalogo_v2")  # v10: herramientas de seguridad de código e IA
if not os.path.exists(_cat_mark2):
    _import_catalog({e["n"] for e in TOOL_CATALOG if e["c"] == "Seguridad de código e IA"})
    open(_cat_mark2, "w").write("ok")
# Usuarios del portal: PORTAL_USERS="ana:clave1,luis:clave2" (+ PORTAL_USER/PORTAL_PASSWORD)
USERS = {}
for pair in os.getenv("PORTAL_USERS", "").split(","):
    if ":" in pair:
        u, _, pw = pair.strip().partition(":")
        USERS[u] = pw
if os.getenv("PORTAL_PASSWORD"):
    USERS[os.getenv("PORTAL_USER", "soc")] = os.getenv("PORTAL_PASSWORD")
LINKS = {
    "wazuh": WAZUH_DASH,
    "misp": os.getenv("MISP_BASE_URL", f"https://{HOST}:8443").rstrip("/"),
    "shuffle": SHUFFLE_UI,
    "wiki": os.getenv("WIKI_PUBLIC_URL", f"http://{HOST}:3000").rstrip("/"),
}
_cache = {"t": 0.0, "data": None, "wt": 0.0, "wiki": {"runbooks": [], "incidents": []}}
PORTAL_URL = os.getenv("PORTAL_PUBLIC_URL", f"http://{HOST}:8088/portal/")
STATUS_PATH = "soc/status"
basic = HTTPBasic()


authsvc = Auth(store)
authsvc.bootstrap(USERS)  # primera vez: migra PORTAL_USERS o crea «admin» con clave temporal (ver logs)
COOKIE = "soc_session"
COOKIE_SECURE = os.getenv("AUTH_COOKIE_SECURE", "false").lower() in ("1", "true", "yes")  # true si el portal va por HTTPS


def client_ip(request: Request) -> str:
    if os.getenv("AUTH_TRUST_PROXY", "false").lower() in ("1", "true", "yes"):
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "?"


def _scope_ip(scope, headers) -> str:
    if os.getenv("AUTH_TRUST_PROXY", "false").lower() in ("1", "true", "yes") and headers.get("x-forwarded-for"):
        return headers["x-forwarded-for"].split(",")[0].strip()
    return (scope.get("client") or ["?"])[0]


app.add_middleware(AuditMiddleware, audit=audit, client_ip=_scope_ip)


def portal_auth(request: Request) -> str:
    """Sesión por cookie + permisos por rol. Devuelve el nombre de usuario (lo usan todos los endpoints)."""
    ip = client_ip(request)
    u, s = authsvc.check(request.cookies.get(COOKIE), ip, background=request.headers.get("x-background") == "1")
    if not u:
        raise HTTPException(401, "Sesión no iniciada o caducada")
    request.state.user = u  # la auditoría registra quién fue, también si después se le niega el permiso
    path, m = request.url.path, request.method
    if m not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-soc") != "1":
        raise HTTPException(403, "Petición rechazada (falta la cabecera del portal)")  # protección CSRF
    if authsvc.state(u) != "ok" and not path.startswith("/portal/auth/"):
        raise HTTPException(428, "Antes de continuar cambia tu contraseña o activa el MFA")
    if path.startswith("/portal/api/admin") and u["role"] != "admin":
        raise HTTPException(403, "Solo los administradores pueden hacer esto")
    if u["role"] == "viewer" and m not in ("GET", "HEAD") and not path.startswith("/portal/auth/"):
        raise HTTPException(403, "Tu rol es de solo lectura")
    request.state.user, request.state.session = u, s
    return u["username"]


def actor(request: Request, x_api_key: str = Header(default="")) -> str:
    """Usuario del portal (sesión) o Shuffle (cabecera X-API-Key = BRIDGE_TOKEN)."""
    if x_api_key and secrets.compare_digest(x_api_key, TOKEN):
        request.state.actor = "shuffle"
        return "shuffle"
    return portal_auth(request)


def cached_summary(max_age: int = 60) -> dict:
    if _cache["data"] is None or time.time() - _cache["t"] > max_age:
        _cache["data"], _cache["t"] = collect(), time.time()
    return _cache["data"]


def auth(request: Request, x_api_key: str = Header(default="")):
    if not (x_api_key and secrets.compare_digest(x_api_key, TOKEN)):
        raise HTTPException(status_code=401, detail="No autorizado")
    request.state.actor = "integración (BRIDGE_TOKEN)"


def safe(fn, *a):
    try:
        return fn(*a), None
    except Exception as exc:
        log.warning("%s falló: %s", getattr(fn, "__qualname__", fn), exc)
        return None, str(exc)[:150]


def collect() -> dict:
    s = {"generado": now_str()}
    s["agentes"], s["err_agentes"] = safe(wazuh.agents_summary)
    s["alertas"], s["err_alertas"] = safe(wazuh.alerts_24h, 10)
    s["misp_hits"], s["err_misp_hits"] = safe(wazuh.misp_hits_24h)
    s["misp_eventos"], s["err_misp_eventos"] = safe(misp.recent_events, 7)
    s["misp_ioc_24h"], s["err_misp_ioc"] = safe(misp.ioc_count, 1)
    s["workflows"], s["err_workflows"] = safe(shuffle.workflows)
    return s


def esc(v) -> str:
    return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")


def render(s: dict) -> str:
    """Página Wiki soc/status (inglés) con componentes de Wiki.js: tarjetas, avisos y pestañas."""
    ok = lambda err: "🟢 Online" if not err else "🔴 Unreachable"
    misp = LINKS["misp"]
    a, al = s.get("agentes") or {}, s.get("alertas") or {}
    crit = sum(c for lv, c in (al.get("por_nivel") or []) if lv >= 13)
    hits = s.get("misp_hits")
    L = [
        "# SOC Status",
        f"> Updated automatically every {INTERVAL // 60} min · last update **{s['generado']}** · "
        f"do not edit by hand. Interactive view: [SOC Dashboard]({PORTAL_URL})",
        "{.is-info}", "",
    ]
    if crit or a.get("disconnected"):
        L += [f"> **Attention:** {crit} critical alerts (level 13–15) in 24 h · "
              f"{a.get('disconnected', 0)} disconnected agents.", "{.is-warning}", ""]
    L += [
        "## At a glance",
        f"- [{a.get('active', '—')} active agents *{a.get('disconnected', '—')} disconnected · "
        f"{a.get('never_connected', '—')} never connected*]({WAZUH_DASH})",
        f"- [{al.get('total', '—')} alerts ≥ 10 *{crit} critical in the last 24 h*]({WAZUH_DASH})",
        f"- [{len(hits) if hits is not None else '—'} MISP matches *IoCs seen in Wazuh alerts, 24 h*](/soc/runbooks/misp-ioc-match)",
        f"- [{s.get('misp_ioc_24h', '—')} new IoCs *Actionable (to_ids) added to MISP in 24 h*]({misp})",
        "{.grid-list}", "",
        "## Services",
        "| Platform | Status | Access |", "|---|---|---|",
        f"| Wazuh | {ok(s.get('err_alertas'))} | [Dashboard]({WAZUH_DASH}) |",
        f"| MISP | {ok(s.get('err_misp_eventos'))} | [MISP]({misp}) |",
        f"| Shuffle (SOAR) | {ok(s.get('err_workflows'))} | [Shuffle]({SHUFFLE_UI}) |",
        "",
        "# Details {.tabset}",
        "## Alerts (24 h)",
    ]
    if al:
        L += ["| Top rules | Alerts |", "|---|---|"]
        L += [f"| {esc(k)} | {v} |" for k, v in al.get("top_rules", [])] or ["| — | 0 |"]
        L += ["", "| Top agents | Alerts |", "|---|---|"]
        L += [f"| {esc(k)} | {v} |" for k, v in al.get("top_agents", [])] or ["| — | 0 |"]
    else:
        L.append(f"_Unavailable: {esc(s.get('err_alertas'))}_")
    L += ["", "## MISP matches"]
    if hits:
        L += ["| Time | Agent | IoC | Type | MISP event |", "|---|---|---|---|---|"]
        for h in hits:
            m = h.get("data", {}).get("misp", {})
            L.append(f"| {esc(h.get('timestamp', '')[:19])} | {esc(h.get('agent', {}).get('name'))} | "
                     f"`{esc(m.get('value'))}` | {esc(m.get('type'))} | "
                     f"[#{esc(m.get('event_id'))}]({misp}/events/view/{esc(m.get('event_id'))}) {esc(m.get('event_info'))} |")
        L += ["", "> Follow the [MISP IoC runbook](/soc/runbooks/misp-ioc-match). A match does not imply automatic blocking.", "{.is-warning}"]
    elif hits == []:
        L.append("No matches in the last 24 h. The absence of matches does not guarantee an indicator is safe.")
    else:
        L.append(f"_Unavailable: {esc(s.get('err_misp_hits'))}_")
    L += ["", "## Threat intel (7 days)"]
    ev = s.get("misp_eventos")
    if ev:
        L += ["| ID | Date | Event | Threat | Attributes |", "|---|---|---|---|---|"]
        L += [f"| [{e['id']}]({misp}/events/view/{e['id']}) | {esc(e['date'])} | {esc(e['info'])} | "
              f"{THREAT_EN.get(str(e['threat_level_id']), '-')} | {esc(e['attribute_count'])} |" for e in ev]
    elif ev == []:
        L.append("No new MISP events in the last 7 days.")
    else:
        L.append(f"_Unavailable: {esc(s.get('err_misp_eventos'))}_")
    L += ["", "## Automation"]
    wf = s.get("workflows")
    if wf:
        L += ["| Workflow | Triggers | Valid |", "|---|---|---|"]
        L += [f"| [{esc(w['name'])}]({SHUFFLE_UI}/workflows/{w['id']}) | {esc(', '.join(w['triggers']) or '-')} | "
              f"{'✅' if w['valid'] else '⚠️'} |" for w in wf]
    elif wf == []:
        L.append("No workflows yet.")
    else:
        L.append(f"_Unavailable: {esc(s.get('err_workflows'))}_")
    return "\n".join(L) + "\n"


def wiki_pages() -> dict:
    """Runbooks e incidentes publicados en la Wiki (para el portal)."""
    pages = [p for p in wiki.list_pages() if p["locale"] == wiki.locale and p.get("isPublished", True)]
    pick = lambda pre, skip=(): sorted(
        [{"title": p["title"], "path": p["path"], "description": p.get("description") or "",
          "updated": (p.get("updatedAt") or "")[:10]}
         for p in pages if p["path"].startswith(pre) and p["path"] not in skip],
        key=lambda x: x["updated"], reverse=True)
    return {"runbooks": pick("soc/runbooks/"), "incidents": pick("soc/incidents/")[:8]}


async def sync_loop():
    while True:
        try:
            summary = await asyncio.to_thread(collect)
            _cache["data"], _cache["t"] = summary, time.time()
            if not wiki:
                await asyncio.sleep(INTERVAL)
                continue
            r = await asyncio.to_thread(wiki.upsert, STATUS_PATH, "SOC Status",
                                        render(summary), "Auto-generated by soc-bridge",
                                        ["soc", "status", "auto"])
            log.info("Página %s %s", STATUS_PATH, r)
        except Exception as exc:
            log.error("Actualización falló: %s", exc)
        await asyncio.sleep(INTERVAL)


INTEGRITY_MIN = int(os.getenv("INTEGRITY_INTERVAL_MIN", "60") or 60)
_integrity_at: dict = {}


def _check_one(site: dict):
    if site.get("watch_content") and time.time() - _integrity_at.get(site["id"], 0) > INTEGRITY_MIN * 60:
        site = {**site, "_integrity": True}  # huella de scripts/estilos: como mucho una vez por hora
        _integrity_at[site["id"]] = time.time()
    res, ok, _changed = feeds.check_site(site)
    snap = res.pop("_snap", None)
    sid, prev = site["id"], site.get("state") or "pending"
    fails = 0 if ok else (site.get("fails") or 0) + 1
    # caído tras 2 fallos seguidos (evita falsas alarmas por un corte puntual); 1 fallo = degradado
    state = "up" if ok else "down" if fails >= 2 or prev == "down" else "degraded"
    res.update(fails=fails, state=state)
    if snap is not None and site.get("watch_content"):
        res.update(_deface_eval(site, snap))
    store.site_result(sid, res, ok)
    if state != prev and not (prev == "pending" and state == "up"):
        txt = {"up": "Vuelve a estar en línea", "down": f"Caído: {res['last_error']}", "degraded": f"Fallo puntual: {res['last_error']}"}.get(state, state)
        store.site_event(sid, state, txt)
        log.info("Portal %s: %s", site["name"], txt)
        if state == "down" and site.get("auto_incident"):
            code = propose_incident({"title": f"Portal caído: {site['name']}", "severity": "High",
                                     "detected_by": "Monitor de portales", "assets": site["url"],
                                     "summary": res["last_error"]}, "monitor", f"site-down-{sid}")
            _inc_event(sid, code)


def exposure_scope_nets():
    """Rangos de IP de ACME (los define el administrador en Exposición). Sirven para detectar secuestros de DNS."""
    try:
        return exposure.scope_nets()
    except Exception:
        return []


AUTO_INCIDENTS = os.getenv("AUTO_INCIDENTS", "false").lower() in ("1", "true", "yes")


def propose_incident(data: dict, source: str, key: str):
    """Con AUTO_INCIDENTS=false (por defecto) no se crea nada: queda una sugerencia que una persona confirma
    en Incidentes. Devuelve el código si se creó, o None si quedó propuesto."""
    if AUTO_INCIDENTS:
        return store.create_incident(data, source)
    store.suggest_incident(data, source, key)
    log.info("Sugerencia de incidente (%s): %s", source, data.get("title"))
    return None


def _inc_event(sid, code):
    store.site_event(sid, "incident", f"Incidente {code} creado automáticamente" if code
                     else "Sugerencia de incidente registrada: confírmala en Incidentes")


def _max_level(*lv):
    return max((x or "ok" for x in lv), key=deface.LEVELS.index)


DEFACE_LABEL = {"ok": "coincide con la versión aprobada", "cambio": "cambio de contenido",
                "sospecha": "posible desfiguración o inyección", "defacement": "DESFIGURACIÓN detectada"}


def _deface_eval(site: dict, snap: dict) -> dict:
    """Compara con la línea base; registra eventos e incidentes solo cuando el nivel sube."""
    if "assets" not in snap and site.get("snapshot"):  # sin huella nueva: se conserva la de la última lectura
        try:
            prev = json.loads(site["snapshot"]).get("assets")
            if prev:
                snap["assets"] = prev
        except ValueError:
            pass
    out = {"snapshot": json.dumps(snap, ensure_ascii=False), "page_title": snap["title"][:300]}
    if not site.get("baseline"):  # primera vez: esta versión se toma como la buena
        out.update(baseline=out["snapshot"], baseline_at=now_str()[:16], baseline_by="automático (primera comprobación)",
                   deface="ok", deface_pct=0, deface_reasons="[]")
        return out
    try:
        base = json.loads(site["baseline"])
    except ValueError:
        return out
    v = deface.compare(base, snap, site.get("change_threshold") or 40, scope=exposure_scope_nets())
    prev = site.get("deface_text") or site.get("deface") or "ok"
    vis = site.get("visual_level") or "ok"
    motivos = v["motivos"] + ([{"nivel": vis, "motivo": f"La página se ve un {site.get('visual_pct') or 0:g} % distinta "
                                                       "de la captura aprobada"}] if vis != "ok" else [])
    out.update(deface=_max_level(v["nivel"], vis), deface_text=v["nivel"], deface_pct=v["cambio_pct"],
               deface_reasons=json.dumps(motivos, ensure_ascii=False))
    sid, rank = site["id"], deface.LEVELS.index
    if v["nivel"] != prev:
        out["deface_at"] = now_str()[:16]
        detail = "; ".join(m["motivo"][:110] for m in v["motivos"][:3]) + (f" (+{len(v['motivos']) - 3} más)" if len(v["motivos"]) > 3 else "")
        if rank(v["nivel"]) > rank(prev):
            store.site_event(sid, "deface" if v["nivel"] in ("sospecha", "defacement") else "content",
                             f"{DEFACE_LABEL[v['nivel']].capitalize()}: {detail}")
            log.warning("Portal %s: %s (%s %%)", site["name"], DEFACE_LABEL[v["nivel"]], v["cambio_pct"])
            if site.get("auto_incident") and v["nivel"] in ("sospecha", "defacement"):
                crit = v["nivel"] == "defacement"
                code = propose_incident({
                    "title": f"{'Desfiguración' if crit else 'Posible desfiguración'} en {site['name']}",
                    "severity": "Critical" if crit else "High", "detected_by": "Monitor de portales (desfiguración)",
                    "assets": site["url"], "runbook": "desfiguracion-web",
                    "summary": f"{DEFACE_LABEL[v['nivel']].capitalize()} en {site['url']}"
                               f"{' (sin WAF: ' + site['waf'] + ')' if site.get('waf') in ('bypass', 'directo') else ''}.\n\n"
                               + "\n".join("- " + m["motivo"] for m in v["motivos"])
                               + "\n\nRevisa el detalle en Portales (qué cambió respecto a la versión aprobada)."},
                                        "monitor", f"site-deface-{sid}")
                _inc_event(sid, code)
        else:
            store.site_event(sid, "up" if v["nivel"] == "ok" else "content", f"Ahora: {DEFACE_LABEL[v['nivel']]}")
    return out


MONITOR_PARALLEL = int(os.getenv("MONITOR_PARALLEL", "16") or 16)


async def monitor_loop():
    """Comprueba los portales según su intervalo (MONITOR_PARALLEL en paralelo, 16 por defecto)."""
    n = 0
    sem = asyncio.Semaphore(MONITOR_PARALLEL)

    async def one(site):
        async with sem:
            try:
                await asyncio.to_thread(_check_one, site)
            except Exception as exc:
                log.warning("Portal %s: %s", site.get("name"), exc)
    while True:
        try:
            due = store.sites_due()
            await asyncio.gather(*[one(s) for s in due[:600]])
            n += 1
            if n % 360 == 0:
                store.prune_checks(30)
        except Exception as exc:
            log.error("Monitor de portales: %s", exc)
        await asyncio.sleep(30)


def _migrate_v3():
    """Pasa los IoC del módulo anterior (tabla iocs de soc.db) al motor de inteligencia, una sola vez."""
    if intel.kv("migrated_v3"):
        return
    by = {}
    for r in store._q("SELECT value, type, source, tlp, description, incident FROM iocs"):
        by.setdefault(r["source"] or "Carga manual", []).append(r)
    for name, rows in by.items():
        intel.add_text("\n".join(r["value"] for r in rows), {"source": name, "tlp": rows[0]["tlp"],
                       "description": rows[0]["description"], "incident": rows[0]["incident"]}, "migración")
    intel.kv("migrated_v3", "1")


def _auto_incident(new):
    """Con INTEL_AUTO_INCIDENT_SCORE=80 (por ejemplo), cada IoC nuevo visto con esa puntuación abre un incidente."""
    lim = int(os.getenv("INTEL_AUTO_INCIDENT_SCORE", "0") or 0)
    if not lim:
        return
    for x in new:
        if x["score"] >= lim:
            code = propose_incident({
                "title": f"IoC visto en Wazuh: {x['value']}", "severity": "High" if x["score"] < 90 else "Critical",
                "detected_by": "Motor de inteligencia · correlación con Wazuh", "assets": x["agent"], "iocs": x["value"],
                "runbook": "misp-ioc-match",
                "summary": f"El indicador {x['value']} (puntuación {x['score']}) aparece en el campo {x['field']} de alertas de "
                           f"{x['agent']}. Regla: {x['rule']}. Fuentes: " + ", ".join(f["name"] for f in x["fuentes"])},
                "inteligencia", f"ioc-{x['value']}")
            if code:
                log.info("Incidente %s por IoC %s", code, x["value"])


def _correlate_window():
    lt = int((time.time() - 120) * 1000)  # margen de 2 min para alertas que llegan tarde al indexer
    gte = int(intel.kv("corr_last") or (lt - 3600 * 1000))
    if lt - gte < 60000:
        return
    total, new = intel.correlate(wazuh, gte, lt, additive=True)
    intel.kv("corr_last", lt)
    intel.kv("corr_last_ok", now_str()[:16])
    intel.kv("corr_msg", f"{total} coincidencias en la última ventana · {len(new)} nuevas")
    if new:
        log.info("Correlación: %s coincidencias nuevas", len(new))
        _auto_incident(new)


async def intel_loop():
    """Descarga las fuentes cuando les toca y correlaciona con Wazuh cada 5 minutos."""
    await asyncio.to_thread(_migrate_v3)
    n = 0
    while True:
        try:
            for src in intel.due_sources():
                intel.enqueue(("src", src["id"]), intel.run_source, src["id"], None, "programado", "first", misp)
            if n % 5 == 0:
                await asyncio.to_thread(_correlate_window)
            if n % 60 == 0:
                await asyncio.to_thread(authsvc.cleanup)
                await asyncio.to_thread(audit.purge, AUDIT_DAYS)
        except Exception as exc:
            log.warning("Motor de inteligencia: %s", exc)
            intel.kv("corr_msg", f"Error: {str(exc)[:150]}")
        n += 1
        await asyncio.sleep(60)


def _sophos_sync():
    sophos.sync(intel, feeds.parse_iocs, lambda d: propose_incident({k: v for k, v in d.items() if k != "_key"}, "sophos",
                                                                         "sophos-" + str(d.get("_key") or d["title"])))


async def sophos_loop():
    """Sophos Central no envía webhooks: se consultan sus alertas cada SOPHOS_POLL_MIN minutos."""
    await asyncio.sleep(20)
    while True:
        if sophos.on:
            await asyncio.to_thread(_sophos_sync)
        await asyncio.sleep(sophos.poll_min * 60)


def _m365_sync():
    m365.sync(intel, lambda d, key: propose_incident(d, "m365", key))


async def m365_loop():
    """Microsoft Graph no se suscribe aquí a webhooks: se consultan las alertas de Defender cada M365_POLL_MIN min."""
    await asyncio.sleep(25)
    while True:
        if m365.on:
            await asyncio.to_thread(_m365_sync)
        await asyncio.sleep(m365.poll_min * 60)


@app.on_event("startup")
async def startup():
    asyncio.create_task(sync_loop())
    asyncio.create_task(monitor_loop())
    asyncio.create_task(intel_loop())
    asyncio.create_task(sophos_loop())
    asyncio.create_task(m365_loop())


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/portal/")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    try:
        resp = await call_next(request)
    except Exception as exc:  # error no controlado: una línea clara en el log y un mensaje útil (sin traza) al navegador
        import traceback
        fr = [f for f in traceback.extract_tb(exc.__traceback__) if f.filename.startswith("/app/") or "soc-portal" in f.filename]
        where = " ← ".join(f"{os.path.basename(f.filename)}:{f.lineno} {f.name}" for f in reversed(fr[-3:]))
        log.error("500 en %s %s: %s: %s [%s]", request.method, request.url.path, type(exc).__name__, exc, where)
        resp = JSONResponse({"detail": f"Error interno ({type(exc).__name__}). Revisa: docker logs soc-bridge | grep '500 en'"},
                            status_code=500)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    return resp


@app.get("/portal/login", include_in_schema=False)
def login_page(request: Request):
    u, _ = authsvc.check(request.cookies.get(COOKIE), client_ip(request), background=True)
    if u:
        return RedirectResponse("/portal/")
    return HTMLResponse((STATIC / "login.html").read_text(encoding="utf-8").replace("{{LDAP}}", "1" if ldap_conf()["on"] else "0"),
                        headers={"Cache-Control": "no-store"})


def _set_cookie(resp, token):
    resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=COOKIE_SECURE, path="/", max_age=12 * 3600)
    return resp


@app.get("/portal/auth/config", include_in_schema=False)
def auth_config():
    """Configuración pública del inicio de sesión (la usa la interfaz React)."""
    return {"ldap": ldap_conf()["on"]}


@app.post("/portal/auth/login", include_in_schema=False)
def auth_login(request: Request, data: dict = Body(...)):
    r = authsvc.login(data.get("username"), data.get("password"), client_ip(request), request.headers.get("user-agent", ""))
    if "error" in r:
        time.sleep(0.6)  # frena la fuerza bruta
        return JSONResponse({"error": r["error"]}, status_code=401)
    if "mfa" in r:
        return {"mfa": r["mfa"]}
    return _set_cookie(JSONResponse({"ok": True}), r["ok"])


@app.post("/portal/auth/mfa", include_in_schema=False)
def auth_mfa(request: Request, data: dict = Body(...)):
    r = authsvc.login_mfa(data.get("ticket"), data.get("code"), client_ip(request), request.headers.get("user-agent", ""))
    if "error" in r:
        time.sleep(0.6)
        return JSONResponse({"error": r["error"]}, status_code=401)
    return _set_cookie(JSONResponse({"ok": True}), r["ok"])


@app.post("/portal/auth/logout", include_in_schema=False)
def auth_logout(request: Request):
    authsvc.logout(request.cookies.get(COOKIE), client_ip(request))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/")
    return resp


@app.get("/portal/auth/me")
def auth_me(request: Request, user: str = Depends(portal_auth)):
    u = request.state.user
    import hashlib as _h
    cur = _h.sha256((request.cookies.get(COOKIE) or "").encode()).hexdigest()
    return authsvc.public(u) | {"state": authsvc.state(u), "sessions": authsvc.sessions_of(u["id"], cur), "roles": ROLES}


@app.post("/portal/auth/password")
def auth_password(request: Request, data: dict = Body(...), user: str = Depends(portal_auth)):
    err = authsvc.change_password(request.state.user, data.get("current"), data.get("new"), client_ip(request))
    if err:
        raise HTTPException(400, err)
    import hashlib as _h
    authsvc.revoke(request.state.user["id"], keep=_h.sha256((request.cookies.get(COOKIE) or "").encode()).hexdigest())
    return {"ok": True}


@app.post("/portal/auth/mfa/setup")
def auth_mfa_setup(request: Request, user: str = Depends(portal_auth)):
    if request.state.user["mfa_enabled"]:
        raise HTTPException(400, "El MFA ya está activado")
    return authsvc.mfa_setup(request.state.user)


@app.post("/portal/auth/mfa/enable")
def auth_mfa_enable(request: Request, data: dict = Body(...), user: str = Depends(portal_auth)):
    codes, err = authsvc.mfa_enable(request.state.user, data.get("code"), client_ip(request))
    if err:
        raise HTTPException(400, err)
    return {"recovery": codes}


@app.post("/portal/auth/mfa/disable")
def auth_mfa_disable(request: Request, data: dict = Body(...), user: str = Depends(portal_auth)):
    err = authsvc.mfa_disable(authsvc.user(uid=request.state.user["id"]), data.get("code"), client_ip(request))
    if err:
        raise HTTPException(400, err)
    return {"ok": True}


@app.post("/portal/auth/sessions/revoke")
def auth_revoke(request: Request, data: dict = Body(...), user: str = Depends(portal_auth)):
    import hashlib as _h
    cur = _h.sha256((request.cookies.get(COOKIE) or "").encode()).hexdigest()
    authsvc.revoke(request.state.user["id"], data.get("id") or None, keep=cur)
    return {"ok": True}


# ---------------------------------------------------------------- administración de usuarios
@app.get("/portal/api/admin/users")
def admin_users(user: str = Depends(portal_auth)):
    return {"rows": authsvc.users(), "stats": authsvc.stats(), "roles": ROLES, "events": AUTH_EVENTS}


@app.post("/portal/api/admin/users")
def admin_create(request: Request, data: dict = Body(...), user: str = Depends(portal_auth)):
    r, err = authsvc.create_user(data, request.state.user, client_ip(request))
    if err:
        raise HTTPException(400, err)
    return r


@app.put("/portal/api/admin/users/{uid}")
def admin_update(uid: int, request: Request, data: dict = Body(...), user: str = Depends(portal_auth)):
    r, err = authsvc.update_user(uid, data, request.state.user, client_ip(request))
    if err:
        raise HTTPException(400, err)
    return r


@app.delete("/portal/api/admin/users/{uid}")
def admin_delete(uid: int, request: Request, user: str = Depends(portal_auth)):
    err = authsvc.delete_user(uid, request.state.user, client_ip(request))
    if err:
        raise HTTPException(400, err)
    return {"ok": True}


@app.get("/portal/api/admin/authlog")
def admin_log(q: str = "", event: str = "", days: int = 7, user: str = Depends(portal_auth)):
    return authsvc.log(q, event, max(1, min(365, days)))


@app.get("/portal/", include_in_schema=False)
def portal(request: Request):
    u, _ = authsvc.check(request.cookies.get(COOKIE), client_ip(request), background=True)
    if not u:
        return RedirectResponse("/portal/login")
    # Se añade ?v=<fecha del archivo> a app.js para que el navegador no use una versión vieja en caché
    v = int(max(f.stat().st_mtime for f in STATIC.glob("*.*")))
    html = (STATIC / "index.html").read_text(encoding="utf-8").replace('src="assets/app.js"', f'src="assets/app.js?v={v}"')
    return HTMLResponse(html, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})


app.mount("/portal/assets", StaticFiles(directory=STATIC), name="assets")


@app.get("/portal/data")
def portal_data(user: str = Depends(portal_auth)):
    return {"summary": cached_summary(), "links": LINKS, "user": user,
            "incidents": {"stats": store.stats(), "recent": store.incidents(limit=6)},
            "runbooks": store.runbooks(), "metrics": store.metrics(), "vulns": store.vuln_stats(),
            "sites": [{"name": x["name"], "state": x["state"], "enabled": x["enabled"]} for x in store._q("SELECT name, state, enabled FROM sites")],
            "iocs": _intel_brief()}


# ---------------------------------------------------------------- panel ampliado
_pc: dict = {}
# Segundos de caché por consulta: el indexer de Wazuh va justo de disco, así que los rangos largos se cachean más
TTL = {"24h": 120, "7d": 600, "30d": 1800}


def cached(key: str, ttl: int, fn, *a):
    hit = _pc.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    val = fn(*a)
    _pc[key] = (time.time(), val)
    return val


def _wrap(fn, *a):
    try:
        return fn(*a)
    except HTTPException:
        raise
    except Exception as exc:
        log.warning("%s falló: %s", getattr(fn, "__qualname__", fn), exc)
        raise HTTPException(502, f"Fuente no disponible: {str(exc)[:160]}")


@app.get("/portal/api/threats")
def threats(range: str = "24h", min_level: int = 10, user: str = Depends(portal_auth)):
    rng = range if range in wazuh.RANGES else "24h"
    lv = min(max(min_level, 3), 15)
    return _wrap(cached, f"thr:{rng}:{lv}", TTL[rng], wazuh.threats, rng, lv)


@app.get("/portal/api/alerts")
def alerts(field: str, value: str, range: str = "24h", min_level: int = 10, user: str = Depends(portal_auth)):
    if field not in wazuh.ALERT_FIELDS:
        raise HTTPException(400, "Campo no permitido")
    return _wrap(wazuh.alerts_by, field, value, range, min(max(min_level, 0), 15))


@app.get("/portal/api/agents")
def agents_detail(user: str = Depends(portal_auth)):
    return _wrap(cached, "agents", 300, wazuh.agents_detail)


@app.get("/portal/api/intel")
def intel_page(user: str = Depends(portal_auth)):
    out = {}
    for k, fn, a, ttl in (("eventos", misp.recent_events, (30,), 600), ("iocs", misp.ioc_stats, (7,), 900),
                          ("shuffle", shuffle.executions, (), 120)):
        try:
            out[k] = cached("intel:" + k, ttl, fn, *a)
        except Exception as exc:
            log.warning("intel %s falló: %s", k, exc)
            out[k], out["err_" + k] = None, str(exc)[:160]
    return out


@app.get("/portal/api/ioc")
def ioc_search(q: str, user: str = Depends(portal_auth)):
    q = q.strip()
    if len(q) < 3:
        raise HTTPException(400, "Escribe al menos 3 caracteres")
    out = {"q": q, "incidentes": [{"code": i["code"], "title": i["title"], "status": i["status"], "severity": i["severity"]}
                                  for i in store.incidents(q=q, limit=10)]}
    try:
        r = intel_normalize(q)
        if r:
            hits = intel.lookup([r[0]])
            out["intel"] = intel.describe(hits[r[0]]) if r[0] in hits else {"score": 0, "fuentes": []}
    except Exception as exc:
        out["err_intel"] = str(exc)[:160]
    for k, fn in (("misp", misp.search), ("wazuh", wazuh.search_ioc)):
        try:
            out[k] = fn(q)
        except Exception as exc:
            out[k], out["err_" + k] = None, str(exc)[:160]
    return out


@app.get("/portal/api/metrics")
def metrics(user: str = Depends(portal_auth)):
    return store.metrics()


# ---------------------------------------------------------------- vulnerabilidades
@app.get("/portal/api/vulns/wazuh")
def vulns_wazuh(severity: str = "", agent: str = "", q: str = "", user: str = Depends(portal_auth)):
    return _wrap(cached, f"vw:{severity}:{agent}:{q}", 600, wazuh.vulns, severity, agent, q)


@app.get("/portal/api/vulns/wazuh/{cve}")
def vulns_wazuh_cve(cve: str, user: str = Depends(portal_auth)):
    return _wrap(cached, "vwc:" + cve, 600, wazuh.vuln_detail, cve)


@app.get("/portal/api/vulns")
def vulns_list(status: str = "active", severity: str = "", source: str = "", q: str = "", user: str = Depends(portal_auth)):
    return {"rows": store.vulns(status or None, severity or None, source or None, q or None), "stats": store.vuln_stats(),
            "statuses": VULN_STATUSES, "today": datetime.date.today().isoformat()}


@app.post("/portal/api/vulns")
def vulns_create(data: dict = Body(...), user: str = Depends(actor)):
    vid, new = store.save_vuln(None, data, user, source=data.get("source") or "manual")
    if not vid:
        raise HTTPException(400, "Indica al menos un título o un CVE")
    return {"id": vid}


@app.put("/portal/api/vulns/{vid}")
def vulns_update(vid: int, data: dict = Body(...), user: str = Depends(portal_auth)):
    store.save_vuln(vid, data, user)
    return {"ok": True}


@app.delete("/portal/api/vulns/{vid}")
def vulns_delete(vid: int, user: str = Depends(portal_auth)):
    store.delete_vuln(vid)
    return {"ok": True}


@app.post("/portal/api/vulns/track")
def vulns_track(data: dict = Body(...), user: str = Depends(portal_auth)):
    """Pasa a seguimiento un CVE detectado por Wazuh (un registro por CVE con todos los equipos afectados)."""
    cve = (data.get("cve") or "").strip()
    if not cve:
        raise HTTPException(400, "Falta el CVE")
    det = _wrap(cached, "vwc:" + cve, 600, wazuh.vuln_detail, cve)
    sev = (data.get("severity") or (det[0]["severity"] if det else "") or "Medium").capitalize()
    pk = sorted({d["package"] for d in det if d.get("package")})
    vid, new = store.save_vuln(None, {
        "cve": cve, "title": (det[0].get("description") or "")[:200] if det and det[0].get("description") else f"{cve} en {', '.join(pk) or 'paquete'}",
        "severity": sev if sev in SEVERITIES else "Medium", "cvss": det[0].get("score") if det else None,
        "asset": ", ".join(d["agent"] for d in det if d.get("agent"))[:2000], "package": ", ".join(pk)[:300],
        "solution": f"Actualizar {', '.join(pk)}. Referencia: {det[0].get('reference') or ''}" if det else "",
        "notes": f"{len(det)} equipos afectados según Wazuh"}, user, source="wazuh", ext_key="wazuh|" + cve)
    return {"id": vid, "nuevo": new}


@app.post("/portal/api/vulns/import")
def vulns_import(data: dict = Body(...), user: str = Depends(portal_auth)):
    scanner = re.sub(r"[^a-z0-9-]", "", (data.get("scanner") or "csv").lower()) or "csv"
    parsed = feeds.parse_scan(data.get("text") or "", scanner)
    if parsed.get("error"):
        raise HTTPException(400, parsed["error"])
    if data.get("preview"):
        return {"total": len(parsed["items"]), "omitidos": parsed["omitidos"], "columnas": parsed["columnas"],
                "muestra": parsed["items"][:8]}
    new = upd = 0
    for it in parsed["items"]:
        _, created = store.save_vuln(None, {k: it[k] for k in it if k != "ext_key"}, user, source=scanner, ext_key=it["ext_key"])
        new += created; upd += (not created)
    return {"nuevas": new, "actualizadas": upd, "omitidos": parsed["omitidos"]}


# ---------------------------------------------------------------- inteligencia de amenazas (IoC)
def intel_normalize(tok):
    from intel import normalize
    return normalize(tok)


def _intel_brief():
    try:
        o = intel.cached("brief", 60, lambda: {"activos": sum(x["n"] or 0 for x in intel.sources()),
                                               "vistos": intel.overview()["coincidencias_24h"]})
        return o
    except Exception:
        return {"activos": 0, "vistos": 0}


@app.get("/portal/api/intel/overview")
def intel_overview(user: str = Depends(portal_auth)):
    o = intel.overview()
    o["fuentes"] = [intel.public(x) for x in o.get("fuentes") or []]
    o["tipos_es"] = TYPE_ES
    o["providers"] = intel.providers()
    return o


@app.get("/portal/api/intel/overlap")
def intel_overlap(user: str = Depends(portal_auth)):
    return intel.overlap()


@app.get("/portal/api/intel/jobs")
def intel_jobs(user: str = Depends(portal_auth)):
    return {"jobs": intel.jobs(15), "cola": len(intel.pending)}


@app.get("/portal/api/intel/catalog")
def intel_catalog(user: str = Depends(portal_auth)):
    names = {s["name"] for s in intel.sources()}
    return [{**c, "added": c["name"] in names} for c in CATALOG]


@app.post("/portal/api/intel/catalog")
def intel_catalog_add(data: dict = Body(...), user: str = Depends(portal_auth)):
    return {"added": intel.add_catalog(set(data.get("keys") or []), user)}


@app.get("/portal/api/intel/sources")
def intel_sources(user: str = Depends(portal_auth)):
    return [intel.public(x) for x in intel.sources()]


@app.post("/portal/api/intel/sources")
def intel_source_add(data: dict = Body(...), user: str = Depends(portal_auth)):
    if not (data.get("name") or "").strip():
        raise HTTPException(400, "El nombre es obligatorio")
    if intel.source_by_name(data["name"].strip()):
        raise HTTPException(400, "Ya existe una fuente con ese nombre")
    kind = data.get("kind") or "feed"
    if kind == "feed" and not re.match(r"^https?://", data.get("url") or ""):
        raise HTTPException(400, "La URL del feed debe empezar por http:// o https://")
    sid = intel.save_source(None, {**data, "name": data["name"].strip(), "kind": kind}, user)
    if kind in ("feed", "misp"):
        intel.enqueue(("src", sid), intel.run_source, sid, None, user, "first", misp)
    return intel.public(intel.source(sid))


@app.put("/portal/api/intel/sources/{sid}")
def intel_source_edit(sid: int, data: dict = Body(...), user: str = Depends(portal_auth)):
    data.pop("kind", None)
    intel.save_source(sid, data, user)
    return intel.public(intel.source(sid))


@app.post("/portal/api/intel/sources/{sid}/run")
def intel_source_run(sid: int, user: str = Depends(portal_auth)):
    src = intel.source(sid)
    if not src or src["kind"] not in ("feed", "misp"):
        raise HTTPException(400, "Solo se pueden actualizar feeds y MISP")
    return {"encolado": intel.enqueue(("src", sid), intel.run_source, sid, None, user, "first", misp)}


@app.delete("/portal/api/intel/sources/{sid}")
def intel_source_delete(sid: int, user: str = Depends(portal_auth)):
    intel.delete_source(sid, user)
    return {"ok": True}


UPLOAD_MAX_MB = int(os.getenv("INTEL_UPLOAD_MAX_MB", "2048"))


@app.post("/portal/api/intel/upload")
async def intel_upload(request: Request, name: str, weight: int = 70, tlp: str = "amber", expires_days: int = 0,
                       mode: str = "first", ioc_type: str = "auto", description: str = "", incident: str = "",
                       retro: int = 0, user: str = Depends(portal_auth)):
    """Carga de archivos grandes (TXT, CSV o .gz; millones de líneas). El archivo llega en el cuerpo de la petición."""
    name = name.strip()[:80] or "Carga de archivo"
    src = intel.source_by_name(name)
    sid = src["id"] if src else intel.save_source(None, {"name": name, "kind": "manual", "weight": weight, "tlp": tlp,
                                                         "retention_days": expires_days, "ioc_type": ioc_type, "interval_h": 0,
                                                         "description": description, "incident": incident}, user)
    tmp = os.path.join(os.path.dirname(intel.path), "tmp")
    os.makedirs(tmp, exist_ok=True)
    path = os.path.join(tmp, f"upload-{sid}-{int(time.time())}.bin")
    size = 0
    with open(path, "wb") as fh:
        async for chunk in request.stream():
            size += len(chunk)
            if size > UPLOAD_MAX_MB * 1024 * 1024:
                fh.close(); os.remove(path)
                raise HTTPException(413, f"Archivo mayor de {UPLOAD_MAX_MB} MB")
            fh.write(chunk)
    if not size:
        os.remove(path)
        raise HTTPException(400, "Archivo vacío")
    intel.enqueue(("up", path), intel.run_source, sid, path, user, mode if mode in ("first", "all") else "first", misp)
    if retro:
        intel.enqueue(("retro", sid, time.time()), _retro_job, int(retro), user)
    if incident:
        store.add_note(incident, user, f"Carga de IoC «{name}» ({size // 1024} KB) en el motor de inteligencia")
    return {"source_id": sid, "bytes": size}


def _push_misp(items, src, to_ids=True):
    """Envía a MISP en un evento (por bloques de 2000 atributos). Solo para cargas de hasta 50 000 IoC."""
    from intel import MISP_TYPE
    info = src["description"] or f"Portal SOC · {src['name']} · {now_str()[:10]}"
    first, rest = items[:2000], items[2000:]
    ev = misp.add_event(info, [{"value": v, "type": MISP_TYPE.get(t, "text")} for v, t, _ in first], src["tlp"], to_ids, src["name"])
    key = os.getenv("MISP_WRITE_API_KEY") or os.environ["MISP_API_KEY"]
    for i in range(0, len(rest), 2000):
        attrs = [{"type": MISP_TYPE.get(t, "text"), "category": misp.CATEGORY.get(MISP_TYPE.get(t), "Other"), "value": v,
                  "to_ids": bool(to_ids)} for v, t, _ in rest[i:i + 2000]]
        r = requests.post(f"{misp.url}/attributes/add/{ev}", headers={**misp.h, "Authorization": key}, json=attrs,
                          verify=misp.verify, timeout=300)
        r.raise_for_status()
    return ev


@app.post("/portal/api/iocs")
@app.post("/portal/api/intel/add")
def intel_add(data: dict = Body(...), user: str = Depends(actor)):
    """Carga desde texto (hasta 50 000 líneas). También la usa Shuffle con X-API-Key."""
    text = data.get("text") or ""
    if text.count("\n") > 50000:
        raise HTTPException(400, "Para más de 50 000 líneas usa «Cargar archivo»")
    sid, items, added = intel.add_text(text, data, user)
    if not items:
        raise HTTPException(400, "No se reconoció ningún IoC válido")
    out = {"source_id": sid, "leidos": len(items), "añadidos": added, "misp_event": None}
    if data.get("misp"):
        try:
            out["misp_event"] = _push_misp(items, intel.source(sid), bool(data.get("to_ids", True)))
        except Exception as exc:
            out["misp_error"] = str(exc)[:200]
    if data.get("incident"):
        store.add_note(data["incident"], user, f"{len(items)} IoC cargados en el motor de inteligencia"
                       + (f" y enviados a MISP (evento #{out['misp_event']})" if out["misp_event"] else ""))
    hits = intel.lookup([i[0] for i in items])
    out["ya_conocidos"] = sum(1 for v in hits.values() if len({m["sid"] for m in v} - {sid}) > 0)
    if data.get("retro", True):
        intel.enqueue(("retro", sid, time.time()), _retro_job, int(data.get("retro_days") or 7), user)
    return out


@app.post("/portal/api/iocs/parse")
def iocs_parse(data: dict = Body(...), user: str = Depends(portal_auth)):
    return feeds.parse_iocs(data.get("text") or "")


def _retro_job(days, user):
    jid = intel.job_new("retro", None, user)
    try:
        lt = int(time.time() * 1000)
        total, new = intel.correlate(wazuh, lt - days * 86400 * 1000, lt, additive=False, job=jid)
        intel.job_set(jid, status="ok", done=total, added=len(new), finished=now_str()[:16],
                      msg=f"Retrobúsqueda {days} días: {total} indicadores vistos · {len(new)} nuevos")
        _auto_incident(new)
    except Exception as exc:
        intel.job_set(jid, status="error", finished=now_str()[:16], msg=str(exc)[:200])
    intel.invalidate()


@app.post("/portal/api/intel/retro")
def intel_retro(data: dict = Body(...), user: str = Depends(portal_auth)):
    days = max(1, min(90, int(data.get("days") or 7)))
    return {"encolado": intel.enqueue(("retro", "manual", days), _retro_job, days, user)}


@app.get("/portal/api/intel/sightings")
def intel_sightings(days: int = 7, q: str = "", min_score: int = 0, user: str = Depends(portal_auth)):
    return intel.sightings(max(1, min(365, days)), q, min_score)


@app.post("/portal/api/intel/check")
def intel_check(data: dict = Body(...), user: str = Depends(portal_auth)):
    items = []
    for line in (data.get("text") or "").splitlines():
        for tok in re.split(r"[\s,;|]+", line):
            r = intel_normalize(tok)
            if r and r not in items:
                items.append(r)
    items = [{"value": v, "type": t} for v, t in items[:1000]]
    if not items:
        raise HTTPException(400, "No se reconoció ningún indicador")
    return {"resultados": intel.bulk_check(items, wazuh, misp), "limite": 1000}


@app.get("/portal/api/intel/lookup")
def intel_lookup(v: str, deep: int = 0, user: str = Depends(portal_auth)):
    r = intel_normalize(v)
    if not r:
        raise HTTPException(400, "No es un indicador válido (IP pública, dominio, URL, hash o correo)")
    value, t = r
    out = intel.bulk_check([{"value": value, "type": t}], wazuh, misp)[0]
    out["sightings_detalle"] = [x for x in intel.sightings(365, value) if x["value"] == value]
    if deep:
        out["enriquecimiento"] = intel.enrich(value, t)
    if sophos.on:
        out["sophos"] = sophos.find_alerts_with(value)
    if m365.on:
        out["m365"] = m365.q("SELECT id, created, severity, title, users FROM alerts WHERE ips LIKE ? OR urls LIKE ? "
                             "ORDER BY created DESC LIMIT 20", (f"%{value}%", f"%{value}%"))
    return out


@app.get("/portal/api/intel/browse")
def intel_browse(q: str = "", source: int = 0, type: str = "", user: str = Depends(portal_auth)):
    return intel.browse(q, source or None, type if type in TYPES else "")


# Listas para otras herramientas (cabecera X-API-Key = BRIDGE_TOKEN)
@app.get("/feeds/misp/{kind}.txt", dependencies=[Depends(auth)])
def feed_misp(kind: str, min_weight: int = 60):
    """Feed de texto para MISP (Sync Actions → Feeds → «Freetext Parsed Feed»). Excluye lo que vino de MISP."""
    types = {"ip": ["ip", "cidr"], "domain": ["domain"], "url": ["url"], "hash": ["md5", "sha1", "sha256"]}.get(kind)
    if not types:
        raise HTTPException(404, "Usa ip, domain, url o hash")
    return StreamingResponse((v + "\n" for v, _, _ in intel.export_values(types, min_weight)), media_type="text/plain")


@app.get("/feeds/wazuh/{kind}.cdb", dependencies=[Depends(auth)])
def feed_wazuh(kind: str, min_weight: int = 75):
    """Lista CDB para Wazuh (clave:valor). Solo fuentes con confianza >= min_weight para no inflar las listas."""
    types = {"ip": ["ip"], "domain": ["domain"], "hash": ["md5", "sha1", "sha256"]}.get(kind)
    if not types:
        raise HTTPException(404, "Usa ip, domain o hash")
    W = intel.weights()

    def gen():
        for v, _, sids in intel.export_values(types, min_weight, exclude_kinds=()):
            if kind == "ip" and ":" in v:
                continue  # las claves IPv6 no son válidas en CDB sin comillas
            best = max((W.get(int(s), (0, "?"))[0], W.get(int(s), (0, "?"))[1]) for s in str(sids).split(","))
            yield f"{v}:{re.sub(r'[^A-Za-z0-9 ._-]', '', best[1])[:40]}\n"
    return StreamingResponse(gen(), media_type="text/plain")


# ---------------------------------------------------------------- Asistente de investigación (IA)
def _compact_alert(a):
    r, d = a.get("rule", {}), a.get("data", {}) or {}
    return {"ts": a.get("timestamp"), "agente": (a.get("agent") or {}).get("name"), "regla": r.get("id"), "nivel": r.get("level"),
            "desc": r.get("description"), "mitre": (r.get("mitre") or {}).get("id"), "srcip": d.get("srcip"), "dstip": d.get("dstip"),
            "log": (a.get("full_log") or "")[:300]}


AI_FIELDS = {"agent.name", "rule.id", "data.srcip", "data.dstip", "rule.mitre.id", "rule.groups", "rule.level",
             "data.win.eventdata.targetUserName", "data.win.eventdata.image", "syscheck.path"}


def t_resumen_soc(**_):
    s = cached_summary()
    al = s.get("alertas") or {}
    return {"generado": s.get("generado"), "agentes": s.get("agentes"), "alertas_24h_nivel10": al.get("total"),
            "top_reglas": al.get("top_rules"), "top_agentes": al.get("top_agents"), "coincidencias_misp_24h": len(s.get("misp_hits") or []),
            "incidentes": store.stats(), "sla_vencidos": [v["code"] for v in store.metrics()["vencidos"]],
            "portales_caidos": [x["name"] for x in store.sites() if x["enabled"] and x["state"] == "down"]}


def t_buscar_alertas(campo="", valor="", texto="", horas=24, nivel_min=7, limite=20, **_):
    horas, limite = max(1, min(24 * 30, int(horas))), max(1, min(50, int(limite)))
    flt = [{"range": {"timestamp": {"gte": f"now-{horas}h"}}}, {"range": {"rule.level": {"gte": int(nivel_min)}}}]
    if campo:
        if campo not in AI_FIELDS:
            return {"error": f"campo no permitido; usa uno de {sorted(AI_FIELDS)}"}
        flt.append({"term": {campo: valor}})
    if texto:
        flt.append({"simple_query_string": {"query": texto, "fields": ["rule.description", "full_log"], "default_operator": "and"}})
    body = {"size": limite, "sort": [{"timestamp": "desc"}], "track_total_hits": True, "query": {"bool": {"filter": flt}},
            "_source": ["timestamp", "agent.name", "rule.id", "rule.level", "rule.description", "rule.mitre.id", "data.srcip", "data.dstip", "full_log"],
            "aggs": {"reglas": {"terms": {"field": "rule.description", "size": 8}}, "agentes": {"terms": {"field": "agent.name", "size": 8}}}}
    d = wazuh._search("wazuh-alerts-*", body)
    return {"total": d["hits"]["total"]["value"], "alertas": [_compact_alert(h["_source"]) for h in d["hits"]["hits"]],
            "reglas": [(b["key"], b["doc_count"]) for b in d["aggregations"]["reglas"]["buckets"]],
            "agentes": [(b["key"], b["doc_count"]) for b in d["aggregations"]["agentes"]["buckets"]]}


def t_amenazas(rango="24h", nivel_min=10, **_):
    t = cached(f"thr:{rango}:{nivel_min}", TTL.get(rango, 120), wazuh.threats, rango if rango in wazuh.RANGES else "24h", int(nivel_min))
    return {k: t[k] for k in ("total", "niveles", "reglas", "agentes", "tacticas", "tecnicas", "ips", "paises")} | {"recientes": [_compact_alert(a) for a in t["recientes"][:8]]}


def t_comprobar_ioc(valores=None, **_):
    vals = [v for v in (valores or []) if isinstance(v, str)][:200]
    items = []
    for v in vals:
        r = intel_normalize(v)
        if r:
            items.append({"value": r[0], "type": r[1]})
    if not items:
        return {"error": "ningún indicador válido (IP pública, dominio, URL, hash, correo)"}
    return {"resultados": intel.bulk_check(items, wazuh, misp)}


def t_analizar_ioc(valor="", **_):
    r = intel_normalize(valor)
    if not r:
        return {"error": "indicador no válido"}
    out = intel.bulk_check([{"value": r[0], "type": r[1]}], wazuh, misp)[0]
    out["vista_en"] = [x for x in intel.sightings(90, r[0]) if x["value"] == r[0]][:5]
    out["enriquecimiento"] = intel.enrich(r[0], r[1])
    return out


def t_buscar_misp(valor="", **_):
    return {"atributos": misp.search(valor)[:20]}


def t_incidentes(estado="active", texto="", **_):
    return {"incidentes": [{k: i[k] for k in ("code", "title", "severity", "status", "owner", "runbook", "updated_at", "assets", "iocs")}
                           for i in store.incidents(estado or None, None, texto or None, limit=30)]}


def t_ver_incidente(codigo="", **_):
    i = store.incident(codigo)
    if not i:
        return {"error": "no existe"}
    i["events"] = i["events"][:25]
    return i


def t_buscar_runbooks(texto="", **_):
    t = texto.lower()
    return {"runbooks": [{k: r[k] for k in ("slug", "title", "description", "level", "mitre", "owasp")} for r in store.runbooks()
                         if not t or t in " ".join(str(r.get(k) or "") for k in ("title", "description", "mitre", "owasp", "category")).lower()][:15]}


def t_ver_runbook(slug="", **_):
    r = store.runbook(slug)
    return {"slug": r["slug"], "title": r["title"], "level": r["level"], "mitre": r["mitre"], "contenido": r["body"][:6000]} if r else {"error": "no existe"}


def t_tecnica_mitre(id="", **_):
    tid = id.upper().split(".")[0]
    d = mitre_db.detail(tid)
    if not d:
        return {"error": "técnica no encontrada"}
    try:
        w = cached(f"mitret:{tid}:30", 600, wazuh.mitre_rules, tid, 30)
    except Exception as exc:
        w = {"error": str(exc)[:120]}
    return {"id": d["id"], "nombre": d["name"], "tacticas": d["tactics_es"], "descripcion": d["desc"][:1500], "deteccion": d["detection"][:800],
            "wazuh_30d": {"total": w.get("total"), "reglas": w.get("reglas", [])[:5], "agentes": w.get("agentes", [])[:5]},
            "runbooks": _rb_by("mitre").get(tid, []), "cobertura": store.marks("mitre").get(tid, {})}


def t_vulnerabilidades(severidad="", texto="", **_):
    out = {"seguimiento": [{k: v[k] for k in ("cve", "title", "severity", "asset", "status", "owner", "due_date")}
                           for v in store.vulns("active", severidad or None, None, texto or None, limit=25)]}
    try:
        w = cached(f"vw:{severidad}::{texto}", 600, wazuh.vulns, severidad, "", texto)
        out["wazuh"] = {"total": w["total"], "cves": w["cves"][:15], "agentes": w["agentes"][:8]}
    except Exception as exc:
        out["wazuh"] = {"error": str(exc)[:120]}
    return out


def t_estado_agentes(**_):
    d = cached("agents", 300, wazuh.agents_detail)
    return {"total": d["total"], "estados": d["estados"], "so": d["so"][:6],
            "desconectados": [{k: a[k] for k in ("name", "ip", "os", "last")} for a in d["lista"] if a["status"] == "disconnected"][:25]}


def t_estado_portales(**_):
    return {"portales": [{k: x[k] for k in ("name", "url", "state", "last_code", "last_ms", "last_error", "uptime24", "ssl_expiry", "content_changed")} for x in store.sites()]}


def t_herramientas(texto="", **_):
    return {"herramientas": [{k: t[k] for k in ("name", "category", "platform", "description", "status", "requires_auth")} for t in store.tools(texto or None)][:15]}


def t_proponer_incidente(titulo="", severidad="High", resumen="", iocs="", activos="", runbook="", **_):
    return {"_propuesta": {"tipo": "incidente", "title": titulo[:200], "severity": severidad if severidad in SEVERITIES else "High",
                           "summary": resumen[:3000], "iocs": iocs[:3000], "assets": activos[:500], "runbook": runbook, "detected_by": "Asistente IA (propuesta revisada por analista)"},
            "mensaje": "Propuesta registrada; el analista debe confirmarla en la interfaz."}


def t_proponer_nota(codigo="", texto="", **_):
    return {"_propuesta": {"tipo": "nota", "code": codigo, "text": texto[:3000]}, "mensaje": "Propuesta registrada; el analista debe confirmarla."}


_P = lambda props, req=(): {"type": "object", "properties": props, "required": list(req)}
_S, _I = {"type": "string"}, {"type": "integer"}
AI_TOOLS = [
    ("resumen_soc", "Estado general del SOC ahora: agentes, alertas ≥10 de 24 h, coincidencias MISP, incidentes, SLA y portales caídos.", _P({})),
    ("buscar_alertas", "Busca alertas de Wazuh. Filtra por un campo exacto (campo+valor) y/o por texto en la descripción y el log.",
     _P({"campo": {"type": "string", "enum": sorted(AI_FIELDS)}, "valor": _S, "texto": _S, "horas": _I, "nivel_min": _I, "limite": _I})),
    ("amenazas", "Panorama de amenazas: niveles, reglas, agentes, tácticas/técnicas MITRE, IPs y países de origen.",
     _P({"rango": {"type": "string", "enum": ["24h", "7d", "30d"]}, "nivel_min": _I})),
    ("comprobar_ioc", "Comprueba hasta 200 indicadores en las fuentes de inteligencia, en Wazuh (30 días) y en MISP.", _P({"valores": {"type": "array", "items": _S}}, ["valores"])),
    ("analizar_ioc", "Análisis a fondo de UN indicador: fuentes, dónde se vio, MISP y servicios externos (Shodan, AbuseIPDB, VirusTotal…).", _P({"valor": _S}, ["valor"])),
    ("buscar_misp", "Busca un valor en los atributos de MISP.", _P({"valor": _S}, ["valor"])),
    ("incidentes", "Lista incidentes del portal (estado: active, Open, Investigating, Contained, Closed o vacío para todos).", _P({"estado": _S, "texto": _S})),
    ("ver_incidente", "Detalle y cronología de un incidente (código INC-AAAA-NNN).", _P({"codigo": _S}, ["codigo"])),
    ("buscar_runbooks", "Busca runbooks por texto, técnica MITRE (T1486) u OWASP (A05).", _P({"texto": _S})),
    ("ver_runbook", "Contenido de un runbook por su identificador (slug).", _P({"slug": _S}, ["slug"])),
    ("tecnica_mitre", "Información de una técnica MITRE ATT&CK, sus alertas en Wazuh, runbooks y cobertura.", _P({"id": _S}, ["id"])),
    ("vulnerabilidades", "Vulnerabilidades en seguimiento y detectadas por Wazuh (severidad Critical/High/Medium/Low).", _P({"severidad": _S, "texto": _S})),
    ("estado_agentes", "Estado de los agentes de Wazuh y lista de desconectados.", _P({})),
    ("estado_portales", "Estado de los portales web monitoreados.", _P({})),
    ("herramientas", "Busca herramientas del repositorio interno del SOC.", _P({"texto": _S})),
    ("proponer_incidente", "PROPONE crear un incidente (no lo crea: lo confirma el analista).",
     _P({"titulo": _S, "severidad": {"type": "string", "enum": SEVERITIES}, "resumen": _S, "iocs": _S, "activos": _S, "runbook": _S}, ["titulo", "resumen"])),
    ("proponer_nota", "PROPONE añadir una nota a la cronología de un incidente existente (la confirma el analista).", _P({"codigo": _S, "texto": _S}, ["codigo", "texto"])),
]
_impl = {n: globals()["t_" + n] for n, _, _ in AI_TOOLS}
assistant = AI.Assistant(store, _impl, [{"name": n, "description": d, "parameters": p} for n, d, p in AI_TOOLS])
auditor = code_audit.CodeAuditor(store, toolfs)


@app.get("/portal/api/ai/status")
def ai_status(user: str = Depends(portal_auth)):
    c = AI.cfg()
    return {"on": c["on"], "provider": c["provider"], "model": c["model"], "local": c["local"], "redact": c["redact"] and not c["local"],
            "tools": [n for n, _, _ in AI_TOOLS], "max_steps": c["max_steps"]}


@app.get("/portal/api/ai/chats")
def ai_chats(user: str = Depends(portal_auth)):
    return assistant.chats(user)


@app.post("/portal/api/ai/chats")
def ai_chat_new(data: dict = Body(...), user: str = Depends(portal_auth)):
    return {"id": assistant.chat_new(user, data.get("title") or "Nueva investigación", data.get("context") or "")}


@app.get("/portal/api/ai/chats/{cid}")
def ai_chat_get(cid: str, user: str = Depends(portal_auth)):
    c = assistant.chat_get(cid, user)
    if not c:
        raise HTTPException(404, "Conversación no encontrada")
    return c


@app.delete("/portal/api/ai/chats/{cid}")
def ai_chat_del(cid: str, user: str = Depends(portal_auth)):
    assistant.chat_delete(cid, user)
    return {"ok": True}


@app.post("/portal/api/ai/chats/{cid}/messages")
def ai_send(cid: str, request: Request, data: dict = Body(...), user: str = Depends(portal_auth)):
    if not AI.cfg()["on"]:
        raise HTTPException(400, "El asistente no está configurado: un administrador debe definir AI_PROVIDER y AI_MODEL en el .env")
    if not assistant.chat_get(cid, user):
        raise HTTPException(404, "Conversación no encontrada")
    text = (data.get("text") or "").strip()[:4000]
    if not text:
        raise HTTPException(400, "Escribe una pregunta")
    return {"run": assistant.start(cid, user, request.state.user["role"], text, bool(data.get("verify", True)))}


@app.get("/portal/api/ai/runs/{rid}")
def ai_run(rid: str, user: str = Depends(portal_auth)):
    r = assistant.run_state(rid, user)
    if not r:
        raise HTTPException(404, "Ejecución no encontrada")
    return {k: v for k, v in r.items() if k != "user"}


@app.get("/portal/api/admin/ai-audit")
def ai_audit(user: str = Depends(portal_auth)):
    return assistant.audit_log()


# ---------------------------------------------------------------- MITRE ATT&CK y OWASP Top 10
MARK_STATES = {"detectada": "Detectada", "parcial": "Parcial", "sin_cobertura": "Sin cobertura", "no_aplica": "No aplica"}
OWASP_STATES = {"cumple": "Cumple", "parcial": "Parcial", "no_cumple": "No cumple", "no_aplica": "No aplica"}


def _rb_by(field):
    out = {}
    for r in store.runbooks():
        for k in [x.strip() for x in (r.get(field) or "").split(",") if x.strip()]:
            out.setdefault(k, []).append({"slug": r["slug"], "title": r["title"], "level": r["level"]})
    return out


@app.get("/portal/api/mitre")
def mitre_matrix(days: int = 30, user: str = Depends(portal_auth)):
    days = max(1, min(90, days))
    try:
        alerts, err = cached(f"mitre:{days}", 900, wazuh.mitre_counts, days), None
    except Exception as exc:
        alerts, err = {}, str(exc)[:160]
    m = mitre_db.matrix(alerts, _rb_by("mitre"), store.marks("mitre"))
    return {**m, "days": days, "err_wazuh": err, "estados": MARK_STATES}


@app.get("/portal/api/mitre/{tid}")
def mitre_tech(tid: str, days: int = 30, user: str = Depends(portal_auth)):
    tid = tid.upper()
    t = mitre_db.detail(tid)
    if not t:
        raise HTTPException(404, "Técnica no encontrada en los datos cargados")
    rb = _rb_by("mitre")
    try:
        w = cached(f"mitret:{tid}:{days}", 600, wazuh.mitre_rules, tid, days)
    except Exception as exc:
        w = {"error": str(exc)[:160]}
    seen, rbs = set(), []
    for x in rb.get(tid, []) + [x for k, v in rb.items() if k.startswith(tid + ".") for x in v]:
        if x["slug"] not in seen:
            seen.add(x["slug"]); rbs.append(x)
    return {**t, "runbooks": rbs,
            "wazuh": w, "mark": store.marks("mitre").get(tid, {}), "estados": MARK_STATES}


@app.post("/portal/api/mitre/refresh")
def mitre_refresh(request: Request, user: str = Depends(portal_auth)):
    if request.state.user["role"] != "admin":
        raise HTTPException(403, "Solo administradores")
    threading.Thread(target=mitre_db.refresh, daemon=True).start()
    return {"ok": True}


@app.get("/portal/api/owasp")
def owasp_page(days: int = 30, user: str = Depends(portal_auth)):
    try:
        web, err = cached(f"web:{days}", 900, wazuh.web_attacks, days), None
    except Exception as exc:
        web, err = [], str(exc)[:160]
    per = {}
    for w in web:
        c = OWASP.classify(w["desc"])
        w["owasp"] = c
        if c:
            per[c] = per.get(c, 0) + w["n"]
    rb, marks = _rb_by("owasp"), store.marks("owasp")
    return {"items": [{**i, "runbooks": rb.get(i["id"], []), "mark": marks.get(i["id"], {}), "alertas": per.get(i["id"], 0)} for i in OWASP.ITEMS],
            "web": web[:40], "err_wazuh": err, "estados": OWASP_STATES, "days": days}


@app.put("/portal/api/frameworks/{fw}/{key}")
def framework_mark(fw: str, key: str, data: dict = Body(...), user: str = Depends(portal_auth)):
    states = {"mitre": MARK_STATES, "owasp": OWASP_STATES}.get(fw)
    if states is None:
        raise HTTPException(404, "Marco desconocido")
    st = data.get("status") or ""
    if st and st not in states:
        raise HTTPException(400, "Estado no válido")
    store.set_mark(fw, key.upper(), st, (data.get("note") or "")[:1000], user)
    return {"ok": True}


# ---------------------------------------------------------------- herramientas
TOOL_CATS = ["Inteligencia y OSINT", "Monitoreo de filtraciones", "Escaneo y reconocimiento", "Redes y tráfico",
             "Análisis de malware", "Forense", "Respuesta a incidentes", "Detección (reglas YARA/Sigma)",
             "Windows / Active Directory", "Automatización", "Seguridad de código e IA", "Utilidades"]
TOOL_PLATFORMS = ["Kali", "Windows", "Linux", "Multiplataforma"]


def _tool_or_404(tid):
    t = store.tool(tid)
    if not t:
        raise HTTPException(404, "Herramienta no encontrada")
    return t


@app.get("/portal/api/tools")
def tools_list(q: str = "", cat: str = "", platform: str = "", user: str = Depends(portal_auth)):
    rows = store.tools(q or None, cat or None, platform or None)
    allr = store.tools()
    return {"rows": rows, "categorias": TOOL_CATS, "estados": store.TOOL_STATUSES, "plataformas": TOOL_PLATFORMS,
            "por_categoria": {c: sum(1 for r in allr if r["category"] == c) for c in TOOL_CATS},
            "por_plataforma": {p: sum(1 for r in allr if r["platform"] == p) for p in TOOL_PLATFORMS}, "total": len(allr)}


@app.get("/portal/api/tools/catalog")
def tools_catalog(user: str = Depends(portal_auth)):
    have = {r["name"].lower() for r in store._q("SELECT name FROM tools")}
    return [{"name": e["n"], "category": e["c"], "platform": e["p"], "description": e["d"], "auth": bool(e.get("a")),
             "url": e.get("gh") or e.get("web"), "added": e["n"].lower() in have} for e in TOOL_CATALOG]


@app.get("/portal/api/tools/security-summary")
def tools_security_summary(user: str = Depends(portal_auth)):
    return auditor.summary()


@app.post("/portal/api/tools/catalog")
def tools_catalog_add(data: dict = Body(...), user: str = Depends(portal_auth)):
    names = data.get("names")
    return {"añadidas": _import_catalog(set(names) if names else None, user)}


@app.post("/portal/api/tools")
def tools_create(data: dict = Body(...), user: str = Depends(portal_auth)):
    tid = store.save_tool(None, data, user)
    if not tid:
        raise HTTPException(400, "El nombre es obligatorio")
    t = store.tool(tid)
    if t["repo_url"] and data.get("sync", True):
        try:
            toolfs.github_sync(t, user)
        except Exception as exc:
            store.tool_log(tid, user, f"No se pudo sincronizar con GitHub: {str(exc)[:150]}")
    return store.tool(tid)


@app.get("/portal/api/tools/{tid}")
def tools_get(tid: str, user: str = Depends(portal_auth)):
    return _tool_or_404(tid)


@app.put("/portal/api/tools/{tid}")
def tools_edit(tid: str, data: dict = Body(...), user: str = Depends(portal_auth)):
    t = _tool_or_404(tid)
    store.save_tool(t["id"], data, user)
    return store.tool(t["id"])


@app.delete("/portal/api/tools/{tid}")
def tools_delete(tid: str, user: str = Depends(portal_auth)):
    t = _tool_or_404(tid)
    toolfs.remove_all(t["id"])
    store.delete_tool(t["id"])
    return {"ok": True}


@app.get("/portal/api/tools/{tid}/metrics")
def tools_metrics(tid: str, user: str = Depends(portal_auth)):
    t = _tool_or_404(tid)
    return _wrap(cached, f"tmetrics:{t['id']}:{t['updated_at']}:{len(t['files'])}", 3600, auditor.metrics_for, t)


@app.get("/portal/api/tools/{tid}/audits")
def tools_audits(tid: str, user: str = Depends(portal_auth)):
    t = _tool_or_404(tid)
    return {"rows": auditor.audits(t["id"]), "profiles": code_audit.PROFILES, "ai": AI.cfg()["on"], "local": AI.cfg()["local"]}


@app.post("/portal/api/tools/{tid}/audits")
def tools_audit_start(tid: str, data: dict = Body(...), user: str = Depends(portal_auth)):
    if not AI.cfg()["on"]:
        raise HTTPException(400, "La auditoría necesita el asistente de IA configurado (AI_PROVIDER, AI_MODEL)")
    t = _tool_or_404(tid)
    try:
        return {"id": auditor.start(t, data.get("profile") or "standard", user)}
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/portal/api/tools/{tid}/audits/{aid}")
def tools_audit_get(tid: str, aid: int, user: str = Depends(portal_auth)):
    t = _tool_or_404(tid)
    a = auditor.audit(aid)
    if not a or a["tool_id"] != t["id"]:
        raise HTTPException(404, "Auditoría no encontrada")
    return a


@app.get("/portal/api/tools/{tid}/audits/{aid}/export")
def tools_audit_export(tid: str, aid: int, fmt: str = "md", user: str = Depends(portal_auth)):
    a = tools_audit_get(tid, aid, user)
    if fmt == "json":
        return JSONResponse({"tool": tid, "audit": aid, "findings": a["findings"], "recon": a["recon"], "cost": a["cost"]},
                            headers={"Content-Disposition": f'attachment; filename="findings-{tid}-{aid}.json"'})
    return Response(a["report"], media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="auditoria-{tid}-{aid}.md"'})


@app.post("/portal/api/tools/{tid}/audits/{aid}/findings/{fid}/vuln")
def tools_finding_to_vuln(tid: str, aid: int, fid: str, user: str = Depends(portal_auth)):
    a = tools_audit_get(tid, aid, user)
    f = next((x for x in a["findings"] if x["id"] == fid), None)
    if not f or f["status"] != "confirmed":
        raise HTTPException(400, "Solo se pasan a seguimiento los hallazgos confirmados")
    sev = {"critical": "Critical", "high": "High", "medium": "Medium"}.get(f["severity"], "Low")
    vid, new = store.save_vuln(None, {"title": f"{tid}: {f['title']}", "severity": sev, "asset": f"Herramienta {tid} · {f['file']}:{f['line_start']}",
                                      "package": tid, "solution": f["fix"], "notes": f"{f['class']}. Impacto: {f['impact']}"},
                               user, source="auditoría IA", ext_key=f"audit|{tid}|{f['fingerprint']}")
    return {"id": vid, "nuevo": new}


@app.post("/portal/api/tools/{tid}/github")
def tools_sync(tid: str, cache: int = 0, user: str = Depends(portal_auth)):
    t = _tool_or_404(tid)
    try:
        r = toolfs.github_sync(t, user)
        if cache:
            r["copiados"] = toolfs.cache_all(store.tool(t["id"]), user)
    except Exception as exc:
        raise HTTPException(502, f"GitHub: {str(exc)[:200]}")
    return r


@app.post("/portal/api/tools/{tid}/files")
async def tools_upload(tid: str, request: Request, path: str, user: str = Depends(portal_auth)):
    t = _tool_or_404(tid)
    chunks = [c async for c in request.stream()]
    if not sum(len(c) for c in chunks):
        raise HTTPException(400, "Archivo vacío")
    try:
        f = await asyncio.to_thread(toolfs.save, t["id"], path, chunks, user)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    store.tool_log(t["id"], user, f"Archivo subido: {f['path']} ({f['size']:,} bytes · SHA256 {f['sha256'][:12]}…)".replace(",", "."))
    return f


@app.get("/portal/api/tools/{tid}/files/{fid}")
def tools_file(tid: str, fid: int, user: str = Depends(portal_auth)):
    t = _tool_or_404(tid)
    f = store.tool_file(t["id"], fid)
    if not f:
        raise HTTPException(404, "Archivo no encontrado")
    try:
        data, _ = toolfs.read(t, f)
    except Exception as exc:
        raise HTTPException(502, f"No se pudo leer el archivo: {str(exc)[:160]}")
    f = store.tool_file(t["id"], fid)
    text = toolfs.as_text(data)
    return {**f, "text": text, "lang": lang_of(f["path"]), "lines": text.count("\n") + 1 if text is not None else None}


@app.get("/portal/api/tools/{tid}/files/{fid}/download")
def tools_download(tid: str, fid: int, user: str = Depends(portal_auth)):
    t = _tool_or_404(tid)
    f = store.tool_file(t["id"], fid)
    if not f:
        raise HTTPException(404, "Archivo no encontrado")
    data, _ = toolfs.read(t, f)
    name = f["path"].rsplit("/", 1)[-1].replace('"', "")
    # siempre como descarga binaria: el navegador nunca ejecuta ni interpreta el archivo
    return Response(data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "X-Content-Type-Options": "nosniff"})


@app.delete("/portal/api/tools/{tid}/files/{fid}")
def tools_file_delete(tid: str, fid: int, user: str = Depends(portal_auth)):
    t = _tool_or_404(tid)
    f = store.tool_file(t["id"], fid)
    if f:
        toolfs.remove(t["id"], f["path"])
        store.delete_tool_file(t["id"], fid)
        store.tool_log(t["id"], user, f"Archivo eliminado: {f['path']}")
    return {"ok": True}


# ---------------------------------------------------------------- portales monitoreados
@app.get("/portal/api/sites")
def sites_list(user: str = Depends(portal_auth)):
    return {"rows": store.sites(), "events": store.site_events(), "today": datetime.date.today().isoformat()}


def _valid_site(data):
    u = (data.get("url") or "").strip()
    if not re.match(r"^https?://[^\s/]+", u):
        raise HTTPException(400, "La URL debe empezar por http:// o https://")
    if not (data.get("name") or "").strip():
        raise HTTPException(400, "El nombre es obligatorio")
    data["url"] = u
    return data


@app.post("/portal/api/sites")
def sites_add(data: dict = Body(...), user: str = Depends(portal_auth)):
    sid = store.save_site(None, _valid_site(data))
    _check_one(store.site(sid))
    return store.site(sid)


@app.put("/portal/api/sites/{sid}")
def sites_edit(sid: int, data: dict = Body(...), user: str = Depends(portal_auth)):
    store.save_site(sid, _valid_site(data))
    return store.site(sid)


@app.post("/portal/api/sites/{sid}/check")
def sites_check(sid: int, user: str = Depends(portal_auth)):
    s = store.site(sid)
    if not s:
        raise HTTPException(404, "No encontrado")
    _check_one(s)
    return store.site(sid)


_bulk = {"running": False, "total": 0, "done": 0, "errors": 0, "by": "", "started": "", "finished": "", "lock": threading.Lock()}


def _bulk_run(ids, user):
    from concurrent.futures import ThreadPoolExecutor

    def one(sid):
        try:
            s = store.site(sid)
            if s:
                _check_one(s)
        except Exception as exc:
            _bulk["errors"] += 1
            log.warning("Comprobación masiva, portal %s: %s", sid, exc)
        finally:
            with _bulk["lock"]:
                _bulk["done"] += 1
    try:
        with ThreadPoolExecutor(max_workers=MONITOR_PARALLEL, thread_name_prefix="sites-all") as ex:
            list(ex.map(one, ids))
    finally:
        _bulk.update(running=False, finished=now_str()[:16])
        log.info("Comprobación masiva de %s portales terminada (%s)", len(ids), user)


@app.post("/portal/api/sites/check-all")
def sites_check_all(data: dict = Body(default={}), user: str = Depends(portal_auth)):
    """Comprueba ya todos los portales activos (o solo los ids indicados, p. ej. los filtrados) en segundo plano."""
    with _bulk["lock"]:
        if _bulk["running"]:
            raise HTTPException(409, f"Ya hay una comprobación en curso ({_bulk['done']}/{_bulk['total']}, la lanzó {_bulk['by']})")
        active = [r["id"] for r in store._q("SELECT id FROM sites WHERE enabled = 1 ORDER BY name")]
        want = set(int(i) for i in (data or {}).get("ids") or [] if str(i).isdigit())
        ids = [i for i in active if not want or i in want]
        if not ids:
            raise HTTPException(400, "No hay portales activos que comprobar")
        _bulk.update(running=True, total=len(ids), done=0, errors=0, by=user, started=now_str()[:16], finished="")
    threading.Thread(target=_bulk_run, args=(ids, user), daemon=True, name="sites-check-all").start()
    return sites_check_status(user)


@app.get("/portal/api/sites/check-all")
def sites_check_status(user: str = Depends(portal_auth)):
    return {k: v for k, v in _bulk.items() if k != "lock"}


@app.get("/portal/api/sites/{sid}/deface")
def sites_deface(sid: int, user: str = Depends(portal_auth)):
    """Qué cambió respecto a la versión aprobada (para decidir si es legítimo o una desfiguración)."""
    s = store.site(sid)
    if not s:
        raise HTTPException(404, "No encontrado")
    base = json.loads(s["baseline"]) if s.get("baseline") else None
    snap = json.loads(s["snapshot"]) if s.get("snapshot") else None
    out = {"nivel": s.get("deface") or "", "cambio_pct": s.get("deface_pct"), "desde": s.get("deface_at"),
           "motivos": json.loads(s.get("deface_reasons") or "[]"), "base_at": s.get("baseline_at"), "base_by": s.get("baseline_by"),
           "umbral": s.get("change_threshold") or 40, "vigilado": bool(s.get("watch_content"))}
    if base and snap:
        out.update(titulo_base=base.get("title"), titulo_ahora=snap.get("title"), palabras_base=base.get("words"),
                   palabras_ahora=snap.get("words"), dominios_base=base.get("domains"), dominios_ahora=snap.get("domains"),
                   **deface.diff(base.get("text", ""), snap.get("text", "")))
    return out


@app.post("/portal/api/sites/{sid}/baseline")
def sites_baseline(sid: int, user: str = Depends(portal_auth)):
    """El analista confirma que el contenido actual es legítimo: pasa a ser la versión aprobada."""
    s = store.site(sid)
    if not s or not s.get("snapshot"):
        raise HTTPException(400, "Aún no hay una comprobación del contenido de este portal")
    prev = s.get("deface") or "ok"
    store._x("""UPDATE sites SET baseline = snapshot, baseline_at = ?, baseline_by = ?, deface = 'ok', deface_text = 'ok',
                deface_pct = 0, deface_reasons = '[]', deface_at = ?, visual_level = CASE WHEN visual_at != '' THEN 'ok' ELSE '' END,
                visual_pct = 0, visual_base_at = CASE WHEN visual_at != '' THEN ? ELSE visual_base_at END
                WHERE id = ?""", (now_str()[:16], user, now_str()[:16], now_str()[:16], sid))
    shots.promote(sid)
    store.site_event(sid, "baseline", f"{user} aceptó el contenido actual como versión buena (antes: {DEFACE_LABEL.get(prev, prev)})")
    return store.site(sid)


@app.post("/portal/api/sites/import/parse")
async def sites_import_parse(request: Request, filename: str = "portales.xlsx", user: str = Depends(portal_auth)):
    """Lee un Excel (p. ej. el inventario de cobertura WAF) o un CSV y devuelve los portales encontrados."""
    data = await request.body()
    if not data:
        raise HTTPException(400, "Archivo vacío")
    if len(data) > 20 * 1024 * 1024:
        raise HTTPException(413, "Archivo mayor de 20 MB")
    try:
        rows = await asyncio.to_thread(feeds.parse_sites_file, data, filename)
    except Exception as exc:
        raise HTTPException(400, f"No se pudo leer el archivo ({type(exc).__name__}: {str(exc)[:120]})")
    if not rows:
        raise HTTPException(400, "No encontré una columna «Portal», «Dominio» o «URL» con valores")
    known = {(urlparse_host(x["url"])): x["id"] for x in store._q("SELECT id, url FROM sites")}
    for r in rows:
        r["existe"] = urlparse_host(r["url"]) in known
    return {"rows": rows, "nuevos": sum(not r["existe"] for r in rows), "existentes": sum(r["existe"] for r in rows)}


def urlparse_host(u: str) -> str:
    return feeds.site_key(u)


@app.post("/portal/api/sites/import")
def sites_import(data: dict = Body(...), user: str = Depends(portal_auth)):
    """Alta o actualización masiva. Las comprobaciones se reparten en el intervalo para no lanzar todas a la vez."""
    import random
    rows = (data.get("rows") or [])[:3000]
    interval = int(data.get("interval_min") or 15)
    watch = 1 if data.get("watch_content", True) else 0
    auto = data.get("auto_incident", "sin_waf")  # "todos" | "sin_waf" | "ninguno"
    known = {urlparse_host(x["url"]): x["id"] for x in store._q("SELECT id, url FROM sites")}
    new = upd = 0
    now = datetime.datetime.now()
    for r in rows:
        url = str(r.get("url") or "").strip()
        if not re.match(r"^https?://[^\s/]+", url):
            continue
        meta = {k: str(r.get(k) or "")[:200] for k in ("waf", "plan", "public_ip", "backend_ip", "server", "vs", "grp")}
        sid = known.get(urlparse_host(url))
        if sid:
            store.save_site(sid, meta)
            upd += 1
            continue
        ai = 1 if auto == "todos" or (auto == "sin_waf" and meta["waf"] in ("bypass", "directo", "externo")) else 0
        sid = store.save_site(None, {"name": str(r.get("name") or urlparse_host(url))[:100], "url": url,
                                     "interval_min": interval, "watch_content": watch, "auto_incident": ai, "enabled": 1, **meta})
        offset = random.uniform(0, interval * 60)  # reparte la primera comprobación dentro del intervalo
        store._x("UPDATE sites SET last_check = ? WHERE id = ?",
                 ((now - datetime.timedelta(seconds=interval * 60 - offset)).strftime("%Y-%m-%d %H:%M:%S"), sid))
        known[urlparse_host(url)] = sid
        new += 1
    log.info("Portales importados por %s: %s nuevos, %s actualizados", user, new, upd)
    return {"nuevos": new, "actualizados": upd}


@app.delete("/portal/api/sites/{sid}")
def sites_delete(sid: int, user: str = Depends(portal_auth)):
    store.delete_site(sid)
    shots.remove(sid)
    return {"ok": True}


# ---------------------------------------------------------------- incidentes
@app.get("/portal/api/meta")
def meta(request: Request, user: str = Depends(portal_auth)):
    return {"user": user, "severities": SEVERITIES, "statuses": STATUSES, "users": sorted(x["username"] for x in authsvc.users() if x["enabled"]), "links": LINKS,
            "role": request.state.user["role"], "role_name": ROLES.get(request.state.user["role"]),
            "display": request.state.user["display"] or user,
            "runbooks": [{"slug": r["slug"], "title": r["title"]} for r in store.runbooks()]}


@app.get("/portal/api/incidents")
def list_incidents(status: str = "", severity: str = "", q: str = "", user: str = Depends(portal_auth)):
    return store.incidents(status or None, severity or None, q or None)


@app.post("/portal/api/incidents")
def new_incident(data: dict = Body(...), user: str = Depends(actor)):
    if not (data.get("title") or "").strip():
        raise HTTPException(400, "El título es obligatorio")
    sid = data.pop("suggestion_id", None)
    if user == "shuffle" and not AUTO_INCIDENTS:  # las automatizaciones también proponen, no crean
        key = "shuffle-" + hashlib.sha1((data.get("title", "") + data.get("assets", "")).encode()).hexdigest()[:16]
        data.setdefault("detected_by", "Shuffle (SOAR)")
        return {"code": None, "sugerencia": store.suggest_incident(data, "shuffle", key),
                "mensaje": "Registrado como sugerencia: un analista debe confirmarlo (AUTO_INCIDENTS=false)"}
    code = store.create_incident(data, user)
    if sid:
        store.decide_suggestion(int(sid), "accepted", user, code)
    return {"code": code}


@app.get("/portal/api/incidents/suggestions")
def incident_suggestions(status: str = "pending", user: str = Depends(portal_auth)):
    st = status if status in ("pending", "accepted", "dismissed", "") else "pending"
    return {"items": store.suggestions(st), "auto": AUTO_INCIDENTS}


@app.post("/portal/api/incidents/suggestions/{sid}/dismiss")
def incident_suggestion_dismiss(sid: int, data: dict = Body(default={}), user: str = Depends(portal_auth)):
    if not store.decide_suggestion(sid, "dismissed", user, note=(data or {}).get("note", "")):
        raise HTTPException(400, "La sugerencia no existe o ya se decidió")
    return {"ok": True}


@app.get("/portal/api/incidents/{code}")
def get_incident(code: str, user: str = Depends(portal_auth)):
    inc = store.incident(code)
    if not inc:
        raise HTTPException(404, "No encontrado")
    return inc


@app.put("/portal/api/incidents/{code}")
def edit_incident(code: str, data: dict = Body(...), user: str = Depends(portal_auth)):
    inc = store.update_incident(code, data, user)
    if not inc:
        raise HTTPException(404, "No encontrado")
    return inc


@app.post("/portal/api/incidents/{code}/close")
def close_incident(code: str, data: dict = Body(...), user: str = Depends(portal_auth)):
    res = (data.get("resolution") or "").strip()
    if len(res) < 5:
        raise HTTPException(400, "Describe brevemente cómo se resolvió (mínimo 5 caracteres)")
    inc = store.close_incident(code, user, res[:5000], data.get("root_cause"), data.get("lessons"))
    if not inc:
        raise HTTPException(404, "No encontrado")
    return inc


@app.delete("/portal/api/incidents/{code}")
def delete_incident(code: str, request: Request, user: str = Depends(portal_auth)):
    """Borrado definitivo (solo administradores). Para el día a día se cierra; borrar es para duplicados o pruebas."""
    if request.state.user["role"] != "admin":
        raise HTTPException(403, "Solo los administradores pueden eliminar incidentes; los analistas pueden cerrarlos")
    inc = store.delete_incident(code)
    if not inc:
        raise HTTPException(404, "No encontrado")
    authsvc.audit(user, client_ip(request), "incident_delete", f"{inc['code']} · {inc['title'][:120]} ({inc['status']})")
    log.warning("Incidente %s eliminado por %s", inc["code"], user)
    _cache["data"] = None
    return {"deleted": inc["code"]}


@app.post("/portal/api/incidents/{code}/notes")
def note(code: str, data: dict = Body(...), user: str = Depends(actor)):
    inc = store.add_note(code, user, data.get("text") or "")
    if not inc:
        raise HTTPException(400, "Nota vacía o incidente no encontrado")
    return inc


# ---------------------------------------------------------------- runbooks
@app.get("/portal/api/runbooks")
def list_runbooks(user: str = Depends(portal_auth)):
    return store.runbooks()


@app.get("/portal/api/runbooks/{slug}")
def get_runbook(slug: str, user: str = Depends(portal_auth)):
    rb = store.runbook(slug)
    if not rb:
        raise HTTPException(404, "No encontrado")
    return rb


@app.post("/portal/api/runbooks")
def create_runbook(data: dict = Body(...), user: str = Depends(portal_auth)):
    rb = store.save_runbook(None, data, user)
    if not rb:
        raise HTTPException(400, "El título es obligatorio")
    return rb


@app.put("/portal/api/runbooks/{slug}")
def update_runbook(slug: str, data: dict = Body(...), user: str = Depends(actor)):
    """Actualiza el runbook o lo crea con ese slug si no existe."""
    rb = store.save_runbook(slug, data, user)
    if not rb:
        raise HTTPException(400, "El título es obligatorio")
    return rb


@app.delete("/portal/api/runbooks/{slug}")
def remove_runbook(slug: str, user: str = Depends(portal_auth)):
    store.delete_runbook(slug)
    return {"ok": True}


# ---------------------------------------------------------------- contactos y exportación
@app.get("/portal/api/contacts")
def get_contacts(user: str = Depends(portal_auth)):
    return store.contacts()


@app.put("/portal/api/contacts")
def put_contacts(rows: list = Body(...), user: str = Depends(portal_auth)):
    return store.save_contacts(rows)


@app.get("/portal/api/export")
def export(user: str = Depends(portal_auth)):
    return JSONResponse(store.export(), headers={"Content-Disposition": "attachment; filename=soc-portal-export.json"})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/soc/summary", dependencies=[Depends(auth)])
def summary():
    return collect()


@app.get("/api/soc/agents", dependencies=[Depends(auth)])
def agents():
    return wazuh.agents_summary()


@app.get("/api/soc/ioc", dependencies=[Depends(auth)])
def ioc():
    return {"eventos_7d": misp.recent_events(7), "coincidencias_24h": wazuh.misp_hits_24h()}


@app.post("/api/soc/sync", dependencies=[Depends(auth)])
def sync_now():
    if not wiki:
        raise HTTPException(400, "WIKI_SYNC desactivado")
    return {"resultado": wiki.upsert(STATUS_PATH, "SOC Status", render(collect()),
                                     "Auto-generated by soc-bridge", ["soc", "status", "auto"])}


# ---------------------------------------------------------------- Sophos Central
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


def _sophos_guard():
    if not sophos.on:
        raise HTTPException(400, "Sophos Central no está configurado: añade SOPHOS_CLIENT_ID y SOPHOS_CLIENT_SECRET al .env")


def _sophos_err(exc):
    raise HTTPException(502 if not isinstance(exc, SophosError) else 400, sophos_friendly(exc))


@app.get("/portal/api/sophos/status")
def sophos_status(user: str = Depends(portal_auth)):
    return sophos.status()


@app.post("/portal/api/sophos/sync")
def sophos_sync_now(user: str = Depends(portal_auth)):
    _sophos_guard()
    sophos.kv("eps_at", 0)
    threading.Thread(target=_sophos_sync, daemon=True, name="sophos-sync").start()
    return {"ok": True}


@app.get("/portal/api/sophos/alerts")
def sophos_alerts(days: int = 7, severity: str = "", q: str = "", user: str = Depends(portal_auth)):
    days = max(1, min(days, 90))
    return {"items": sophos.alerts(days, severity if severity in ("low", "medium", "high") else "", q[:100]),
            "stats": sophos.alert_stats(days)}


@app.get("/portal/api/sophos/endpoints")
def sophos_endpoints(q: str = "", health: str = "", isolated: str = "", user: str = Depends(portal_auth)):
    return sophos.endpoints(q[:100], health, isolated)


@app.get("/portal/api/sophos/blocked")
def sophos_blocked(user: str = Depends(portal_auth)):
    _sophos_guard()
    try:
        return sophos.blocked()
    except Exception as exc:
        _sophos_err(exc)


@app.get("/portal/api/sophos/actions")
def sophos_actions(status: str = "", user: str = Depends(portal_auth)):
    return sophos.actions(status if status in ("pending", "done", "failed", "rejected", "running") else "")


def _sophos_target(kind: str, t: dict) -> dict:
    """Valida y completa el objetivo de una acción antes de ponerla en cola."""
    if kind in ("isolate", "unisolate", "scan"):
        ids = [str(i) for i in (t.get("ids") or []) if i][:50]
        if not ids:
            raise HTTPException(400, "Indica al menos un equipo")
        eps = {e["id"]: e["hostname"] for e in sophos.endpoints()["items"]}
        unknown = [i for i in ids if i not in eps]
        if unknown:
            raise HTTPException(400, f"Equipo(s) no encontrados en Sophos: {', '.join(unknown[:3])}")
        return {"ids": ids, "hostnames": [eps[i] for i in ids]}
    if kind == "alert_action":
        a = sophos.q("SELECT id, description, allowed FROM alerts WHERE id = ?", (t.get("alert_id"),), one=True)
        if not a:
            raise HTTPException(400, "Alerta no encontrada")
        if t.get("action") not in json.loads(a["allowed"] or "[]"):
            raise HTTPException(400, "Sophos no permite esa acción para esta alerta")
        return {"alert_id": a["id"], "action": t["action"], "description": a["description"][:200]}
    if kind in ("block_hash", "block_web"):
        vals, bad = [], []
        for raw in (t.get("values") or [])[:100]:
            c = feeds.classify(str(raw).strip())
            if kind == "block_hash":
                (vals if c and _SHA256.match(c["value"]) else bad).append(c["value"] if c else str(raw))
            elif not c or c["type"] not in ("domain", "url", "ip-dst") or c.get("private") or c.get("safe"):
                bad.append(str(raw))
            else:
                vals.append(c["value"])
        if bad:
            why = ("Solo se pueden bloquear SHA-256 (64 caracteres hexadecimales)" if kind == "block_hash" else
                   "Solo dominios, URL o IP públicas; se rechazan IP privadas y dominios de la lista segura")
            raise HTTPException(400, f"{why}. Revisa: {', '.join(bad[:5])}")
        if not vals:
            raise HTTPException(400, "Indica al menos un valor")
        return {"values": list(dict.fromkeys(vals))}
    if kind in ("unblock_hash", "unblock_web"):
        if not t.get("id"):
            raise HTTPException(400, "Falta el identificador del bloqueo")
        return {"id": str(t["id"]), "label": str(t.get("label") or t["id"])[:200]}
    raise HTTPException(400, "Acción no soportada")


def _sophos_hook(ip):
    def hook(a):
        txt = f"Sophos · {a['nombre']} ({a['label']}): {'✔' if a['status'] == 'done' else '✖'} {a['result']}"
        authsvc.audit(a["decided_by"], ip, "sophos_action", f"#{a['id']} {a['kind']} {a['label']} → {a['status']}")
        if a.get("incident"):
            store.add_note(a["incident"], a["decided_by"], txt + f"\nMotivo: {a['reason']} · pedida por {a['requested_by']}")
    return hook


@app.post("/portal/api/sophos/actions")
def sophos_action_new(request: Request, data: dict = Body(...), user: str = Depends(actor)):
    """Desde el portal la acción se ejecuta al confirmarla (la persona aprueba). Desde Shuffle queda pendiente."""
    _sophos_guard()
    kind = data.get("kind")
    if kind not in SOPHOS_KINDS:
        raise HTTPException(400, "Acción no soportada")
    reason = (data.get("reason") or "").strip()
    if len(reason) < 5:
        raise HTTPException(400, "Indica el motivo (mínimo 5 caracteres): queda en la auditoría")
    inc = (data.get("incident") or "").strip()
    if inc and not store.incident(inc):
        raise HTTPException(400, f"No existe el incidente {inc}")
    target = _sophos_target(kind, data.get("target") or {})
    human = user != "shuffle"
    try:
        return sophos.request(kind, target, reason, user, "portal" if human else "shuffle", inc, execute=human,
                              hooks=_sophos_hook(client_ip(request)))
    except SophosError as exc:
        raise HTTPException(400, str(exc))


@app.post("/portal/api/sophos/actions/{aid}/{decision}")
def sophos_action_decide(aid: int, decision: str, request: Request, data: dict = Body(default={}),
                         user: str = Depends(portal_auth)):
    """Aprobar o rechazar una acción pendiente: solo personas con sesión en el portal (nunca Shuffle)."""
    if decision not in ("approve", "reject"):
        raise HTTPException(404, "No encontrado")
    _sophos_guard()
    try:
        return sophos.decide(aid, decision == "approve", user, (data or {}).get("note", ""), hooks=_sophos_hook(client_ip(request)))
    except SophosError as exc:
        raise HTTPException(400, str(exc))


# ---------------------------------------------------------------- auditoría y registro del sistema (solo admin)
@app.get("/portal/api/admin/audit")
def audit_list(user_f: str = "", module: str = "", q: str = "", since: str = "", until: str = "", result: str = "",
               user: str = Depends(portal_auth)):
    return {"items": audit.query(user_f, module, q[:100], since, until, result), "stats": audit.stats(7),
            "conservacion_dias": AUDIT_DAYS}


@app.get("/portal/api/admin/audit/verify")
def audit_verify(user: str = Depends(portal_auth)):
    return audit.verify()


@app.get("/portal/api/admin/audit/export.csv")
def audit_export(user_f: str = "", module: str = "", q: str = "", since: str = "", until: str = "", result: str = "",
                 user: str = Depends(portal_auth)):
    data = audit.csv(user=user_f, module=module, q=q[:100], since=since, until=until, result=result)
    log.info("Auditoría exportada a CSV por %s", user)
    audit.record(user=user, role="admin", method="GET", path="/portal/api/admin/audit/export.csv", module="Auditoría",
                 action="Exportar", status=200, detail=json.dumps({"filtros": {"usuario": user_f, "modulo": module, "q": q,
                                                                              "desde": since, "hasta": until}}, ensure_ascii=False))
    return Response("\ufeff" + data, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="auditoria-{now_str()[:10]}.csv"'})


@app.get("/portal/api/admin/syslog")
def syslog_list(level: str = "", q: str = "", user: str = Depends(portal_auth)):
    return syslog.items(level.upper(), q[:100])


# ---------------------------------------------------------------- informes de Pentera → Vulnerabilidades
REPORTS_DIR = os.path.join(os.path.dirname(os.getenv("DB_PATH", "/data/soc.db")), "reports")
PENTERA_MAX_MB = int(os.getenv("PENTERA_MAX_MB", "50") or 50)
store.db.executescript("""CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, source TEXT, sha256 TEXT, size INTEGER, fmt TEXT, uploaded_by TEXT,
  at TEXT, items INTEGER DEFAULT 0, imported INTEGER DEFAULT 0, file TEXT);""")


@app.post("/portal/api/vulns/pentera")
async def pentera_upload(request: Request, filename: str = "informe.pdf", user: str = Depends(portal_auth)):
    """Sube el informe (PDF, JSON o CSV), lo guarda y devuelve los hallazgos para revisarlos antes de importar."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    buf, size = bytearray(), 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > PENTERA_MAX_MB * 1024 * 1024:
            raise HTTPException(413, f"El informe supera {PENTERA_MAX_MB} MB")
        buf.extend(chunk)
    if not size:
        raise HTTPException(400, "Archivo vacío")
    data = bytes(buf)
    name = re.sub(r"[^\w.\- ()áéíóúñÁÉÍÓÚÑ]", "_", os.path.basename(filename))[:120] or "informe"
    try:
        res = await asyncio.wait_for(asyncio.to_thread(pentera.parse, data, name), timeout=240)
    except asyncio.TimeoutError:
        raise HTTPException(400, "El informe tardó demasiado en leerse; expórtalo en JSON o CSV desde Pentera")
    except Exception as exc:
        log.warning("Pentera: no se pudo leer %s: %s", name, exc)
        raise HTTPException(400, f"No se pudo leer el archivo ({type(exc).__name__}). ¿Es un PDF, JSON o CSV de Pentera?")
    sha = hashlib.sha256(data).hexdigest()
    ext = {"pdf": ".pdf", "json": ".json", "csv": ".csv"}[res["formato"]]
    path = os.path.join(REPORTS_DIR, sha + ext)
    if not os.path.exists(path):
        with open(path, "wb") as fh:
            fh.write(data)
    prev = store._q("SELECT id, at, uploaded_by FROM reports WHERE sha256 = ? ORDER BY id DESC LIMIT 1", (sha,), one=True)
    rid = store._x("INSERT INTO reports(name, source, sha256, size, fmt, uploaded_by, at, items, file) VALUES(?,?,?,?,?,?,?,?,?)",
                   (name, "pentera", sha, size, res["formato"], user, now_str(), len(res["items"]), os.path.basename(path)))
    return {"report_id": rid, "nombre": name, "formato": res["formato"], "estrategia": res["estrategia"],
            "aviso": res["aviso"] + (f" Este mismo archivo ya se subió el {prev['at']} ({prev['uploaded_by']})." if prev else ""),
            "items": res["items"]}


@app.post("/portal/api/vulns/pentera/{rid}/import")
def pentera_import(rid: int, data: dict = Body(...), user: str = Depends(portal_auth)):
    """Guarda los hallazgos revisados (el analista puede quitar filas o cambiar severidad y título)."""
    rep = store._q("SELECT * FROM reports WHERE id = ?", (rid,), one=True)
    if not rep:
        raise HTTPException(404, "Informe no encontrado")
    items = (data.get("items") or [])[:5000]
    if not items:
        raise HTTPException(400, "No hay hallazgos seleccionados")
    new = upd = 0
    for it in items:
        title = str(it.get("title") or "").strip()[:300]
        if not title:
            continue
        vals = {"title": title, "severity": it.get("severity") if it.get("severity") in SEVERITIES else "Medium",
                "cve": str(it.get("cve") or "")[:300], "asset": str(it.get("asset") or "")[:2000],
                "port": str(it.get("port") or "")[:100], "solution": str(it.get("solution") or "")[:1500],
                "notes": (str(it.get("notes") or "")[:3500] + f"\n\nInforme: {rep['name']} (#{rid}, {rep['at'][:10]})").strip()}
        key = it.get("ext_key") or pentera._key(title)
        _, created = store.save_vuln(None, vals, user, source="pentera", ext_key=str(key)[:64])
        new += created; upd += (not created)
    store._x("UPDATE reports SET imported = ? WHERE id = ?", (new + upd, rid))
    log.info("Pentera: %s nuevas, %s actualizadas desde %s por %s", new, upd, rep["name"], user)
    return {"nuevas": new, "actualizadas": upd}


@app.get("/portal/api/vulns/reports")
def reports_list(user: str = Depends(portal_auth)):
    return store._q("SELECT id, name, source, size, fmt, uploaded_by, at, items, imported FROM reports ORDER BY id DESC LIMIT 200")


@app.get("/portal/api/vulns/reports/{rid}/file")
def report_file(rid: int, user: str = Depends(portal_auth)):
    rep = store._q("SELECT * FROM reports WHERE id = ?", (rid,), one=True)
    if not rep or not rep["file"]:
        raise HTTPException(404, "Informe no encontrado")
    path = os.path.join(REPORTS_DIR, os.path.basename(rep["file"]))
    if not os.path.exists(path):
        raise HTTPException(404, "El archivo ya no está en el servidor")
    audit.record(user=user, method="GET", path=f"/portal/api/vulns/reports/{rid}/file", module="Vulnerabilidades",
                 action="Descargar informe", target=rep["name"], status=200)
    media = {"pdf": "application/pdf", "json": "application/json", "csv": "text/csv"}.get(rep["fmt"], "application/octet-stream")
    return FileResponse(path, media_type=media, filename=rep["name"], content_disposition_type="attachment")


# ---------------------------------------------------------------- Microsoft 365
def _m365_guard():
    if not m365.on:
        raise HTTPException(400, "Microsoft 365 no está configurado: añade M365_TENANT_ID, M365_CLIENT_ID y M365_CLIENT_SECRET al .env")


def _m365_call(fn, *a):
    _m365_guard()
    try:
        return fn(*a)
    except M365Error as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(502, m365_friendly(exc))


@app.get("/portal/api/m365/status")
def m365_status(user: str = Depends(portal_auth)):
    return m365.status()


@app.post("/portal/api/m365/sync")
def m365_sync_now(user: str = Depends(portal_auth)):
    _m365_guard()
    m365._cache.clear()
    threading.Thread(target=_m365_sync, daemon=True, name="m365-sync").start()
    return {"ok": True}


@app.get("/portal/api/m365/alerts")
def m365_alerts(days: int = 7, severity: str = "", status: str = "", q: str = "", user: str = Depends(portal_auth)):
    return m365.alerts(max(1, min(days, 90)), severity if severity in ("low", "medium", "high", "informational") else "",
                       status if status in ("new", "inProgress", "resolved") else "", q[:100])


@app.get("/portal/api/m365/signins")
def m365_signins(hours: int = 24, user: str = Depends(portal_auth)):
    return _m365_call(m365.signins, max(1, min(hours, 168)))


@app.get("/portal/api/m365/risky")
def m365_risky(user: str = Depends(portal_auth)):
    return _m365_call(m365.risky)


@app.get("/portal/api/m365/posture")
def m365_posture(user: str = Depends(portal_auth)):
    return _m365_call(m365.posture)


@app.get("/portal/api/m365/audits")
def m365_audits(days: int = 7, user: str = Depends(portal_auth)):
    return _m365_call(m365.audits, max(1, min(days, 30)))


_m365_scan = {"running": False}


@app.get("/portal/api/m365/rules")
def m365_rules(user: str = Depends(portal_auth)):
    return {"scan": m365.rules(), "running": _m365_scan["running"]}


@app.post("/portal/api/m365/rules/scan")
def m365_rules_scan(user: str = Depends(portal_auth)):
    """Revisa en segundo plano las reglas de bandeja de entrada (primero los usuarios en riesgo o con alertas)."""
    _m365_guard()
    if _m365_scan["running"]:
        raise HTTPException(409, "Ya hay una revisión de reglas en curso")
    prio = set()
    try:
        prio |= {u["upn"] for u in m365.risky()["usuarios"]}
    except Exception:
        pass
    for a in m365.q("SELECT users FROM alerts ORDER BY created DESC LIMIT 200"):
        prio |= set(json.loads(a["users"] or "[]"))

    def run():
        _m365_scan["running"] = True
        try:
            r = m365.scan_rules(priority=prio)
            log.info("M365: reglas revisadas en %s buzones, %s sospechosas", r["revisados"], len(r["reglas"]))
        except Exception as exc:
            log.warning("M365: revisión de reglas: %s", m365_friendly(exc))
        finally:
            _m365_scan["running"] = False
    threading.Thread(target=run, daemon=True, name="m365-rules").start()
    return {"running": True}


@app.get("/portal/api/m365/actions")
def m365_actions(status: str = "", user: str = Depends(portal_auth)):
    return m365.actions(status if status in ("pending", "done", "failed", "rejected", "running") else "")


def _m365_target(kind: str, t: dict) -> dict:
    if kind == "resolve_alert":
        a = m365.q("SELECT id, title FROM alerts WHERE id = ?", (t.get("alert_id"),), one=True)
        if not a:
            raise HTTPException(400, "Alerta no encontrada")
        cls = t.get("classification") or "truePositive"
        if cls not in ("truePositive", "falsePositive", "informationalExpectedActivity"):
            raise HTTPException(400, "Clasificación no válida")
        return {"alert_id": a["id"], "classification": cls, "label": a["title"][:200]}
    who = str(t.get("user") or t.get("user_id") or "").strip()
    if not who or not re.match(r"^[\w.@'-]{3,200}$", who):
        raise HTTPException(400, "Indica el usuario (correo o id)")
    try:
        u = m365.find_user(who)
    except Exception as exc:
        raise HTTPException(400, f"Usuario no encontrado en 365: {m365_friendly(exc)}")
    out = {"user_id": u["id"], "upn": u["upn"], "label": f"{u['name']} <{u['upn']}>" if u["name"] else u["upn"]}
    if kind == "disable_rule":
        if not t.get("rule_id"):
            raise HTTPException(400, "Falta la regla")
        out.update(rule_id=str(t["rule_id"]), label=f"{u['upn']} · regla «{str(t.get('rule_name') or '')[:80]}»")
    return out


def _m365_hook(ip):
    def hook(a):
        txt = f"Microsoft 365 · {a['nombre']} ({a['label']}): {'✔' if a['status'] == 'done' else '✖'} {a['result']}"
        authsvc.audit(a["decided_by"], ip, "m365_action", f"#{a['id']} {a['kind']} {a['label']} → {a['status']}")
        if a.get("incident"):
            store.add_note(a["incident"], a["decided_by"], txt + f"\nMotivo: {a['reason']} · pedida por {a['requested_by']}")
    return hook


@app.post("/portal/api/m365/actions")
def m365_action_new(request: Request, data: dict = Body(...), user: str = Depends(actor)):
    """Desde el portal la acción se ejecuta al confirmarla (la persona aprueba). Desde Shuffle queda pendiente."""
    _m365_guard()
    kind = data.get("kind")
    if kind not in M365_KINDS:
        raise HTTPException(400, "Acción no soportada")
    reason = (data.get("reason") or "").strip()
    if len(reason) < 5:
        raise HTTPException(400, "Indica el motivo (mínimo 5 caracteres): queda en la auditoría")
    inc = (data.get("incident") or "").strip()
    if inc and not store.incident(inc):
        raise HTTPException(400, f"No existe el incidente {inc}")
    if m365.read_only:
        raise HTTPException(400, "Microsoft 365 está en solo lectura (M365_READ_ONLY=true)")
    target = _m365_target(kind, data.get("target") or {})
    human = user != "shuffle"
    try:
        return m365.request(kind, target, reason, user, "portal" if human else "shuffle", inc, execute=human,
                            hooks=_m365_hook(client_ip(request)))
    except M365Error as exc:
        raise HTTPException(400, str(exc))


@app.post("/portal/api/m365/actions/{aid}/{decision}")
def m365_action_decide(aid: int, decision: str, request: Request, data: dict = Body(default={}),
                       user: str = Depends(portal_auth)):
    if decision not in ("approve", "reject"):
        raise HTTPException(404, "No encontrado")
    _m365_guard()
    try:
        return m365.decide(aid, decision == "approve", user, (data or {}).get("note", ""), hooks=_m365_hook(client_ip(request)))
    except M365Error as exc:
        raise HTTPException(400, str(exc))


# ---------------------------------------------------------------- Resumen ampliado (paneles, riesgo, integraciones, línea de tiempo)
def _local(ts: str) -> str:
    """Normaliza a «AAAA-MM-DD HH:MM» en hora local. Las fechas ISO con Z/UTC (Sophos, 365) se convierten."""
    if not ts:
        return ""
    t = str(ts).replace("T", " ")
    if str(ts).endswith("Z") or "T" in str(ts):
        try:
            d = datetime.datetime.fromisoformat(str(ts)[:19].replace(" ", "T")).replace(tzinfo=datetime.timezone.utc)
            return d.astimezone().strftime("%Y-%m-%d %H:%M")
        except ValueError:
            pass
    return t[:16]


_ES = [(r"\bStatus:", "Estado:"), (r"\bSeverity:", "Severidad:"), (r"\bOwner:", "Responsable:"),
       (r"\bInvestigating\b", "En investigación"), (r"\bContained\b", "Contenido"), (r"\bClosed\b", "Cerrado"),
       (r"\bOpen\b", "Abierto"), (r"\bCritical\b", "Crítica"), (r"\bHigh\b", "Alta"), (r"\bMedium\b", "Media"),
       (r"\bLow\b", "Baja")]


def _es(t: str) -> str:
    """Traduce los textos de cronología que el backend guarda con nombres internos en inglés."""
    for rx, rep in _ES:
        t = re.sub(rx, rep, t)
    return t


def _since(hours: int, utc=False) -> str:
    d = (datetime.datetime.utcnow() if utc else datetime.datetime.now()) - datetime.timedelta(hours=hours)
    return d.strftime("%Y-%m-%dT%H:%M:%S" if utc else "%Y-%m-%d %H:%M:%S")


def _overview(user_role: str) -> dict:
    s = cached_summary(120)
    al = s.get("alertas") or {}
    crit = sum(c for lv, c in (al.get("por_nivel") or []) if lv >= 13)
    M = store.metrics()
    inc_open = store._q("SELECT severity, COUNT(*) n FROM incidents WHERE status != 'Closed' GROUP BY 1")
    io = {r["severity"]: r["n"] for r in inc_open}

    # --- sugerencias
    sug = store.suggestions("pending")
    sugg = {"pendientes": len(sug), "criticas": sum(1 for x in sug if x["severity"] == "Critical"),
            "top": [{"id": x["id"], "title": x["title"], "severity": x["severity"], "source": x["source"], "n": x["n"]}
                    for x in sug[:4]]}

    # --- portales
    sites = store._q("SELECT name, state, enabled, waf, deface, ssl_expiry FROM sites")
    on = [x for x in sites if x["enabled"]]
    today = datetime.date.today()
    ssl30 = sum(1 for x in on if x["ssl_expiry"] and
                (datetime.date.fromisoformat(x["ssl_expiry"][:10]) - today).days <= 30)
    nowaf = {"bypass", "directo"}
    port = {"total": len(sites), "activos": len(on), "en_linea": sum(1 for x in on if x["state"] == "up"),
            "caidos": sum(1 for x in on if x["state"] == "down"),
            "desfigurados": sum(1 for x in on if x["deface"] == "defacement"),
            "sospecha": sum(1 for x in on if x["deface"] == "sospecha"),
            "sin_waf": sum(1 for x in on if x["waf"] in nowaf),
            "sin_waf_con_problema": sum(1 for x in on if x["waf"] in nowaf and (x["state"] == "down" or x["deface"] in ("sospecha", "defacement"))),
            "ssl30": ssl30,
            "alertas": [{"name": x["name"], "estado": x["deface"] if x["deface"] in ("defacement", "sospecha") else x["state"], "waf": x["waf"]}
                        for x in on if x["deface"] in ("defacement", "sospecha") or x["state"] == "down"][:6]}

    # --- Sophos (solo datos locales: no se llama a la API aquí)
    soph = {"configurado": sophos.on}
    if sophos.on:
        since = _since(24, utc=True)
        q1 = lambda sql, *a: sophos.q(sql, a, one=True)["n"]
        eps = [json.loads(r["data"]) for r in sophos.q("SELECT data FROM endpoints")]
        soph.update(alertas_24h=q1("SELECT COUNT(*) n FROM alerts WHERE raised_at >= ?", since),
                    altas_24h=q1("SELECT COUNT(*) n FROM alerts WHERE raised_at >= ? AND severity = 'high'", since),
                    equipos=len(eps), salud_mala=sum(1 for e in eps if (e.get("health") or {}).get("overall") == "bad"),
                    aislados=sum(1 for e in eps if (e.get("isolation") or {}).get("status") == "isolated"),
                    pendientes=q1("SELECT COUNT(*) n FROM actions WHERE status = 'pending'"),
                    ultima_sync=sophos.kv("last_sync") or "", sync_msg=sophos.kv("sync_msg") or "")

    # --- Microsoft 365 (datos locales y lo que ya esté en caché)
    m3 = {"configurado": m365.on}
    if m365.on:
        since7 = _since(24 * 7, utc=True)
        q1 = lambda sql, *a: m365.q(sql, a, one=True)["n"]
        risky = (m365._cache.get("risky") or (0, None))[1]
        rules = m365.rules()
        m3.update(abiertas=q1("SELECT COUNT(*) n FROM alerts WHERE status != 'resolved' AND created >= ?", since7),
                  altas=q1("SELECT COUNT(*) n FROM alerts WHERE status != 'resolved' AND severity = 'high' AND created >= ?", since7),
                  usuarios_riesgo=len(risky["usuarios"]) if risky else None,
                  reglas_sospechosas=sum(1 for r in rules["reglas"] if r["enabled"]) if rules else None,
                  pendientes=q1("SELECT COUNT(*) n FROM actions WHERE status = 'pending'"),
                  ultima_sync=m365.kv("last_sync") or "", sync_msg=m365.kv("sync_msg") or "")

    # --- vulnerabilidades y Pentera
    V = store.vuln_stats()
    vsev = dict(V["por_severidad"])
    rep = store._q("SELECT id, name, at, items, imported FROM reports ORDER BY id DESC LIMIT 1", one=True)
    pent = store._q("SELECT COUNT(*) n FROM vulns WHERE source = 'pentera' AND status IN ('Open','Remediating')", one=True)["n"]
    vul = {"criticas": vsev.get("Critical", 0), "altas": vsev.get("High", 0), "activas": V["activas"], "vencidas": V["vencidas"],
           "pentera_abiertas": pent, "ultimo_informe": rep}

    # --- integraciones
    def st(name, configured, err="", last="", detail="", to="", warn=False):
        return {"name": name, "estado": "off" if not configured else ("error" if err else "aviso" if warn else "ok"),
                "detalle": (err or detail)[:160], "ultima": last, "to": to}
    corr_msg = intel.kv("corr_msg") or ""
    feeds_err = intel.rq("SELECT COUNT(*) n FROM sources WHERE enabled = 1 AND last_status LIKE 'Error%'", one=True)["n"]
    last_site = store._q("SELECT MAX(last_check) t FROM sites", one=True)["t"] or ""
    integ = [
        st("Wazuh", True, s.get("err_alertas") or "", s.get("generado", ""), "alertas e inventario", "/threats"),
        st("MISP", bool(os.getenv("MISP_BASE_URL")), s.get("err_misp_eventos") or "", s.get("generado", ""), "eventos e IoC", "/intel"),
        st("Shuffle", bool(os.getenv("SHUFFLE_URL")), s.get("err_workflows") or "", s.get("generado", ""),
           f"{len(s.get('workflows') or [])} workflows", ""),
        st("Sophos Central", sophos.on, (soph.get("sync_msg") or "") if (soph.get("sync_msg") or "").startswith("Error") else "",
           soph.get("ultima_sync", ""), "alertas y equipos", "/sophos"),
        st("Microsoft 365", m365.on, (m3.get("sync_msg") or "") if (m3.get("sync_msg") or "").startswith("Error") else "",
           m3.get("ultima_sync", ""), "Defender, Entra ID, correo", "/m365"),
        st("Motor de IoC", True, corr_msg if corr_msg.startswith("Error") else "", intel.kv("corr_last_ok") or "",
           f"correlación con Wazuh · {feeds_err} fuentes con error" if feeds_err else "correlación con Wazuh", "/iocs",
           warn=bool(feeds_err)),
        st("Monitor de portales", bool(sites), "", last_site[:16], f"{len(on)} portales", "/sites"),
        st("Asistente IA", bool(os.getenv("AI_PROVIDER")), "", "", os.getenv("AI_MODEL", ""), "/ai"),
        st("Capturas (soc-screens)", screens.enabled(),
           "" if not screens.enabled() else (lambda h: "" if h["ok"] else h["detalle"] or "sin respuesta")(cached("screens-health", 60, screens.health)),
           _visual.get("last", ""), f"comparación visual cada {SCREENS_INTERVAL_H:g} h", "/sites"),
        st("Exposición / Shadow IT", bool(exposure.config()["dominios"] or exposure.config()["rangos"]),
           (exposure.job() or {}).get("msg", "") if (exposure.job() or {}).get("status") == "failed" else "",
           ((exposure.job() or {}).get("finished") or "")[:16], "superficie de ataque", "/exposure"),
    ]
    down = sum(1 for x in integ if x["estado"] == "error")

    # --- puntuación de riesgo (0 = tranquilo · 100 = crítico)
    F = []

    def f(label, n, per, cap, to):
        if n:
            F.append({"factor": label, "n": n, "puntos": min(cap, n * per), "to": to})
    f("Sitios desfigurados", port["desfigurados"], 25, 30, "/sites?deface=defacement")
    f("Alertas críticas de Wazuh (24 h)", crit, 2, 20, "/threats")
    f("Incidentes críticos abiertos", io.get("Critical", 0), 10, 20, "/incidents?severity=Critical")
    f("Alertas altas de Defender abiertas", m3.get("altas", 0), 5, 15, "/m365")
    f("Sugerencias críticas sin revisar", sugg["criticas"], 5, 10, "/incidents")
    f("Alertas altas de Sophos (24 h)", soph.get("altas_24h", 0), 3, 10, "/sophos")
    f("Portales con sospecha de inyección", port["sospecha"], 5, 10, "/sites?deface=alerta")
    f("SLA de incidentes vencidos", len(M["vencidos"]), 2, 10, "/incidents")
    f("Vulnerabilidades críticas abiertas", vul["criticas"], 1, 10, "/vulns?view=track&severity=Critical")
    f("Usuarios de 365 en riesgo", m3.get("usuarios_riesgo") or 0, 3, 10, "/m365?view=riesgo")
    f("Reglas de correo sospechosas", m3.get("reglas_sospechosas") or 0, 4, 10, "/m365?view=correo")
    f("Incidentes altos abiertos", io.get("High", 0), 2, 10, "/incidents?severity=High")
    f("Portales caídos", port["caidos"], 2, 10, "/sites?state=down")
    f("Equipos con mala salud (Sophos)", soph.get("salud_mala", 0), 1, 5, "/sophos?view=equipos")
    ex = exposure.summary()["hallazgos"]
    f("Exposiciones críticas (puertos, .git/.env, CVE)", ex.get("critical", 0), 5, 15, "/exposure?view=hallazgos&severity=critical")
    f("Exposiciones altas", ex.get("high", 0), 1, 5, "/exposure?view=hallazgos&severity=high")
    f("Integraciones con error", down, 3, 10, "")
    F.sort(key=lambda x: -x["puntos"])
    score = min(100, sum(x["puntos"] for x in F))
    nivel = "Bajo" if score < 20 else "Moderado" if score < 45 else "Alto" if score < 70 else "Crítico"

    # --- línea de tiempo (todas las fuentes)
    T = []
    for e in store._q("SELECT e.at, e.kind, e.text, s.name FROM site_events e JOIN sites s ON s.id = e.site_id "
                      "ORDER BY e.id DESC LIMIT 25"):
        T.append({"at": _local(e["at"]), "fuente": "Portales", "tipo": e["kind"], "texto": f"{e['name']}: {e['text']}"[:220], "to": "/sites"})
    for e in store._q("SELECT e.at, e.kind, e.text, e.author, i.code FROM incident_events e JOIN incidents i ON i.id = e.incident_id "
                      "ORDER BY e.id DESC LIMIT 25"):
        T.append({"at": _local(e["at"]), "fuente": "Incidentes", "tipo": e["kind"],
                  "texto": f"{e['code']} · {e['author']}: {_es(e['text'])}"[:220], "to": f"/incidents/{e['code']}"})
    for x in store._q("SELECT at, title, severity, source FROM incident_suggestions ORDER BY id DESC LIMIT 15"):
        T.append({"at": _local(x["at"]), "fuente": "Sugerencias", "tipo": x["severity"], "texto": x["title"][:220], "to": "/incidents"})
    if sophos.on:
        for x in sophos.q("SELECT raised_at, severity, description, endpoint FROM alerts ORDER BY raised_at DESC LIMIT 15"):
            T.append({"at": _local(x["raised_at"]), "fuente": "Sophos", "tipo": x["severity"],
                      "texto": f"{x['endpoint'] or 'equipo'}: {x['description']}"[:220], "to": "/sophos"})
        for x in sophos.q("SELECT at, kind, label, status, decided_by FROM actions ORDER BY id DESC LIMIT 10"):
            T.append({"at": _local(x["at"]), "fuente": "Sophos", "tipo": "accion",
                      "texto": f"Acción {x['kind']} sobre {x['label']} · {x['status']}"[:220], "to": "/sophos?view=acciones"})
    if m365.on:
        for x in m365.q("SELECT created, severity, title, users FROM alerts ORDER BY created DESC LIMIT 15"):
            T.append({"at": _local(x["created"]), "fuente": "Microsoft 365", "tipo": x["severity"],
                      "texto": f"{x['title']} · {', '.join(json.loads(x['users'] or '[]')[:2])}"[:220], "to": "/m365"})
        for x in m365.q("SELECT at, kind, label, status FROM actions ORDER BY id DESC LIMIT 10"):
            T.append({"at": _local(x["at"]), "fuente": "Microsoft 365", "tipo": "accion",
                      "texto": f"Acción {x['kind']} sobre {x['label']} · {x['status']}"[:220], "to": "/m365?view=acciones"})
    for x in intel.rq("SELECT last_seen, value, agent, n FROM sightings ORDER BY last_seen DESC LIMIT 10"):
        T.append({"at": _local(x["last_seen"]), "fuente": "IoC", "tipo": "coincidencia",
                  "texto": f"{x['value']} visto en {x['agent']} ({x['n']} alertas)"[:220], "to": "/iocs?view=coincidencias"})
    T.sort(key=lambda x: x["at"], reverse=True)

    exs = exposure.summary()
    expo = {"configurado": bool(exposure.config()["dominios"] or exposure.config()["rangos"]), "criticos": exs["hallazgos"].get("critical", 0),
            "altos": exs["hallazgos"].get("high", 0), "shadow": exs["shadow"], "servicios": exs["servicios"], "con_cve": exs["con_cve"],
            "ultimo": ((exs["ultimo"] or {}).get("finished") or "")[:16]}
    return {"generado": now_str()[:19], "sugerencias": sugg, "portales": port, "sophos": soph, "m365": m3, "exposicion": expo,
            "vulns": vul, "integraciones": integ,
            "acciones_pendientes": (soph.get("pendientes") or 0) + (m3.get("pendientes") or 0),
            "riesgo": {"puntuacion": score, "nivel": nivel, "factores": F},
            "incidentes": {"abiertos": sum(io.values()), "criticos": io.get("Critical", 0), "altos": io.get("High", 0),
                           "sla_vencidos": len(M["vencidos"])},
            "timeline": T[:60]}


@app.get("/portal/api/overview")
def overview(request: Request, user: str = Depends(portal_auth)):
    return _overview(request.state.user["role"])


# ---------------------------------------------------------------- comparación visual (capturas en soc-screens)
shots = screens.Store(os.path.join(os.path.dirname(os.getenv("DB_PATH", "/data/soc.db")), "screens"))
SCREENS_INTERVAL_H = float(os.getenv("SCREENS_INTERVAL_H", "6") or 6)
SCREENS_PARALLEL = int(os.getenv("SCREENS_PARALLEL", "3") or 3)
VISUAL_CHANGE = int(os.getenv("VISUAL_CHANGE_PCT", "30") or 30)
VISUAL_ALERT = int(os.getenv("VISUAL_ALERT_PCT", "60") or 60)
_visual = {"running": False, "done": 0, "total": 0, "last": ""}


def _visual_one(site: dict):
    sid = site["id"]
    try:
        img = screens.capture(site["url"])
    except Exception as exc:
        store._x("UPDATE sites SET visual_error = ?, visual_at = ? WHERE id = ?", (str(exc)[:200], now_str()[:16], sid))
        return
    shots.save(sid, "current", img)
    base = shots.read(sid, "baseline")
    if not base:  # primera captura: es la aprobada
        shots.save(sid, "baseline", img)
        store._x("""UPDATE sites SET visual_level = 'ok', visual_pct = 0, visual_at = ?, visual_base_at = ?, visual_error = ''
                    WHERE id = ?""", (now_str()[:16], now_str()[:16], sid))
        return
    pct, diff = screens.compare(base, img)
    shots.save(sid, "diff", diff)
    lv = screens.level(pct, VISUAL_CHANGE, VISUAL_ALERT)
    prev = site.get("visual_level") or "ok"
    total = _max_level(site.get("deface_text") or "ok", lv)
    reasons = [r for r in json.loads(site.get("deface_reasons") or "[]") if "captura aprobada" not in r.get("motivo", "")]
    if lv != "ok":
        reasons.append({"nivel": lv, "motivo": f"La página se ve un {pct:g} % distinta de la captura aprobada"})
    store._x("""UPDATE sites SET visual_level = ?, visual_pct = ?, visual_at = ?, visual_error = '', deface = ?, deface_reasons = ?
                WHERE id = ?""", (lv, pct, now_str()[:16], total, json.dumps(reasons, ensure_ascii=False), sid))
    if deface.LEVELS.index(lv) > deface.LEVELS.index(prev):
        store.site_event(sid, "deface" if lv == "sospecha" else "content",
                         f"Cambio visual: la página se ve un {pct:g} % distinta de la captura aprobada")
        log.warning("Portal %s: cambio visual %s %%", site["name"], pct)
        if lv == "sospecha" and site.get("auto_incident"):
            code = propose_incident({
                "title": f"Posible desfiguración visual en {site['name']}", "severity": "High",
                "detected_by": "Monitor de portales (comparación visual)", "assets": site["url"], "runbook": "desfiguracion-web",
                "summary": f"La captura de {site['url']} difiere un {pct:g} % de la versión aprobada. "
                           "Revisa la comparación (antes / ahora / diferencias) en Portales."}, "monitor", f"site-visual-{sid}")
            _inc_event(sid, code)


def _visual_due():
    if not screens.enabled():
        return []
    lim = (datetime.datetime.now() - datetime.timedelta(hours=SCREENS_INTERVAL_H)).strftime("%Y-%m-%d %H:%M")
    return store._q("""SELECT * FROM sites WHERE enabled = 1 AND watch_content = 1 AND state != 'down'
                       AND (visual_at = '' OR visual_at IS NULL OR visual_at < ?) ORDER BY critical DESC, visual_at LIMIT 200""", (lim,))


def _visual_run(sites):
    from concurrent.futures import ThreadPoolExecutor
    _visual.update(running=True, done=0, total=len(sites))
    try:
        with ThreadPoolExecutor(max_workers=SCREENS_PARALLEL, thread_name_prefix="visual") as ex:
            for _ in ex.map(lambda s: (_visual_one(s), _visual.__setitem__("done", _visual["done"] + 1)), sites):
                pass
    finally:
        _visual.update(running=False, last=now_str()[:16])


async def visual_loop():
    """Recorre los portales vigilados y captura los que tocan (cada SCREENS_INTERVAL_H horas)."""
    await asyncio.sleep(60)
    while True:
        try:
            due = await asyncio.to_thread(_visual_due)
            if due and not _visual["running"]:
                await asyncio.to_thread(_visual_run, due)
        except Exception as exc:
            log.warning("Comparación visual: %s", exc)
        await asyncio.sleep(300)


@app.on_event("startup")
async def _start_visual():
    asyncio.create_task(visual_loop())


@app.get("/portal/api/sites/{sid}/screen/{which}")
def site_screen(sid: int, which: str, user: str = Depends(portal_auth)):
    if which not in ("baseline", "current", "diff"):
        raise HTTPException(404, "No encontrado")
    img = shots.read(sid, which)
    if not img:
        raise HTTPException(404, "Aún no hay captura")
    return Response(img, media_type="image/jpeg", headers={"Cache-Control": "no-store"})


@app.post("/portal/api/sites/{sid}/screen")
def site_screen_now(sid: int, user: str = Depends(portal_auth)):
    if not screens.enabled():
        raise HTTPException(400, "La comparación visual está desactivada: define SCREENS_TOKEN en el .env")
    s = store.site(sid)
    if not s:
        raise HTTPException(404, "No encontrado")
    _visual_one(s)
    return store.site(sid)


@app.get("/portal/api/sites/visual/status")
def visual_status(user: str = Depends(portal_auth)):
    return {**_visual, "activo": screens.enabled(), "intervalo_h": SCREENS_INTERVAL_H,
            "umbral_cambio": VISUAL_CHANGE, "umbral_alerta": VISUAL_ALERT}


# ---------------------------------------------------------------- Exposición cibernética y Shadow IT
def _inventory():
    """Lo que ACME ya tiene registrado (Portales): todo lo demás que se descubra es candidato a Shadow IT."""
    hosts, ips = set(), set()
    for r in store._q("SELECT url, public_ip FROM sites"):
        h = (urlparse_host(r["url"]).split("/")[0] or "")
        if h:
            hosts.add(h)
        for ip in re.split(r"[,;\s]+", r["public_ip"] or ""):
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
                ips.add(ip)
    for e in exposure.q("SELECT value FROM assets WHERE status = 'conocido'"):
        (ips if re.fullmatch(r"[\d.]+", e["value"]) else hosts).add(e["value"])
    return {"hosts": sorted(hosts), "ips": sorted(ips)}


def _exp_suggest(d, key):
    propose_incident(d, "exposure", key)


@app.get("/portal/api/exposure/summary")
def exposure_summary(user: str = Depends(portal_auth)):
    c = exposure.config()
    ok, why = exposure.authorized()
    return {**exposure.summary(), "alcance": {"dominios": len(c["dominios"]), "rangos": c["rangos"], "perfil": c["perfil"],
                                              "autorizado": ok, "motivo": why}}


@app.get("/portal/api/exposure/config")
def exposure_config(user: str = Depends(portal_auth)):
    import exposure as E
    return {**exposure.config(), "perfiles": {k: len(v) for k, v in E.PROFILES.items()}, "max_ips": E.MAX_SCAN_IPS}


@app.put("/portal/api/admin/exposure/config")
def exposure_config_save(data: dict = Body(...), user: str = Depends(portal_auth)):
    try:
        return exposure.save_config(data, user)
    except ScopeError as exc:
        raise HTTPException(400, str(exc))


@app.post("/portal/api/exposure/scan")
def exposure_scan(request: Request, data: dict = Body(default={}), user: str = Depends(portal_auth)):
    kind = (data or {}).get("kind", "pasivo")
    if kind not in ("pasivo", "completo"):
        raise HTTPException(400, "Tipo de escaneo no válido")
    if kind == "completo" and request.state.user["role"] != "admin":
        raise HTTPException(403, "El escaneo activo solo lo pueden lanzar administradores")
    try:
        jid = exposure.start(kind, user, _inventory(), _exp_suggest)
    except ScopeError as exc:
        raise HTTPException(400, str(exc))
    authsvc.audit(user, client_ip(request), "exposure_scan", f"#{jid} {kind} · alcance {exposure.config()['rangos']}")
    log.warning("Exposición: escaneo %s #%s lanzado por %s", kind, jid, user)
    return exposure.job(jid)


@app.post("/portal/api/exposure/stop")
def exposure_stop(user: str = Depends(portal_auth)):
    exposure.stop()
    return {"ok": True}


@app.get("/portal/api/exposure/jobs")
def exposure_jobs(user: str = Depends(portal_auth)):
    return {"items": exposure.jobs(), "en_curso": exposure.running}


@app.get("/portal/api/exposure/findings")
def exposure_findings(status: str = "open", severity: str = "", category: str = "", q: str = "", user: str = Depends(portal_auth)):
    return exposure.findings(status if status in ("open", "accepted", "fixed", "") else "open", severity, category, q[:100])


@app.put("/portal/api/exposure/findings/{key}")
def exposure_finding_set(key: str, data: dict = Body(...), user: str = Depends(portal_auth)):
    try:
        exposure.set_finding(key, data.get("status", ""), user, data.get("note", ""))
    except ScopeError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True}


@app.get("/portal/api/exposure/assets")
def exposure_assets(only: str = "", q: str = "", user: str = Depends(portal_auth)):
    return exposure.assets(only if only in ("shadow", "inventario", "") else "", q[:100])


@app.put("/portal/api/exposure/assets/{key:path}")
def exposure_asset_set(key: str, data: dict = Body(...), user: str = Depends(portal_auth)):
    try:
        exposure.set_asset(key, data.get("status", ""), data.get("note", ""))
    except ScopeError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True}


@app.post("/portal/api/exposure/assets/{key:path}/portal")
def exposure_asset_to_site(key: str, user: str = Depends(portal_auth)):
    """Un subdominio descubierto pasa a Portales (queda inventariado y vigilado contra desfiguración)."""
    a = exposure.q("SELECT * FROM assets WHERE key = ?", (key,), one=True)
    if not a or a["type"] != "host":
        raise HTTPException(400, "Solo se pueden añadir subdominios")
    web = json.loads(a["web"] or "{}")
    url = next((u for u in web if u.startswith("https") and web[u].get("status")), None) or f"https://{a['value']}/"
    if any(urlparse_host(r["url"]) == urlparse_host(url) for r in store._q("SELECT url FROM sites")):
        raise HTTPException(400, "Ya está en Portales")
    sid = store.save_site(None, {"name": a["value"], "url": url, "interval_min": 15, "watch_content": 1, "auto_incident": 1,
                                 "enabled": 1, "public_ip": ", ".join(json.loads(a["ips"] or "[]"))[:200], "grp": "Shadow IT"})
    exposure.x("UPDATE assets SET inventoried = 1, status = 'conocido' WHERE key = ?", (key,))
    exposure.x("UPDATE findings SET status='fixed', note='Añadido a Portales' WHERE asset = ? AND category = 'shadow'", (key,))
    return store.site(sid)


@app.get("/portal/api/exposure/services")
def exposure_services(q: str = "", user: str = Depends(portal_auth)):
    return exposure.services(q[:60])


async def exposure_loop():
    """Escaneo programado (programado_dias > 0): activo si hay autorización vigente; si no, pasivo."""
    await asyncio.sleep(120)
    while True:
        try:
            c = exposure.config()
            days = c.get("programado_dias") or 0
            last = exposure.job()
            due = days and (not last or last["at"] < (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S"))
            if due and not exposure.running and (c["dominios"] or c["rangos"]):
                kind = "completo" if exposure.authorized()[0] and c["perfil"] != "pasivo" else "pasivo"
                exposure.start(kind, "programado", _inventory(), _exp_suggest)
                log.info("Exposición: escaneo programado (%s)", kind)
        except Exception as exc:
            log.warning("Exposición programada: %s", exc)
        await asyncio.sleep(3600)


@app.on_event("startup")
async def _start_exposure():
    asyncio.create_task(exposure_loop())
