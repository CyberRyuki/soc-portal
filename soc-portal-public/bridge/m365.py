"""Integración con Microsoft 365 (Microsoft Graph, permisos de aplicación).

Lectura:
- Alertas de Microsoft Defender XDR (security/alerts_v2), con evidencias (usuarios, IP, URL, correo, archivos).
- Inicios de sesión (Entra ID): fallidos, con riesgo y desde el extranjero; usuarios en riesgo y detecciones.
- Secure Score con las recomendaciones de más puntos y estado de los servicios de 365.
- Auditoría del directorio (roles, acceso condicional, aplicaciones, contraseñas) y reglas de bandeja de entrada que
  reenvían a dominios externos o borran correo (señal típica de cuenta comprometida / BEC).
Respuesta (regla del piloto: siempre confirmada por una persona, con motivo y auditoría):
- Revocar sesiones, bloquear/desbloquear inicio de sesión, forzar cambio de contraseña, confirmar compromiso o
  descartar el riesgo de un usuario, resolver una alerta de Defender y desactivar una regla de bandeja de entrada.
"""
import datetime
import json
import logging
import os
import re
import sqlite3
import threading
import time

import requests

log = logging.getLogger("soc-bridge.m365")
AUTH_URL = os.getenv("M365_AUTH_URL", "https://login.microsoftonline.com").rstrip("/")
GRAPH = os.getenv("M365_GRAPH_URL", "https://graph.microsoft.com/v1.0").rstrip("/")
TIMEOUT = 40
SEV_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3}
SENSITIVE_AUDIT = re.compile(r"role|conditional access|policy|consent|credential|certificate|secret|service principal|"
                             r"reset (user )?password|delete user|federation|domain|mfa|authentication method", re.I)

KINDS = {  # acción → (nombre, ¿contención?)
    "revoke_sessions": ("Revocar sesiones", True),
    "disable_user": ("Bloquear inicio de sesión", True),
    "enable_user": ("Desbloquear inicio de sesión", False),
    "force_password": ("Forzar cambio de contraseña", True),
    "confirm_compromised": ("Confirmar cuenta comprometida", True),
    "dismiss_risk": ("Descartar riesgo del usuario", False),
    "resolve_alert": ("Resolver alerta de Defender", False),
    "disable_rule": ("Desactivar regla de bandeja de entrada", True),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts(
  id TEXT PRIMARY KEY, created TEXT, updated TEXT, severity TEXT, status TEXT, title TEXT, category TEXT, service TEXT,
  detection TEXT, incident_id TEXT, url TEXT, users TEXT, ips TEXT, urls TEXT, mitre TEXT, description TEXT,
  recommended TEXT, matches TEXT DEFAULT '{}', classification TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_m_created ON alerts(created);
CREATE TABLE IF NOT EXISTS actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, requested_by TEXT, origin TEXT, kind TEXT, target TEXT, label TEXT,
  reason TEXT, incident TEXT DEFAULT '', status TEXT, decided_by TEXT DEFAULT '', decided_at TEXT DEFAULT '', result TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
"""


def now_s():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _env(k, d=""):
    return (os.getenv(k) or d).strip()


class M365Error(RuntimeError):
    pass


def friendly(exc) -> str:
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        c = exc.response.status_code
        try:
            e = exc.response.json().get("error") or {}
            msg = e.get("message") if isinstance(e, dict) else str(e)
        except Exception:
            msg = ""
        base = {400: "Microsoft Graph rechazó la petición", 401: "credenciales de la app de Entra no válidas o caducadas",
                403: "a la app le falta un permiso de Graph (o el consentimiento de administrador)",
                404: "no existe en Microsoft 365", 429: "Microsoft limita las peticiones; espera un momento"}.get(c, f"HTTP {c} de Graph")
        return f"{base}{': ' + str(msg)[:220] if msg else ''}"
    if isinstance(exc, requests.ConnectionError):
        return "no conecta con Microsoft (¿salida a login.microsoftonline.com y graph.microsoft.com?)"
    return str(exc)[:250]


class M365:
    def __init__(self, db_path: str):
        self.tenant, self.cid, self.secret = _env("M365_TENANT_ID"), _env("M365_CLIENT_ID"), _env("M365_CLIENT_SECRET")
        self.read_only = _env("M365_READ_ONLY", "false").lower() in ("1", "true", "yes")
        self.four_eyes = _env("M365_FOUR_EYES", "false").lower() in ("1", "true", "yes")
        self.poll_min = max(1, int(_env("M365_POLL_MIN", "5") or 5))
        self.suggest_sev = _env("M365_SUGGEST_SEVERITY", "high").lower()
        self.home_country = _env("M365_HOME_COUNTRY", "DO").upper()
        self.path, self.lock = db_path, threading.Lock()
        self._tok, self._exp, self._cache = None, 0, {}
        with self._db() as c:
            c.executescript(SCHEMA)

    # ------------------------------------------------------------ base local
    def _db(self):
        c = sqlite3.connect(self.path, timeout=60)
        c.row_factory = sqlite3.Row
        return c

    def q(self, sql, args=(), one=False):
        with self._db() as c:
            rows = [dict(r) for r in c.execute(sql, args).fetchall()]
        return (rows[0] if rows else None) if one else rows

    def x(self, sql, args=()):
        with self.lock, self._db() as c:
            return c.execute(sql, args).lastrowid

    def kv(self, k, v=None):
        if v is None:
            r = self.q("SELECT v FROM kv WHERE k = ?", (k,), one=True)
            return r["v"] if r else None
        self.x("INSERT INTO kv(k, v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, str(v)))

    def cached(self, key, ttl, fn):
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        val = fn()
        self._cache[key] = (time.time(), val)
        return val

    # ------------------------------------------------------------ Graph
    @property
    def on(self):
        return bool(self.tenant and self.cid and self.secret)

    def _token(self):
        if self._tok and time.time() < self._exp - 120:
            return self._tok
        r = requests.post(f"{AUTH_URL}/{self.tenant}/oauth2/v2.0/token", timeout=TIMEOUT,
                          data={"grant_type": "client_credentials", "client_id": self.cid, "client_secret": self.secret,
                                "scope": "https://graph.microsoft.com/.default"})
        if r.status_code in (400, 401):
            try:
                why = r.json().get("error_description", "")[:200]
            except Exception:
                why = ""
            raise M365Error(f"Entra rechazó la app (revisa M365_TENANT_ID / CLIENT_ID / CLIENT_SECRET). {why}")
        r.raise_for_status()
        d = r.json()
        self._tok, self._exp = d["access_token"], time.time() + int(d.get("expires_in", 3600))
        return self._tok

    def g(self, method, path, **kw):
        if not self.on:
            raise M365Error("Microsoft 365 no está configurado (M365_TENANT_ID, M365_CLIENT_ID, M365_CLIENT_SECRET)")
        url = path if path.startswith("http") else GRAPH + path
        h = {"Authorization": f"Bearer {self._token()}", "Accept": "application/json", **kw.pop("headers", {})}
        for attempt in range(3):
            r = requests.request(method, url, headers=h, timeout=TIMEOUT, **kw)
            if r.status_code == 429 and attempt < 2:  # Graph pide esperar
                time.sleep(min(10, int(r.headers.get("Retry-After", "3") or 3)))
                continue
            break
        r.raise_for_status()
        return r.json() if r.content else {}

    def pages(self, path, params=None, limit=5000):
        out, url, p = [], path, dict(params or {})
        while url and len(out) < limit:
            d = self.g("GET", url, params=p)
            out += d.get("value", [])
            url, p = d.get("@odata.nextLink"), None
        return out[:limit]

    # ------------------------------------------------------------ estado
    def status(self):
        if not self.on:
            return {"configurado": False}
        try:
            org = self.cached("org", 3600, lambda: (self.g("GET", "/organization", params={
                "$select": "displayName,verifiedDomains"}).get("value") or [{}])[0])
            ok, err = True, ""
        except Exception as exc:
            org, ok, err = {}, False, friendly(exc)
        return {"configurado": True, "conectado": ok, "error": err, "organizacion": org.get("displayName", ""),
                "dominios": [d["name"] for d in org.get("verifiedDomains") or []][:20],
                "ultima_sync": self.kv("last_sync") or "", "sync_msg": self.kv("sync_msg") or "",
                "solo_lectura": self.read_only, "four_eyes": self.four_eyes, "poll_min": self.poll_min,
                "sugerir": self.suggest_sev, "pais": self.home_country,
                "pendientes": self.q("SELECT COUNT(*) n FROM actions WHERE status = 'pending'", one=True)["n"]}

    def domains(self):
        try:
            return {d.lower() for d in self.status().get("dominios") or []}
        except Exception:
            return set()

    # ------------------------------------------------------------ alertas de Defender
    def sync(self, intel=None, suggest=None):
        if not self.on:
            return
        try:
            since = self.kv("alerts_since") or iso(datetime.datetime.utcnow() - datetime.timedelta(days=7))
            items = self.pages("/security/alerts_v2", {"$filter": f"lastUpdateDateTime ge {since}", "$top": 200}, limit=3000)
            new, newest = 0, since
            for a in items:
                if self._store(a, intel, suggest):
                    new += 1
                newest = max(newest, (a.get("lastUpdateDateTime") or "")[:19] + "Z")
            if newest != since:
                self.kv("alerts_since", newest)
            self.kv("last_sync", now_s()[:16])
            self.kv("sync_msg", f"OK · {new} alertas nuevas · {len(items)} actualizadas")
        except Exception as exc:
            self.kv("sync_msg", "Error: " + friendly(exc))
            log.warning("Microsoft 365: %s", friendly(exc))

    def _store(self, a, intel, suggest):
        ev = a.get("evidence") or []
        users = sorted({(e.get("userAccount") or {}).get("userPrincipalName") or (e.get("userAccount") or {}).get("accountName")
                        for e in ev if e.get("userAccount")} - {None, ""})
        users += sorted({e.get("recipientEmailAddress") for e in ev if e.get("recipientEmailAddress")} - set(users))
        ips = sorted({e.get("ipAddress") for e in ev if e.get("ipAddress")})
        urls = sorted({e.get("url") for e in ev if e.get("url")})
        mitre = a.get("mitreTechniques") or []
        matches = {}
        if intel and (ips or urls):
            matches = {v: len({m["sid"] for m in ms}) for v, ms in intel.lookup(ips + urls).items()}
        existed = self.q("SELECT id FROM alerts WHERE id = ?", (a["id"],), one=True)
        row = (a.get("createdDateTime", "")[:19], (a.get("lastUpdateDateTime") or "")[:19], (a.get("severity") or "").lower(),
               a.get("status", ""), a.get("title", ""), a.get("category", ""), a.get("serviceSource", ""),
               a.get("detectionSource", ""), str(a.get("incidentId") or ""), a.get("alertWebUrl") or a.get("incidentWebUrl") or "",
               json.dumps(users[:30]), json.dumps(ips[:30]), json.dumps(urls[:30]), json.dumps(mitre[:20]),
               (a.get("description") or "")[:4000], (a.get("recommendedActions") or "")[:3000], json.dumps(matches),
               a.get("classification") or "")
        if existed:
            self.x("""UPDATE alerts SET created=?, updated=?, severity=?, status=?, title=?, category=?, service=?, detection=?,
                      incident_id=?, url=?, users=?, ips=?, urls=?, mitre=?, description=?, recommended=?, matches=?,
                      classification=? WHERE id=?""", row + (a["id"],))
            return False
        self.x("""INSERT INTO alerts(created, updated, severity, status, title, category, service, detection, incident_id, url,
                  users, ips, urls, mitre, description, recommended, matches, classification, id)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", row + (a["id"],))
        sev = row[2]
        if suggest and self.suggest_sev in SEV_RANK and SEV_RANK.get(sev, 0) >= SEV_RANK[self.suggest_sev] \
                and a.get("status") != "resolved":
            suggest({"title": f"Microsoft 365: {a.get('title', 'alerta')}"[:200],
                     "severity": "Critical" if sev == "high" and matches else "High" if sev == "high" else "Medium",
                     "detected_by": f"Microsoft Defender ({a.get('serviceSource', '')})", "assets": ", ".join(users[:10]),
                     "iocs": "\n".join(ips + urls),
                     "summary": f"{a.get('description') or a.get('title')}\n\nCategoría: {a.get('category')}. "
                                f"MITRE: {', '.join(mitre) or '—'}. Usuarios: {', '.join(users[:10]) or '—'}."
                                + (f"\nIoC ya conocidos: {', '.join(matches)}" if matches else "")
                                + (f"\nDefender: {row[9]}" if row[9] else "")},
                    f"m365-{a.get('incidentId') or a['id']}")
        return True

    def alerts(self, days=7, severity="", status="", q="", limit=300):
        since = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        sql, a = "SELECT * FROM alerts WHERE created >= ?", [since]
        if severity:
            sql += " AND severity = ?"; a.append(severity)
        if status:
            sql += " AND status = ?"; a.append(status)
        if q:
            sql += " AND (title LIKE ? OR users LIKE ? OR ips LIKE ? OR description LIKE ?)"; a += [f"%{q}%"] * 4
        rows = self.q(sql + " ORDER BY created DESC LIMIT ?", a + [limit])
        for r in rows:
            for k in ("users", "ips", "urls", "mitre", "matches"):
                r[k] = json.loads(r[k] or ("{}" if k == "matches" else "[]"))
        stats = {"severidad": [[r["severity"], r["n"]] for r in self.q(
                     "SELECT severity, COUNT(*) n FROM alerts WHERE created >= ? GROUP BY 1", (since,))],
                 "servicio": [[r["service"], r["n"]] for r in self.q(
                     "SELECT service, COUNT(*) n FROM alerts WHERE created >= ? GROUP BY 1 ORDER BY 2 DESC LIMIT 8", (since,))],
                 "abiertas": self.q("SELECT COUNT(*) n FROM alerts WHERE created >= ? AND status != 'resolved'", (since,), one=True)["n"]}
        return {"items": rows, "stats": stats}

    # ------------------------------------------------------------ identidad
    def signins(self, hours=24):
        def load():
            since = iso(datetime.datetime.utcnow() - datetime.timedelta(hours=hours))
            rows = self.pages("/auditLogs/signIns", {"$filter": f"createdDateTime ge {since}", "$top": 1000}, limit=8000)
            out, by_user, by_country, by_ip = [], {}, {}, {}
            for s in rows:
                st = s.get("status") or {}
                loc = s.get("location") or {}
                fail = bool(st.get("errorCode"))
                risk = (s.get("riskLevelDuringSignIn") or "none").lower()
                country = (loc.get("countryOrRegion") or "").upper()
                foreign = bool(country) and country != self.home_country
                upn = s.get("userPrincipalName") or ""
                if fail:
                    by_user[upn] = by_user.get(upn, 0) + 1
                    by_ip[s.get("ipAddress", "")] = by_ip.get(s.get("ipAddress", ""), 0) + 1
                if country:
                    by_country[country] = by_country.get(country, 0) + 1
                if fail or risk not in ("none", "hidden") or foreign:
                    out.append({"at": (s.get("createdDateTime") or "")[:19].replace("T", " "), "user": upn,
                                "app": s.get("appDisplayName", ""), "ip": s.get("ipAddress", ""), "country": country,
                                "city": loc.get("city", ""), "ok": not fail, "error": st.get("failureReason", "") if fail else "",
                                "code": st.get("errorCode"), "risk": risk, "ca": s.get("conditionalAccessStatus", ""),
                                "client": s.get("clientAppUsed", ""), "foreign": foreign})
            top = lambda d: sorted(d.items(), key=lambda x: -x[1])[:10]
            return {"total": len(rows), "fallidos": sum(by_user.values()), "items": out[:1500],
                    "por_usuario": top(by_user), "por_pais": top(by_country), "por_ip": top(by_ip),
                    "extranjero_ok": sum(1 for x in out if x["foreign"] and x["ok"]),
                    "riesgo": sum(1 for x in out if x["risk"] not in ("none", "hidden")), "truncado": len(rows) >= 8000}
        return self.cached(f"signins-{hours}", 300, load)

    def risky(self):
        def load():
            users = self.pages("/identityProtection/riskyUsers",
                               {"$filter": "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'", "$top": 500}, limit=2000)
            since = iso(datetime.datetime.utcnow() - datetime.timedelta(days=7))
            det = self.pages("/identityProtection/riskDetections", {"$filter": f"detectedDateTime ge {since}", "$top": 500}, limit=2000)
            return {"usuarios": [{"id": u["id"], "upn": u.get("userPrincipalName", ""), "name": u.get("userDisplayName", ""),
                                  "level": u.get("riskLevel", ""), "state": u.get("riskState", ""),
                                  "detail": u.get("riskDetail", ""), "updated": (u.get("riskLastUpdatedDateTime") or "")[:16]}
                                 for u in users],
                    "detecciones": [{"at": (d.get("detectedDateTime") or "")[:16].replace("T", " "), "upn": d.get("userPrincipalName", ""),
                                     "type": d.get("riskEventType", ""), "level": d.get("riskLevel", ""), "ip": d.get("ipAddress", ""),
                                     "country": ((d.get("location") or {}).get("countryOrRegion") or ""),
                                     "state": d.get("riskState", "")} for d in det[:500]]}
        return self.cached("risky", 300, load)

    # ------------------------------------------------------------ postura
    def posture(self):
        def load():
            sc = (self.g("GET", "/security/secureScores", params={"$top": 1}).get("value") or [{}])[0]
            prof = {p.get("id") or p.get("controlName"): p for p in self.pages("/security/secureScoreControlProfiles", {"$top": 300}, 600)}
            rec = []
            for c in sc.get("controlScores") or []:
                p = prof.get(c.get("controlName"), {})
                mx = float(p.get("maxScore") or 0)
                got = float(c.get("score") or 0)
                if mx and got < mx and not p.get("deprecated"):
                    rec.append({"control": c.get("controlName"), "title": p.get("title") or c.get("controlName"),
                                "category": c.get("controlCategory") or p.get("controlCategory", ""), "score": got, "max": mx,
                                "gain": round(mx - got, 2), "impact": p.get("userImpact", ""), "cost": p.get("implementationCost", ""),
                                "url": p.get("actionUrl", "")})
            rec.sort(key=lambda r: -r["gain"])
            try:
                health = [{"service": h.get("service"), "status": h.get("status")} for h in
                          self.pages("/admin/serviceAnnouncement/healthOverviews", {"$select": "service,status"}, 200)]
                issues = [{"id": i.get("id"), "title": i.get("title"), "service": i.get("service"), "status": i.get("status"),
                           "class": i.get("classification"), "start": (i.get("startDateTime") or "")[:16].replace("T", " ")}
                          for i in self.pages("/admin/serviceAnnouncement/issues", {"$filter": "isResolved eq false", "$top": 100}, 100)]
            except Exception as exc:
                health, issues = [], [{"id": "", "title": f"No disponible: {friendly(exc)}", "service": "", "status": "",
                                       "class": "", "start": ""}]
            return {"score": sc.get("currentScore"), "max": sc.get("maxScore"), "fecha": (sc.get("createdDateTime") or "")[:10],
                    "comparativa": [{"tipo": a.get("basis"), "media": a.get("averageScore")} for a in sc.get("averageComparativeScores") or []],
                    "recomendaciones": rec[:15], "servicios": health, "incidencias": issues}
        return self.cached("posture", 3600, load)

    # ------------------------------------------------------------ auditoría y correo
    def audits(self, days=7):
        def load():
            since = iso(datetime.datetime.utcnow() - datetime.timedelta(days=days))
            rows = self.pages("/auditLogs/directoryAudits", {"$filter": f"activityDateTime ge {since}", "$top": 500}, limit=3000)
            out = []
            for a in rows:
                ib = a.get("initiatedBy") or {}
                who = (ib.get("user") or {}).get("userPrincipalName") or (ib.get("app") or {}).get("displayName") or "—"
                targets = ", ".join(t.get("userPrincipalName") or t.get("displayName") or "" for t in a.get("targetResources") or [])
                act = a.get("activityDisplayName", "")
                out.append({"at": (a.get("activityDateTime") or "")[:19].replace("T", " "), "activity": act,
                            "category": a.get("category", ""), "by": who, "target": targets[:300], "result": a.get("result", ""),
                            "sensible": bool(SENSITIVE_AUDIT.search(f"{act} {a.get('category', '')}"))})
            return out
        return self.cached(f"audits-{days}", 600, load)

    def scan_rules(self, max_users=None, priority=()):
        """Recorre buzones y marca reglas que reenvían fuera de la organización o borran/ocultan correo."""
        max_users = max_users or int(_env("M365_RULES_SCAN_USERS", "300") or 300)
        own = self.domains()
        users = self.pages("/users", {"$select": "id,userPrincipalName,mail", "$filter": "accountEnabled eq true", "$top": 999},
                           limit=20000)
        prio = {p.lower() for p in priority}
        users.sort(key=lambda u: (u.get("userPrincipalName", "").lower() not in prio))
        found, scanned, errors = [], 0, 0
        for u in users[:max_users]:
            try:
                rules = self.g("GET", f"/users/{u['id']}/mailFolders/inbox/messageRules").get("value", [])
            except requests.HTTPError:
                errors += 1  # buzón no existe o sin licencia de Exchange
                continue
            scanned += 1
            for r in rules:
                act = r.get("actions") or {}
                dests = [a.get("emailAddress", {}).get("address", "") for k in ("forwardTo", "redirectTo", "forwardAsAttachmentTo")
                         for a in act.get(k) or []]
                ext = [d for d in dests if d and d.split("@")[-1].lower() not in own]
                hides = bool(act.get("delete") or act.get("permanentDelete")) or (
                    act.get("markAsRead") and act.get("moveToFolder") and act.get("stopProcessingRules"))
                if ext or hides:
                    found.append({"user_id": u["id"], "upn": u.get("userPrincipalName", ""), "rule_id": r.get("id"),
                                  "name": r.get("displayName", ""), "enabled": r.get("isEnabled", True), "externos": ext,
                                  "oculta": bool(hides), "nivel": "alto" if ext else "medio",
                                  "condiciones": json.dumps(r.get("conditions") or {}, ensure_ascii=False)[:300]})
        res = {"at": now_s()[:16], "usuarios": len(users), "revisados": scanned, "sin_buzon": errors, "reglas": found}
        self.kv("rules_scan", json.dumps(res, ensure_ascii=False))
        return res

    def rules(self):
        raw = self.kv("rules_scan")
        return json.loads(raw) if raw else None

    def find_user(self, upn_or_id):
        u = self.g("GET", f"/users/{upn_or_id}", params={"$select": "id,userPrincipalName,displayName,accountEnabled"})
        return {"id": u["id"], "upn": u.get("userPrincipalName", ""), "name": u.get("displayName", ""),
                "enabled": u.get("accountEnabled")}

    # ------------------------------------------------------------ cola de acciones (aprobación humana)
    def request(self, kind, target, reason, user, origin="portal", incident="", execute=False, hooks=None):
        if self.read_only:
            raise M365Error("Microsoft 365 está en solo lectura (M365_READ_ONLY=true)")
        if kind not in KINDS:
            raise M365Error("Acción no soportada")
        aid = self.x("""INSERT INTO actions(at, requested_by, origin, kind, target, label, reason, incident, status)
                        VALUES(?,?,?,?,?,?,?,?, 'pending')""",
                     (now_s(), user, origin, kind, json.dumps(target), str(target.get("label", ""))[:300], reason[:1000], incident))
        if execute and not (KINDS[kind][1] and self.four_eyes):
            return self.decide(aid, True, user, hooks=hooks, _self_ok=True)
        return self.action(aid)

    def decide(self, aid, approve, user, note="", hooks=None, _self_ok=False):
        a = self.action(aid)
        if not a:
            raise M365Error("Acción no encontrada")
        if a["status"] != "pending":
            raise M365Error(f"La acción ya está «{a['status']}»")
        if approve and KINDS[a["kind"]][1] and self.four_eyes and a["requested_by"] == user and not _self_ok:
            raise M365Error("Regla de cuatro ojos: la contención la debe aprobar otra persona")
        if not approve:
            self.x("UPDATE actions SET status='rejected', decided_by=?, decided_at=?, result=? WHERE id=?",
                   (user, now_s(), note[:500] or "Rechazada", aid))
            return self.action(aid)
        self.x("UPDATE actions SET status='running', decided_by=?, decided_at=? WHERE id=?", (user, now_s(), aid))
        try:
            res, status = self._execute(a["kind"], a["target"], a["reason"], user), "done"
        except Exception as exc:
            res, status = "Error: " + friendly(exc), "failed"
        self.x("UPDATE actions SET status=?, result=? WHERE id=?", (status, res[:1000], aid))
        out = self.action(aid)
        if hooks:
            try:
                hooks(out)
            except Exception as exc:
                log.warning("M365: hook de acción: %s", exc)
        return out

    def action(self, aid):
        a = self.q("SELECT * FROM actions WHERE id = ?", (aid,), one=True)
        if a:
            a["target"] = json.loads(a["target"] or "{}")
            a["nombre"], a["contencion"] = KINDS.get(a["kind"], (a["kind"], False))
        return a

    def actions(self, status="", limit=200):
        sql, args = "SELECT id FROM actions", []
        if status:
            sql += " WHERE status = ?"; args.append(status)
        return [self.action(r["id"]) for r in self.q(sql + " ORDER BY id DESC LIMIT ?", args + [limit])]

    def _execute(self, kind, t, reason, user):
        uid = t.get("user_id")
        if kind == "revoke_sessions":
            self.g("POST", f"/users/{uid}/revokeSignInSessions")
            self._cache.pop("risky", None)
            return "Sesiones revocadas: el usuario debe volver a iniciar sesión en todos sus dispositivos"
        if kind in ("disable_user", "enable_user"):
            self.g("PATCH", f"/users/{uid}", json={"accountEnabled": kind == "enable_user"})
            return "Inicio de sesión bloqueado" if kind == "disable_user" else "Inicio de sesión desbloqueado"
        if kind == "force_password":
            self.g("PATCH", f"/users/{uid}", json={"passwordProfile": {"forceChangePasswordNextSignIn": True}})
            return "Deberá cambiar la contraseña en el próximo inicio de sesión"
        if kind in ("confirm_compromised", "dismiss_risk"):
            self.g("POST", f"/identityProtection/riskyUsers/{'confirmCompromised' if kind == 'confirm_compromised' else 'dismiss'}",
                   json={"userIds": [uid]})
            self._cache.pop("risky", None)
            return "Marcado como comprometido (riesgo alto)" if kind == "confirm_compromised" else "Riesgo descartado"
        if kind == "resolve_alert":
            body = {"status": "resolved", "classification": t.get("classification") or "truePositive",
                    "determination": t.get("determination") or "other"}
            self.g("PATCH", f"/security/alerts_v2/{t['alert_id']}", json=body)
            self.x("UPDATE alerts SET status = 'resolved', classification = ? WHERE id = ?", (body["classification"], t["alert_id"]))
            return f"Alerta resuelta ({body['classification']})"
        if kind == "disable_rule":
            self.g("PATCH", f"/users/{uid}/mailFolders/inbox/messageRules/{t['rule_id']}", json={"isEnabled": False})
            raw = self.rules()
            if raw:
                for r in raw["reglas"]:
                    if r["rule_id"] == t["rule_id"]:
                        r["enabled"] = False
                self.kv("rules_scan", json.dumps(raw, ensure_ascii=False))
            return "Regla desactivada"
        raise M365Error("Acción no soportada")
