"""Integración con Sophos Central (API pública v1).

- Lectura: alertas, equipos (salud, aislamiento), elementos bloqueados y sitios web locales.
- Respuesta: aislar / quitar aislamiento, escanear, acciones sobre alertas, bloquear SHA-256 y
  dominios/URL/IP (sitio web local con una etiqueta que la política de control web bloquea).
- Regla del piloto: toda acción pasa por la cola `actions`. Desde el portal la ejecuta la persona que
  confirma; desde Shuffle o la IA queda «pendiente» hasta que alguien la aprueba. Con SOPHOS_FOUR_EYES=true
  la contención la tiene que aprobar una persona distinta de quien la pidió.

Autenticación: OAuth2 client_credentials en id.sophos.com → whoami → host de la región del tenant.
"""
import datetime
import json
import logging
import os
import sqlite3
import threading
import time

import requests

log = logging.getLogger("soc-bridge.sophos")

AUTH_URL = os.getenv("SOPHOS_AUTH_URL", "https://id.sophos.com/api/v2/oauth2/token")
GLOBAL_URL = os.getenv("SOPHOS_GLOBAL_URL", "https://api.central.sophos.com").rstrip("/")
TIMEOUT = 40
SEV_RANK = {"low": 1, "medium": 2, "high": 3}

# acción → (descripción, ¿es contención?)
KINDS = {
    "isolate": ("Aislar equipo", True),
    "unisolate": ("Quitar aislamiento", True),
    "scan": ("Escanear equipo", False),
    "alert_action": ("Acción sobre alerta", False),
    "block_hash": ("Bloquear SHA-256", True),
    "block_web": ("Bloquear sitio web / IP", True),
    "unblock_hash": ("Quitar bloqueo SHA-256", False),
    "unblock_web": ("Quitar bloqueo web", False),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts(
  id TEXT PRIMARY KEY, raised_at TEXT, severity TEXT, category TEXT, type TEXT, product TEXT,
  description TEXT, endpoint_id TEXT, endpoint TEXT, person TEXT, allowed TEXT, raw TEXT,
  iocs TEXT DEFAULT '[]', matches TEXT DEFAULT '{}', incident TEXT DEFAULT '', state TEXT DEFAULT 'open',
  seen_at TEXT);
CREATE INDEX IF NOT EXISTS ix_sa_raised ON alerts(raised_at);
CREATE TABLE IF NOT EXISTS endpoints(id TEXT PRIMARY KEY, hostname TEXT, data TEXT, synced_at TEXT);
CREATE TABLE IF NOT EXISTS actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, requested_by TEXT, origin TEXT, kind TEXT, target TEXT,
  label TEXT, reason TEXT, incident TEXT DEFAULT '', status TEXT, decided_by TEXT DEFAULT '', decided_at TEXT DEFAULT '',
  result TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
"""


def now_s():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _env(k, d=""):
    return (os.getenv(k) or d).strip()


class SophosError(RuntimeError):
    pass


def friendly(exc) -> str:
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        c = exc.response.status_code
        try:
            msg = exc.response.json().get("message") or exc.response.json().get("error") or ""
        except Exception:
            msg = ""
        base = {400: "Sophos rechazó la petición", 401: "credenciales de Sophos no válidas o caducadas",
                403: "la credencial de API no tiene permiso para esto (revisa el rol: «Service Principal Super Admin» o «Management»)",
                404: "no existe en Sophos Central", 409: "ya existe en Sophos Central",
                429: "Sophos limita las peticiones; espera un momento"}.get(c, f"HTTP {c} de Sophos")
        return f"{base}{': ' + str(msg)[:200] if msg else ''}"
    if isinstance(exc, requests.ConnectionError):
        return "no conecta con Sophos Central (¿salida a Internet hacia *.sophos.com?)"
    return str(exc)[:250]


class SophosCentral:
    def __init__(self, db_path: str):
        self.cid, self.secret = _env("SOPHOS_CLIENT_ID"), _env("SOPHOS_CLIENT_SECRET")
        self.tenant_cfg = _env("SOPHOS_TENANT_ID")
        self.web_tag = _env("SOPHOS_WEB_TAG", "SOC-ACME-BLOQUEO")
        self.four_eyes = _env("SOPHOS_FOUR_EYES", "false").lower() in ("1", "true", "yes")
        self.auto_sev = _env("SOPHOS_AUTO_INCIDENT", "high").lower()  # high | medium | low | "" (no)
        self.poll_min = max(1, int(_env("SOPHOS_POLL_MIN", "5") or 5))
        # credencial «Service Principal ReadOnly»: se ven alertas y equipos, pero no se ofrecen acciones
        self.read_only = _env("SOPHOS_READ_ONLY", "false").lower() in ("1", "true", "yes")
        self.verify = _env("SOPHOS_VERIFY_TLS", "true").lower() not in ("0", "false", "no")
        self.path = db_path
        self.lock = threading.Lock()
        self._tok, self._tok_exp, self._ctx = None, 0, None
        with self._db() as c:
            c.executescript(SCHEMA)

    # ------------------------------------------------------------ base de datos local
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
            cur = c.execute(sql, args)
            return cur.lastrowid

    def kv(self, k, v=None):
        if v is None:
            r = self.q("SELECT v FROM kv WHERE k = ?", (k,), one=True)
            return r["v"] if r else None
        self.x("INSERT INTO kv(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, str(v)))

    # ------------------------------------------------------------ autenticación
    @property
    def on(self) -> bool:
        return bool(self.cid and self.secret)

    def _token(self):
        if self._tok and time.time() < self._tok_exp - 60:
            return self._tok
        r = requests.post(AUTH_URL, data={"grant_type": "client_credentials", "client_id": self.cid,
                                          "client_secret": self.secret, "scope": "token"},
                          timeout=TIMEOUT, verify=self.verify)
        if r.status_code in (400, 401):
            raise SophosError("Sophos rechazó el client ID / secret (revisa SOPHOS_CLIENT_ID y SOPHOS_CLIENT_SECRET)")
        r.raise_for_status()
        d = r.json()
        self._tok, self._tok_exp = d["access_token"], time.time() + int(d.get("expires_in", 3600))
        return self._tok

    def context(self):
        """Tenant e host de su región. Admite credenciales de tenant, partner u organización."""
        if self._ctx and time.time() - self._ctx["t"] < 3600:
            return self._ctx
        h = {"Authorization": f"Bearer {self._token()}"}
        r = requests.get(f"{GLOBAL_URL}/whoami/v1", headers=h, timeout=TIMEOUT, verify=self.verify)
        r.raise_for_status()
        w = r.json()
        kind = w.get("idType")
        if kind == "tenant":
            ctx = {"tenant": w["id"], "host": w["apiHosts"]["dataRegion"].rstrip("/"), "tipo": "tenant"}
        elif kind in ("partner", "organization"):
            if not self.tenant_cfg:
                raise SophosError(f"La credencial es de {kind}: define SOPHOS_TENANT_ID con el tenant a gestionar")
            hdr = {**h, ("X-Partner-ID" if kind == "partner" else "X-Organization-ID"): w["id"]}
            r = requests.get(f"{GLOBAL_URL}/{kind}/v1/tenants/{self.tenant_cfg}", headers=hdr, timeout=TIMEOUT,
                             verify=self.verify)
            r.raise_for_status()
            t = r.json()
            ctx = {"tenant": t["id"], "host": t["apiHost"].rstrip("/"), "tipo": kind, "nombre": t.get("name", "")}
        else:
            raise SophosError(f"Tipo de credencial no reconocido: {kind}")
        ctx["t"] = time.time()
        self._ctx = ctx
        return ctx

    def api(self, method, path, **kw):
        if not self.on:
            raise SophosError("Sophos Central no está configurado (SOPHOS_CLIENT_ID / SOPHOS_CLIENT_SECRET)")
        ctx = self.context()
        h = {"Authorization": f"Bearer {self._token()}", "X-Tenant-ID": ctx["tenant"], "Accept": "application/json"}
        r = requests.request(method, ctx["host"] + path, headers=h, timeout=TIMEOUT, verify=self.verify, **kw)
        if r.status_code == 401:  # token revocado: se renueva una vez
            self._tok = None
            h["Authorization"] = f"Bearer {self._token()}"
            r = requests.request(method, ctx["host"] + path, headers=h, timeout=TIMEOUT, verify=self.verify, **kw)
        r.raise_for_status()
        return r.json() if r.content else {}

    def _pages(self, path, params, key="items", limit=20000):
        """Recorre la paginación de Sophos (pageFromKey/nextKey o page/total)."""
        params, out = dict(params), []
        while True:
            d = self.api("GET", path, params=params)
            out += d.get(key) or []
            p = d.get("pages") or {}
            if p.get("nextKey") and len(out) < limit:
                params["pageFromKey"] = p["nextKey"]
            elif p.get("current") and p.get("total") and p["current"] < p["total"] and len(out) < limit:
                params["page"] = p["current"] + 1
            else:
                return out

    # ------------------------------------------------------------ estado
    def status(self):
        if not self.on:
            return {"configurado": False}
        try:
            ctx = self.context()
            ok, err = True, ""
        except Exception as exc:
            ctx, ok, err = {}, False, friendly(exc)
        return {"configurado": True, "conectado": ok, "error": err, "tenant": ctx.get("tenant", ""),
                "region": ctx.get("host", ""), "tipo": ctx.get("tipo", ""), "ultima_sync": self.kv("last_sync") or "",
                "sync_msg": self.kv("sync_msg") or "", "web_tag": self.web_tag, "four_eyes": self.four_eyes, "solo_lectura": self.read_only,
                "auto_incidente": self.auto_sev, "poll_min": self.poll_min,
                "pendientes": self.q("SELECT COUNT(*) n FROM actions WHERE status = 'pending'", one=True)["n"]}

    # ------------------------------------------------------------ sincronización (alertas y equipos)
    def sync(self, intel=None, parse_iocs=None, create_incident=None):
        """Trae alertas nuevas (desde la última vista) y, cada 15 min, el inventario de equipos."""
        if not self.on:
            return
        try:
            if time.time() - float(self.kv("eps_at") or 0) > 900:
                self.sync_endpoints()  # primero el inventario: así cada alerta lleva el nombre del equipo
            since = self.kv("alerts_since") or (datetime.datetime.utcnow() - datetime.timedelta(days=7)).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z")
            items = self._pages("/common/v1/alerts", {"pageSize": 100, "from": since}, limit=5000)
            new, newest = 0, since
            for a in items:
                if self._store_alert(a, intel, parse_iocs, create_incident):
                    new += 1
                newest = max(newest, a.get("raisedAt") or "")
            if newest != since:
                self.kv("alerts_since", newest)
            self.kv("last_sync", now_s()[:16])
            self.kv("sync_msg", f"OK · {new} alertas nuevas")
            if new:
                log.info("Sophos: %s alertas nuevas", new)
        except Exception as exc:
            self.kv("sync_msg", "Error: " + friendly(exc))
            log.warning("Sophos: %s", friendly(exc))

    def sync_endpoints(self):
        eps = self._pages("/endpoint/v1/endpoints", {"pageSize": 500, "view": "full"})
        ts = now_s()
        with self.lock, self._db() as c:
            c.execute("DELETE FROM endpoints")
            c.executemany("INSERT INTO endpoints(id, hostname, data, synced_at) VALUES(?,?,?,?)",
                          [(e["id"], e.get("hostname", ""), json.dumps(e), ts) for e in eps])
        self.kv("eps_at", time.time())
        return len(eps)

    def _store_alert(self, a, intel, parse_iocs, create_incident):
        if self.q("SELECT 1 FROM alerts WHERE id = ?", (a["id"],), one=True):
            return False
        ag, person = a.get("managedAgent") or {}, a.get("person") or {}
        raw = json.dumps(a)
        iocs, matches = [], {}
        if parse_iocs:
            iocs = [i["value"] for i in parse_iocs(raw)["iocs"]][:50]
            if intel and iocs:
                matches = {v: len({m["sid"] for m in ms}) for v, ms in intel.lookup(iocs).items()}
        host = ag.get("name") or self._hostname(ag.get("id"))
        sev = (a.get("severity") or "").lower()
        self.x("""INSERT INTO alerts(id, raised_at, severity, category, type, product, description, endpoint_id, endpoint,
                  person, allowed, raw, iocs, matches, seen_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
               (a["id"], a.get("raisedAt", ""), sev, a.get("category", ""), a.get("type", ""), a.get("product", ""),
                a.get("description", ""), ag.get("id", ""), host, person.get("name", ""),
                json.dumps(a.get("allowedActions") or []), raw, json.dumps(iocs), json.dumps(matches), now_s()))
        if create_incident and self.auto_sev in SEV_RANK and SEV_RANK.get(sev, 0) >= SEV_RANK[self.auto_sev]:
            code = create_incident({
                "_key": a["id"], "title": f"Sophos: {a.get('description', '')[:150] or a.get('type', 'alerta')}",
                "severity": "Critical" if sev == "high" and matches else ("High" if sev == "high" else "Medium"),
                "detected_by": "Sophos Central", "assets": host or "", "iocs": "\n".join(iocs),
                "summary": f"Alerta de Sophos Central ({a.get('category', '')} · {a.get('type', '')}) en {host or 'equipo desconocido'}"
                           f"{' · usuario ' + person.get('name') if person.get('name') else ''}.\n\n{a.get('description', '')}"
                           + (f"\n\nIoC ya conocidos en el motor de inteligencia: {', '.join(matches)}" if matches else ""),
                "runbook": "malware-equipo" if a.get("category") in ("malware", "pua") else ""})
            if code:  # con AUTO_INCIDENTS=false queda como sugerencia y no hay código todavía
                self.x("UPDATE alerts SET incident = ? WHERE id = ?", (code, a["id"]))
        return True

    def _hostname(self, eid):
        if not eid:
            return ""
        r = self.q("SELECT hostname FROM endpoints WHERE id = ?", (eid,), one=True)
        return r["hostname"] if r else ""

    # ------------------------------------------------------------ consultas para el portal
    def alerts(self, days=7, severity="", q="", limit=300):
        since = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        sql, args = "SELECT * FROM alerts WHERE raised_at >= ?", [since]
        if severity:
            sql += " AND severity = ?"; args.append(severity)
        if q:
            sql += " AND (description LIKE ? OR endpoint LIKE ? OR person LIKE ? OR raw LIKE ?)"; args += [f"%{q}%"] * 4
        rows = self.q(sql + " ORDER BY raised_at DESC LIMIT ?", args + [limit])
        for r in rows:
            r.pop("raw", None)
            r["endpoint"] = r["endpoint"] or self._hostname(r["endpoint_id"])
            for k in ("allowed", "iocs", "matches"):
                r[k] = json.loads(r[k] or ("{}" if k == "matches" else "[]"))
        return rows

    def alert_stats(self, days=7):
        since = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        sev = self.q("SELECT severity k, COUNT(*) n FROM alerts WHERE raised_at >= ? GROUP BY 1", (since,))
        cat = self.q("SELECT category k, COUNT(*) n FROM alerts WHERE raised_at >= ? GROUP BY 1 ORDER BY 2 DESC LIMIT 8", (since,))
        top = self.q("SELECT endpoint k, COUNT(*) n FROM alerts WHERE raised_at >= ? AND endpoint != '' GROUP BY 1 ORDER BY 2 DESC LIMIT 8", (since,))
        ioc = self.q("SELECT COUNT(*) n FROM alerts WHERE raised_at >= ? AND matches != '{}'", (since,), one=True)["n"]
        return {"severidad": [[r["k"], r["n"]] for r in sev], "categorias": [[r["k"], r["n"]] for r in cat],
                "equipos": [[r["k"], r["n"]] for r in top], "con_ioc": ioc}

    def endpoints(self, q="", health="", isolated=""):
        out = []
        for r in self.q("SELECT data FROM endpoints ORDER BY hostname"):
            e = json.loads(r["data"])
            hl = (e.get("health") or {})
            iso = (e.get("isolation") or {}).get("status", "")
            item = {"id": e["id"], "hostname": e.get("hostname", ""), "type": e.get("type", ""),
                    "os": (e.get("os") or {}).get("name", ""), "ip": (e.get("ipv4Addresses") or [""])[0],
                    "person": (e.get("associatedPerson") or {}).get("viaLogin") or (e.get("associatedPerson") or {}).get("name", ""),
                    "health": hl.get("overall", "unknown"), "threats": (hl.get("threats") or {}).get("status", ""),
                    "services": (hl.get("services") or {}).get("status", ""), "isolation": iso or "notIsolated",
                    "tamper": e.get("tamperProtectionEnabled"), "last_seen": e.get("lastSeenAt", ""),
                    "products": [p.get("code") for p in e.get("assignedProducts") or []]}
            if q and q.lower() not in f"{item['hostname']} {item['ip']} {item['person']}".lower():
                continue
            if health and item["health"] != health:
                continue
            if isolated and (item["isolation"] == "isolated") != (isolated == "1"):
                continue
            out.append(item)
        sync = self.q("SELECT MAX(synced_at) s FROM endpoints", one=True)["s"]
        return {"items": out, "sincronizado": sync or ""}

    def blocked(self):
        hashes = self._pages("/endpoint/v1/settings/blocked-items", {"pageSize": 100})
        sites = self._pages("/endpoint/v1/settings/web-control/local-sites", {"pageSize": 100})
        return {"hashes": [{"id": h["id"], "sha256": (h.get("properties") or {}).get("sha256", ""),
                            "comment": h.get("comment", ""), "created": h.get("createdAt", ""),
                            "by": (h.get("createdBy") or {}).get("name", "")} for h in hashes],
                "web": [{"id": s["id"], "url": s.get("url", ""), "tags": s.get("tags") or [], "comment": s.get("comment", "")}
                        for s in sites],
                "web_tag": self.web_tag}

    def find_alerts_with(self, value):
        """Alertas guardadas que mencionan un valor (para el análisis de un IoC)."""
        rows = self.q("SELECT id, raised_at, severity, endpoint, description FROM alerts WHERE raw LIKE ? "
                      "ORDER BY raised_at DESC LIMIT 20", (f"%{value}%",))
        return rows

    # ------------------------------------------------------------ cola de acciones
    def request(self, kind, target: dict, reason, user, origin="portal", incident="", execute=False, hooks=None):
        if self.read_only:
            raise SophosError("La credencial de Sophos es de solo lectura (SOPHOS_READ_ONLY=true): no se pueden hacer acciones")
        if kind not in KINDS:
            raise SophosError("Acción no soportada")
        label = self._label(kind, target)
        aid = self.x("""INSERT INTO actions(at, requested_by, origin, kind, target, label, reason, incident, status)
                        VALUES(?,?,?,?,?,?,?,?, 'pending')""",
                     (now_s(), user, origin, kind, json.dumps(target), label, reason[:1000], incident or ""))
        contain = KINDS[kind][1]
        if execute and not (contain and self.four_eyes):
            return self.decide(aid, True, user, hooks=hooks, _self_ok=True)
        return self.action(aid)

    def decide(self, aid, approve, user, note="", hooks=None, _self_ok=False):
        a = self.action(aid)
        if not a:
            raise SophosError("Acción no encontrada")
        if a["status"] != "pending":
            raise SophosError(f"La acción ya está «{a['status']}»")
        if approve and KINDS[a["kind"]][1] and self.four_eyes and a["requested_by"] == user and not _self_ok:
            raise SophosError("Regla de cuatro ojos: la contención la debe aprobar otra persona")
        if not approve:
            self.x("UPDATE actions SET status='rejected', decided_by=?, decided_at=?, result=? WHERE id=?",
                   (user, now_s(), note[:500] or "Rechazada", aid))
            return self.action(aid)
        self.x("UPDATE actions SET status='running', decided_by=?, decided_at=? WHERE id=?", (user, now_s(), aid))
        try:
            res = self._execute(a["kind"], a["target"], a["reason"], user)
            status = "done"
        except Exception as exc:
            res, status = "Error: " + friendly(exc), "failed"
        self.x("UPDATE actions SET status=?, result=? WHERE id=?", (status, res[:1000], aid))
        out = self.action(aid)
        if hooks:
            try:
                hooks(out)
            except Exception as exc:
                log.warning("Sophos: hook de acción: %s", exc)
        return out

    def action(self, aid):
        a = self.q("SELECT * FROM actions WHERE id = ?", (aid,), one=True)
        if a:
            a["target"] = json.loads(a["target"] or "{}")
            a["contencion"] = KINDS.get(a["kind"], ("", False))[1]
            a["nombre"] = KINDS.get(a["kind"], (a["kind"], False))[0]
        return a

    def actions(self, status="", limit=200):
        sql, args = "SELECT id FROM actions", []
        if status:
            sql += " WHERE status = ?"; args.append(status)
        return [self.action(r["id"]) for r in self.q(sql + " ORDER BY id DESC LIMIT ?", args + [limit])]

    def _label(self, kind, t):
        if kind in ("isolate", "unisolate", "scan"):
            return ", ".join(t.get("hostnames") or t.get("ids") or [])[:300]
        if kind == "alert_action":
            return f"{t.get('action')} · {t.get('description', t.get('alert_id', ''))[:200]}"
        if kind in ("block_hash", "block_web"):
            return ", ".join(t.get("values") or [])[:300]
        return t.get("label") or t.get("id", "")

    def _execute(self, kind, t, reason, user):
        comment = f"SOC ACME · {user}: {reason}"[:250]
        if kind in ("isolate", "unisolate"):
            self.api("POST", "/endpoint/v1/endpoints/isolation",
                     json={"enabled": kind == "isolate", "ids": t["ids"], "comment": comment})
            self.kv("eps_at", 0)  # refrescar estado de aislamiento en la próxima sync
            return f"{'Aislamiento solicitado' if kind == 'isolate' else 'Aislamiento retirado'} en {len(t['ids'])} equipo(s)"
        if kind == "scan":
            for eid in t["ids"]:
                self.api("POST", f"/endpoint/v1/endpoints/{eid}/scans", json={})
            return f"Escaneo lanzado en {len(t['ids'])} equipo(s)"
        if kind == "alert_action":
            self.api("POST", f"/common/v1/alerts/{t['alert_id']}/actions", json={"action": t["action"], "message": comment})
            self.x("UPDATE alerts SET state = ? WHERE id = ?", (t["action"], t["alert_id"]))
            return f"Acción «{t['action']}» enviada"
        if kind == "block_hash":
            ok, errs = 0, []
            for v in t["values"]:
                try:
                    self.api("POST", "/endpoint/v1/settings/blocked-items",
                             json={"type": "sha256", "properties": {"sha256": v.lower()}, "comment": comment})
                    ok += 1
                except Exception as exc:
                    errs.append(f"{v[:12]}…: {friendly(exc)}")
            if not ok:
                raise SophosError("; ".join(errs)[:500])
            return f"{ok} hash(es) bloqueados" + (f" · errores: {'; '.join(errs)[:300]}" if errs else "")
        if kind == "block_web":
            ok, errs = 0, []
            for v in t["values"]:
                try:
                    self.api("POST", "/endpoint/v1/settings/web-control/local-sites",
                             json={"url": v, "tags": [self.web_tag], "comment": comment})
                    ok += 1
                except Exception as exc:
                    errs.append(f"{v}: {friendly(exc)}")
            if not ok:
                raise SophosError("; ".join(errs)[:500])
            return (f"{ok} sitio(s) añadidos con la etiqueta {self.web_tag}" + (f" · errores: {'; '.join(errs)[:300]}" if errs else ""))
        if kind == "unblock_hash":
            self.api("DELETE", f"/endpoint/v1/settings/blocked-items/{t['id']}")
            return "Bloqueo retirado"
        if kind == "unblock_web":
            self.api("DELETE", f"/endpoint/v1/settings/web-control/local-sites/{t['id']}")
            return "Sitio retirado"
        raise SophosError("Acción no soportada")
