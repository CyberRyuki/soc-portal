"""Auditoría de cambios y registro del sistema.

- Toda petición que modifica algo (POST, PUT, PATCH, DELETE) queda registrada: quién (usuario, rol o integración),
  cuándo, desde qué IP, qué módulo y objeto, el resultado (código HTTP) y un resumen del cuerpo con los secretos
  ocultos. También se registran los intentos rechazados (401/403/4xx): sirven para detectar abusos.
- Cadena de hashes: cada registro guarda el hash del anterior. Si alguien edita o borra una fila directamente en la
  base de datos, la verificación lo detecta.
- Registro del sistema: los últimos mensajes del bridge (INFO/WARNING/ERROR) en memoria, para verlos en el portal
  sin entrar al servidor.
"""
import collections
import csv
import datetime
import hashlib
import io
import json
import logging
import re
import sqlite3
import threading
import time
import urllib.parse

SCHEMA = """
CREATE TABLE IF NOT EXISTS changes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, ts INTEGER, user TEXT, role TEXT, ip TEXT, method TEXT, path TEXT,
  module TEXT, action TEXT, target TEXT, status INTEGER, ms INTEGER, detail TEXT, prev_hash TEXT, hash TEXT);
CREATE INDEX IF NOT EXISTS ix_changes_ts ON changes(ts);
CREATE INDEX IF NOT EXISTS ix_changes_user ON changes(user);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
"""
SECRET_KEYS = re.compile(r"pass|secret|token|api[_-]?key|^key$|private|auth|otp|^code$|cookie|credential|recovery|pwd|"
                         r"^current$|^new2?$", re.I)
# en estas rutas se oculta TODO valor salvo los campos inocuos (cuentas, contraseñas, MFA)
STRICT_PATHS = ("/portal/auth/", "/portal/api/admin/users")
SAFE_KEYS = {"username", "display", "email", "role", "enabled", "source", "reset_mfa", "must_change"}
MAX_BODY = 64 * 1024

# (regex de la ruta, módulo legible). El primer grupo con nombre «id», si existe, es el objeto afectado.
MODULES = [
    (r"^/portal/api/vulns/pentera/(?P<id>\d+)", "Vulnerabilidades · Pentera"),
    (r"^/portal/api/vulns/pentera", "Vulnerabilidades · Pentera"),
    (r"^/portal/api/incidents/(?P<id>[^/]+)/notes", "Incidentes · nota"),
    (r"^/portal/api/incidents/(?P<id>[^/]+)/close", "Incidentes · cierre"),
    (r"^/portal/api/incidents(?:/(?P<id>[^/]+))?", "Incidentes"),
    (r"^/portal/api/vulns(?:/(?P<id>[^/]+))?", "Vulnerabilidades"),
    (r"^/portal/api/(?:iocs|intel)(?:/[^/]+)*?(?:/(?P<id>\d+))?(?:/[a-z]+)?$", "IoC / inteligencia"),
    (r"^/portal/api/sophos/actions(?:/(?P<id>\d+))?", "Sophos · acciones"),
    (r"^/portal/api/sophos", "Sophos"),
    (r"^/portal/api/(?:admin/)?exposure", "Exposición"),
    (r"^/portal/api/m365/actions(?:/(?P<id>\d+))?", "Microsoft 365 · acciones"),
    (r"^/portal/api/m365", "Microsoft 365"),
    (r"^/portal/api/incidents/suggestions/(?P<id>\d+)", "Incidentes · sugerencias"),
    (r"^/portal/api/runbooks(?:/(?P<id>[^/]+))?", "Runbooks"),
    (r"^/portal/api/tools(?:/(?P<id>[^/]+))?", "Herramientas"),
    (r"^/portal/api/sites(?:/(?P<id>[^/]+))?", "Portales"),
    (r"^/portal/api/contacts(?:/(?P<id>[^/]+))?", "Contactos"),
    (r"^/portal/api/(?:mitre|owasp|frameworks)(?:/(?P<id>[^/]+))?", "MITRE / OWASP"),
    (r"^/portal/api/ai", "Asistente IA"),
    (r"^/portal/api/admin/users(?:/(?P<id>[^/]+))?", "Usuarios y accesos"),
    (r"^/portal/api/admin", "Administración"),
    (r"^/portal/auth/", "Mi cuenta"),
    (r"^/api/soc", "Integración (Shuffle/Wazuh)"),
]
ACTION = {"POST": "Crear / ejecutar", "PUT": "Modificar", "PATCH": "Modificar", "DELETE": "Eliminar"}
# acción concreta según el final de la ruta (tiene prioridad sobre el verbo HTTP)
SUFFIX = [(r"/vulns/pentera$", "Subir informe"), (r"/import$", "Importar"), (r"/close$", "Cerrar"),
          (r"/approve$", "Aprobar"), (r"/reject$", "Rechazar"), (r"/notes$", "Añadir nota"), (r"/run$", "Ejecutar ahora"),
          (r"/sync$", "Sincronizar"), (r"/upload$", "Subir archivo"), (r"/password$", "Cambiar contraseña"),
          (r"/mfa/(setup|enable)$", "Activar MFA"), (r"/mfa/disable$", "Desactivar MFA"), (r"/sessions", "Cerrar sesiones"),
          (r"/sophos/actions$", "Pedir acción"), (r"/m365/actions$", "Pedir acción"), (r"/dismiss$", "Descartar"),
          (r"/rules/scan$", "Revisar reglas de correo"),
          (r"/exposure/scan$", "Lanzar escaneo de exposición"), (r"/exposure/stop$", "Detener escaneo"), (r"/portal$", "Añadir a Portales")]
SKIP = {"/portal/auth/login", "/portal/auth/mfa", "/portal/auth/logout"}  # ya están en el registro de accesos


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def redact(obj, depth=0, strict=False):
    """Oculta valores de campos sensibles y recorta textos largos."""
    if depth > 4:
        return "…"
    if isinstance(obj, dict):
        hide = (lambda k: str(k) not in SAFE_KEYS) if strict else (lambda k: bool(SECRET_KEYS.search(str(k))))
        return {k: ("••••" if hide(k) and v not in (None, "", False) else redact(v, depth + 1, strict))
                for k, v in list(obj.items())[:40]}
    if isinstance(obj, list):
        out = [redact(v, depth + 1, strict) for v in obj[:20]]
        return out + [f"… ({len(obj) - 20} más)"] if len(obj) > 20 else out
    if isinstance(obj, str) and len(obj) > 300:
        return obj[:300] + f"… ({len(obj)} caracteres)"
    return obj


class Audit:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        with self._db() as c:
            c.executescript(SCHEMA)

    def _db(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        return c

    @staticmethod
    def _hash(prev, row):
        payload = json.dumps([prev] + [row[k] for k in ("at", "user", "role", "ip", "method", "path", "target",
                                                         "status", "detail")], ensure_ascii=False)
        return hashlib.sha256(payload.encode()).hexdigest()

    def record(self, **row):
        row = {"at": _now(), "ts": int(time.time()), "user": "", "role": "", "ip": "", "method": "", "path": "",
               "module": "", "action": "", "target": "", "status": 0, "ms": 0, "detail": "", **row}
        with self.lock, self._db() as c:
            last = c.execute("SELECT hash FROM changes ORDER BY id DESC LIMIT 1").fetchone()
            row["prev_hash"] = last["hash"] if last else (self._kv(c, "anchor") or "")
            row["hash"] = self._hash(row["prev_hash"], row)
            cols = list(row)
            c.execute(f"INSERT INTO changes({','.join(cols)}) VALUES({','.join('?' * len(cols))})", [row[k] for k in cols])

    @staticmethod
    def _kv(c, k, v=None):
        if v is None:
            r = c.execute("SELECT v FROM kv WHERE k = ?", (k,)).fetchone()
            return r["v"] if r else None
        c.execute("INSERT INTO kv(k, v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, v))

    # ------------------------------------------------------------ consulta
    def query(self, user="", module="", q="", since="", until="", result="", limit=500):
        sql, args = "SELECT * FROM changes WHERE 1=1", []
        if user:
            sql += " AND user = ?"; args.append(user)
        if module:
            sql += " AND module LIKE ?"; args.append(module + "%")
        if q:
            sql += " AND (path LIKE ? OR target LIKE ? OR detail LIKE ? OR ip LIKE ?)"; args += [f"%{q}%"] * 4
        if since:
            sql += " AND at >= ?"; args.append(since)
        if until:
            sql += " AND at <= ?"; args.append(until + " 23:59:59" if len(until) == 10 else until)
        if result == "ok":
            sql += " AND status < 400"
        elif result == "error":
            sql += " AND status >= 400"
        with self._db() as c:
            rows = [dict(r) for r in c.execute(sql + " ORDER BY id DESC LIMIT ?", args + [min(limit, 5000)])]
        for r in rows:
            r.pop("prev_hash", None); r.pop("hash", None)
        return rows

    def stats(self, days=7):
        since = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        with self._db() as c:
            g = lambda sql: [[r[0], r[1]] for r in c.execute(sql, (since,))]
            return {"usuarios": g("SELECT user, COUNT(*) FROM changes WHERE at >= ? GROUP BY 1 ORDER BY 2 DESC LIMIT 8"),
                    "modulos": g("SELECT module, COUNT(*) FROM changes WHERE at >= ? GROUP BY 1 ORDER BY 2 DESC LIMIT 10"),
                    "total": c.execute("SELECT COUNT(*) FROM changes WHERE at >= ?", (since,)).fetchone()[0],
                    "rechazados": c.execute("SELECT COUNT(*) FROM changes WHERE at >= ? AND status >= 400", (since,)).fetchone()[0],
                    "usuarios_lista": [r[0] for r in c.execute("SELECT DISTINCT user FROM changes ORDER BY 1")]}

    def verify(self):
        """Recorre la cadena de hashes. Devuelve el primer registro alterado, si lo hay."""
        with self._db() as c:
            prev = self._kv(c, "anchor") or ""
            n = 0
            for r in c.execute("SELECT * FROM changes ORDER BY id"):
                r = dict(r)
                if r["prev_hash"] != prev or self._hash(prev, r) != r["hash"]:
                    return {"ok": False, "registros": n, "alterado": r["id"], "fecha": r["at"],
                            "mensaje": f"El registro #{r['id']} ({r['at']}) fue modificado o falta uno anterior"}
                prev, n = r["hash"], n + 1
        return {"ok": True, "registros": n, "mensaje": f"Cadena íntegra: {n} registros verificados"}

    def purge(self, days):
        """Borra lo anterior a `days` días y guarda el hash del último borrado como ancla de la cadena."""
        if days <= 0:
            return 0
        lim = int(time.time()) - days * 86400
        with self.lock, self._db() as c:
            last = c.execute("SELECT hash FROM changes WHERE ts < ? ORDER BY id DESC LIMIT 1", (lim,)).fetchone()
            if not last:
                return 0
            self._kv(c, "anchor", last["hash"])
            return c.execute("DELETE FROM changes WHERE ts < ?", (lim,)).rowcount

    def csv(self, **f):
        out = io.StringIO()
        w = csv.writer(out)
        cols = ["id", "at", "user", "role", "ip", "module", "action", "target", "method", "path", "status", "ms", "detail"]
        w.writerow(cols)
        for r in self.query(limit=5000, **f):
            w.writerow([r[k] for k in cols])
        return out.getvalue()


def describe(method, path):
    act = next((a for rx, a in SUFFIX if re.search(rx, path)), ACTION.get(method, method))
    for rx, name in MODULES:
        m = re.match(rx, path)
        if m:
            tid = urllib.parse.unquote((m.groupdict().get("id") or "") if m.groupdict() else "")
            if name.endswith("Pentera") and tid:
                tid = f"Informe #{tid}"
            elif name.endswith("· acciones") and tid:
                tid = f"Acción #{tid}"
            return name, act, tid
    return "Otros", act, ""


class AuditMiddleware:
    """Middleware ASGI puro: observa la petición sin consumirla (no rompe las subidas grandes en streaming)."""

    def __init__(self, app, audit: Audit, client_ip):
        self.app, self.audit, self.client_ip = app, audit, client_ip

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ACTION or scope["path"] in SKIP:
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode(errors="ignore") for k, v in scope.get("headers", [])}
        ctype = headers.get("content-type", "")
        size = int(headers.get("content-length") or 0)
        keep = "json" in ctype and size <= MAX_BODY
        buf, status, t0 = bytearray(), {"code": 0}, time.monotonic()

        async def recv():
            msg = await receive()
            if keep and msg.get("type") == "http.request" and len(buf) < MAX_BODY:
                buf.extend(msg.get("body", b"")[: MAX_BODY - len(buf)])
            return msg

        async def snd(msg):
            if msg["type"] == "http.response.start":
                status["code"] = msg["status"]
            await send(msg)

        try:
            await self.app(scope, recv, snd)
        finally:
            try:
                self._log(scope, headers, ctype, size, bytes(buf) if keep else None, status["code"] or 500,
                          int((time.monotonic() - t0) * 1000))
            except Exception as exc:  # la auditoría nunca debe tumbar una petición
                logging.getLogger("soc-bridge").warning("Auditoría: %s", exc)

    def _log(self, scope, headers, ctype, size, body, status, ms):
        st = scope.get("state") or {}
        u = st.get("user")
        user = (u or {}).get("username") if isinstance(u, dict) else None
        role = (u or {}).get("role", "") if isinstance(u, dict) else ""
        if not user:
            user = st.get("actor") or ("API key no válida" if headers.get("x-api-key") else "sin sesión")
            role = role or ("integración" if st.get("actor") else "")
        module, action, target = describe(scope["method"], scope["path"])
        if body:
            try:
                strict = scope["path"].startswith(STRICT_PATHS)
                detail = json.dumps(redact(json.loads(body), strict=strict), ensure_ascii=False)[:2000]
            except ValueError:
                detail = "(cuerpo no JSON)"
        elif size:
            qs = scope.get("query_string", b"").decode()[:300]
            detail = json.dumps({"archivo": f"{ctype.split(';')[0] or 'binario'} · {size // 1024} KB",
                                 **({"parámetros": qs} if qs else {})}, ensure_ascii=False)
        else:
            qs = scope.get("query_string", b"").decode()[:300]
            detail = json.dumps({"parámetros": qs}, ensure_ascii=False) if qs else ""
        self.audit.record(user=user, role=role, ip=self.client_ip(scope, headers), method=scope["method"],
                          path=scope["path"], module=module, action=action, target=target[:200], status=status, ms=ms,
                          detail=detail)


class RingLog(logging.Handler):
    """Últimos N mensajes del registro del bridge, para verlos desde el portal."""

    def __init__(self, n=3000):
        super().__init__(logging.INFO)
        self.buf = collections.deque(maxlen=n)
        self.seq = 0

    def emit(self, rec):
        try:
            msg = rec.getMessage()
            if rec.exc_info and rec.levelno >= logging.ERROR:
                msg += "\n" + logging.Formatter().formatException(rec.exc_info).splitlines()[-1]
            self.seq += 1
            self.buf.append({"id": self.seq, "at": datetime.datetime.fromtimestamp(rec.created).strftime("%Y-%m-%d %H:%M:%S"),
                             "level": rec.levelname, "logger": rec.name, "msg": SECRETS_IN_TEXT.sub(r"\1=••••", msg)[:2000]})
        except Exception:
            pass

    def items(self, level="", q="", limit=500):
        rank = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
        mn = rank.get(level, 0)
        out = [r for r in reversed(self.buf) if rank.get(r["level"], 0) >= mn and (not q or q.lower() in r["msg"].lower())]
        return out[:limit]


SECRETS_IN_TEXT = re.compile(r"((?:password|passwd|secret|token|api[_-]?key|authorization)\s*)[=:]\s*\S+", re.I)
