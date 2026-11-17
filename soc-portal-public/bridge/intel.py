"""Motor de inteligencia de amenazas del portal SOC.

- Guarda millones de IoC en SQLite (intel.db) con una fila por (indicador, fuente).
- Fuentes: feeds públicos, MISP (se descarga), cargas manuales o de archivo y Shuffle.
- Correlación con Wazuh: se extraen de las alertas los valores ÚNICOS (IPs, dominios, hashes...) con
  agregaciones "composite" y se cruzan en bloque con la base local. Nunca se consulta IoC por IoC.
- Puntuación: cada fuente tiene una confianza (0-100); la puntuación combina todas las fuentes
  en las que aparece el indicador: 1 - Π(1 - confianza).
- Exporta listas para MISP (feed de texto) y para Wazuh (listas CDB, detección en tiempo real).
"""
import base64
import csv
import datetime
import gzip
import io
import ipaddress
import json
import logging
import os
import queue
import re
import sqlite3
import threading
import time

import requests

import feeds

log = logging.getLogger("soc-bridge.intel")
MAX_PER_SOURCE = int(os.getenv("INTEL_MAX_PER_SOURCE", "10000000"))
BATCH = 20000
TYPES = ["ip", "cidr", "domain", "url", "md5", "sha1", "sha256", "email"]
TYPE_ES = {"ip": "IP", "cidr": "Red (CIDR)", "domain": "Dominio", "url": "URL", "md5": "MD5", "sha1": "SHA1",
           "sha256": "SHA256", "email": "Correo"}
MISP_TYPE = {"ip": "ip-dst", "cidr": "ip-dst", "domain": "domain", "url": "url", "md5": "md5", "sha1": "sha1",
             "sha256": "sha256", "email": "email-src"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, url TEXT DEFAULT '',
  fmt TEXT DEFAULT 'lines', ioc_type TEXT DEFAULT 'auto', csv_col INTEGER DEFAULT 0, ref_col INTEGER,
  weight INTEGER DEFAULT 70, interval_h REAL DEFAULT 12, retention_days INTEGER DEFAULT 30,
  auth_header TEXT DEFAULT '', tlp TEXT DEFAULT 'amber', description TEXT DEFAULT '', incident TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1, n INTEGER DEFAULT 0, last_run TEXT, last_status TEXT DEFAULT '',
  last_added INTEGER DEFAULT 0, created_by TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS obs(
  value TEXT NOT NULL, source_id INTEGER NOT NULL, type TEXT NOT NULL,
  first_seen INTEGER, last_seen INTEGER, ref TEXT, PRIMARY KEY(value, source_id)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_obs_src ON obs(source_id, last_seen);
CREATE TABLE IF NOT EXISTS nets(
  source_id INTEGER, cidr TEXT, net INTEGER, plen INTEGER, last_seen INTEGER, PRIMARY KEY(source_id, cidr));
CREATE TABLE IF NOT EXISTS sightings(
  value TEXT, type TEXT, field TEXT, agent TEXT, n INTEGER, first_seen TEXT, last_seen TEXT, rule TEXT,
  matched TEXT, created INTEGER, PRIMARY KEY(value, field, agent));
CREATE INDEX IF NOT EXISTS ix_sight_last ON sightings(last_seen);
CREATE TABLE IF NOT EXISTS enrich(value TEXT, provider TEXT, at INTEGER, verdict TEXT, score INTEGER, data TEXT,
  PRIMARY KEY(value, provider));
CREATE TABLE IF NOT EXISTS jobs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, source_id INTEGER, status TEXT, done INTEGER DEFAULT 0,
  added INTEGER DEFAULT 0, msg TEXT DEFAULT '', started TEXT, finished TEXT, user TEXT);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
"""

# Feeds públicos recomendados. Comprueba las condiciones de uso de cada proveedor.
# abuse.ch puede pedir una Auth-Key gratuita: ponla en "Cabecera de autenticación" como  Auth-Key: TU_CLAVE
CATALOG = [
    {"key": "feodo", "name": "abuse.ch · Feodo Tracker (C2 de botnets)", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
     "ioc_type": "ip", "weight": 90, "interval_h": 1, "retention_days": 30},
    {"key": "urlhaus", "name": "abuse.ch · URLhaus (URLs de malware)", "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
     "ioc_type": "url", "weight": 85, "interval_h": 1, "retention_days": 30},
    {"key": "bazaar", "name": "abuse.ch · MalwareBazaar (SHA256 de malware)", "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
     "ioc_type": "sha256", "weight": 90, "interval_h": 1, "retention_days": 90},
    {"key": "threatfox", "name": "abuse.ch · ThreatFox (IoC recientes)", "url": "https://threatfox.abuse.ch/export/csv/recent/",
     "fmt": "csv", "csv_col": 2, "ref_col": 7, "ioc_type": "auto", "weight": 85, "interval_h": 1, "retention_days": 30},
    {"key": "drop", "name": "Spamhaus DROP (redes secuestradas)", "url": "https://www.spamhaus.org/drop/drop.txt",
     "ioc_type": "cidr", "weight": 95, "interval_h": 12, "retention_days": 7},
    {"key": "et", "name": "Emerging Threats · IPs comprometidas", "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
     "ioc_type": "ip", "weight": 70, "interval_h": 12, "retention_days": 7},
    {"key": "cins", "name": "CINS Army (IPs maliciosas)", "url": "https://cinsscore.com/list/ci-badguys.txt",
     "ioc_type": "ip", "weight": 60, "interval_h": 12, "retention_days": 7},
    {"key": "blocklistde", "name": "Blocklist.de (ataques SSH, web, correo)", "url": "https://lists.blocklist.de/lists/all.txt",
     "ioc_type": "ip", "weight": 60, "interval_h": 12, "retention_days": 7},
    {"key": "ipsum", "name": "IPsum nivel 3 (IPs en ≥ 3 listas negras)", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
     "ioc_type": "ip", "weight": 75, "interval_h": 24, "retention_days": 7},
    {"key": "openphish", "name": "OpenPhish (URLs de phishing)", "url": "https://openphish.com/feed.txt",
     "ioc_type": "url", "weight": 80, "interval_h": 6, "retention_days": 14},
    {"key": "phishingarmy", "name": "Phishing Army (dominios de phishing)", "url": "https://phishing.army/download/phishing_army_blocklist.txt",
     "ioc_type": "domain", "weight": 70, "interval_h": 24, "retention_days": 14},
    {"key": "tor", "name": "Nodos de salida Tor (contexto, no malicioso)", "url": "https://check.torproject.org/torbulkexitlist",
     "ioc_type": "ip", "weight": 30, "interval_h": 6, "retention_days": 3},
]

# Campos de las alertas de Wazuh que se cruzan con la base (deben ser keyword en el índice)
WAZUH_FIELDS = {
    "ip": ["data.srcip", "data.dstip", "data.src_ip", "data.dest_ip", "data.win.eventdata.destinationIp",
           "data.win.eventdata.sourceIp", "data.aws.sourceIPAddress", "data.office365.ClientIP"],
    "domain": ["data.win.eventdata.queryName", "data.dns.rrname", "data.http.hostname"],
    "url": ["data.url", "data.http.url"],
    "hash": ["syscheck.sha256_after", "syscheck.md5_after", "syscheck.sha1_after", "data.virustotal.source.sha1"],
}

_IPPORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$")


def now_s():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def normalize(tok: str, fixed: str = "auto"):
    """Devuelve (valor, tipo) o None. Admite formato defanged, ip:puerto y redes CIDR IPv4."""
    v = feeds.refang(tok).strip().strip('"').strip("'").rstrip(".,;")
    if not v or len(v) > 2048:
        return None
    m = _IPPORT.match(v)
    if m:
        v = m.group(1)
    if "/" in v and re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", v):
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            return None
        if net.is_private or net.prefixlen < 8:
            return None
        res = (str(net.network_address), "ip") if net.prefixlen == 32 else (str(net), "cidr")
    else:
        c = feeds.classify(v)
        if not c or c.get("private") or c.get("safe"):
            return None
        t = {"ip-dst": "ip", "email-src": "email"}.get(c["type"], c["type"])
        res = (c["value"], t)
    if fixed not in ("auto", "", None) and res[1] != fixed and not (fixed == "ip" and res[1] == "cidr"):
        return None
    return res


def friendly(exc) -> str:
    """Mensaje de error comprensible para el analista."""
    if isinstance(exc, requests.exceptions.HTTPError) and exc.response is not None:
        c = exc.response.status_code
        return {401: "HTTP 401: el proveedor pide autenticación (añade la cabecera, p. ej. Auth-Key)",
                403: "HTTP 403: acceso denegado (¿falta Auth-Key o la IP está bloqueada?)",
                404: "HTTP 404: la URL del feed ya no existe",
                410: "HTTP 410: el proveedor retiró esta URL (abuse.ch se movió a api.spamhaus.com y pide clave)", 429: "HTTP 429: demasiadas descargas; sube el intervalo"
                }.get(c, f"HTTP {c} del proveedor")
    if isinstance(exc, requests.exceptions.SSLError):
        return "certificado SSL no válido en el proveedor"
    if isinstance(exc, (requests.exceptions.ProxyError, requests.exceptions.ConnectionError)):
        host = re.search(r"host='([^']+)'", str(exc))
        return f"no conecta con {host.group(1) if host else 'el servidor'} (¿el servidor tiene salida a Internet o la bloquea el firewall/proxy?)"
    if isinstance(exc, requests.exceptions.Timeout):
        return "tiempo de espera agotado al descargar"
    return str(exc)[:200]


class Intel:
    def __init__(self, path: str):
        self.path = path
        for d in {os.getenv("SQLITE_TMPDIR"), os.getenv("TMPDIR")} - {None, ""}:
            os.makedirs(d, exist_ok=True)  # temporales de SQLite (el contenedor es de solo lectura)
        self.w = sqlite3.connect(path, check_same_thread=False, timeout=120)
        self.w.execute("PRAGMA journal_mode=WAL")
        self.w.execute("PRAGMA synchronous=NORMAL")
        self.w.executescript(SCHEMA)
        self.wlock = threading.Lock()
        self._nets = None
        self._cache = {}
        self.q = queue.Queue()
        self.pending = set()
        threading.Thread(target=self._worker, daemon=True, name="intel-worker").start()

    # ------------------------------------------------------------ utilidades SQL
    def rq(self, sql, args=(), one=False):
        c = sqlite3.connect(self.path, timeout=60)
        c.row_factory = sqlite3.Row
        try:
            rows = [dict(r) for r in c.execute(sql, args).fetchall()]
        finally:
            c.close()
        return (rows[0] if rows else None) if one else rows

    def wx(self, sql, args=(), many=False):
        with self.wlock:
            cur = self.w.executemany(sql, args) if many else self.w.execute(sql, args)
            self.w.commit()
            return cur.lastrowid

    def kv(self, k, v=None):
        if v is None:
            r = self.rq("SELECT v FROM kv WHERE k = ?", (k,), one=True)
            return r["v"] if r else None
        self.wx("INSERT INTO kv(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (k, str(v)))

    def cached(self, key, ttl, fn):
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        val = fn()
        self._cache[key] = (time.time(), val)
        return val

    def invalidate(self):
        self._cache.clear()
        self._nets = None

    # ------------------------------------------------------------ cola de trabajos (uno a la vez)
    def _worker(self):
        while True:
            fn, args, key = self.q.get()
            try:
                fn(*args)
            except Exception as exc:
                log.exception("Trabajo de inteligencia falló: %s", exc)
            finally:
                self.pending.discard(key)

    def enqueue(self, key, fn, *args):
        if key in self.pending:
            return False
        self.pending.add(key)
        self.q.put((fn, args, key))
        return True

    def job_new(self, kind, sid, user):
        return self.wx("INSERT INTO jobs(kind, source_id, status, started, user) VALUES(?,?,?,?,?)",
                       (kind, sid, "running", now_s(), user))

    def job_set(self, jid, **kw):
        self.wx(f"UPDATE jobs SET {','.join(k + ' = ?' for k in kw)} WHERE id = ?", list(kw.values()) + [jid])

    def jobs(self, n=12):
        return self.rq("""SELECT j.*, s.name source FROM jobs j LEFT JOIN sources s ON s.id = j.source_id
                          ORDER BY j.id DESC LIMIT ?""", (n,))

    # ------------------------------------------------------------ fuentes
    SRC_FIELDS = ["name", "kind", "url", "fmt", "ioc_type", "csv_col", "ref_col", "weight", "interval_h",
                  "retention_days", "auth_header", "tlp", "description", "incident", "enabled"]

    def sources(self):
        return self.rq("SELECT * FROM sources ORDER BY weight DESC, name")

    def source(self, sid):
        return self.rq("SELECT * FROM sources WHERE id = ?", (sid,), one=True)

    def source_by_name(self, name):
        return self.rq("SELECT * FROM sources WHERE name = ?", (name,), one=True)

    AUTH_MASK = "••••••"

    @classmethod
    def public(cls, src):
        """Copia de la fuente apta para el navegador: oculta el valor de la cabecera de autenticación."""
        if not src:
            return src
        d = dict(src)
        h = d.get("auth_header") or ""
        d["auth_header"] = (h.partition(":")[0].strip() + ": " + cls.AUTH_MASK) if h else ""
        return d

    def save_source(self, sid, data, user=""):
        vals = {k: data[k] for k in self.SRC_FIELDS if k in data}
        if self.AUTH_MASK in str(vals.get("auth_header") or ""):
            vals.pop("auth_header")  # sin cambios: se conserva la clave guardada
        for k in ("csv_col", "ref_col", "weight", "retention_days"):
            if k in vals:
                vals[k] = int(vals[k]) if str(vals[k]).strip() not in ("", "None") else None
        if "interval_h" in vals:
            vals["interval_h"] = float(vals["interval_h"] or 12)
        if "weight" in vals and vals["weight"] is not None:
            vals["weight"] = max(1, min(100, vals["weight"]))
        if "enabled" in vals:
            vals["enabled"] = 1 if vals["enabled"] in (True, 1, "1", "on", "true") else 0
        if sid:
            self.wx(f"UPDATE sources SET {','.join(k + ' = ?' for k in vals)} WHERE id = ?", list(vals.values()) + [sid])
        else:
            vals.setdefault("kind", "feed")
            sid = self.wx(f"INSERT INTO sources({','.join(vals)}, created_by, created_at) VALUES({','.join('?' * len(vals))}, ?, ?)",
                          list(vals.values()) + [user, now_s()])
        self.invalidate()
        return sid

    def add_catalog(self, keys, user):
        out = []
        for c in CATALOG:
            if c["key"] in keys and not self.source_by_name(c["name"]):
                sid = self.save_source(None, {**{k: v for k, v in c.items() if k != "key"}, "kind": "feed",
                                              "fmt": c.get("fmt", "lines")}, user)
                self.enqueue(("src", sid), self.run_source, sid, None, user)
                out.append(sid)
        return out

    def delete_source(self, sid, user=""):
        def _del():
            jid = self.job_new("delete", sid, user)
            while True:
                with self.wlock:
                    cur = self.w.execute("""DELETE FROM obs WHERE source_id = ? AND value IN
                                            (SELECT value FROM obs WHERE source_id = ? LIMIT 50000)""", (sid, sid))
                    self.w.commit()
                if cur.rowcount == 0:
                    break
            self.wx("DELETE FROM nets WHERE source_id = ?", (sid,))
            self.wx("DELETE FROM sources WHERE id = ?", (sid,))
            self.job_set(jid, status="ok", finished=now_s(), msg="Fuente eliminada")
            self.invalidate()
        self.wx("UPDATE sources SET enabled = 0, last_status = 'Eliminando…' WHERE id = ?", (sid,))
        self.enqueue(("del", sid), _del)

    def due_sources(self):
        out = []
        for s in self.rq("SELECT * FROM sources WHERE enabled = 1 AND kind IN ('feed', 'misp')"):
            if not s["last_run"]:
                out.append(s)
                continue
            last = datetime.datetime.strptime(s["last_run"], "%Y-%m-%d %H:%M")
            if (datetime.datetime.now() - last).total_seconds() >= (s["interval_h"] or 12) * 3600:
                out.append(s)
        return out

    # ------------------------------------------------------------ ingesta
    def _flush(self, sid, batch, nets, ts):
        with self.wlock:
            if batch:
                self.w.executemany("""INSERT INTO obs(value, source_id, type, first_seen, last_seen, ref) VALUES(?,?,?,?,?,?)
                    ON CONFLICT(value, source_id) DO UPDATE SET last_seen = excluded.last_seen,
                    ref = COALESCE(excluded.ref, obs.ref)""", [(v, sid, t, ts, ts, r) for v, t, r in batch])
            if nets:
                rows = []
                for cidr in nets:
                    n = ipaddress.ip_network(cidr)
                    rows.append((sid, cidr, int(n.network_address), n.prefixlen, ts))
                self.w.executemany("""INSERT INTO nets(source_id, cidr, net, plen, last_seen) VALUES(?,?,?,?,?)
                    ON CONFLICT(source_id, cidr) DO UPDATE SET last_seen = excluded.last_seen""", rows)
            self.w.commit()

    def _extract(self, src, lines, mode="first"):
        """Genera (valor, tipo, referencia) a partir de líneas de texto o CSV."""
        fixed, fmt = src.get("ioc_type") or "auto", src.get("fmt") or "lines"
        col, refc = src.get("csv_col") or 0, src.get("ref_col")
        split = re.compile(r"[\s,;|]+")
        for raw in lines:
            line = raw.strip()
            if not line or line[0] in "#;/" or line.startswith("//"):
                continue
            ref = None
            if fmt == "csv":
                try:
                    parts = [p.strip() for p in next(csv.reader([line], skipinitialspace=True))]
                except (csv.Error, StopIteration):
                    continue
                toks = [parts[col]] if col < len(parts) else []
                if refc is not None and refc < len(parts):
                    ref = parts[refc][:120] or None
            elif mode == "all":
                toks = split.split(line)
            else:
                toks = [split.split(line, 1)[0]]
                if fixed in ("auto", "") and not normalize(toks[0], fixed):
                    toks = split.split(line)  # la primera columna no es un IoC: se busca el primero válido
            for t in toks:
                r = normalize(t, fixed)
                if r:
                    yield r[0], r[1], ref
                    if mode != "all":
                        break

    @staticmethod
    def _open_stream(raw):
        """Admite archivos .gz detectándolos por la cabecera."""
        buf = io.BufferedReader(raw, buffer_size=1 << 20)
        if buf.peek(2)[:2] == b"\x1f\x8b":
            buf = gzip.GzipFile(fileobj=buf)
        return io.TextIOWrapper(buf, encoding="utf-8", errors="ignore", newline=None)

    def run_source(self, sid, path=None, user="", mode="first", misp=None):
        """Descarga (feed / MISP) o lee un archivo subido y lo carga en la base."""
        src = self.source(sid)
        if not src:
            return
        jid = self.job_new("upload" if path else src["kind"], sid, user)
        ts = int(time.time())
        before = self.rq("SELECT COUNT(*) n FROM obs WHERE source_id = ?", (sid,), one=True)["n"]
        done, batch, nets = 0, [], []
        resp = None
        try:
            if src["kind"] == "misp":
                it = self._misp_iter(src, misp)
            else:
                if path:
                    fh = open(path, "rb")
                else:
                    hdr = {"User-Agent": "SOC-ACME-portal/1.0"}
                    if src["auth_header"] and ":" in src["auth_header"]:
                        k, _, v = src["auth_header"].partition(":")
                        hdr[k.strip()] = v.strip()
                    r = requests.get(src["url"], headers=hdr, stream=True, timeout=(20, 600))
                    r.raise_for_status()
                    r.raw.decode_content = True
                    # urllib3 2.x cierra el flujo al llegar al final y io.BufferedReader falla con
                    # «I/O operation on closed file»; el cierre lo hacemos nosotros en finally.
                    r.raw.auto_close = False
                    resp = r
                    fh = r.raw
                it = self._extract(src, self._open_stream(fh), mode)
            for v, t, ref in it:
                if t == "cidr":
                    nets.append(v)
                else:
                    batch.append((v, t, ref))
                done += 1
                if len(batch) + len(nets) >= BATCH:
                    self._flush(sid, batch, nets, ts)
                    batch, nets = [], []
                    self.job_set(jid, done=done)
                if done >= MAX_PER_SOURCE:
                    log.warning("Fuente %s: se alcanzó el máximo de %s indicadores", src["name"], MAX_PER_SOURCE)
                    break
            self._flush(sid, batch, nets, ts)
            # caducidad: se borra lo que la fuente dejó de publicar hace más de retention_days
            if src["kind"] == "misp":
                self._purge(sid, ts)  # MISP se descarga completo: lo que no vino ya no está vigente
            elif src["retention_days"]:
                self._purge(sid, ts - src["retention_days"] * 86400)
            n = self.rq("SELECT COUNT(*) n FROM obs WHERE source_id = ?", (sid,), one=True)["n"]
            n += self.rq("SELECT COUNT(*) n FROM nets WHERE source_id = ?", (sid,), one=True)["n"]
            added = max(0, n - before)
            msg = f"OK · {done:,} leídos · {n:,} vigentes".replace(",", ".")
            self.wx("UPDATE sources SET n = ?, last_run = ?, last_status = ?, last_added = ? WHERE id = ?",
                    (n, now_s(), msg, added, sid))
            self.job_set(jid, status="ok", done=done, added=added, finished=now_s(), msg=msg)
            log.info("Fuente %s: %s", src["name"], msg)
        except Exception as exc:
            msg = "Error: " + friendly(exc)
            self.wx("UPDATE sources SET last_run = ?, last_status = ? WHERE id = ?", (now_s(), msg, sid))
            self.job_set(jid, status="error", done=done, finished=now_s(), msg=msg)
            log.warning("Fuente %s: %s", src["name"], msg)
        finally:
            if resp is not None:
                resp.close()
            if path:
                try:
                    os.remove(path)
                except OSError:
                    pass
            self.invalidate()

    def _purge(self, sid, older_than):
        while True:
            with self.wlock:
                cur = self.w.execute("""DELETE FROM obs WHERE source_id = ? AND value IN
                    (SELECT value FROM obs WHERE source_id = ? AND last_seen < ? LIMIT 50000)""", (sid, sid, older_than))
                self.w.commit()
            if cur.rowcount == 0:
                break
        self.wx("DELETE FROM nets WHERE source_id = ? AND last_seen < ?", (sid, older_than))

    def _misp_iter(self, src, misp):
        """Descarga los atributos to_ids de MISP de los últimos retention_days días, por páginas."""
        days = src["retention_days"] or 90
        since = int(time.time()) - days * 86400
        tmap = {"ip-src": "ip", "ip-dst": "ip", "domain": "domain", "hostname": "domain", "url": "url", "md5": "md5",
                "sha1": "sha1", "sha256": "sha256", "email-src": "email", "email-dst": "email", "email": "email"}
        page, limit = 1, 20000
        while True:
            body = {"returnFormat": "json", "to_ids": 1, "timestamp": since, "limit": limit, "page": page,
                    "includeContext": 0, "deleted": 0, "includeEventTags": 0, "enforceWarninglist": 1,
                    "requested_attributes": ["value", "type", "event_id"]}
            r = requests.post(f"{misp.url}/attributes/restSearch", headers=misp.h, json=body, verify=misp.verify, timeout=600)
            r.raise_for_status()
            attrs = r.json().get("response", {}).get("Attribute", [])
            for a in attrs:
                t, v = a.get("type", ""), a.get("value", "")
                if "|" in t:  # ip-dst|port, filename|sha256, domain|ip...
                    t1, t2 = t.split("|", 1)
                    v1, _, v2 = v.partition("|")
                    t, v = (t1, v1) if t1 in tmap else (t2, v2)
                if t in tmap:
                    res = normalize(v, tmap[t])
                    if res:
                        yield res[0], res[1], f"MISP #{a.get('event_id')}"
            if len(attrs) < limit:
                break
            page += 1

    def add_text(self, text, meta, user):
        """Carga pequeña desde el portal o Shuffle: crea (o reutiliza) una fuente manual."""
        name = (meta.get("source") or "Carga manual").strip()[:80]
        src = self.source_by_name(name)
        days = int(meta.get("expires_days") or 0)
        if not src:
            sid = self.save_source(None, {"name": name, "kind": "manual", "weight": int(meta.get("weight") or 70),
                                          "retention_days": days, "tlp": meta.get("tlp") or "amber",
                                          "description": meta.get("description") or "", "incident": meta.get("incident") or "",
                                          "interval_h": 0}, user)
            src = self.source(sid)
        items = list(dict.fromkeys(self._extract({"ioc_type": "auto", "fmt": "lines"}, text.splitlines(), "all")))
        ts = int(time.time())
        before = self.rq("SELECT COUNT(*) n FROM obs WHERE source_id = ?", (src["id"],), one=True)["n"]
        self._flush(src["id"], [i for i in items if i[1] != "cidr"], [i[0] for i in items if i[1] == "cidr"], ts)
        n = self.rq("SELECT COUNT(*) n FROM obs WHERE source_id = ?", (src["id"],), one=True)["n"]
        self.wx("UPDATE sources SET n = ?, last_run = ?, last_status = ?, last_added = ? WHERE id = ?",
                (n, now_s(), f"OK · {len(items)} cargados", n - before, src["id"]))
        self.invalidate()
        return src["id"], items, n - before

    # ------------------------------------------------------------ búsqueda y puntuación
    def weights(self):
        return self.cached("weights", 30, lambda: {s["id"]: (s["weight"], s["name"], s["kind"]) for s in self.sources()})

    def score(self, sids):
        W = self.weights()
        p = 1.0
        for s in set(sids):
            p *= 1 - (W.get(s, (50,))[0] or 50) / 100
        return round((1 - p) * 100)

    def _load_nets(self):
        if self._nets is None:
            d = {}
            for r in self.rq("SELECT source_id, cidr, net, plen FROM nets"):
                d.setdefault(r["plen"], {}).setdefault(r["net"], []).append((r["source_id"], r["cidr"]))
            self._nets = d
        return self._nets

    def lookup(self, values):
        """values: iterable de cadenas. Devuelve {valor: [{sid, type, ref, via}]} solo con los que coinciden."""
        out, vals = {}, list(dict.fromkeys(v for v in values if v))
        c = sqlite3.connect(self.path, timeout=60)
        try:
            for i in range(0, len(vals), 900):
                chunk = vals[i:i + 900]
                for v, sid, t, ref in c.execute(f"SELECT value, source_id, type, ref FROM obs WHERE value IN ({','.join('?' * len(chunk))})", chunk):
                    out.setdefault(v, []).append({"sid": sid, "type": t, "ref": ref, "via": v})
        finally:
            c.close()
        nets = self._load_nets()
        if nets:
            for v in vals:
                if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v):
                    continue
                try:
                    ip = int(ipaddress.IPv4Address(v))
                except ValueError:
                    continue
                for plen, table in nets.items():
                    hit = table.get(ip >> (32 - plen) << (32 - plen))
                    if hit:
                        out.setdefault(v, []).extend({"sid": s, "type": "cidr", "ref": None, "via": cidr} for s, cidr in hit)
        return out

    def describe(self, matches):
        W = self.weights()
        seen, srcs = set(), []
        for m in matches:
            if m["sid"] in seen:
                continue
            seen.add(m["sid"])
            srcs.append({"id": m["sid"], "name": W.get(m["sid"], (0, "?"))[1], "weight": W.get(m["sid"], (0,))[0],
                         "ref": m["ref"], "via": m["via"], "type": m["type"]})
        return {"score": self.score([m["sid"] for m in matches]), "fuentes": sorted(srcs, key=lambda x: -x["weight"])}

    def browse(self, q="", sid=None, type_="", limit=200):
        sql, a = "SELECT value, source_id, type, first_seen, last_seen, ref FROM obs WHERE 1=1", []
        if q:
            q = q.strip().lower() if not re.match(r"^https?://", q.strip(), re.I) else q.strip()
            sql += " AND value >= ? AND value < ?"; a += [q, q + "￿"]  # búsqueda por prefijo (usa el índice)
        if sid:
            sql += " AND source_id = ?"; a.append(int(sid))
        if type_:
            sql += " AND type = ?"; a.append(type_)
        sql += " LIMIT ?"; a.append(limit)
        W = self.weights()
        return [{**r, "source": W.get(r["source_id"], (0, "?"))[1], "weight": W.get(r["source_id"], (0,))[0]} for r in self.rq(sql, a)]

    # ------------------------------------------------------------ estadísticas
    def overview(self):
        def heavy():
            types = {r["type"]: r["n"] for r in self.rq("SELECT type, COUNT(*) n FROM obs GROUP BY type")}
            nets = self.rq("SELECT COUNT(*) n FROM nets", one=True)["n"]
            if nets:
                types["cidr"] = nets
            uniq = self.rq("SELECT COUNT(*) n FROM (SELECT DISTINCT value FROM obs)", one=True)["n"] + nets
            multi = self.rq("SELECT COUNT(*) n FROM (SELECT value FROM obs GROUP BY value HAVING COUNT(*) > 1)", one=True)["n"]
            return {"por_tipo": sorted(types.items(), key=lambda x: -x[1]), "unicos": uniq, "multi": multi}
        h = self.cached("heavy", 900, heavy)
        d1 = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M")
        d7 = (datetime.datetime.now() - datetime.timedelta(days=7)).strftime("%Y-%m-%d %H:%M")
        s = self.rq("""SELECT SUM(CASE WHEN last_seen >= ? THEN 1 ELSE 0 END) h24, SUM(CASE WHEN last_seen >= ? THEN 1 ELSE 0 END) d7,
                       COUNT(DISTINCT CASE WHEN last_seen >= ? THEN value END) v7, COUNT(DISTINCT CASE WHEN last_seen >= ? THEN agent END) ag7
                       FROM sightings""", (d1, d7, d7, d7), one=True)
        return {**h, "coincidencias_24h": s["h24"] or 0, "coincidencias_7d": s["d7"] or 0, "iocs_vistos_7d": s["v7"] or 0,
                "equipos_7d": s["ag7"] or 0, "fuentes": self.sources(), "jobs": self.jobs(8),
                "correlacion": self.kv("corr_last_ok"), "correlacion_msg": self.kv("corr_msg")}

    def overlap(self, top=10):
        """Solapamiento entre fuentes: cuántos indicadores comparten cada par."""
        def calc():
            srcs = [s for s in self.sources() if s["n"]][:top]
            ids = [s["id"] for s in srcs]
            if len(ids) < 2:
                return {"fuentes": [{"id": s["id"], "name": s["name"], "n": s["n"]} for s in srcs], "pares": []}
            q = f"""SELECT a.source_id x, b.source_id y, COUNT(*) n FROM obs a JOIN obs b ON a.value = b.value AND a.source_id < b.source_id
                    WHERE a.source_id IN ({','.join('?' * len(ids))}) AND b.source_id IN ({','.join('?' * len(ids))}) GROUP BY 1, 2"""
            return {"fuentes": [{"id": s["id"], "name": s["name"], "n": s["n"]} for s in srcs],
                    "pares": [[r["x"], r["y"], r["n"]] for r in self.rq(q, ids + ids)]}
        return self.cached("overlap", 1800, calc)

    # ------------------------------------------------------------ correlación con Wazuh
    def correlate(self, wazuh, gte_ms, lt_ms, additive=True, job=None):
        """Cruza los valores únicos vistos en las alertas entre gte_ms y lt_ms con la base de IoC."""
        if not self.rq("SELECT 1 FROM sources WHERE n > 0 LIMIT 1", one=True):
            return 0, []
        new, total = [], 0
        rng = {"range": {"timestamp": {"gte": gte_ms, "lt": lt_ms, "format": "epoch_millis"}}}
        for kind, fields in WAZUH_FIELDS.items():
            for field in fields:
                after = None
                while True:
                    comp = {"size": 3000, "sources": [{"v": {"terms": {"field": field}}}]}
                    if after:
                        comp["after"] = after
                    body = {"size": 0, "query": {"bool": {"filter": [rng, {"exists": {"field": field}}]}},
                            "aggs": {"c": {"composite": comp, "aggs": {
                                "ag": {"terms": {"field": "agent.name", "size": 5}},
                                "r": {"terms": {"field": "rule.description", "size": 1}},
                                "first": {"min": {"field": "timestamp"}}, "last": {"max": {"field": "timestamp"}}}}}}
                    try:
                        d = wazuh._search("wazuh-alerts-*", body)["aggregations"]["c"]
                    except Exception as exc:
                        log.debug("Correlación: campo %s omitido (%s)", field, str(exc)[:100])
                        break
                    buckets = d.get("buckets", [])
                    obs = {}
                    for b in buckets:
                        raw = str(b["key"]["v"]).strip().rstrip(".")
                        val = raw.lower() if kind in ("domain", "hash") else raw
                        cands = [val]
                        if kind == "domain":  # sub.dominio.malo.com también coincide con malo.com
                            parts = val.split(".")
                            cands += [".".join(parts[i:]) for i in range(1, max(1, len(parts) - 1))]
                        obs[val] = (b, cands)
                    hits = self.lookup([c for _, cands in obs.values() for c in cands])
                    for val, (b, cands) in obs.items():
                        m = [x for c in cands for x in hits.get(c, [])]
                        if not m:
                            continue
                        total += 1
                        rule = (b["r"]["buckets"] or [{"key": ""}])[0]["key"][:200]
                        first = (b["first"].get("value_as_string") or "")[:19].replace("T", " ")
                        last = (b["last"].get("value_as_string") or "")[:19].replace("T", " ")
                        matched = ",".join(sorted({x["via"] for x in m}))[:300]
                        agents = b["ag"]["buckets"] or [{"key": "—", "doc_count": b["doc_count"]}]
                        for ag in agents:
                            row = (val, m[0]["type"], field, ag["key"], ag["doc_count"], first, last, rule, matched, int(time.time()))
                            with self.wlock:
                                exists = self.w.execute("SELECT 1 FROM sightings WHERE value = ? AND field = ? AND agent = ?",
                                                        (val, field, ag["key"])).fetchone()
                                upd = "n + excluded.n" if additive else "MAX(n, excluded.n)"
                                self.w.execute(f"""INSERT INTO sightings(value, type, field, agent, n, first_seen, last_seen, rule, matched, created)
                                    VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(value, field, agent) DO UPDATE SET n = {upd},
                                    first_seen = MIN(first_seen, excluded.first_seen), last_seen = MAX(last_seen, excluded.last_seen),
                                    rule = excluded.rule, matched = excluded.matched""", row)
                                self.w.commit()
                            if not exists:
                                new.append({"value": val, "field": field, "agent": ag["key"], "rule": rule,
                                            **self.describe(m)})
                    if job:
                        self.job_set(job, done=total, msg=f"Revisando {field}…")
                    after = d.get("after_key")
                    if not after or len(buckets) < 3000:
                        break
        return total, new

    def sightings(self, days=7, q="", min_score=0, limit=500):
        since = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M")
        sql, a = "SELECT * FROM sightings WHERE last_seen >= ?", [since]
        if q:
            sql += " AND (value LIKE ? OR agent LIKE ? OR rule LIKE ?)"; a += [f"%{q}%"] * 3
        rows = self.rq(sql + " ORDER BY last_seen DESC LIMIT 5000", a)
        hits = self.lookup({k for r in rows for k in [r["value"]] + r["matched"].split(",")})
        grouped = {}
        for r in rows:  # una fila por indicador, con los equipos agregados
            g = grouped.setdefault(r["value"], {"value": r["value"], "type": r["type"], "n": 0, "agents": {}, "fields": set(),
                                                 "first_seen": r["first_seen"], "last_seen": r["last_seen"], "rule": r["rule"],
                                                 "matched": r["matched"]})
            g["n"] += r["n"]
            g["agents"][r["agent"]] = g["agents"].get(r["agent"], 0) + r["n"]
            g["fields"].add(r["field"])
            g["first_seen"] = min(g["first_seen"], r["first_seen"])
            g["last_seen"] = max(g["last_seen"], r["last_seen"])
        out = []
        for g in grouped.values():
            m = [x for k in [g["value"]] + g["matched"].split(",") for x in hits.get(k, [])]
            d = self.describe(m) if m else {"score": 0, "fuentes": []}
            if d["score"] < min_score:
                continue
            out.append({**g, **d, "fields": sorted(g["fields"]),
                        "agents": sorted(g["agents"].items(), key=lambda x: -x[1])})
        out.sort(key=lambda x: x["last_seen"], reverse=True)
        return out[:limit]

    # ------------------------------------------------------------ comprobación masiva
    def bulk_check(self, items, wazuh, misp, days=30):
        values = [i["value"] for i in items]
        cands = {i["value"]: [i["value"]] + ([".".join(i["value"].split(".")[k:]) for k in range(1, max(1, i["value"].count(".")))]
                                             if i["type"] == "domain" else []) for i in items}
        hits = self.lookup([c for cs in cands.values() for c in cs])
        res = {}
        for i in items:
            m = [x for c in cands[i["value"]] for x in hits.get(c, [])]
            res[i["value"]] = {"value": i["value"], "type": i["type"], **(self.describe(m) if m else {"score": 0, "fuentes": []}),
                               "wazuh": None, "misp": None, "sightings": 0}
        for r in self.rq(f"SELECT value, SUM(n) n FROM sightings WHERE value IN ({','.join('?' * len(values))}) GROUP BY value", values):
            res[r["value"]]["sightings"] = r["n"]
        # Wazuh: una sola consulta con todos los valores (agregación por campo)
        try:
            fields = [f for fs in WAZUH_FIELDS.values() for f in fs]
            aggs = {f"f{i}": {"terms": {"field": f, "include": values, "size": len(values)}} for i, f in enumerate(fields)}
            body = {"size": 0, "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{days}d"}}}],
                                                  "should": [{"terms": {f: values}} for f in fields], "minimum_should_match": 1}},
                    "aggs": aggs}
            d = wazuh._search("wazuh-alerts-*", body)["aggregations"]
            for k in d:
                for b in d[k]["buckets"]:
                    key = str(b["key"])
                    if key in res:
                        res[key]["wazuh"] = (res[key]["wazuh"] or 0) + b["doc_count"]
            for v in res.values():
                v["wazuh"] = v["wazuh"] or 0
        except Exception as exc:
            log.warning("Comprobación masiva en Wazuh: %s", exc)
        # MISP: una consulta con la lista de valores
        try:
            body = {"returnFormat": "json", "value": values, "limit": 5000, "includeContext": 0,
                    "requested_attributes": ["value", "event_id", "to_ids"]}
            r = requests.post(f"{misp.url}/attributes/restSearch", headers=misp.h, json=body, verify=misp.verify, timeout=120)
            r.raise_for_status()
            for a in r.json().get("response", {}).get("Attribute", []):
                v = a.get("value")
                if v in res:
                    res[v]["misp"] = sorted(set((res[v]["misp"] or []) + [str(a.get("event_id"))]))
            for v in res.values():
                v["misp"] = v["misp"] or []
        except Exception as exc:
            log.warning("Comprobación masiva en MISP: %s", exc)
        return list(res.values())

    # ------------------------------------------------------------ enriquecimiento externo (bajo demanda)
    def providers(self):
        p = [("shodan", "Shodan InternetDB", True)]
        for k, name, env in (("abuseipdb", "AbuseIPDB", "ABUSEIPDB_KEY"), ("virustotal", "VirusTotal", "VT_API_KEY"),
                             ("otx", "AlienVault OTX", "OTX_API_KEY"), ("threatfox", "ThreatFox", "ABUSECH_AUTH_KEY")):
            p.append((k, name, bool(os.getenv(env))))
        return [{"key": k, "name": n, "on": on} for k, n, on in p]

    def enrich(self, value, type_, force=False):
        out = []
        for p in self.providers():
            if not p["on"]:
                continue
            row = self.rq("SELECT * FROM enrich WHERE value = ? AND provider = ?", (value, p["key"]), one=True)
            if row and not force and time.time() - row["at"] < 86400:
                out.append({"provider": p["name"], "verdict": row["verdict"], "score": row["score"], "data": json.loads(row["data"] or "{}"), "cache": True})
                continue
            try:
                verdict, score, data = getattr(self, "_e_" + p["key"])(value, type_)
            except _Skip:
                continue
            except Exception as exc:
                out.append({"provider": p["name"], "verdict": "error", "score": None, "data": {"error": friendly(exc)}})
                continue
            self.wx("INSERT OR REPLACE INTO enrich(value, provider, at, verdict, score, data) VALUES(?,?,?,?,?,?)",
                    (value, p["key"], int(time.time()), verdict, score, json.dumps(data)[:20000]))
            out.append({"provider": p["name"], "verdict": verdict, "score": score, "data": data})
        return out

    def _e_shodan(self, v, t):
        if t != "ip":
            raise _Skip
        r = requests.get(f"https://internetdb.shodan.io/{v}", timeout=15)
        if r.status_code == 404:
            return "sin datos", 0, {}
        r.raise_for_status()
        d = r.json()
        return ("vulnerable" if d.get("vulns") else "info"), min(100, len(d.get("vulns", [])) * 10), {
            "puertos": d.get("ports", []), "vulns": d.get("vulns", [])[:15], "tags": d.get("tags", []), "hostnames": d.get("hostnames", [])[:5]}

    def _e_abuseipdb(self, v, t):
        if t != "ip":
            raise _Skip
        r = requests.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": v, "maxAgeInDays": 90},
                         headers={"Key": os.environ["ABUSEIPDB_KEY"], "Accept": "application/json"}, timeout=20)
        r.raise_for_status()
        d = r.json()["data"]
        s = d.get("abuseConfidenceScore", 0)
        return ("malicioso" if s >= 75 else "sospechoso" if s >= 25 else "limpio"), s, {
            "reportes": d.get("totalReports"), "pais": d.get("countryCode"), "isp": d.get("isp"), "uso": d.get("usageType"),
            "tor": d.get("isTor"), "ultimo_reporte": d.get("lastReportedAt")}

    def _e_virustotal(self, v, t):
        path = {"ip": "ip_addresses", "domain": "domains", "md5": "files", "sha1": "files", "sha256": "files"}.get(t)
        if t == "url":
            path, v = "urls", base64.urlsafe_b64encode(v.encode()).decode().strip("=")
        if not path:
            raise _Skip
        r = requests.get(f"https://www.virustotal.com/api/v3/{path}/{v}", headers={"x-apikey": os.environ["VT_API_KEY"]}, timeout=20)
        if r.status_code == 404:
            return "sin datos", 0, {}
        r.raise_for_status()
        a = r.json()["data"]["attributes"]
        st = a.get("last_analysis_stats", {})
        mal = st.get("malicious", 0) + st.get("suspicious", 0)
        tot = sum(st.values()) or 1
        return ("malicioso" if st.get("malicious", 0) >= 3 else "sospechoso" if mal else "limpio"), round(mal / tot * 100), {
            "maliciosos": st.get("malicious", 0), "sospechosos": st.get("suspicious", 0), "motores": tot,
            "reputacion": a.get("reputation"), "nombre": a.get("meaningful_name") or a.get("as_owner")}

    def _e_otx(self, v, t):
        sec = {"ip": "IPv4", "domain": "domain", "url": "url", "md5": "file", "sha1": "file", "sha256": "file"}.get(t)
        if not sec:
            raise _Skip
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/{sec}/{v}/general",
                         headers={"X-OTX-API-KEY": os.environ["OTX_API_KEY"]}, timeout=20)
        if r.status_code == 404:
            return "sin datos", 0, {}
        r.raise_for_status()
        p = r.json().get("pulse_info", {})
        n = p.get("count", 0)
        return ("malicioso" if n >= 3 else "sospechoso" if n else "sin datos"), min(100, n * 15), {
            "pulsos": n, "nombres": [x.get("name") for x in p.get("pulses", [])[:5]]}

    def _e_threatfox(self, v, t):
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": v},
                          headers={"Auth-Key": os.environ["ABUSECH_AUTH_KEY"]}, timeout=20)
        r.raise_for_status()
        d = r.json()
        if d.get("query_status") != "ok":
            return "sin datos", 0, {}
        x = d["data"][0]
        return "malicioso", x.get("confidence_level") or 75, {"malware": x.get("malware_printable"), "tipo": x.get("threat_type"),
                                                               "visto": x.get("first_seen"), "etiquetas": x.get("tags")}

    # ------------------------------------------------------------ exportación (MISP / Wazuh)
    def export_values(self, types, min_weight=0, exclude_kinds=("misp",)):
        """Genera los valores únicos de esos tipos, de fuentes con confianza >= min_weight."""
        W = self.weights()
        sids = [s for s, (w, _, kind) in W.items() if (w or 0) >= min_weight and kind not in exclude_kinds]
        if not sids:
            return
        c = sqlite3.connect(self.path, timeout=60)
        try:
            if "cidr" in types:
                for (cidr,) in c.execute(f"SELECT DISTINCT cidr FROM nets WHERE source_id IN ({','.join('?' * len(sids))})", sids):
                    yield cidr, "cidr", ""
            ts = [t for t in types if t != "cidr"]
            if ts:
                cur = c.execute(f"""SELECT value, type, GROUP_CONCAT(source_id) FROM obs WHERE type IN ({','.join('?' * len(ts))})
                                    AND source_id IN ({','.join('?' * len(sids))}) GROUP BY value""", ts + sids)
                for v, t, s in cur:
                    yield v, t, s
        finally:
            c.close()


class _Skip(Exception):
    pass
