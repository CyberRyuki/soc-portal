"""Exposición cibernética y Shadow IT (gestión de la superficie de ataque).

Descubrimiento
- Pasivo: subdominios de los dominios raíz en la Transparencia de Certificados (crt.sh), resolución DNS y
  Shodan InternetDB (puertos, CVE y nombres conocidos por IP; gratuito y sin clave).
- Activo (requiere autorización registrada): escaneo TCP de los rangos de ACME, lectura de banners, revisión TLS y
  comprobación de rutas sensibles en los servicios web (/.git, /.env, phpinfo, paneles, copias de seguridad…).

Salvaguardas (no configurables desde la interfaz):
- Solo se escanean IP dentro de los rangos del alcance y fuera de los excluidos. Nunca fuera.
- Máximo MAX_SCAN_IPS direcciones por escaneo; velocidad y concurrencia limitadas.
- El escaneo activo exige «autorización» (quién, referencia del documento, vigencia) y no vencida.
- Las rutas sensibles solo se piden a dominios del alcance o a IP del alcance.

Shadow IT = activo de ACME que no está en el inventario (Portales): subdominios vistos en certificados/DNS y
servidores de los rangos con servicios abiertos que nadie ha registrado.
"""
import asyncio
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import socket
import sqlite3
import ssl
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests

log = logging.getLogger("soc-bridge.exposure")
CRTSH = os.getenv("EXPOSURE_CRTSH_URL", "https://crt.sh").rstrip("/")
INTERNETDB = os.getenv("EXPOSURE_INTERNETDB_URL", "https://internetdb.shodan.io").rstrip("/")
MAX_SCAN_IPS = 65536
UA = "Mozilla/5.0 (SOC-ACME exposicion; +portal SOC)"

STANDARD = [21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1080, 1433,
            1521, 1723, 2049, 2082, 2083, 2086, 2087, 2375, 2376, 2379, 3000, 3128, 3268, 3306, 3389, 4443, 4848, 5000,
            5432, 5601, 5900, 5984, 5985, 5986, 6379, 6443, 7001, 7443, 8000, 8008, 8080, 8081, 8088, 8443, 8500, 8888,
            9000, 9001, 9090, 9200, 9300, 9443, 10000, 10250, 11211, 15672, 27017, 50000]
PROFILES = {
    "pasivo": [],
    "estandar": STANDARD,
    "amplio": sorted(set(range(1, 1025)) | set(STANDARD) | {1194, 1883, 2222, 3001, 4000, 4444, 5001, 5060, 5672, 5800,
                                                            6000, 6001, 7000, 7070, 7777, 8001, 8002, 8009, 8010, 8082,
                                                            8083, 8090, 8181, 8282, 8880, 8983, 9002, 9080, 9091, 9100,
                                                            9418, 9999, 10443, 16992, 18080, 20000, 25565, 28017, 32400,
                                                            49152, 55443, 61616}),
    "completo": list(range(1, 65536)),
}
WEB_PORTS = {80, 81, 443, 3000, 4443, 5000, 7443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9443, 10443}
TLS_PORTS = {443, 4443, 7443, 8443, 9443, 10443, 465, 993, 995, 636, 5986, 6443}

# puerto → (servicio, severidad, explicación)
RISKY = {
    23: ("Telnet", "critical", "acceso remoto sin cifrar"), 445: ("SMB", "critical", "compartición de Windows expuesta (ransomware)"),
    3389: ("RDP", "critical", "escritorio remoto expuesto (fuerza bruta, BlueKeep)"), 5900: ("VNC", "critical", "control remoto expuesto"),
    2375: ("Docker API", "critical", "API de Docker sin TLS = control total del servidor"), 2379: ("etcd", "critical", "almacén de secretos de Kubernetes"),
    10250: ("Kubelet", "critical", "API de nodo Kubernetes"), 6379: ("Redis", "critical", "base de datos en memoria, suele no tener contraseña"),
    11211: ("Memcached", "critical", "caché expuesta (amplificación DDoS)"), 9200: ("Elasticsearch", "critical", "índices de datos expuestos"),
    27017: ("MongoDB", "critical", "base de datos expuesta"), 5984: ("CouchDB", "critical", "base de datos expuesta"),
    3306: ("MySQL/MariaDB", "critical", "base de datos expuesta a Internet"), 5432: ("PostgreSQL", "critical", "base de datos expuesta a Internet"),
    1433: ("SQL Server", "critical", "base de datos expuesta a Internet"), 1521: ("Oracle", "critical", "base de datos expuesta a Internet"),
    135: ("MS-RPC", "high", "servicio interno de Windows"), 139: ("NetBIOS", "high", "servicio interno de Windows"),
    5985: ("WinRM", "high", "administración remota de Windows"), 5986: ("WinRM (TLS)", "high", "administración remota de Windows"),
    21: ("FTP", "high", "credenciales en claro"), 389: ("LDAP", "high", "directorio expuesto"), 636: ("LDAPS", "high", "directorio expuesto"),
    3268: ("LDAP GC", "high", "catálogo global de AD expuesto"), 111: ("rpcbind", "high", "servicio RPC de Unix"), 2049: ("NFS", "high", "sistema de archivos en red"),
    1723: ("PPTP", "high", "VPN obsoleta e insegura"), 5601: ("Kibana", "high", "panel de datos"), 8500: ("Consul", "high", "configuración de servicios"),
    9090: ("Prometheus/Cockpit", "high", "panel de administración"), 10000: ("Webmin", "high", "panel de administración del servidor"),
    4848: ("GlassFish admin", "high", "consola de administración"), 7001: ("WebLogic", "high", "servidor con fallos críticos frecuentes"),
    2082: ("cPanel", "high", "panel de hosting"), 2083: ("cPanel", "high", "panel de hosting"), 2086: ("WHM", "high", "panel de hosting"),
    2087: ("WHM", "high", "panel de hosting"), 15672: ("RabbitMQ admin", "high", "consola de colas"), 9300: ("Elasticsearch nodos", "high", "cluster expuesto"),
    6443: ("Kubernetes API", "high", "plano de control expuesto"), 50000: ("SAP/Jenkins", "high", "servicio de administración"),
    22: ("SSH", "medium", "acceso remoto: restringir por IP o VPN"), 1080: ("SOCKS", "high", "proxy abierto"), 3128: ("Proxy HTTP", "high", "proxy abierto"),
}
SENSITIVE = [  # (ruta, comprobación del contenido, severidad, título)
    ("/.git/HEAD", lambda r, t: t.startswith("ref:") or re.match(r"^[0-9a-f]{40}\s*$", t), "critical", "Repositorio .git expuesto (código fuente y secretos)"),
    ("/.env", lambda r, t: bool(re.search(r"^(APP_|DB_|DATABASE_|SECRET|AWS_|MAIL_)[A-Z_]*=", t, re.M)) and "<html" not in t.lower(),
     "critical", "Archivo .env expuesto (contraseñas y claves)"),
    ("/wp-config.php.bak", lambda r, t: "DB_PASSWORD" in t, "critical", "Copia de wp-config con credenciales"),
    ("/backup.sql", lambda r, t: "INSERT INTO" in t or "CREATE TABLE" in t, "critical", "Volcado de base de datos expuesto"),
    ("/db.sql", lambda r, t: "INSERT INTO" in t or "CREATE TABLE" in t, "critical", "Volcado de base de datos expuesto"),
    ("/actuator/env", lambda r, t: '"propertySources"' in t, "critical", "Spring Actuator /env expuesto (secretos)"),
    ("/.svn/entries", lambda r, t: t[:3].strip().isdigit() or "svn:" in t, "high", "Repositorio .svn expuesto"),
    ("/server-status", lambda r, t: "Apache Server Status" in t, "high", "Estado interno de Apache expuesto"),
    ("/phpinfo.php", lambda r, t: "phpinfo()" in t or ("PHP Version" in t and "PHP License" in t), "high", "phpinfo() expuesto"),
    ("/info.php", lambda r, t: "phpinfo()" in t or ("PHP Version" in t and "PHP License" in t), "high", "phpinfo() expuesto"),
    ("/phpmyadmin/", lambda r, t: "phpMyAdmin" in t and ("pma_" in t or "login" in t.lower()), "high", "phpMyAdmin accesible desde Internet"),
    ("/adminer.php", lambda r, t: "Adminer" in t and "login" in t.lower(), "high", "Adminer (gestor de BD) accesible"),
    ("/web.config", lambda r, t: "<configuration" in t, "high", "web.config de IIS expuesto"),
    ("/elmah.axd", lambda r, t: "Error Log for" in t, "high", "Registro de errores ELMAH expuesto"),
    ("/backup.zip", lambda r, t: r.headers.get("content-type", "").startswith(("application/zip", "application/x-zip", "application/octet")) and len(r.content) > 1000,
     "high", "Copia de seguridad descargable"),
    ("/.DS_Store", lambda r, t: r.content[:8] == b"\x00\x00\x00\x01Bud1", "medium", "Archivo .DS_Store (lista de archivos internos)"),
    ("/actuator", lambda r, t: '"_links"' in t and "actuator" in t, "medium", "Spring Actuator expuesto"),
    ("/wp-login.php", lambda r, t: "wp-submit" in t, "low", "Acceso de administración de WordPress público"),
    ("/administrator/", lambda r, t: "Joomla" in t and "passwd" in t.lower(), "low", "Acceso de administración de Joomla público"),
    ("/uploads/", lambda r, t: "<title>Index of /" in t, "medium", "Listado de directorio activo (/uploads)"),
]
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets(
  key TEXT PRIMARY KEY, type TEXT, value TEXT, ips TEXT DEFAULT '[]', sources TEXT DEFAULT '[]', first_seen TEXT,
  last_seen TEXT, inventoried INTEGER DEFAULT 0, in_scope INTEGER DEFAULT 0, status TEXT DEFAULT 'nuevo', note TEXT DEFAULT '',
  web TEXT DEFAULT '{}', idb TEXT DEFAULT '{}');
CREATE TABLE IF NOT EXISTS services(
  ip TEXT, port INTEGER, service TEXT, banner TEXT, tls TEXT DEFAULT '{}', source TEXT, first_seen TEXT, last_seen TEXT,
  PRIMARY KEY(ip, port));
CREATE TABLE IF NOT EXISTS findings(
  key TEXT PRIMARY KEY, asset TEXT, severity TEXT, category TEXT, title TEXT, detail TEXT, evidence TEXT, first_seen TEXT,
  last_seen TEXT, status TEXT DEFAULT 'open', note TEXT DEFAULT '', decided_by TEXT DEFAULT '', job INTEGER);
CREATE INDEX IF NOT EXISTS ix_f_status ON findings(status, severity);
CREATE TABLE IF NOT EXISTS jobs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, by TEXT, kind TEXT, status TEXT, phase TEXT, done INTEGER DEFAULT 0,
  total INTEGER DEFAULT 0, msg TEXT DEFAULT '', finished TEXT DEFAULT '', stats TEXT DEFAULT '{}');
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
"""


def now_s():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class ScopeError(ValueError):
    pass


class Exposure:
    def __init__(self, db_path: str):
        self.path, self.lock = db_path, threading.Lock()
        self.cancel = threading.Event()
        self.running = None
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

    # ------------------------------------------------------------ alcance
    DEFAULT = {"dominios": [], "rangos": [], "excluidos": [], "perfil": "estandar", "velocidad": 400, "concurrencia": 300,
               "timeout_ms": 1500, "rutas_web": True, "programado_dias": 0,
               "autorizacion": {"por": "", "referencia": "", "hasta": "", "registrado_por": "", "registrado_at": ""}}

    def config(self):
        raw = self.kv("config")
        c = json.loads(raw) if raw else {}
        out = {**self.DEFAULT, **c}
        out["autorizacion"] = {**self.DEFAULT["autorizacion"], **(c.get("autorizacion") or {})}
        return out

    def save_config(self, data: dict, user: str):
        c = self.config()
        doms = []
        for d in data.get("dominios", c["dominios"]):
            d = str(d).strip().lower().lstrip("*.").rstrip(".")
            if d and re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", d):
                doms.append(d)
            elif d:
                raise ScopeError(f"Dominio no válido: {d}")
        nets = []
        for r in data.get("rangos", c["rangos"]):
            r = str(r).strip()
            if not r:
                continue
            try:
                n = ipaddress.ip_network(r, strict=False)
            except ValueError:
                raise ScopeError(f"Rango no válido: {r}")
            if n.version != 4:
                raise ScopeError(f"Solo rangos IPv4: {r}")
            if n.is_private or n.is_loopback or n.is_multicast:
                if not os.getenv("EXPOSURE_ALLOW_PRIVATE"):
                    raise ScopeError(f"{r} es un rango privado: este módulo mide la exposición a Internet")
            nets.append(str(n))
        total = sum(ipaddress.ip_network(n).num_addresses for n in nets)
        if total > MAX_SCAN_IPS:
            raise ScopeError(f"El alcance suma {total} direcciones; el máximo es {MAX_SCAN_IPS} (/16)")
        exc = []
        for r in data.get("excluidos", c["excluidos"]):
            r = str(r).strip()
            if r:
                try:
                    exc.append(str(ipaddress.ip_network(r, strict=False)))
                except ValueError:
                    raise ScopeError(f"Exclusión no válida: {r}")
        perfil = data.get("perfil", c["perfil"])
        if perfil not in PROFILES:
            raise ScopeError("Perfil no válido")
        c.update(dominios=sorted(set(doms)), rangos=nets, excluidos=exc, perfil=perfil,
                 velocidad=max(10, min(5000, int(data.get("velocidad", c["velocidad"])))),
                 concurrencia=max(10, min(2000, int(data.get("concurrencia", c["concurrencia"])))),
                 timeout_ms=max(300, min(10000, int(data.get("timeout_ms", c["timeout_ms"])))),
                 rutas_web=bool(data.get("rutas_web", c["rutas_web"])),
                 programado_dias=max(0, min(90, int(data.get("programado_dias", c["programado_dias"])))))
        a = data.get("autorizacion")
        if isinstance(a, dict):
            if a.get("hasta"):
                try:
                    datetime.date.fromisoformat(a["hasta"])
                except ValueError:
                    raise ScopeError("Fecha de vigencia no válida (AAAA-MM-DD)")
            c["autorizacion"] = {"por": str(a.get("por", ""))[:120], "referencia": str(a.get("referencia", ""))[:200],
                                 "hasta": str(a.get("hasta", ""))[:10], "registrado_por": user, "registrado_at": now_s()[:16]}
        self.kv("config", json.dumps(c, ensure_ascii=False))
        return c

    def scope_nets(self):
        return [ipaddress.ip_network(n) for n in self.config()["rangos"]]

    def _excluded(self):
        return [ipaddress.ip_network(n) for n in self.config()["excluidos"]]

    def in_scope_ip(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.scope_nets()) and not any(a in n for n in self._excluded())

    def in_scope_host(self, host):
        h = (host or "").lower().rstrip(".")
        return any(h == d or h.endswith("." + d) for d in self.config()["dominios"])

    def authorized(self):
        a = self.config()["autorizacion"]
        if not (a.get("por") and a.get("referencia") and a.get("hasta")):
            return False, "Falta registrar la autorización del escaneo activo (quién lo autoriza, referencia y vigencia)"
        if a["hasta"] < datetime.date.today().isoformat():
            return False, f"La autorización venció el {a['hasta']}"
        return True, ""

    # ------------------------------------------------------------ estado / trabajos
    def job(self, jid=None):
        r = self.q("SELECT * FROM jobs WHERE id = ?", (jid,), one=True) if jid else self.q("SELECT * FROM jobs ORDER BY id DESC LIMIT 1", one=True)
        if r:
            r["stats"] = json.loads(r["stats"] or "{}")
        return r

    def jobs(self, n=20):
        out = self.q("SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (n,))
        for r in out:
            r["stats"] = json.loads(r["stats"] or "{}")
        return out

    def _jset(self, jid, **kw):
        self.x(f"UPDATE jobs SET {', '.join(k + ' = ?' for k in kw)} WHERE id = ?", list(kw.values()) + [jid])

    def start(self, kind: str, user: str, inventory: dict, suggest=None):
        """kind: pasivo | completo. Devuelve el id del trabajo (se ejecuta en segundo plano)."""
        if self.running:
            raise ScopeError("Ya hay un escaneo en curso")
        c = self.config()
        if not c["dominios"] and not c["rangos"]:
            raise ScopeError("Define primero el alcance: dominios raíz y/o rangos de IP")
        if kind == "completo":
            ok, why = self.authorized()
            if not ok:
                raise ScopeError(why)
            if c["perfil"] == "pasivo":
                raise ScopeError("El perfil está en «pasivo»: elige un perfil de puertos para el escaneo activo")
        jid = self.x("INSERT INTO jobs(at, by, kind, status, phase) VALUES(?,?,?, 'running', 'preparando')", (now_s(), user, kind))
        self.cancel.clear()
        self.running = jid
        threading.Thread(target=self._run, args=(jid, kind, inventory, suggest), daemon=True, name="exposure").start()
        return jid

    def stop(self):
        self.cancel.set()

    # ------------------------------------------------------------ ejecución
    def _run(self, jid, kind, inv, suggest):
        t0 = now_s()
        st = {"subdominios": 0, "ips": 0, "puertos_abiertos": 0, "web": 0, "hallazgos_nuevos": 0}
        try:
            c = self.config()
            hosts = self._discover_hosts(jid, c, inv, st)
            if self.cancel.is_set():
                raise InterruptedError
            ips = self._resolve(jid, hosts)
            scan_ips = set()
            if kind == "completo":
                for n in self.scope_nets():
                    scan_ips |= {str(a) for a in (n.hosts() if n.num_addresses > 2 else n)}
                scan_ips = {i for i in scan_ips if self.in_scope_ip(i)}
            all_ips = sorted({i for v in ips.values() for i in v} | scan_ips | set(inv.get("ips", [])))
            st["ips"] = len(all_ips)
            self._internetdb(jid, all_ips)
            if self.cancel.is_set():
                raise InterruptedError
            if kind == "completo":
                open_ports = self._portscan(jid, sorted(scan_ips), PROFILES[c["perfil"]], c)
                st["puertos_abiertos"] = sum(len(v) for v in open_ports.values())
                self._banners(jid, open_ports)
            if self.cancel.is_set():
                raise InterruptedError
            targets = self._web_targets(hosts, ips, kind)
            st["web"] = len(targets)
            self._web(jid, targets, c, kind)
            self._classify(jid, inv, t0, st, suggest, scanned_ips=scan_ips, kind=kind)
            self._jset(jid, status="done", phase="terminado", finished=now_s(), stats=json.dumps(st),
                       msg=f"{st['subdominios']} subdominios · {st['ips']} IP · {st['puertos_abiertos']} puertos abiertos · "
                           f"{st['hallazgos_nuevos']} hallazgos nuevos")
        except InterruptedError:
            self._jset(jid, status="cancelled", phase="cancelado", finished=now_s(), stats=json.dumps(st), msg="Cancelado por un usuario")
        except Exception as exc:
            log.exception("Exposición: escaneo %s", jid)
            self._jset(jid, status="failed", phase="error", finished=now_s(), stats=json.dumps(st), msg=str(exc)[:300])
        finally:
            self.running = None

    def _asset(self, typ, value, source, ips=None, inv=False, in_scope=False, web=None, idb=None):
        key = f"{typ}:{value}"
        old = self.q("SELECT * FROM assets WHERE key = ?", (key,), one=True)
        srcs = sorted(set(json.loads(old["sources"]) if old else []) | {source})
        ipl = sorted(set(json.loads(old["ips"]) if old else []) | set(ips or []))
        if old:
            self.x("""UPDATE assets SET sources=?, ips=?, last_seen=?, inventoried=?, in_scope=?, web=COALESCE(?, web),
                      idb=COALESCE(?, idb) WHERE key=?""",
                   (json.dumps(srcs), json.dumps(ipl), now_s(), int(inv or old["inventoried"]), int(in_scope or old["in_scope"]),
                    json.dumps(web) if web is not None else None, json.dumps(idb) if idb is not None else None, key))
        else:
            self.x("""INSERT INTO assets(key, type, value, ips, sources, first_seen, last_seen, inventoried, in_scope, web, idb)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                   (key, typ, value, json.dumps(ipl), json.dumps(srcs), now_s(), now_s(), int(inv), int(in_scope),
                    json.dumps(web or {}), json.dumps(idb or {})))

    def _discover_hosts(self, jid, c, inv, st):
        self._jset(jid, phase="certificados (crt.sh)")
        hosts = {h: "inventario" for h in inv.get("hosts", [])}
        for d in c["dominios"]:
            if self.cancel.is_set():
                break
            hosts.setdefault(d, "alcance")
            try:
                r = requests.get(f"{CRTSH}/", params={"q": f"%.{d}", "output": "json"}, timeout=90, headers={"User-Agent": UA})
                r.raise_for_status()
                for row in r.json()[:20000]:
                    for n in str(row.get("name_value", "")).lower().split("\n"):
                        n = n.strip().lstrip("*.").rstrip(".")
                        if n and (n == d or n.endswith("." + d)) and re.fullmatch(r"[a-z0-9.-]+", n):
                            hosts.setdefault(n, "crt.sh")
            except Exception as exc:
                log.warning("crt.sh %s: %s", d, exc)
                self._jset(jid, msg=f"crt.sh no respondió para {d}: {str(exc)[:120]}")
        st["subdominios"] = sum(1 for v in hosts.values() if v == "crt.sh")
        return hosts

    def _resolve(self, jid, hosts):
        self._jset(jid, phase="DNS", done=0, total=len(hosts))
        out = {}

        def one(h):
            try:
                return h, sorted({a[4][0] for a in socket.getaddrinfo(h, None, socket.AF_INET)})
            except OSError:
                return h, []
        inv_hosts = {h for h, src in hosts.items() if src == "inventario"}
        with ThreadPoolExecutor(max_workers=40) as ex:
            for i, (h, ips) in enumerate(ex.map(one, list(hosts))):
                out[h] = ips
                self._asset("host", h, hosts[h], ips, inv=h in inv_hosts, in_scope=self.in_scope_host(h))
                if i % 50 == 0:
                    self._jset(jid, done=i)
                if self.cancel.is_set():
                    break
        return out

    def _internetdb(self, jid, ips):
        self._jset(jid, phase="Shodan InternetDB", done=0, total=len(ips))
        sess = requests.Session()

        def one(ip):
            try:
                r = sess.get(f"{INTERNETDB}/{ip}", timeout=15)
                return ip, (r.json() if r.status_code == 200 else None)
            except Exception:
                return ip, None
        with ThreadPoolExecutor(max_workers=8) as ex:
            for i, (ip, d) in enumerate(ex.map(one, ips)):
                if d:
                    self._asset("ip", ip, "internetdb", [ip], in_scope=self.in_scope_ip(ip),
                                idb={k: d.get(k) for k in ("ports", "cpes", "hostnames", "tags", "vulns")})
                    for p in d.get("ports") or []:
                        self._service(ip, p, "", "internetdb")
                if i % 25 == 0:
                    self._jset(jid, done=i)
                if self.cancel.is_set():
                    break

    def _service(self, ip, port, banner, source, tls=None, service=None):
        name = service or (RISKY.get(port, ("", "", ""))[0] or ("HTTP" if port in WEB_PORTS else ""))
        old = self.q("SELECT 1 FROM services WHERE ip = ? AND port = ?", (ip, port), one=True)
        if old:
            self.x("""UPDATE services SET last_seen=?, banner=CASE WHEN ? != '' THEN ? ELSE banner END, service=?,
                      tls=COALESCE(?, tls), source=CASE WHEN source LIKE '%' || ? || '%' THEN source ELSE source || ',' || ? END
                      WHERE ip=? AND port=?""",
                   (now_s(), banner, banner[:300], name, json.dumps(tls) if tls else None, source, source, ip, port))
        else:
            self.x("INSERT INTO services(ip, port, service, banner, tls, source, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?)",
                   (ip, port, name, banner[:300], json.dumps(tls or {}), source, now_s(), now_s()))

    def _portscan(self, jid, ips, ports, c):
        """Escaneo TCP «connect» (no requiere privilegios). Limitado en velocidad y concurrencia."""
        ips = [i for i in ips if self.in_scope_ip(i)]  # doble comprobación del alcance
        total = len(ips) * len(ports)
        self._jset(jid, phase=f"puertos ({len(ports)} por IP)", done=0, total=total)
        found = {}
        timeout = c["timeout_ms"] / 1000
        rate, conc = c["velocidad"], c["concurrencia"]

        async def main():
            sem = asyncio.Semaphore(conc)
            done = 0
            interval = 1 / rate
            nxt = time.monotonic()

            async def probe(ip, port):
                nonlocal done
                async with sem:
                    try:
                        fut = asyncio.open_connection(ip, port)
                        r, w = await asyncio.wait_for(fut, timeout)
                        w.close()
                        found.setdefault(ip, []).append(port)
                    except Exception:
                        pass
                    finally:
                        done += 1
            tasks = []
            order = [(ip, p) for p in ports for ip in ips]  # se alternan IP para no concentrar en un solo servidor
            for ip, p in order:
                if self.cancel.is_set():
                    break
                now = time.monotonic()
                if now < nxt:
                    await asyncio.sleep(nxt - now)
                nxt = max(nxt + interval, time.monotonic() - 1)
                tasks.append(asyncio.create_task(probe(ip, p)))
                if len(tasks) >= 2000:
                    await asyncio.gather(*tasks)
                    tasks = []
                    self._jset(jid, done=done)
            if tasks:
                await asyncio.gather(*tasks)
            self._jset(jid, done=done)
        asyncio.run(main())
        for ip, ps in found.items():
            for p in ps:
                self._service(ip, p, "", "escaneo")
            self._asset("ip", ip, "escaneo", [ip], in_scope=True)
        return found

    def _banners(self, jid, open_ports):
        items = [(ip, p) for ip, ps in open_ports.items() for p in ps]
        self._jset(jid, phase="banners y TLS", done=0, total=len(items))

        def one(item):
            ip, port = item
            banner, tls = "", None
            try:
                if port in TLS_PORTS or port in (443, 8443):
                    tls = _tls(ip, port)
                if port not in WEB_PORTS:
                    with socket.create_connection((ip, port), timeout=3) as s:
                        s.settimeout(2)
                        try:
                            banner = s.recv(200).decode("latin-1", "replace").strip()
                        except OSError:
                            banner = ""
            except Exception:
                pass
            return ip, port, re.sub(r"[\x00-\x08\x0b-\x1f]", " ", banner)[:200], tls
        with ThreadPoolExecutor(max_workers=30) as ex:
            for i, (ip, port, b, tls) in enumerate(ex.map(one, items)):
                self._service(ip, port, b, "escaneo", tls=tls)
                if i % 25 == 0:
                    self._jset(jid, done=i)

    def _web_targets(self, hosts, ips, kind):
        """URL a revisar: dominios del alcance que resuelven y, en escaneo activo, IP:puerto web abiertos."""
        t = set()
        for h, v in ips.items():
            if v and (self.in_scope_host(h) or hosts.get(h) == "inventario"):
                t.add(f"https://{h}/")
                t.add(f"http://{h}/")
        if kind == "completo":
            for s in self.q("SELECT ip, port FROM services"):
                if s["port"] in WEB_PORTS and self.in_scope_ip(s["ip"]):
                    sch = "https" if s["port"] in TLS_PORTS or s["port"] == 443 else "http"
                    t.add(f"{sch}://{s['ip']}:{s['port']}/")
        return sorted(t)

    def _web(self, jid, targets, c, kind):
        self._jset(jid, phase="servicios web", done=0, total=len(targets))
        sess = requests.Session()
        sess.headers["User-Agent"] = UA

        def one(url):
            u = urlparse(url)
            host = u.hostname or ""
            out = {"url": url, "ok": False}
            try:
                r = sess.get(url, timeout=12, allow_redirects=True, verify=False)
            except Exception as exc:
                out["error"] = type(exc).__name__
                return out
            t = r.text[:200000] if "text" in r.headers.get("content-type", "") or not r.headers.get("content-type") else ""
            m = re.search(r"<title[^>]*>(.*?)</title>", t, re.I | re.S)
            gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', t, re.I)
            hdr = {k.lower(): v for k, v in r.headers.items()}
            out.update(ok=True, status=r.status_code, final=r.url, title=re.sub(r"\s+", " ", m.group(1)).strip()[:150] if m else "",
                       server=hdr.get("server", "")[:80], powered=hdr.get("x-powered-by", "")[:80],
                       generator=gen.group(1)[:80] if gen else "", hsts="strict-transport-security" in hdr,
                       login=bool(re.search(r'type=["\']?password', t, re.I)), listing="<title>Index of /" in t, hits=[])
            # rutas sensibles (solo destinos del alcance); se descarta el «soft 404» comparando con una ruta aleatoria
            scoped = self.in_scope_host(host) or self.in_scope_ip(host)
            if c["rutas_web"] and scoped and r.status_code < 500 and kind == "completo":  # sondeo activo: solo con autorización
                base = f"{u.scheme}://{u.netloc}"
                rnd = "/" + "".join(random.choice(string.ascii_lowercase) for _ in range(12)) + ".txt"
                try:
                    soft = sess.get(base + rnd, timeout=8, verify=False, allow_redirects=False)
                    soft_len = len(soft.content) if soft.status_code == 200 else -1
                except Exception:
                    soft_len = -1
                for path, check, sev, title in SENSITIVE:
                    if self.cancel.is_set():
                        break
                    try:
                        rr = sess.get(base + path, timeout=8, verify=False, allow_redirects=False)
                    except Exception:
                        continue
                    if rr.status_code != 200 or (soft_len >= 0 and abs(len(rr.content) - soft_len) < 32):
                        continue
                    tt = rr.text[:100000] if rr.content[:1] != b"\x00" else ""
                    try:
                        if check(rr, tt):
                            out["hits"].append({"path": path, "sev": sev, "title": title, "len": len(rr.content)})
                    except Exception:
                        continue
            return out
        res = []
        requests.packages.urllib3.disable_warnings()
        with ThreadPoolExecutor(max_workers=16) as ex:
            for i, o in enumerate(ex.map(one, targets)):
                res.append(o)
                if o.get("ok"):
                    h = urlparse(o["url"]).hostname
                    typ = "ip" if re.fullmatch(r"[\d.]+", h or "") else "host"
                    old = self.q("SELECT web FROM assets WHERE key = ?", (f"{typ}:{h}",), one=True)
                    web = json.loads(old["web"]) if old else {}
                    web[o["url"]] = {k: o.get(k) for k in ("status", "final", "title", "server", "powered", "generator", "hsts",
                                                          "login", "listing", "hits")}
                    self._asset(typ, h, "web", None, in_scope=typ == "host" and self.in_scope_host(h) or self.in_scope_ip(h), web=web)
                if i % 10 == 0:
                    self._jset(jid, done=i)
                if self.cancel.is_set():
                    break
        return res

    # ------------------------------------------------------------ hallazgos
    def _finding(self, jid, asset, sev, cat, title, detail, evidence=""):
        key = hashlib.sha1(f"{asset}|{cat}|{title}".encode()).hexdigest()[:20]
        old = self.q("SELECT status FROM findings WHERE key = ?", (key,), one=True)
        if old:
            reopen = old["status"] == "fixed"
            self.x("""UPDATE findings SET last_seen=?, severity=?, detail=?, evidence=?, job=?,
                      status=CASE WHEN status='fixed' THEN 'open' ELSE status END WHERE key=?""",
                   (now_s(), sev, detail[:600], evidence[:600], jid, key))
            return reopen
        self.x("""INSERT INTO findings(key, asset, severity, category, title, detail, evidence, first_seen, last_seen, job)
                  VALUES(?,?,?,?,?,?,?,?,?,?)""", (key, asset, sev, cat, title[:200], detail[:600], evidence[:600], now_s(), now_s(), jid))
        return True

    def _classify(self, jid, inv, t0, st, suggest, scanned_ips=(), kind="pasivo"):
        self._jset(jid, phase="hallazgos")
        inv_hosts, inv_ips = set(inv.get("hosts", [])), set(inv.get("ips", []))
        for v in inv_hosts | inv_ips:  # lo que está en Portales (o marcado «conocido») no es Shadow IT
            self.x("UPDATE assets SET inventoried = 1 WHERE value = ?", (v,))
        new = []
        assets = self.q("SELECT * FROM assets WHERE last_seen >= ?", (t0,))
        for a in assets:
            ips, web, idb = json.loads(a["ips"]), json.loads(a["web"] or "{}"), json.loads(a["idb"] or "{}")
            val = a["value"]
            # --- Shadow IT
            if a["type"] == "host" and a["in_scope"] and not a["inventoried"] and val not in inv_hosts and ips and a["status"] != "ignorado":
                live = [w for w in web.values() if w.get("status")]
                sev = "high" if any(w.get("login") or w.get("hits") for w in live) else "medium" if live else "low"
                if self._finding(jid, f"host:{val}", sev, "shadow", "Subdominio no inventariado",
                                 f"{val} resuelve a {', '.join(ips[:3])} y no está en Portales"
                                 + (f" · responde: «{live[0].get('title') or live[0].get('status')}»" if live else ""),
                                 "fuentes: " + ", ".join(json.loads(a["sources"]))):
                    new.append((sev, f"Subdominio no inventariado: {val}", f"host:{val}"))
            if a["type"] == "ip" and a["in_scope"] and val not in inv_ips and a["status"] != "ignorado":
                svc = self.q("SELECT port FROM services WHERE ip = ?", (val,))
                if svc and not any(val in json.loads(h["ips"]) for h in self.q(
                        "SELECT ips FROM assets WHERE type='host' AND inventoried=1 AND ips LIKE ?", (f"%{val}%",))):
                    if self._finding(jid, f"ip:{val}", "medium", "shadow", "Servidor no inventariado",
                                     f"{val} tiene {len(svc)} servicio(s) abiertos ({', '.join(str(s['port']) for s in svc[:8])}) "
                                     "y ningún portal inventariado apunta a esa IP", ""):
                        new.append(("medium", f"Servidor no inventariado: {val}", f"ip:{val}"))
            # --- CVE conocidos (Shodan InternetDB)
            if idb.get("vulns"):
                v = idb["vulns"]
                sev = "critical" if len(v) >= 10 else "high"
                if self._finding(jid, f"ip:{val}", sev, "cve", "Vulnerabilidades conocidas (Shodan)",
                                 f"{len(v)} CVE reportados para {val}: {', '.join(sorted(v)[:12])}",
                                 "CPE: " + ", ".join((idb.get("cpes") or [])[:6])):
                    new.append((sev, f"{len(v)} CVE en {val}", f"ip:{val}"))
            # --- web
            for url, w in web.items():
                for h in w.get("hits") or []:
                    if self._finding(jid, url.rstrip("/") + h["path"], h["sev"], "web", h["title"],
                                     f"{url.rstrip('/')}{h['path']} responde 200 ({h['len']} bytes)", ""):
                        new.append((h["sev"], f"{h['title']}: {url.rstrip('/')}{h['path']}", url))
                if w.get("listing"):
                    self._finding(jid, url, "medium", "web", "Listado de directorio activo", f"{url} muestra «Index of /»")
                if url.startswith("https") and w.get("status") and not w.get("hsts"):
                    self._finding(jid, url, "low", "web", "Falta la cabecera HSTS", f"{url} no envía Strict-Transport-Security")
                ver = [x for x in (w.get("server"), w.get("powered"), w.get("generator")) if x and re.search(r"\d", x)]
                if ver:
                    self._finding(jid, url, "low", "web", "Versión de software visible", f"{url}: {' · '.join(ver)}")
                if url.startswith("http://") and w.get("status") == 200 and w.get("login") and not str(w.get("final", "")).startswith("https"):
                    self._finding(jid, url, "high", "web", "Formulario de acceso sin HTTPS", f"{url} pide contraseña por HTTP en claro")
        # --- puertos de riesgo y TLS
        for s in self.q("SELECT * FROM services WHERE last_seen >= ?", (t0,)):
            if not self.in_scope_ip(s["ip"]):
                continue
            if s["port"] in RISKY:
                name, sev, why = RISKY[s["port"]]
                if self._finding(jid, f"ip:{s['ip']}", sev, "puerto", f"{name} expuesto a Internet (puerto {s['port']})",
                                 f"{s['ip']}:{s['port']} — {why}", s["banner"] or ""):
                    new.append((sev, f"{name} expuesto: {s['ip']}:{s['port']}", f"ip:{s['ip']}"))
            t = json.loads(s["tls"] or "{}")
            if t.get("expired"):
                self._finding(jid, f"ip:{s['ip']}", "high", "tls", f"Certificado caducado (puerto {s['port']})", f"Caducó el {t.get('expiry')}")
            elif t.get("self_signed"):
                self._finding(jid, f"ip:{s['ip']}", "medium", "tls", f"Certificado autofirmado (puerto {s['port']})", t.get("issuer", ""))
            elif t.get("days") is not None and t["days"] <= 30:
                self._finding(jid, f"ip:{s['ip']}", "medium", "tls", f"Certificado caduca pronto (puerto {s['port']})", f"{t['days']} días")
        # --- lo que no apareció en este escaneo, en activos revisados de nuevo, se da por corregido
        if kind == "completo":
            for ip in scanned_ips:
                self.x("""UPDATE findings SET status='fixed' WHERE status='open' AND category IN ('puerto','tls') AND asset=? AND last_seen < ?""",
                       (f"ip:{ip}", t0))
        self.x("UPDATE findings SET status='fixed' WHERE status='open' AND category='web' AND last_seen < ? AND job IS NOT NULL "
               "AND asset IN (SELECT DISTINCT asset FROM findings WHERE job = ?)", (t0, jid))
        st["hallazgos_nuevos"] = len(new)
        if suggest:
            for sev, title, asset in new:
                if sev == "critical":
                    suggest({"title": f"Exposición crítica: {title}"[:200], "severity": "Critical",
                             "detected_by": "Exposición / Shadow IT", "assets": asset.split(":", 1)[-1],
                             "summary": f"El escaneo de exposición encontró: {title}. Revisa el detalle en Exposición → Hallazgos."},
                            "exposure-" + hashlib.sha1(title.encode()).hexdigest()[:16])

    # ------------------------------------------------------------ consultas
    def summary(self):
        f = self.q("SELECT severity, COUNT(*) n FROM findings WHERE status = 'open' GROUP BY 1")
        sev = {r["severity"]: r["n"] for r in f}
        shadow = self.q("SELECT COUNT(*) n FROM findings WHERE status='open' AND category='shadow'", one=True)["n"]
        cats = self.q("SELECT category, COUNT(*) n FROM findings WHERE status='open' GROUP BY 1 ORDER BY 2 DESC")
        ports = self.q("SELECT port, service, COUNT(*) n FROM services GROUP BY port ORDER BY n DESC LIMIT 12")
        cves = self.q("SELECT COUNT(*) n FROM findings WHERE status='open' AND category='cve'", one=True)["n"]
        return {"hallazgos": sev, "abiertos": sum(sev.values()), "shadow": shadow, "categorias": [[r["category"], r["n"]] for r in cats],
                "puertos": [[f"{r['port']} {r['service'] or ''}".strip(), r["n"]] for r in ports],
                "activos": self.q("SELECT COUNT(*) n FROM assets", one=True)["n"],
                "servicios": self.q("SELECT COUNT(*) n FROM services", one=True)["n"], "con_cve": cves,
                "ultimo": self.job(), "en_curso": self.running}

    def findings(self, status="open", severity="", category="", q="", limit=1000):
        sql, a = "SELECT * FROM findings WHERE 1=1", []
        if status:
            sql += " AND status = ?"; a.append(status)
        if severity:
            sql += " AND severity = ?"; a.append(severity)
        if category:
            sql += " AND category = ?"; a.append(category)
        if q:
            sql += " AND (asset LIKE ? OR title LIKE ? OR detail LIKE ?)"; a += [f"%{q}%"] * 3
        sql += (" ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,"
                " last_seen DESC LIMIT ?")
        return self.q(sql, a + [limit])

    def assets(self, only="", q="", limit=2000):
        sql, a = "SELECT * FROM assets WHERE 1=1", []
        if only == "shadow":
            sql += " AND inventoried = 0 AND in_scope = 1 AND status != 'ignorado' AND ips != '[]'"
        elif only == "inventario":
            sql += " AND inventoried = 1"
        if q:
            sql += " AND (value LIKE ? OR ips LIKE ? OR web LIKE ?)"; a += [f"%{q}%"] * 3
        rows = self.q(sql + " ORDER BY inventoried, type, value LIMIT ?", a + [limit])
        fc = {r["asset"]: r["n"] for r in self.q("SELECT asset, COUNT(*) n FROM findings WHERE status='open' GROUP BY asset")}
        for r in rows:
            for k in ("ips", "sources", "web", "idb"):
                r[k] = json.loads(r[k] or ("[]" if k in ("ips", "sources") else "{}"))
            r["hallazgos"] = fc.get(r["key"], 0) + sum(n for k, n in fc.items() if k.startswith(f"http") and r["value"] in k)
            r["servicios"] = [s["port"] for s in self.q("SELECT port FROM services WHERE ip IN (%s)" % ",".join("?" * len(r["ips"])), r["ips"])] if r["ips"] else []
        return rows

    def services(self, q="", limit=3000):
        sql, a = "SELECT * FROM services", []
        if q:
            sql += " WHERE ip LIKE ? OR banner LIKE ? OR service LIKE ? OR CAST(port AS TEXT) = ?"; a += [f"%{q}%"] * 3 + [q]
        rows = self.q(sql + " ORDER BY ip, port LIMIT ?", a + [limit])
        for r in rows:
            r["tls"] = json.loads(r["tls"] or "{}")
            r["riesgo"] = RISKY.get(r["port"], ("", "", ""))[1]
            r["en_alcance"] = self.in_scope_ip(r["ip"])
        return rows

    def set_finding(self, key, status, user, note=""):
        if status not in ("open", "accepted", "fixed"):
            raise ScopeError("Estado no válido")
        self.x("UPDATE findings SET status = ?, decided_by = ?, note = ? WHERE key = ?", (status, user, note[:300], key))

    def set_asset(self, key, status, note=""):
        if status not in ("nuevo", "conocido", "ignorado"):
            raise ScopeError("Estado no válido")
        self.x("UPDATE assets SET status = ?, note = ? WHERE key = ?", (status, note[:300], key))
        if status in ("conocido", "ignorado"):
            self.x("UPDATE findings SET status='accepted', note=? WHERE asset=? AND category='shadow' AND status='open'",
                   (f"Activo marcado como {status}", key))


def _tls(host, port):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            der = s.getpeercert(binary_form=True)
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        exp = c.not_valid_after_utc.date()
        iss = c.issuer.rfc4514_string()
        days = (exp - datetime.date.today()).days
        return {"expiry": exp.isoformat(), "days": days, "expired": days < 0, "issuer": iss[:120],
                "self_signed": c.issuer == c.subject, "subject": c.subject.rfc4514_string()[:120]}
    except Exception:
        return {"fp": hashlib.sha256(der).hexdigest()}
