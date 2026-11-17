"""Entrada de datos al portal: IoC (detección de tipo), importación de escáneres de vulnerabilidades
y comprobación de portales web monitoreados."""
import csv
import datetime
import hashlib
import io
import ipaddress
import re
import socket
import ssl
import time
from urllib.parse import urlparse

import requests

# ----------------------------------------------------------------- IoC
_HASH = {32: "md5", 40: "sha1", 64: "sha256"}
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_EMAIL = re.compile(r"^[\w.+-]+@([\w-]+\.)+[a-z]{2,63}$", re.I)
_TOKEN = re.compile(r"[^\s,;\"'<>|]+")
# Dominios que nunca se deben cargar como IoC por error (se pueden ampliar)
# Extensiones de archivo que parecen dominios (hola.txt, setup.exe) y no lo son
FILE_EXT = {"txt", "exe", "dll", "php", "html", "htm", "js", "png", "jpg", "jpeg", "gif", "pdf", "doc", "docx", "xls", "xlsx",
            "log", "csv", "json", "xml", "py", "bat", "ps1", "ini", "cfg", "tmp", "msi", "vbs", "lnk", "iso", "rar", "7z"}
SAFE = {"acme.example", "gob.do", "google.com", "microsoft.com", "windowsupdate.com", "wazuh.com"}


def refang(t: str) -> str:
    return (t.strip().strip("()[]{}").replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
            .replace("[:]", ":").replace("hxxp", "http").replace("hXXp", "http").replace("[@]", "@"))


def classify(raw: str):
    v = refang(raw).rstrip(".,")
    if not v:
        return None
    if re.fullmatch(r"[a-fA-F0-9]+", v) and len(v) in _HASH:
        return {"value": v.lower(), "type": _HASH[len(v)]}
    if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I):
        return {"value": v, "type": "url"}
    try:
        ip = ipaddress.ip_address(v)
        return {"value": str(ip), "type": "ip-dst", "private": ip.is_private or ip.is_loopback}
    except ValueError:
        pass
    if "/" in v:
        try:
            net = ipaddress.ip_network(v, strict=False)
            return {"value": str(net), "type": "ip-dst", "private": net.is_private}
        except ValueError:
            pass
    if _EMAIL.match(v):
        return {"value": v.lower(), "type": "email-src"}
    if _DOMAIN.match(v) and not re.fullmatch(r"[\d.]+", v) and v.rsplit(".", 1)[-1].lower() not in FILE_EXT:
        d = v.lower()
        return {"value": d, "type": "domain", "safe": any(d == s or d.endswith("." + s) for s in SAFE)}
    return None


def parse_iocs(text: str) -> dict:
    """Extrae IoC de texto libre o CSV. Devuelve válidos, ignorados (privados / lista segura) y no reconocidos."""
    ok, skipped, unknown, seen = [], [], [], set()
    for tok in _TOKEN.findall(text or ""):
        c = classify(tok)
        if not c:
            if len(tok) > 5 and any(ch in tok for ch in ".:/@"):
                unknown.append(tok)
            continue
        key = (c["value"], c["type"])
        if key in seen:
            continue
        seen.add(key)
        if c.pop("private", False):
            skipped.append({**c, "motivo": "IP privada"})
        elif c.pop("safe", False):
            skipped.append({**c, "motivo": "dominio en lista segura"})
        else:
            ok.append(c)
    return {"iocs": ok, "ignorados": skipped, "no_reconocidos": unknown[:50]}


# ----------------------------------------------------------------- escáneres
SEV_MAP = {"critical": "Critical", "crítica": "Critical", "critica": "Critical", "urgent": "Critical", "5": "Critical",
           "high": "High", "alta": "High", "serious": "High", "4": "High",
           "medium": "Medium", "media": "Medium", "moderate": "Medium", "3": "Medium",
           "low": "Low", "baja": "Low", "minor": "Low", "2": "Low", "1": "Low"}
COLS = {  # nombre normalizado -> posibles cabeceras (Nessus, OpenVAS/Greenbone, Qualys, genérico)
    "cve": ["cve", "cves", "cve id", "vulnerability.id"],
    "title": ["name", "nvt name", "title", "vulnerability", "plugin name", "nombre", "título", "titulo"],
    "severity": ["risk", "severity", "risk factor", "threat", "severidad", "riesgo"],
    "cvss": ["cvss v3.0 base score", "cvss3 base score", "cvss v3 base score", "cvss", "cvss base score",
             "cvss v2.0 base score", "score"],
    "asset": ["host", "ip", "hostname", "asset", "dns name", "activo", "equipo", "target"],
    "port": ["port", "puerto"],
    "solution": ["solution", "solución", "solucion", "remediation", "fix"],
    "plugin": ["plugin id", "nvt oid", "qid", "id"],
    "package": ["package", "paquete", "product"],
}


def _sev_from_cvss(x):
    return "Critical" if x >= 9 else "High" if x >= 7 else "Medium" if x >= 4 else "Low"


def parse_scan(text: str, scanner: str = "csv") -> dict:
    """Lee un CSV de Nessus, OpenVAS/Greenbone, Qualys o uno propio. Omite hallazgos informativos."""
    text = text.lstrip("﻿")
    try:
        dialect = csv.Sniffer().sniff(text[:4000], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    if len(rows) < 2:
        return {"items": [], "omitidos": 0, "error": "El archivo no tiene filas de datos"}
    head = [h.strip().lower() for h in rows[0]]
    idx = {k: next((head.index(c) for c in cands if c in head), None) for k, cands in COLS.items()}
    if idx["title"] is None and idx["cve"] is None:
        return {"items": [], "omitidos": 0, "error": "No encuentro columnas de nombre o CVE. Cabeceras: " + ", ".join(rows[0][:12])}
    items, skipped = [], 0
    for r in rows[1:]:
        g = lambda k: (r[idx[k]].strip() if idx[k] is not None and idx[k] < len(r) else "")
        sev_raw, cvss = g("severity").lower(), None
        try:
            cvss = float(g("cvss").replace(",", ".")) if g("cvss") else None
        except ValueError:
            pass
        sev = SEV_MAP.get(sev_raw) or (_sev_from_cvss(cvss) if cvss is not None else None)
        if sev_raw in ("none", "log", "info", "informational", "0", "") and not (cvss and cvss > 0):
            skipped += 1
            continue
        if not sev or (cvss is not None and cvss == 0):
            skipped += 1
            continue
        cves = re.findall(r"CVE-\d{4}-\d{4,}", g("cve"), re.I)
        title, asset, port = g("title") or (cves[0] if cves else ""), g("asset"), g("port")
        if not title:
            skipped += 1
            continue
        key = "|".join([scanner, asset, g("plugin") or title, port])
        items.append({"ext_key": hashlib.sha1(key.encode()).hexdigest(), "cve": ", ".join(dict.fromkeys(c.upper() for c in cves)),
                      "title": title[:300], "severity": sev, "cvss": cvss, "asset": asset, "port": port,
                      "package": g("package"), "solution": g("solution")[:1500]})
    return {"items": items, "omitidos": skipped, "columnas": {k: rows[0][v] for k, v in idx.items() if v is not None}}


# ----------------------------------------------------------------- portales
UA = "Mozilla/5.0 (SOC-ACME monitor; +portal SOC)"


def _ssl_expiry(host: str, port: int):
    return _tls_info(host, port)["expiry"]


def _tls_info(host: str, port: int) -> dict:
    """Caducidad, emisor y huella del certificado. Si no valida, se vuelve a leer sin validar para saber si es autofirmado."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                c, der = s.getpeercert(), s.getpeercert(binary_form=True)
        valid = True
    except ssl.SSLCertVerificationError:
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
        return {"expiry": None, "issuer": "", "self_signed": True, "valid": False, "fp": hashlib.sha256(der).hexdigest()}
    rdn = lambda seq: {k: v for t in seq for k, v in t}
    iss, sub = rdn(c.get("issuer", ())), rdn(c.get("subject", ()))
    exp = datetime.datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z").date().isoformat()
    return {"expiry": exp, "issuer": iss.get("organizationName") or iss.get("commonName", ""),
            "self_signed": iss == sub, "valid": valid, "fp": hashlib.sha256(der).hexdigest()}


def _dns_a(host: str) -> list:
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None, socket.AF_INET)})
    except OSError:
        return []


def _integrity(urls: list) -> dict:
    """Huella SHA-256 de los scripts y hojas de estilo del propio sitio (clave = ruta, sin query)."""
    out = {}
    for u in urls[:15]:
        try:
            r = requests.get(u, timeout=8, headers={"User-Agent": UA}, stream=True)
            if r.status_code != 200:
                continue
            body = r.raw.read(1_500_000, decode_content=True)
            out[urlparse(u).path or u] = hashlib.sha256(body).hexdigest()
        except Exception:
            continue
    return out


def _decode(r, ctype: str) -> str:
    """Texto de la respuesta con el charset correcto: cabecera HTTP, luego <meta charset>, luego UTF-8."""
    raw = r.content[:3_000_000]
    enc = r.encoding if "charset" in ctype.lower() else None
    if not enc:
        m = re.search(rb"<meta[^>]+charset\s*=\s*[\"']?([\w-]+)", raw[:4096], re.I)
        enc = m.group(1).decode() if m else "utf-8"
    try:
        return raw.decode(enc, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def check_site(site: dict) -> tuple:
    """Devuelve (campos a guardar, ok, contenido cambiado)."""
    url = site["url"]
    res = {"last_code": None, "last_ms": None, "last_error": ""}
    ok, changed = False, False
    t0 = time.monotonic()
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": UA}, allow_redirects=True)
        res["last_ms"] = round((time.monotonic() - t0) * 1000)
        res["last_code"] = r.status_code
        exp = site.get("expect_code")
        ok = (r.status_code == exp) if exp else r.status_code < 400
        if not ok:
            res["last_error"] = f"HTTP {r.status_code}" + (f" (se esperaba {exp})" if exp else "")
        ctype = r.headers.get("content-type", "")
        if r.status_code < 400 and ("html" in ctype or not ctype):
            import deface  # instantánea para la detección de desfiguración (aunque falte la palabra clave)
            try:
                snap = deface.snapshot(_decode(r, ctype), r.url)
                hdr = {k.lower(): v for k, v in r.headers.items()}
                snap["headers"] = {"security": sorted(h for h in deface.SEC_HEADERS if h in hdr),
                                   "server": hdr.get("server", "")[:80], "powered_by": hdr.get("x-powered-by", "")[:80]}
                snap["redirects"] = [urlparse(h.headers.get("location", "") or h.url).hostname or "" for h in r.history][:5]
                snap["dns"] = _dns_a(urlparse(url).hostname or "")
                if site.get("_integrity"):
                    snap["assets"] = _integrity(snap["local_res"])
                res["_snap"] = snap
            except Exception:
                pass
        kw = (site.get("keyword") or "").strip()
        if ok and kw and kw.lower() not in r.text.lower():
            ok, res["last_error"] = False, f"No aparece el texto «{kw}» (posible desfiguración o error)"
        if site.get("watch_content"):
            # se ignoran números y espacios para reducir falsos positivos (fechas, contadores, tokens)
            norm = re.sub(r"[\d\s]+", "", re.sub(r"<script.*?</script>|<!--.*?-->", "", r.text, flags=re.S | re.I))
            h = hashlib.sha256(norm.encode("utf-8", "ignore")).hexdigest()
            if site.get("content_hash") and site["content_hash"] != h:
                changed = True
                res["content_changed"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            res["content_hash"] = h
    except requests.exceptions.SSLError as e:
        res["last_error"] = "Error de certificado SSL: " + str(e)[:160]
    except requests.exceptions.Timeout:
        res["last_error"] = "Tiempo de espera agotado (20 s)"
    except requests.exceptions.ConnectionError as e:
        res["last_error"] = "No conecta: " + (str(e.args[0])[-160:] if e.args else "error de conexión")
    except Exception as e:
        res["last_error"] = str(e)[:200]
    u = urlparse(url)
    if u.scheme == "https":
        try:
            t = _tls_info(u.hostname, u.port or 443)
            res["ssl_expiry"], res["ssl_error"] = t["expiry"], "" if t["valid"] else "certificado no válido (autofirmado o de otro dominio)"
            if "_snap" in res:
                res["_snap"]["tls"] = {k: t[k] for k in ("issuer", "self_signed", "fp")}
        except Exception as e:
            res["ssl_error"] = str(e)[:160]
    return res, ok, changed


# ----------------------------------------------------------------- inventario de portales (Excel / CSV)
WAF_MAP = [("no pasan", ""), ("pasan por waf", "waf"), ("protegido", "waf"), ("bypass", "bypass"),
           ("backend directo", "directo"), ("directo", "directo"), ("extern", "externo"), ("sin vip", "externo")]
SITE_COLS = {"name": ("portal", "dominio", "domain", "sitio", "nombre", "name", "url", "host"),
             "plan": ("plan",), "estado": ("estado", "status", "waf"), "public_ip": ("ip pública", "ip publica", "ips públicas", "public ip"),
             "backend_ip": ("ip privada (backend)", "ip privada", "backend"), "server": ("servidor", "server"),
             "vs": ("vs fortiweb", "vs correcto", "vs"), "grp": ("grupo", "institución", "institucion", "dependencia")}


def _waf_of(*texts):
    t = " ".join(str(x or "").lower() for x in texts)
    for k, v in WAF_MAP:
        if k in t:
            return v  # «no pasan» devuelve "" (lo decide la columna Estado de cada fila)
    return ""


def parse_sites_file(data: bytes, filename: str) -> list:
    """Devuelve [{name, url, waf, plan, public_ip, backend_ip, server, vs, grp}] sin duplicados por dominio."""
    sheets = []
    if data[:2] == b"PK" or filename.lower().endswith((".xlsx", ".xlsm")):
        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        for ws in wb.worksheets:
            sheets.append((ws.title, [list(r) for r in ws.iter_rows(values_only=True)]))
    else:
        text = data.decode("utf-8-sig", errors="ignore")
        try:
            dialect = csv.Sniffer().sniff(text[:4000], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        sheets.append(("csv", list(csv.reader(io.StringIO(text), dialect))))
    out = {}
    for title, rows in sheets:
        hi = next((i for i, r in enumerate(rows[:15]) if any(str(c or "").strip().lower() in SITE_COLS["name"] for c in r)), None)
        if hi is None:
            continue
        head = [str(c or "").strip().lower() for c in rows[hi]]
        col = {k: next((head.index(c) for c in cands if c in head), None) for k, cands in SITE_COLS.items()}
        sheet_waf = _waf_of(title)
        for r in rows[hi + 1:]:
            g = lambda k: (str(r[col[k]]).strip() if col[k] is not None and col[k] < len(r) and r[col[k]] is not None else "")
            raw = g("name").strip().rstrip("/")
            if not raw or " " in raw or "." not in raw:
                continue
            url = raw if re.match(r"^https?://", raw, re.I) else f"https://{raw.lower()}/"
            host = (urlparse(url).hostname or "").lower().removeprefix("www.")
            if not host:
                continue
            key = site_key(url)
            item = {"name": key, "url": url, "waf": _waf_of(g("estado")) or sheet_waf, "plan": g("plan"),
                    "public_ip": g("public_ip"), "backend_ip": g("backend_ip"), "server": g("server"), "vs": g("vs"),
                    "grp": g("grp")}
            if key in out:  # aparece en otra hoja (p. ej. «Duplicados»): solo completa lo que falta
                o = out[key]
                for k, v in item.items():
                    if v and not o.get(k):
                        o[k] = v
                if item["public_ip"] and item["public_ip"] not in o["public_ip"]:
                    o["public_ip"] = f"{o['public_ip']},{item['public_ip']}".strip(",")
            else:
                out[key] = item
    return list(out.values())


def site_key(url: str) -> str:
    """Identidad de un portal: dominio (sin www) + ruta, sin barra final."""
    u = urlparse(url.strip())
    return ((u.hostname or "").lower().removeprefix("www.") + (u.path or "").rstrip("/")) or url
