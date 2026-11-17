"""Detección de desfiguración (defacement) e inyecciones en portales web.

Para cada página se toma una «instantánea»: título, texto visible (sin scripts, estilos ni comentarios) y dominios
externos de los que carga código o a los que redirige. Se compara con la **línea base aprobada**:

- Firmas de atacante nuevas (p. ej. «hacked by», «defaced by», «hackeado por») o spam SEO de casinos/apuestas
  → DEFACEMENT / SOSPECHA.
- % de texto visible que cambió (shingles de 4 palabras, índice de Jaccard) ≥ umbral → CAMBIO; ≥ 80 % → SOSPECHA.
- La página se quedó casi vacía (< 25 % del texto de la base) → SOSPECHA.
- Título distinto + cambio grande → SOSPECHA.
- Scripts, iframes, formularios o redirecciones hacia dominios nuevos → SOSPECHA (inyección de código).

Un cambio legítimo se acepta con «Aceptar como versión buena», que convierte la instantánea en la nueva base.
"""
import difflib
import hashlib
import html as htmllib
import ipaddress
import re
from urllib.parse import urljoin, urlparse

LEVELS = ["ok", "cambio", "sospecha", "defacement"]
MAX_TEXT = 30000

SIGNATURES = [  # (regex, descripción, nivel)
    (r"hack(?:e|3)d\s*by", "«hacked by»", "defacement"),
    (r"defac(?:e|3)d\s*by", "«defaced by»", "defacement"),
    (r"(?:owned|pwn(?:e|3)d)\s*by", "«owned/pwned by»", "defacement"),
    (r"hackead[oa]\s*(?:por|by)", "«hackeado por»", "defacement"),
    (r"vulnerad[oa]\s*por", "«vulnerado por»", "defacement"),
    (r"\bh4ck(?:3|e)?r?", "escritura leet «h4ck»", "defacement"),
    (r"\bwas\s+here\b", "«was here»", "sospecha"),
    (r"\bgreetz?\b|\bgreetings\s+to\b", "saludos de grupo atacante («greetz»)", "defacement"),
    (r"your\s+(?:site|website|security|server)\s+(?:has\s+been|is|was)\s+(?:hacked|owned|down|broken|weak)",
     "mensaje al administrador", "defacement"),
    (r"(?:tu|su)\s+seguridad\s+(?:es|está)\s+(?:nula|pésima|débil|cero)", "mensaje al administrador", "defacement"),
    (r"security\s+(?:is\s+)?(?:low|zero|weak|null)", "«security is low/zero»", "defacement"),
    (r"\bcyber\s*(?:army|team|ghost|caliphate|force|warriors?)\b", "nombre de grupo («cyber army/team»)", "sospecha"),
    (r"\bhacktivis", "hacktivismo", "sospecha"),
    (r"\b(?:slot\s*gacor|judi\s*(?:online|bola)|togel|situs\s+slot|maxwin|casino\s+online|apuestas\s+online)\b",
     "spam SEO de apuestas/casinos (inyección)", "sospecha"),
    (r"\b(?:viagra|cialis)\b", "spam farmacéutico (inyección)", "sospecha"),
]
_SIG = [(re.compile(rx, re.I), d, lv) for rx, d, lv in SIGNATURES]
BLOCK = re.compile(r"<\s*(?:br|p|div|li|h[1-6]|tr|td|th|section|article|header|footer|nav|ul|ol|table|title|option)\b[^>]*>",
                   re.I)
RES = re.compile(r"<\s*(script|iframe|embed|object|form|link)\b[^>]*?\b(src|data|action|href)\s*=\s*[\"']?([^\"'\s>]+)", re.I)
REFRESH = re.compile(r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh[^>]*content\s*=\s*[\"'][^\"']*url\s*=\s*([^\"'>\s]+)", re.I)
PWD = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?password", re.I)
LOCAL_RES = re.compile(r"<\s*(?:script\b[^>]*\bsrc|link\b[^>]*\bhref)\s*=\s*[\"']?([^\"'\s>]+\.(?:js|css)(?:\?[^\"'\s>]*)?)", re.I)
SEC_HEADERS = {"strict-transport-security": "HSTS", "content-security-policy": "CSP", "x-frame-options": "X-Frame-Options",
               "x-content-type-options": "X-Content-Type-Options", "referrer-policy": "Referrer-Policy",
               "permissions-policy": "Permissions-Policy"}
JSREDIR = re.compile(r"(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*[\"'](https?://[^\"']+)", re.I)
_SLD = ("gob.do", "gov.do", "mil.do", "edu.do", "com.do", "org.do", "net.do", "co.uk", "com.ar", "com.mx", "com.co")


def base_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    n = 3 if any(host.endswith("." + s) or host == s for s in _SLD) else 2
    return ".".join(parts[-n:])


def snapshot(html: str, url: str) -> dict:
    """Instantánea comparable de una página HTML."""
    raw = html[:3_000_000]
    m = re.search(r"<title[^>]*>(.*?)</title>", raw, re.I | re.S)
    title = re.sub(r"\s+", " ", htmllib.unescape(m.group(1))).strip()[:300] if m else ""
    own = base_domain(urlparse(url).hostname or "")
    doms = set()
    for tag, attr, val in RES.findall(raw):
        if tag.lower() == "link" and "stylesheet" not in raw[max(0, raw.find(val) - 200):raw.find(val)].lower():
            continue  # <link> solo cuenta si es una hoja de estilos
        doms.add(urlparse(urljoin(url, htmllib.unescape(val))).hostname or "")
    for val in REFRESH.findall(raw) + JSREDIR.findall(raw):
        doms.add(urlparse(urljoin(url, val)).hostname or "")
    ext = sorted(base_domain(d) for d in doms if d and base_domain(d) != own)
    body = re.sub(r"<!--.*?-->|<(script|style|noscript|svg|template)\b.*?</\1\s*>", " ", raw, flags=re.I | re.S)
    body = BLOCK.sub("\n", body)
    body = htmllib.unescape(re.sub(r"<[^>]+>", " ", body))
    lines = [re.sub(r"[ \t\r\f\v]+", " ", ln).strip() for ln in body.split("\n")]
    text = "\n".join(ln for ln in lines if ln)[:MAX_TEXT]
    host = (urlparse(url).hostname or "").lower()
    local = []
    for v in LOCAL_RES.findall(raw):  # scripts y hojas de estilo del propio sitio (para la huella de integridad)
        u = urljoin(url, htmllib.unescape(v))
        if (urlparse(u).hostname or "").lower() == host and u not in local:
            local.append(u)
    return {"title": title, "text": text, "domains": sorted(set(ext)), "words": len(text.split()),
            "hash": hashlib.sha256(re.sub(r"[\d\s]+", "", text).encode()).hexdigest(),
            "pw_inputs": len(PWD.findall(body_raw(raw))), "local_res": local[:25], "final_host": host}


def body_raw(raw: str) -> str:
    return re.sub(r"<!--.*?-->", " ", raw, flags=re.S)


def _shingles(text: str, k=4):
    w = re.findall(r"\w+", text.lower())
    # se ignoran números (fechas, contadores, visitas) para no alertar por ellos
    w = [x for x in w if not x.isdigit()]
    if len(w) < k * 3:
        return set(w)
    return {hash(" ".join(w[i:i + k])) for i in range(len(w) - k + 1)}


def change_pct(a: str, b: str) -> float:
    sa, sb = _shingles(a), _shingles(b)
    if not sa and not sb:
        return 0.0
    return round((1 - len(sa & sb) / max(1, len(sa | sb))) * 100, 1)


def compare(base: dict, snap: dict, threshold: int = 40, scope=None) -> dict:
    """Veredicto y motivos de la instantánea frente a la línea base."""
    reasons, level = [], "ok"

    def flag(lv, msg):
        nonlocal level
        reasons.append({"nivel": lv, "motivo": msg})
        if LEVELS.index(lv) > LEVELS.index(level):
            level = lv

    pct = 0.0 if snap["hash"] == base.get("hash") else change_pct(base.get("text", ""), snap["text"])
    hay_now = f"{snap['title']}\n{snap['text']}"
    hay_base = f"{base.get('title', '')}\n{base.get('text', '')}"
    for rx, desc, lv in _SIG:
        m = rx.search(hay_now)
        if m and not rx.search(hay_base):
            frag = hay_now[max(0, m.start() - 60):m.end() + 60].replace("\n", " ").strip()
            flag(lv, f"Aparece {desc}: «…{frag[:160]}…»")
    if pct >= 80:
        flag("sospecha", f"Cambió el {pct:g} % del texto visible (página casi reemplazada)")
    elif pct >= threshold:
        flag("cambio", f"Cambió el {pct:g} % del texto visible (umbral {threshold} %)")
    bw, nw = base.get("words", 0), snap["words"]
    if bw >= 60 and nw < bw * 0.25:
        flag("sospecha", f"La página casi se vació: {nw} palabras frente a {bw} de la versión aprobada")
    if base.get("title") and snap["title"] != base["title"]:
        msg = f"El título cambió: «{base['title'][:80]}» → «{snap['title'][:80] or '(vacío)'}»"
        flag("sospecha" if pct >= threshold else "cambio", msg)
    new = sorted(set(snap["domains"]) - set(base.get("domains", [])))
    if new:
        flag("sospecha", "Carga código o redirige a dominios nuevos: " + ", ".join(new[:8]))
    _compare_extra(base, snap, flag, scope or [])
    return {"nivel": level, "cambio_pct": pct, "motivos": reasons, "dominios_nuevos": new}


def _in_scope(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in nets)
    except ValueError:
        return False


def _compare_extra(base, snap, flag, scope):
    """Alteraciones fuera del texto: redirecciones, formularios, cabeceras, certificado, DNS y huella de scripts.
    Solo se compara lo que existe en la versión aprobada (las bases antiguas no tienen estos campos)."""
    if base.get("final_host") and snap.get("final_host") and base_domain(snap["final_host"]) != base_domain(base["final_host"]):
        flag("sospecha", f"Ahora redirige a otro dominio: {base['final_host']} → {snap['final_host']}")
    if "pw_inputs" in base and base["pw_inputs"] == 0 and snap.get("pw_inputs", 0) > 0:
        flag("sospecha", "Apareció un formulario de contraseña que antes no estaba (posible página de phishing)")
    bh, sh = base.get("headers"), snap.get("headers")
    if bh and sh:
        gone = [SEC_HEADERS[h] for h in bh.get("security", []) if h not in sh.get("security", [])]
        if gone:
            flag("cambio", "Se quitaron cabeceras de seguridad: " + ", ".join(gone))
        if bh.get("server") and sh.get("server") and bh["server"] != sh["server"]:
            flag("cambio", f"Cambió el servidor web: {bh['server'][:40]} → {sh['server'][:40]}")
        if sh.get("powered_by") and sh["powered_by"] != bh.get("powered_by"):
            flag("cambio", f"Nueva cabecera X-Powered-By: {sh['powered_by'][:60]}")
    bt, st = base.get("tls"), snap.get("tls")
    if bt and st:
        if st.get("self_signed") and not bt.get("self_signed"):
            flag("sospecha", "El certificado ahora es autofirmado (posible interceptación o servidor sustituido)")
        elif bt.get("issuer") and st.get("issuer") and bt["issuer"] != st["issuer"]:
            flag("cambio", f"Cambió el emisor del certificado: {bt['issuer'][:50]} → {st['issuer'][:50]}")
    bd, sd = base.get("dns"), snap.get("dns")
    if bd and sd and set(bd) != set(sd):
        out = [ip for ip in sd if scope and not _in_scope(ip, scope)]
        if out:
            flag("sospecha", f"El dominio apunta a IP fuera de los rangos de ACME: {', '.join(out[:4])} (¿secuestro de DNS?)")
        else:
            flag("cambio", f"Cambió la IP del dominio: {', '.join(bd[:3])} → {', '.join(sd[:3])}")
    ba, sa = base.get("assets"), snap.get("assets")
    if ba and sa:
        changed = [p for p, h in sa.items() if p in ba and ba[p] != h]
        js = [p for p in changed if p.endswith(".js")]
        if len(changed) >= 5:
            flag("cambio", f"Se actualizaron {len(changed)} scripts/estilos del sitio (¿despliegue nuevo?)")
        elif js:
            flag("sospecha", "Se modificó el código de: " + ", ".join(js[:4]) + " (posible inyección en un script existente)")
        elif changed:
            flag("cambio", "Cambiaron hojas de estilo: " + ", ".join(changed[:4]))


def diff(base_text: str, now_text: str, n=20) -> dict:
    """Líneas quitadas y añadidas respecto a la versión aprobada."""
    a = [x for x in base_text.split("\n") if x.strip()]
    b = [x for x in now_text.split("\n") if x.strip()]
    rem, add = [], []
    for ln in difflib.ndiff(a, b):
        if ln.startswith("- ") and len(rem) < n:
            rem.append(ln[2:][:300])
        elif ln.startswith("+ ") and len(add) < n:
            add.append(ln[2:][:300])
    return {"quitado": rem, "añadido": add}
