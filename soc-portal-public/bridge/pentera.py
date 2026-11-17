"""Importación de informes de Pentera (PDF, JSON o CSV) a Vulnerabilidades.

Pentera puntúa la severidad de 0 a 10 (0 = informativo). Correspondencia usada (la misma que aplican otras
plataformas que importan Pentera): <2.5 Baja · <5 Media · <7.5 Alta · ≥7.5 Crítica.

El PDF no tiene un formato fijo entre versiones, así que el lector es heurístico: busca bloques
«título + Severidad/Score», y si no los hay, filas de tabla «puntuación + título», y como último recurso los CVE.
Por eso el portal siempre muestra una vista previa editable antes de guardar.
"""
import csv
import hashlib
import io
import json
import re

MAX_PAGES = 600
IP = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
PORT = re.compile(r"\b(?:port|puerto)\s*[:#]?\s*(\d{1,5})\b|\b(\d{1,5})/(?:tcp|udp)\b", re.I)
SEV_LINE = re.compile(r"^\s*(?:severity|severidad|score|puntuaci[oó]n|risk(?: score)?|riesgo)\s*(?:score)?\s*[:\-]?\s*"
                      r"(?P<num>10(?:[.,]0+)?|\d(?:[.,]\d{1,2})?)?\s*(?:/\s*10)?\s*(?P<word>critical|high|medium|low|"
                      r"cr[ií]tica|alta|media|baja|informational|info)?\s*$", re.I)
LABELS = {
    "desc": re.compile(r"^\s*(insight|description|descripci[oó]n|details|detalles|summary|resumen|finding|hallazgo)\s*:?\s*(.*)$", re.I),
    "fix": re.compile(r"^\s*(remediation|remediaci[oó]n|recommendation|recomendaci[oó]n|mitigation|mitigaci[oó]n|"
                      r"how to fix|soluci[oó]n)\s*:?\s*(.*)$", re.I),
    "assets": re.compile(r"^\s*(affected (?:assets|hosts|targets)|targets?|hosts?|assets?|activos?(?: afectados)?|"
                         r"equipos? afectados|ip addresses)\s*:?\s*(.*)$", re.I),
    "other": re.compile(r"^\s*(priority|prioridad|protocol|protocolo|port|puerto|cve|category|categor[ií]a|"
                        r"discovered|creation time|first seen|status|estado|mitre|technique)\s*:?\s*(.*)$", re.I),
}
NOISE = re.compile(r"^(page \d+|p[aá]gina \d+|\d+\s*(/|of|de)\s*\d+|pentera|confidential|confidencial|"
                   r"table of contents|[ií]ndice|copyright.*|©.*|www\..*)$", re.I)
WORD_SCORE = {"critical": 9.0, "crítica": 9.0, "critica": 9.0, "high": 6.0, "alta": 6.0, "medium": 4.0, "media": 4.0,
              "low": 2.0, "baja": 2.0, "informational": 0.0, "info": 0.0}


def sev_from_score(x):
    if x is None:
        return None
    return "Critical" if x >= 7.5 else "High" if x >= 5 else "Medium" if x >= 2.5 else "Low" if x > 0 else None


def _num(s):
    try:
        return float(str(s).replace(",", "."))
    except (TypeError, ValueError):
        return None


def _key(title):
    return hashlib.sha1(("pentera|" + re.sub(r"\s+", " ", title.strip().lower())).encode()).hexdigest()


def _item(title, score=None, word="", desc="", fix="", assets=(), ports=(), cves=(), extra=""):
    if score is None and word:
        score = WORD_SCORE.get(word.lower())
    sev = sev_from_score(score)
    if not sev or not title.strip():
        return None
    assets = list(dict.fromkeys(a.strip() for a in assets if a and a.strip()))
    notes = f"Importado de Pentera · puntuación {score:g}/10" + (f" · {extra}" if extra else "")
    if desc:
        notes += "\n\n" + desc.strip()[:3000]
    return {"ext_key": _key(title), "title": title.strip()[:300], "severity": sev, "score": score,
            "cve": ", ".join(dict.fromkeys(c.upper() for c in cves)), "asset": ", ".join(assets)[:2000],
            "port": ", ".join(dict.fromkeys(str(p) for p in ports if p))[:100], "solution": fix.strip()[:1500],
            "notes": notes, "n_assets": len(assets)}


# ------------------------------------------------------------------ JSON / CSV (exportaciones de Pentera)
def _from_records(recs):
    out = []
    pick = lambda r, *ks: next((r[k] for k in ks if k in r and r[k] not in (None, "")), "")
    for r in recs:
        if not isinstance(r, dict):
            continue
        r = {str(k).strip().lower().replace(" ", "_"): v for k, v in r.items()}
        title = str(pick(r, "name", "title", "vulnerability", "vulnerability_name", "nombre"))
        sc = pick(r, "severity", "severity_score", "score", "risk_score", "severidad")
        score = _num(sc)
        word = "" if score is not None else str(sc)
        hosts = pick(r, "targets", "target", "target_id", "hosts", "host", "ip", "ip_address", "assets", "asset")
        if isinstance(hosts, list):
            hosts = [h.get("ip") or h.get("name") or h.get("target_id") or str(h) if isinstance(h, dict) else str(h) for h in hosts]
        else:
            hosts = re.split(r"[,;\s]+", str(hosts)) if hosts else []
        it = _item(title, score, word, str(pick(r, "insight", "description", "summary", "descripcion")),
                   str(pick(r, "remediation", "recommendation", "solution", "remediacion")), hosts,
                   [pick(r, "port", "puerto")], CVE.findall(json.dumps(r, default=str)),
                   f"prioridad {pick(r, 'priority')}" if pick(r, "priority") else "")
        if it:
            out.append(it)
    return out


def parse_json(data: bytes):
    d = json.loads(data.decode("utf-8-sig"))
    recs = []
    if isinstance(d, list):
        recs = d
    elif isinstance(d, dict):
        for k in ("vulnerabilities", "Vulnerabilities", "findings", "items", "data"):
            if isinstance(d.get(k), list):
                recs += d[k]
        if isinstance(d.get("achievements"), list):
            recs += [{**a, "name": "Logro de Pentera: " + str(a.get("name", ""))} for a in d["achievements"]]
    return _from_records(recs)


def parse_csv(data: bytes):
    text = data.decode("utf-8-sig", errors="ignore")
    try:
        dialect = csv.Sniffer().sniff(text[:4000], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    return _from_records(list(csv.DictReader(io.StringIO(text), dialect=dialect)))


# ------------------------------------------------------------------ PDF
def pdf_text(data: bytes) -> str:
    from pdfminer.high_level import extract_text
    from pdfminer.layout import LAParams
    return extract_text(io.BytesIO(data), laparams=LAParams(line_margin=0.4), maxpages=MAX_PAGES)


def pdf_rows(data: bytes) -> list:
    """Reconstruye las filas visuales (misma altura en la página) para leer tablas que pdfminer extrae por columnas."""
    from pdfminer.high_level import extract_pages
    from pdfminer.layout import LAParams, LTTextContainer, LTTextLine
    rows = []
    for page in extract_pages(io.BytesIO(data), laparams=LAParams(line_margin=0.4), maxpages=MAX_PAGES):
        frags = []
        for el in page:
            if isinstance(el, LTTextContainer):
                for ln in el:
                    if isinstance(ln, LTTextLine) and ln.get_text().strip():
                        frags.append((round(ln.y0 / 3), ln.x0, ln.get_text().strip()))
        by = {}
        for y, x, t in frags:
            by.setdefault(y, []).append((x, t))
        for y in sorted(by, reverse=True):
            rows.append("  ".join(t for _, t in sorted(by[y])))
    return rows


def _clean_lines(text):
    out = []
    for ln in text.replace("\x0c", "\n").splitlines():
        ln = re.sub(r"\s+", " ", ln).strip()
        if ln and not NOISE.match(ln):
            out.append(ln)
    return out


def _looks_title(ln):
    return (4 <= len(ln) <= 160 and re.search(r"[A-Za-zÁÉÍÓÚáéíóúñÑ]{3}", ln) and not SEV_LINE.match(ln)
            and not any(rx.match(ln) for rx in LABELS.values()) and not IP.fullmatch(ln) and not ln.endswith(":"))


def _blocks(lines):
    """Estrategia 1: «Título» seguido (≤3 líneas) de «Severidad/Score: 8.5»."""
    anchors = []
    for i, ln in enumerate(lines):
        m = SEV_LINE.match(ln)
        if m and (m.group("num") or m.group("word")):
            j = next((k for k in range(i - 1, max(-1, i - 4), -1) if _looks_title(lines[k])), None)
            if j is not None and (not anchors or j > anchors[-1][1]):
                anchors.append((j, i, _num(m.group("num")), m.group("word") or ""))
    items = []
    for n, (t, s, score, word) in enumerate(anchors):
        end = anchors[n + 1][0] if n + 1 < len(anchors) else len(lines)
        body = lines[s + 1:end]
        sect, buf = "desc", {"desc": [], "fix": [], "assets": [], "other": []}
        for ln in body:
            for name, rx in LABELS.items():
                m = rx.match(ln)
                if m:
                    sect = name
                    ln = m.group(2)
                    break
            if ln:
                buf[sect].append(ln)
        blob = " ".join(body)
        hosts = IP.findall(" ".join(buf["assets"])) or IP.findall(blob)
        if not hosts and buf["assets"]:
            hosts = [h for h in re.split(r"[,;]\s*|\s{2,}", " ".join(buf["assets"])) if h][:200]
        ports = [a or b for a, b in PORT.findall(blob)]
        it = _item(lines[t], score, word, " ".join(buf["desc"]), " ".join(buf["fix"]), hosts, ports,
                   CVE.findall(lines[t] + " " + blob))
        if it:
            items.append(it)
    return items


TABLE_ROW = re.compile(r"^(?P<score>10(?:[.,]0+)?|\d[.,]\d{1,2})\s+(?P<title>[A-Za-zÁÉÍÓÚáéíóú].{4,160}?)"
                       r"(?:\s+(?P<n>\d{1,5}))?(?:\s{2,}(?P<hosts>[\d.,\s]+))?$")
TABLE_ROW_R = re.compile(r"^(?P<title>[A-Za-zÁÉÍÓÚáéíóú].{4,160}?)\s+(?P<score>10(?:[.,]0+)?|\d[.,]\d{1,2})"
                         r"(?:\s+(?P<n>\d{1,5}))?$")


def _table(lines):
    """Estrategia 2: filas «8.5 Nombre de la vulnerabilidad [nº de equipos]» (o con la puntuación al final)."""
    items = []
    for i, ln in enumerate(lines):
        m = TABLE_ROW.match(ln) or TABLE_ROW_R.match(ln)
        if not m:
            continue
        nxt = " ".join(lines[i + 1:i + 3])
        hosts = IP.findall(nxt) if not (TABLE_ROW.match(lines[i + 1]) if i + 1 < len(lines) else False) else []
        it = _item(m.group("title"), _num(m.group("score")), assets=hosts, cves=CVE.findall(ln),
                   extra=f"{m.group('n')} equipos según el informe" if m.group("n") else "")
        if it:
            items.append(it)
    return items


def _cves(lines):
    """Estrategia 3: un hallazgo por CVE mencionado (sin puntuación de Pentera → se marca Media para revisar)."""
    seen, items = {}, []
    for i, ln in enumerate(lines):
        for c in CVE.findall(ln):
            c = c.upper()
            if c in seen:
                continue
            ctx = " ".join(lines[max(0, i - 1):i + 2])
            seen[c] = 1
            it = _item(f"{c} (detectado en informe Pentera)", 4.0, desc=ctx[:500], assets=IP.findall(ctx), cves=[c],
                       extra="sin puntuación en el texto: revisar severidad")
            if it:
                items.append(it)
    return items


def _merge(items):
    """Une los repetidos (mismo título): suma equipos y conserva la mayor severidad."""
    by = {}
    for it in items:
        k = it["ext_key"]
        if k not in by:
            by[k] = it
            continue
        o = by[k]
        if (it["score"] or 0) > (o["score"] or 0):
            o.update(severity=it["severity"], score=it["score"])
        assets = list(dict.fromkeys([a for a in (o["asset"] + ", " + it["asset"]).split(", ") if a]))
        o["asset"], o["n_assets"] = ", ".join(assets)[:2000], len(assets)
        for f in ("solution", "cve", "port"):
            o[f] = o[f] or it[f]
    return list(by.values())


def parse(data: bytes, filename: str = "") -> dict:
    name = filename.lower()
    head = data[:5]
    if head.startswith(b"%PDF") or name.endswith(".pdf"):
        text = pdf_text(data)
        lines = _clean_lines(text)
        rows = _clean_lines("\n".join(pdf_rows(data)))
        if len(" ".join(lines)) < 200:
            return {"formato": "pdf", "items": [], "estrategia": "",
                    "aviso": "El PDF casi no tiene texto (¿es un escaneo/imagen?). Exporta desde Pentera en JSON o CSV."}
        for strategy, fn, src in (("bloques", _blocks, lines), ("tabla", _table, rows), ("cve", _cves, lines)):
            items = _merge(fn(src))
            if items:
                aviso = {"bloques": "", "tabla": "Leído como tabla: revisa títulos y equipos afectados.",
                         "cve": "No se encontró el listado de Pentera; se extrajeron los CVE. Revisa la severidad."}[strategy]
                return {"formato": "pdf", "items": items, "estrategia": strategy, "aviso": aviso, "lineas": len(lines)}
        return {"formato": "pdf", "items": [], "estrategia": "", "lineas": len(lines),
                "aviso": "No se reconocieron hallazgos en el PDF. Envíanos una página de ejemplo o exporta en JSON/CSV."}
    if head.lstrip()[:1] in (b"{", b"[") or name.endswith(".json"):
        return {"formato": "json", "items": _merge(parse_json(data)), "estrategia": "json", "aviso": ""}
    return {"formato": "csv", "items": _merge(parse_csv(data)), "estrategia": "csv", "aviso": ""}
