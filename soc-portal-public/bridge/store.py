"""Almacenamiento del portal SOC (SQLite): incidentes, cronología, runbooks y contactos."""
import datetime
import json
import pathlib
import re
import sqlite3
import threading
import time

SEVERITIES = ["Critical", "High", "Medium", "Low"]
STATUSES = ["Open", "Investigating", "Contained", "Closed"]
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL, title TEXT NOT NULL,
  severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Open',
  owner TEXT DEFAULT '', detected_at TEXT, detected_by TEXT DEFAULT '',
  assets TEXT DEFAULT '', summary TEXT DEFAULT '', iocs TEXT DEFAULT '',
  root_cause TEXT DEFAULT '', lessons TEXT DEFAULT '', runbook TEXT DEFAULT '',
  created_by TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS incident_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
  at TEXT NOT NULL, author TEXT, kind TEXT NOT NULL, text TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runbooks (
  id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL, description TEXT DEFAULT '', body TEXT DEFAULT '',
  updated_by TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT NOT NULL, name TEXT DEFAULT '',
  phone TEXT DEFAULT '', email TEXT DEFAULT '', hours TEXT DEFAULT '', sort INTEGER DEFAULT 0);
"""
SCHEMA2 = """
CREATE TABLE IF NOT EXISTS vulns (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ext_key TEXT UNIQUE, source TEXT NOT NULL,
  cve TEXT DEFAULT '', title TEXT NOT NULL, severity TEXT NOT NULL, cvss REAL, asset TEXT DEFAULT '',
  package TEXT DEFAULT '', port TEXT DEFAULT '', solution TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Open',
  owner TEXT DEFAULT '', due_date TEXT, notes TEXT DEFAULT '', first_seen TEXT, last_seen TEXT,
  created_by TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS iocs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL, type TEXT NOT NULL, source TEXT DEFAULT '',
  tlp TEXT DEFAULT 'amber', description TEXT DEFAULT '', incident TEXT DEFAULT '', expires TEXT,
  misp_event TEXT DEFAULT '', seen INTEGER, seen_last TEXT, seen_agents TEXT DEFAULT '', checked_at TEXT,
  do_check INTEGER DEFAULT 1, created_by TEXT, created_at TEXT, UNIQUE(value, type));
CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL, interval_min INTEGER DEFAULT 5,
  expect_code INTEGER, keyword TEXT DEFAULT '', watch_content INTEGER DEFAULT 0, auto_incident INTEGER DEFAULT 0,
  owner TEXT DEFAULT '', enabled INTEGER DEFAULT 1,
  state TEXT DEFAULT 'pending', fails INTEGER DEFAULT 0, last_check TEXT, last_code INTEGER, last_ms INTEGER,
  last_error TEXT DEFAULT '', ssl_expiry TEXT, ssl_error TEXT DEFAULT '', content_hash TEXT, content_changed TEXT,
  since TEXT);
CREATE TABLE IF NOT EXISTS site_checks (site_id INTEGER, at INTEGER, ok INTEGER, code INTEGER, ms INTEGER);
CREATE INDEX IF NOT EXISTS ix_sc ON site_checks(site_id, at);
CREATE TABLE IF NOT EXISTS tools (
  id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL, category TEXT DEFAULT '',
  description TEXT DEFAULT '', repo_url TEXT DEFAULT '', language TEXT DEFAULT '', license TEXT DEFAULT '',
  version TEXT DEFAULT '', tags TEXT DEFAULT '', status TEXT DEFAULT 'En evaluación', requires_auth INTEGER DEFAULT 0,
  auth_note TEXT DEFAULT '', owner TEXT DEFAULT '', readme TEXT DEFAULT '', usage TEXT DEFAULT '',
  stars INTEGER, gh_branch TEXT DEFAULT '', gh_synced TEXT, created_by TEXT, created_at TEXT, updated_by TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS tool_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tool_id INTEGER NOT NULL, path TEXT NOT NULL, size INTEGER, sha256 TEXT,
  source TEXT DEFAULT 'upload', cached INTEGER DEFAULT 0, uploaded_by TEXT, uploaded_at TEXT, UNIQUE(tool_id, path));
CREATE TABLE IF NOT EXISTS tool_log (id INTEGER PRIMARY KEY AUTOINCREMENT, tool_id INTEGER, at TEXT, user TEXT, text TEXT);
CREATE TABLE IF NOT EXISTS framework_marks (
  framework TEXT NOT NULL, key TEXT NOT NULL, status TEXT DEFAULT '', note TEXT DEFAULT '', user TEXT, at TEXT,
  PRIMARY KEY(framework, key));
CREATE TABLE IF NOT EXISTS incident_suggestions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, last_at TEXT, n INTEGER DEFAULT 1, source TEXT, key TEXT, title TEXT,
  severity TEXT, data TEXT, status TEXT DEFAULT 'pending', incident TEXT DEFAULT '', decided_by TEXT DEFAULT '',
  decided_at TEXT DEFAULT '', note TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_sugg ON incident_suggestions(status, key);
CREATE TABLE IF NOT EXISTS site_events (id INTEGER PRIMARY KEY AUTOINCREMENT, site_id INTEGER, at TEXT, kind TEXT, text TEXT);
"""
# columnas añadidas a sites (v17): inventario WAF y detección de desfiguración
SITE_EXTRA = {"waf": "TEXT DEFAULT ''", "plan": "TEXT DEFAULT ''", "public_ip": "TEXT DEFAULT ''",
              "backend_ip": "TEXT DEFAULT ''", "server": "TEXT DEFAULT ''", "vs": "TEXT DEFAULT ''", "grp": "TEXT DEFAULT ''",
              "change_threshold": "INTEGER DEFAULT 40", "deface": "TEXT DEFAULT ''", "deface_pct": "REAL",
              "deface_reasons": "TEXT DEFAULT '[]'", "deface_at": "TEXT DEFAULT ''", "page_title": "TEXT DEFAULT ''",
              "baseline": "TEXT DEFAULT ''", "baseline_at": "TEXT DEFAULT ''", "baseline_by": "TEXT DEFAULT ''",
              "snapshot": "TEXT DEFAULT ''",
              # v20: nivel del análisis de contenido y comparación visual por separado (deface = el mayor de ambos)
              "deface_text": "TEXT DEFAULT ''", "visual_level": "TEXT DEFAULT ''", "visual_pct": "REAL",
              "visual_at": "TEXT DEFAULT ''", "visual_base_at": "TEXT DEFAULT ''", "visual_error": "TEXT DEFAULT ''",
              "critical": "INTEGER DEFAULT 0"}
VULN_STATUSES = ["Open", "Remediating", "Mitigated", "Accepted", "Closed"]
VULN_SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 90, "Low": 180}
VULN_FIELDS = ["cve", "title", "severity", "cvss", "asset", "package", "port", "solution", "status", "owner", "due_date", "notes"]
INC_FIELDS = ["title", "severity", "status", "owner", "detected_at", "detected_by",
              "assets", "summary", "iocs", "root_cause", "lessons", "runbook"]


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


class Store:
    def __init__(self, path: str, seed_dir: pathlib.Path):
        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.executescript(SCHEMA2)
        rcols = [r[1] for r in self.db.execute("PRAGMA table_info(runbooks)")]
        for c in ("level", "category", "severity", "mitre", "owasp"):
            if c not in rcols:
                self.db.execute(f"ALTER TABLE runbooks ADD COLUMN {c} TEXT DEFAULT ''")
        tcols = [r[1] for r in self.db.execute("PRAGMA table_info(tools)")]
        for c in ("platform", "homepage"):
            if c not in tcols:
                self.db.execute(f"ALTER TABLE tools ADD COLUMN {c} TEXT DEFAULT ''")
        cols = [r[1] for r in self.db.execute("PRAGMA table_info(incidents)")]
        if "runbook" not in cols:  # migración de bases creadas antes
            self.db.execute("ALTER TABLE incidents ADD COLUMN runbook TEXT DEFAULT ''")
            self.db.commit()
        have = {r[1] for r in self.db.execute("PRAGMA table_info(sites)")}
        for c, t in SITE_EXTRA.items():
            if c not in have:
                self.db.execute(f"ALTER TABLE sites ADD COLUMN {c} {t}")
        self.db.commit()
        self._seed(seed_dir)

    # ------------------------------------------------------------ utilidades
    def _q(self, sql, args=(), one=False):
        with _lock:
            cur = self.db.execute(sql, args)
            rows = [dict(r) for r in cur.fetchall()]
            self.db.commit()
        return (rows[0] if rows else None) if one else rows

    def _x(self, sql, args=()):
        with _lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur.lastrowid

    RB_META = ["level", "category", "severity", "mitre", "owasp"]

    @staticmethod
    def parse_runbook(txt: str, stem: str) -> dict:
        meta, body = {}, txt
        m = re.match(r"^---\n(.*?)\n---\n(.*)$", txt, re.S)
        if m:
            for line in m.group(1).splitlines():
                k, _, v = line.partition(":")
                meta[k.strip()] = v.strip().strip('"')
            body = m.group(2)
        body = re.sub(r"^\{\.[\w-]+\}\s*$", "", body, flags=re.M)  # clases de Wiki.js
        title = re.sub(r"^Runbook:\s*", "", meta.get("title", stem), flags=re.I)
        return {"title": title[:1].upper() + title[1:], "description": meta.get("description", ""), "body": body.strip(),
                **{k: meta.get(k, "") for k in Store.RB_META}}

    def _seed(self, seed_dir: pathlib.Path):
        """Añade los runbooks del paquete que no existan y completa nivel/MITRE/OWASP de los que ya existían
        sin tocar su contenido (lo que el equipo haya editado se respeta)."""
        if seed_dir.exists():
            for f in sorted(seed_dir.glob("*.md")):
                d = self.parse_runbook(f.read_text(encoding="utf-8"), f.stem)
                old = self._q("SELECT slug, level FROM runbooks WHERE slug = ?", (f.stem,), one=True)
                if not old:
                    self._x("""INSERT INTO runbooks(slug,title,description,body,level,category,severity,mitre,owasp,updated_by,updated_at)
                               VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (f.stem, d["title"], d["description"], d["body"],
                               *[d[k] for k in self.RB_META], "system", now()))
                elif not old["level"]:
                    self._x("UPDATE runbooks SET level=?, category=?, severity=?, mitre=?, owasp=? WHERE slug=?",
                            (*[d[k] for k in self.RB_META], f.stem))
        if self._q("SELECT COUNT(*) n FROM contacts", one=True)["n"] == 0:
            for i, role in enumerate(["Guardia SOC", "Analista nivel 2", "Responsable de seguridad", "Infraestructura", "CSIRT nacional"]):
                self._x("INSERT INTO contacts(role,hours,sort) VALUES(?,?,?)", (role, "24/7" if i == 0 else "", i))

    # ------------------------------------------------------------ incidentes
    def incidents(self, status=None, severity=None, q=None, limit=200):
        sql, args = "SELECT * FROM incidents WHERE 1=1", []
        if status == "active":
            sql += " AND status != 'Closed'"
        elif status:
            sql += " AND status = ?"; args.append(status)
        if severity:
            sql += " AND severity = ?"; args.append(severity)
        if q:
            sql += " AND (code LIKE ? OR title LIKE ? OR assets LIKE ? OR iocs LIKE ?)"
            args += [f"%{q}%"] * 4
        sql += " ORDER BY id DESC LIMIT ?"; args.append(limit)
        return self._q(sql, args)

    def incident(self, code):
        inc = self._q("SELECT * FROM incidents WHERE code = ?", (code,), one=True)
        if inc:
            inc["events"] = self._q("SELECT * FROM incident_events WHERE incident_id = ? ORDER BY id DESC", (inc["id"],))
        return inc

    def create_incident(self, data: dict, user: str):
        year = datetime.date.today().year
        with _lock:
            row = self.db.execute("SELECT code FROM incidents WHERE code LIKE ? ORDER BY id DESC LIMIT 1",
                                  (f"INC-{year}-%",)).fetchone()
        n = int(row["code"].rsplit("-", 1)[1]) + 1 if row else 1
        code = f"INC-{year}-{n:03d}"
        vals = {f: (data.get(f) or "").strip() for f in INC_FIELDS}
        vals["severity"] = vals["severity"] if vals["severity"] in SEVERITIES else "High"
        vals["status"] = "Open"
        vals["detected_at"] = vals["detected_at"] or now()
        vals["owner"] = vals["owner"] or user
        cols = ",".join(["code"] + INC_FIELDS + ["created_by", "created_at", "updated_at"])
        iid = self._x(f"INSERT INTO incidents({cols}) VALUES({','.join('?' * (len(INC_FIELDS) + 4))})",
                      [code] + [vals[f] for f in INC_FIELDS] + [user, now(), now()])
        self.add_event(iid, user, "created", f"Incidente creado · severidad {vals['severity']}")
        return code

    def update_incident(self, code, data: dict, user: str):
        inc = self.incident(code)
        if not inc:
            return None
        changes = {f: (data[f] or "").strip() for f in INC_FIELDS if f in data and data[f] is not None
                   and (data[f] or "").strip() != (inc[f] or "")}
        if "severity" in changes and changes["severity"] not in SEVERITIES:
            changes.pop("severity")
        if "status" in changes and changes["status"] not in STATUSES:
            changes.pop("status")
        if changes:
            sets = ",".join(f"{k} = ?" for k in changes) + ", updated_at = ?"
            self._x(f"UPDATE incidents SET {sets} WHERE id = ?", list(changes.values()) + [now(), inc["id"]])
            for k in ("status", "severity", "owner"):
                if k in changes:
                    self.add_event(inc["id"], user, k, f"{k.capitalize()}: {inc[k] or '—'} → {changes[k]}")
            other = [k for k in changes if k not in ("status", "severity", "owner")]
            if other:
                self.add_event(inc["id"], user, "edit", "Actualizado: " + ", ".join(o.replace("_", " ") for o in other))
        return self.incident(code)

    # ------------------------------------------------------------ sugerencias de incidente (los crea una persona)
    def suggest_incident(self, data: dict, source: str, key: str):
        """Registra una propuesta. Si ya hay una pendiente con la misma clave, solo suma la repetición."""
        old = self._q("SELECT id FROM incident_suggestions WHERE status = 'pending' AND key = ?", (key,), one=True)
        if old:
            self._x("UPDATE incident_suggestions SET n = n + 1, last_at = ?, data = ?, severity = ? WHERE id = ?",
                    (now(), json.dumps(data, ensure_ascii=False), data.get("severity", "High"), old["id"]))
            return old["id"]
        return self._x("""INSERT INTO incident_suggestions(at, last_at, source, key, title, severity, data)
                          VALUES(?,?,?,?,?,?,?)""", (now(), now(), source, key, (data.get("title") or "")[:200],
                                                    data.get("severity", "High"), json.dumps(data, ensure_ascii=False)))

    def suggestions(self, status="pending", limit=200):
        sql, a = "SELECT * FROM incident_suggestions", []
        if status:
            sql += " WHERE status = ?"; a.append(status)
        rows = self._q(sql + " ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,"
                       " last_at DESC LIMIT ?", a + [limit])
        for r in rows:
            r["data"] = json.loads(r["data"] or "{}")
        return rows

    def decide_suggestion(self, sid, status, user, incident="", note=""):
        with _lock:
            cur = self.db.execute("""UPDATE incident_suggestions SET status = ?, decided_by = ?, decided_at = ?, incident = ?,
                                     note = ? WHERE id = ? AND status = 'pending'""", (status, user, now(), incident, note[:300], sid))
            self.db.commit()
            return cur.rowcount

    def add_event(self, incident_id, user, kind, text):
        self._x("INSERT INTO incident_events(incident_id,at,author,kind,text) VALUES(?,?,?,?,?)",
                (incident_id, now(), user, kind, text))
        self._x("UPDATE incidents SET updated_at = ? WHERE id = ?", (now(), incident_id))

    def add_note(self, code, user, text):
        inc = self.incident(code)
        if not inc or not text.strip():
            return None
        self.add_event(inc["id"], user, "note", text.strip())
        return self.incident(code)

    def close_incident(self, code, user, resolution, root_cause=None, lessons=None):
        """Cierra el incidente dejando constancia de la resolución en la cronología."""
        inc = self.incident(code)
        if not inc:
            return None
        data = {"status": "Closed"}
        if root_cause is not None:
            data["root_cause"] = root_cause
        if lessons is not None:
            data["lessons"] = lessons
        self.update_incident(code, data, user)
        self.add_event(inc["id"], user, "note", "✔ Cierre: " + resolution.strip())
        return self.incident(code)

    def delete_incident(self, code):
        """Borra el incidente y su cronología. Devuelve un resumen para la auditoría o None."""
        inc = self._q("SELECT id, code, title, severity, status FROM incidents WHERE code = ?", (code,), one=True)
        if not inc:
            return None
        self._x("DELETE FROM incident_events WHERE incident_id = ?", (inc["id"],))
        self._x("DELETE FROM incidents WHERE id = ?", (inc["id"],))
        return inc

    def stats(self):
        r = self._q("SELECT status, severity, COUNT(*) n FROM incidents GROUP BY status, severity")
        out = {"open": 0, "closed": 0, "critical_open": 0, "by_status": {s: 0 for s in STATUSES}}
        for x in r:
            out["by_status"][x["status"]] = out["by_status"].get(x["status"], 0) + x["n"]
            if x["status"] == "Closed":
                out["closed"] += x["n"]
            else:
                out["open"] += x["n"]
                if x["severity"] == "Critical":
                    out["critical_open"] += x["n"]
        return out

    # ------------------------------------------------------------ métricas
    # Tiempo máximo de primera respuesta por severidad (minutos). Ajustar a la política del SOC.
    SLA_MIN = {"Critical": 15, "High": 60, "Medium": 240, "Low": 1440}

    def metrics(self, days: int = 30):
        P = lambda t: datetime.datetime.strptime(t[:16], "%Y-%m-%d %H:%M") if t else None
        incs = self._q("SELECT * FROM incidents ORDER BY id")
        evs = {}
        for e in self._q("SELECT incident_id, at, author, kind, text FROM incident_events ORDER BY id"):
            evs.setdefault(e["incident_id"], []).append(e)
        today = datetime.date.today()
        dias = [(today - datetime.timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
        creados, cerrados = dict.fromkeys(dias, 0), dict.fromkeys(dias, 0)
        tta, ttr, vencidos, abiertos = [], [], [], []
        por_sev, por_rb, por_owner = {}, {}, {}
        ahora = datetime.datetime.now()
        for i in incs:
            c = P(i["created_at"])
            ev = evs.get(i["id"], [])
            # primera respuesta: primer evento humano tras la creación (nota, cambio de estado o de responsable)
            resp = next((P(e["at"]) for e in ev if e["kind"] != "created" and e["author"] != "shuffle"), None)
            cierre = next((P(e["at"]) for e in reversed(ev) if e["kind"] == "status" and e["text"].endswith("→ Closed")), None)
            if c and c.date().isoformat() in creados:
                creados[c.date().isoformat()] += 1
            if cierre and cierre.date().isoformat() in cerrados:
                cerrados[cierre.date().isoformat()] += 1
            if c and resp:
                tta.append((resp - c).total_seconds() / 60)
            if c and cierre and i["status"] == "Closed":
                ttr.append((cierre - c).total_seconds() / 60)
            if i["runbook"]:
                por_rb[i["runbook"]] = por_rb.get(i["runbook"], 0) + 1
            if i["status"] != "Closed":
                por_sev[i["severity"]] = por_sev.get(i["severity"], 0) + 1
                por_owner[i["owner"] or "—"] = por_owner.get(i["owner"] or "—", 0) + 1
                edad = (ahora - c).total_seconds() / 60 if c else 0
                limite = self.SLA_MIN.get(i["severity"], 240)
                fila = {"code": i["code"], "title": i["title"], "severity": i["severity"], "status": i["status"],
                        "owner": i["owner"], "edad_min": round(edad), "sla_min": limite, "respondido": bool(resp)}
                abiertos.append(fila)
                if not resp and edad > limite:
                    vencidos.append(fila)
        med = lambda xs: round(sorted(xs)[len(xs) // 2]) if xs else None
        return {"dias": dias, "creados": [creados[d] for d in dias], "cerrados": [cerrados[d] for d in dias],
                "mtta_min": med(tta), "mttr_min": med(ttr), "n_tta": len(tta), "n_ttr": len(ttr),
                "por_severidad": [(k, por_sev.get(k, 0)) for k in SEVERITIES],
                "por_runbook": sorted(por_rb.items(), key=lambda x: -x[1])[:8],
                "por_responsable": sorted(por_owner.items(), key=lambda x: -x[1])[:8],
                "sla": self.SLA_MIN, "vencidos": vencidos,
                "abiertos": sorted(abiertos, key=lambda x: -x["edad_min"])[:10], "total": len(incs)}

    # ------------------------------------------------------------ vulnerabilidades (seguimiento)
    @staticmethod
    def due_for(sev, start=None):
        d = (start or datetime.date.today()) + datetime.timedelta(days=VULN_SLA_DAYS.get(sev, 90))
        return d.isoformat()

    def vulns(self, status=None, severity=None, source=None, q=None, limit=2000):
        sql, args = "SELECT * FROM vulns WHERE 1=1", []
        if status == "active":
            sql += " AND status IN ('Open','Remediating')"
        elif status:
            sql += " AND status = ?"; args.append(status)
        for k, v in (("severity", severity), ("source", source)):
            if v:
                sql += f" AND {k} = ?"; args.append(v)
        if q:
            sql += " AND (cve LIKE ? OR title LIKE ? OR asset LIKE ? OR package LIKE ?)"; args += [f"%{q}%"] * 4
        sql += """ ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END,
                   due_date LIMIT ?"""; args.append(limit)
        return self._q(sql, args)

    def vuln_stats(self):
        today = datetime.date.today().isoformat()
        rows = self._q("SELECT severity, status, source, due_date FROM vulns")
        act = [r for r in rows if r["status"] in ("Open", "Remediating")]
        return {"total": len(rows), "activas": len(act),
                "vencidas": sum(1 for r in act if r["due_date"] and r["due_date"] < today),
                "por_severidad": [(k, sum(1 for r in act if r["severity"] == k)) for k in SEVERITIES],
                "por_estado": [(k, sum(1 for r in rows if r["status"] == k)) for k in VULN_STATUSES],
                "por_origen": sorted({r["source"]: sum(1 for x in rows if x["source"] == r["source"]) for r in rows}.items(), key=lambda x: -x[1]),
                "sla_dias": VULN_SLA_DAYS}

    def save_vuln(self, vid, data, user, source="manual", ext_key=None):
        """Crea (vid=None) o actualiza. Con ext_key, una importación repetida actualiza en vez de duplicar."""
        vals = {f: data.get(f) for f in VULN_FIELDS if f in data}
        for k, v in list(vals.items()):
            vals[k] = v.strip() if isinstance(v, str) else v
        if "severity" in vals and vals["severity"] not in SEVERITIES:
            vals["severity"] = "Medium"
        if "status" in vals and vals["status"] not in VULN_STATUSES:
            vals.pop("status")
        if vals.get("cvss") in ("", None):
            vals["cvss"] = None
        old = None
        if vid:
            old = self._q("SELECT * FROM vulns WHERE id = ?", (vid,), one=True)
        elif ext_key:
            old = self._q("SELECT * FROM vulns WHERE ext_key = ?", (ext_key,), one=True)
        if old:
            if ext_key:  # reimportación: no se pisan estado, responsable ni notas del analista
                for k in ("status", "owner", "notes", "due_date"):
                    vals.pop(k, None)
                vals["last_seen"] = now()
            if vals:
                self._x(f"UPDATE vulns SET {','.join(k + ' = ?' for k in vals)}, updated_at = ? WHERE id = ?",
                        list(vals.values()) + [now(), old["id"]])
            return old["id"], False
        if not (vals.get("title") or vals.get("cve")):
            return None, False
        vals.setdefault("severity", "Medium")
        vals["title"] = vals.get("title") or vals.get("cve")
        vals["status"] = vals.get("status") or "Open"
        vals["due_date"] = vals.get("due_date") or self.due_for(vals["severity"])
        cols = list(vals) + ["ext_key", "source", "first_seen", "last_seen", "created_by", "updated_at"]
        vid = self._x(f"INSERT INTO vulns({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                      list(vals.values()) + [ext_key, source, now(), now(), user, now()])
        return vid, True

    def delete_vuln(self, vid):
        self._x("DELETE FROM vulns WHERE id = ?", (vid,))

    # ------------------------------------------------------------ IoC
    def iocs(self, type_=None, q=None, status=None, limit=3000):
        sql, args = "SELECT * FROM iocs WHERE 1=1", []
        if type_:
            sql += " AND type = ?"; args.append(type_)
        if q:
            sql += " AND (value LIKE ? OR description LIKE ? OR source LIKE ? OR incident LIKE ?)"; args += [f"%{q}%"] * 4
        today = datetime.date.today().isoformat()
        if status == "active":
            sql += " AND (expires IS NULL OR expires = '' OR expires >= ?)"; args.append(today)
        elif status == "expired":
            sql += " AND expires != '' AND expires < ?"; args.append(today)
        elif status == "seen":
            sql += " AND seen > 0"
        sql += " ORDER BY id DESC LIMIT ?"; args.append(limit)
        return self._q(sql, args)

    def add_iocs(self, items, meta, user):
        added, dup, ids = 0, 0, []
        for it in items:
            if self._q("SELECT id FROM iocs WHERE value = ? AND type = ?", (it["value"], it["type"]), one=True):
                dup += 1
                continue
            ids.append(self._x("""INSERT INTO iocs(value,type,source,tlp,description,incident,expires,do_check,created_by,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""", (it["value"], it["type"], meta.get("source", ""), meta.get("tlp", "amber"),
                       meta.get("description", ""), meta.get("incident", ""), meta.get("expires") or "",
                       1 if meta.get("check", True) else 0, user, now())))
            added += 1
        return added, dup, ids

    def ioc_update(self, iid, **kw):
        if kw:
            self._x(f"UPDATE iocs SET {','.join(k + ' = ?' for k in kw)} WHERE id = ?", list(kw.values()) + [iid])

    def ioc_pending_checks(self, n=15):
        return self._q("SELECT id, value, type FROM iocs WHERE do_check = 1 AND checked_at IS NULL ORDER BY id LIMIT ?", (n,))

    def ioc_stats(self):
        today = datetime.date.today().isoformat()
        soon = (datetime.date.today() + datetime.timedelta(days=7)).isoformat()
        r = self._q("""SELECT COUNT(*) total,
             SUM(CASE WHEN expires IS NULL OR expires = '' OR expires >= ? THEN 1 ELSE 0 END) activos,
             SUM(CASE WHEN misp_event != '' THEN 1 ELSE 0 END) misp,
             SUM(CASE WHEN seen > 0 THEN 1 ELSE 0 END) vistos,
             SUM(CASE WHEN do_check = 1 AND checked_at IS NULL THEN 1 ELSE 0 END) pendientes,
             SUM(CASE WHEN expires != '' AND expires >= ? AND expires <= ? THEN 1 ELSE 0 END) caducan
             FROM iocs""", (today, today, soon), one=True)
        r = {k: v or 0 for k, v in r.items()}
        r["por_tipo"] = [(x["type"], x["n"]) for x in self._q("SELECT type, COUNT(*) n FROM iocs GROUP BY type ORDER BY n DESC")]
        return r

    def delete_ioc(self, iid):
        self._x("DELETE FROM iocs WHERE id = ?", (iid,))

    # ------------------------------------------------------------ portales monitoreados
    SITE_FIELDS = ["name", "url", "interval_min", "expect_code", "keyword", "watch_content", "auto_incident", "owner", "enabled",
                   "waf", "plan", "public_ip", "backend_ip", "server", "vs", "grp", "change_threshold", "critical"]

    def sites(self, bars=24):
        # baseline/snapshot son grandes (texto de la página): no se envían en el listado
        cols = [c for c in (r[1] for r in self.db.execute("PRAGMA table_info(sites)")) if c not in ("baseline", "snapshot")]
        rows = self._q(f"SELECT {', '.join(cols)} FROM sites ORDER BY name")
        t24 = int(time.time()) - 86400
        hist = {}
        for x in self._q("SELECT site_id, at, ok, ms FROM site_checks WHERE at >= ? ORDER BY at", (t24,)):
            hist.setdefault(x["site_id"], []).append(x)
        for r in rows:
            h = hist.get(r["id"], [])
            r["uptime24"] = round(sum(x["ok"] for x in h) / len(h) * 100, 2) if h else None
            r["avg_ms"] = round(sum(x["ms"] or 0 for x in h if x["ok"]) / max(1, sum(1 for x in h if x["ok"]))) if h else None
            step = max(1, len(h) // bars)
            r["hist"] = [[x["at"], x["ok"], x["ms"]] for x in h[::step]]
            try:
                r["deface_reasons"] = json.loads(r.get("deface_reasons") or "[]")
            except ValueError:
                r["deface_reasons"] = []
        return rows

    def site(self, sid):
        return self._q("SELECT * FROM sites WHERE id = ?", (sid,), one=True)

    def save_site(self, sid, data):
        vals = {k: data[k] for k in self.SITE_FIELDS if k in data}
        for k in ("interval_min", "expect_code", "change_threshold"):
            if k in vals:
                vals[k] = int(vals[k]) if str(vals[k] if vals[k] is not None else "").strip() else None
        if vals.get("change_threshold") is not None:
            vals["change_threshold"] = max(5, min(95, vals["change_threshold"]))
        for k in ("watch_content", "auto_incident", "enabled", "critical"):
            if k in vals:
                vals[k] = 1 if vals[k] in (True, 1, "1", "on", "true") else 0
        if sid:
            self._x(f"UPDATE sites SET {','.join(k + ' = ?' for k in vals)} WHERE id = ?", list(vals.values()) + [sid])
            return sid
        vals.setdefault("interval_min", 5)
        return self._x(f"INSERT INTO sites({','.join(vals)}, since) VALUES({','.join('?' * len(vals))}, ?)", list(vals.values()) + [now()])

    def delete_site(self, sid):
        for t, c in (("site_checks", "site_id"), ("site_events", "site_id"), ("sites", "id")):
            self._x(f"DELETE FROM {t} WHERE {c} = ?", (sid,))

    def sites_due(self):
        out = []
        for r in self._q("SELECT * FROM sites WHERE enabled = 1"):
            last = r["last_check"]
            if not last or (datetime.datetime.now() - datetime.datetime.strptime(last, "%Y-%m-%d %H:%M:%S")).total_seconds() >= (r["interval_min"] or 5) * 60 - 5:
                out.append(r)
        return out

    def site_result(self, sid, res: dict, ok: bool):
        self._x("INSERT INTO site_checks(site_id, at, ok, code, ms) VALUES(?,?,?,?,?)",
                (sid, int(time.time()), 1 if ok else 0, res.get("last_code"), res.get("last_ms")))
        res["last_check"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._x(f"UPDATE sites SET {','.join(k + ' = ?' for k in res)} WHERE id = ?", list(res.values()) + [sid])

    def site_event(self, sid, kind, text):
        self._x("INSERT INTO site_events(site_id, at, kind, text) VALUES(?,?,?,?)", (sid, now(), kind, text))

    def site_events(self, limit=30):
        return self._q("""SELECT e.*, s.name FROM site_events e JOIN sites s ON s.id = e.site_id
                          ORDER BY e.id DESC LIMIT ?""", (limit,))

    def prune_checks(self, days=30):
        self._x("DELETE FROM site_checks WHERE at < ?", (int(time.time()) - days * 86400,))

    # ------------------------------------------------------------ herramientas (repositorio interno)
    TOOL_FIELDS = ["name", "category", "description", "repo_url", "language", "license", "version", "tags", "status",
                   "requires_auth", "auth_note", "owner", "readme", "usage", "platform", "homepage"]
    TOOL_STATUSES = ["Aprobada", "En evaluación", "Obsoleta"]

    def tools(self, q=None, cat=None, platform=None):
        sql, a = """SELECT t.id, t.slug, t.name, t.category, t.description, t.repo_url, t.language, t.license, t.version,
                    t.tags, t.status, t.requires_auth, t.owner, t.stars, t.updated_at, t.updated_by, t.platform, t.homepage,
                    (SELECT COUNT(*) FROM tool_files f WHERE f.tool_id = t.id) files FROM tools t WHERE 1=1""", []
        if q:
            sql += " AND (t.name LIKE ? OR t.description LIKE ? OR t.tags LIKE ? OR t.language LIKE ?)"; a += [f"%{q}%"] * 4
        if cat:
            sql += " AND t.category = ?"; a.append(cat)
        if platform:
            sql += " AND t.platform = ?"; a.append(platform)
        return self._q(sql + " ORDER BY t.status = 'Obsoleta', t.name COLLATE NOCASE", a)

    def tool(self, tid):
        t = self._q("SELECT * FROM tools WHERE id = ? OR slug = ?", (tid, str(tid)), one=True)
        if t:
            t["files"] = self._q("SELECT * FROM tool_files WHERE tool_id = ? ORDER BY path", (t["id"],))
            t["log"] = self._q("SELECT * FROM tool_log WHERE tool_id = ? ORDER BY id DESC LIMIT 30", (t["id"],))
        return t

    def save_tool(self, tid, data, user):
        vals = {k: data[k] for k in self.TOOL_FIELDS if k in data}
        for k, v in list(vals.items()):
            vals[k] = v.strip() if isinstance(v, str) else v
        if "requires_auth" in vals:
            vals["requires_auth"] = 1 if vals["requires_auth"] in (True, 1, "1", "on", "true") else 0
        if "status" in vals and vals["status"] not in self.TOOL_STATUSES:
            vals["status"] = "En evaluación"
        if tid:
            old = self.tool(tid)
            changed = [k for k in vals if str(vals[k] or "") != str(old.get(k) or "")]
            if changed:
                self._x(f"UPDATE tools SET {','.join(k + ' = ?' for k in vals)}, updated_by = ?, updated_at = ? WHERE id = ?",
                        list(vals.values()) + [user, now(), old["id"]])
                self.tool_log(old["id"], user, "Editado: " + ", ".join(changed) if "status" not in changed
                              else f"Estado: {old['status']} → {vals['status']}")
            return old["id"]
        if not vals.get("name"):
            return None
        slug = re.sub(r"[^a-z0-9]+", "-", vals["name"].lower()).strip("-")[:50] or "herramienta"
        base, i = slug, 2
        while self._q("SELECT 1 FROM tools WHERE slug = ?", (slug,), one=True):
            slug, i = f"{base}-{i}", i + 1
        cols = list(vals) + ["slug", "created_by", "created_at", "updated_by", "updated_at"]
        tid = self._x(f"INSERT INTO tools({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                      list(vals.values()) + [slug, user, now(), user, now()])
        self.tool_log(tid, user, "Herramienta registrada")
        return tid

    def tool_meta(self, tid, **kw):
        self._x(f"UPDATE tools SET {','.join(k + ' = ?' for k in kw)} WHERE id = ?", list(kw.values()) + [tid])

    def tool_log(self, tid, user, text):
        self._x("INSERT INTO tool_log(tool_id, at, user, text) VALUES(?,?,?,?)", (tid, now(), user, text))

    def tool_file_upsert(self, tid, path, size, sha, source, cached, user):
        self._x("""INSERT INTO tool_files(tool_id, path, size, sha256, source, cached, uploaded_by, uploaded_at) VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(tool_id, path) DO UPDATE SET size = excluded.size, sha256 = COALESCE(excluded.sha256, sha256),
                   source = excluded.source, cached = excluded.cached, uploaded_by = excluded.uploaded_by, uploaded_at = excluded.uploaded_at""",
                (tid, path, size, sha, source, cached, user, now()))
        return self._q("SELECT * FROM tool_files WHERE tool_id = ? AND path = ?", (tid, path), one=True)

    def tool_file(self, tid, fid):
        return self._q("SELECT * FROM tool_files WHERE tool_id = ? AND id = ?", (tid, fid), one=True)

    def delete_tool_file(self, tid, fid):
        self._x("DELETE FROM tool_files WHERE tool_id = ? AND id = ?", (tid, fid))

    def delete_tool(self, tid):
        for t, c in (("tool_files", "tool_id"), ("tool_log", "tool_id"), ("tools", "id")):
            self._x(f"DELETE FROM {t} WHERE {c} = ?", (tid,))

    # ------------------------------------------------------------ marcos (MITRE / OWASP): estado de cobertura
    def marks(self, fw):
        return {r["key"]: r for r in self._q("SELECT * FROM framework_marks WHERE framework = ?", (fw,))}

    def set_mark(self, fw, key, status, note, user):
        self._x("""INSERT INTO framework_marks(framework, key, status, note, user, at) VALUES(?,?,?,?,?,?)
                   ON CONFLICT(framework, key) DO UPDATE SET status = excluded.status, note = excluded.note, user = excluded.user, at = excluded.at""",
                (fw, key, status, note, user, now()))

    # ------------------------------------------------------------ runbooks
    def runbooks(self):
        return self._q("""SELECT id,slug,title,description,level,category,severity,mitre,owasp,updated_by,updated_at FROM runbooks
                          ORDER BY CASE level WHEN 'Básico' THEN 0 WHEN 'Intermedio' THEN 1 WHEN 'Avanzado' THEN 2 ELSE 3 END, title""")

    def runbook(self, slug):
        return self._q("SELECT * FROM runbooks WHERE slug = ?", (slug,), one=True)

    def save_runbook(self, slug, data, user):
        title = (data.get("title") or "").strip()
        if not title:
            return None
        if not slug or not self.runbook(slug):
            slug = re.sub(r"[^a-z0-9]+", "-", (slug or data.get("slug") or title).lower()).strip("-")[:60] or "runbook"
            base, i = slug, 2
            while self.runbook(slug):
                slug, i = f"{base}-{i}", i + 1
            self._x("""INSERT INTO runbooks(slug,title,description,body,level,category,severity,mitre,owasp,updated_by,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (slug, title, data.get("description", ""), data.get("body", ""),
                       *[(data.get(k) or "").strip() for k in self.RB_META], user, now()))
            return self.runbook(slug)
        else:
            old = self.runbook(slug)
            meta = [(data[k] if k in data else old.get(k) or "") for k in self.RB_META]
            self._x("UPDATE runbooks SET title=?, description=?, body=?, level=?, category=?, severity=?, mitre=?, owasp=?, updated_by=?, updated_at=? WHERE slug=?",
                    (title, data.get("description", ""), data.get("body", ""), *meta, user, now(), slug))
        return self.runbook(slug)

    def delete_runbook(self, slug):
        self._x("DELETE FROM runbooks WHERE slug = ?", (slug,))

    # ------------------------------------------------------------ contactos
    def contacts(self):
        return self._q("SELECT * FROM contacts ORDER BY sort, id")

    def save_contacts(self, rows):
        with _lock:
            self.db.execute("DELETE FROM contacts")
            for i, r in enumerate(rows):
                if (r.get("role") or "").strip():
                    self.db.execute("INSERT INTO contacts(role,name,phone,email,hours,sort) VALUES(?,?,?,?,?,?)",
                                    tuple((r.get(k) or "").strip() for k in ("role", "name", "phone", "email", "hours")) + (i,))
            self.db.commit()
        return self.contacts()

    # ------------------------------------------------------------ exportación
    def export(self):
        return {"exported_at": now(), "incidents": [self.incident(i["code"]) for i in self.incidents(limit=100000)],
                "runbooks": self._q("SELECT * FROM runbooks"), "contacts": self.contacts()}
