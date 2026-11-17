"""Conectores de solo lectura hacia Wazuh, MISP, Shuffle y Wiki.js."""
import os
import time
from datetime import datetime, timezone

from collections import Counter as _counter

import requests
import urllib3

urllib3.disable_warnings()
TIMEOUT = 60


def _get(d: dict, path: str):
    for k in path.split("."):
        d = d.get(k) if isinstance(d, dict) else None
    return d


def _bool(name: str, default: str = "true") -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes")


# ----------------------------------------------------------------- Wazuh
class Wazuh:
    def __init__(self):
        self.api = os.getenv("WAZUH_API_URL", "").rstrip("/")
        self.idx = os.environ["WAZUH_INDEXER_URL"].rstrip("/")
        self.user = os.getenv("WAZUH_API_USER", "")
        self.pwd = os.getenv("WAZUH_API_PASSWORD", "")
        self.idx_auth = (os.environ["WAZUH_INDEXER_USER"], os.environ["WAZUH_INDEXER_PASSWORD"])
        self.verify = _bool("WAZUH_VERIFY_TLS", "false")
        self._token, self._exp = None, 0

    def _headers(self):
        if not self._token or time.time() > self._exp:
            r = requests.post(f"{self.api}/security/user/authenticate",
                              auth=(self.user, self.pwd), verify=self.verify, timeout=TIMEOUT)
            r.raise_for_status()
            self._token = r.json()["data"]["token"]
            self._exp = time.time() + 800  # el token dura 900 s por defecto
        return {"Authorization": f"Bearer {self._token}"}

    def agents_summary(self) -> dict:
        """Estado de los agentes.
        1) Si hay usuario de API configurado, se usa la API (55000).
        2) Si no, se lee del indexer: índice wazuh-monitoring-* (Wazuh lo actualiza cada ~15 min).
        """
        if self.user and not self.user.startswith("CAMBIAR"):
            try:
                r = requests.get(f"{self.api}/agents/summary/status", headers=self._headers(),
                                 verify=self.verify, timeout=TIMEOUT)
                r.raise_for_status()
                return r.json()["data"]["connection"]
            except Exception:
                pass  # se intenta por el indexer
        q = {"size": 0, "aggs": {"last": {"max": {"field": "timestamp"}}}}
        r = requests.post(f"{self.idx}/wazuh-monitoring-*/_search", json=q,
                          auth=self.idx_auth, verify=self.verify, timeout=TIMEOUT)
        r.raise_for_status()
        last = r.json()["aggregations"]["last"].get("value_as_string")
        if not last:
            raise RuntimeError("wazuh-monitoring-* sin datos")
        # Wazuh escribe una "foto" de todos los agentes cada ~15 min, con segundos de diferencia
        # entre agentes: se toma la ventana de 14 min antes de la última foto y se cuenta cada
        # agente una sola vez (su estado más reciente).
        q = {"size": 0, "query": {"range": {"timestamp": {"gte": f"{last}||-14m", "lte": last}}},
             "aggs": {"ag": {"terms": {"field": "id", "size": 20000},
                             "aggs": {"last": {"top_hits": {"size": 1, "_source": ["status"],
                                                            "sort": [{"timestamp": "desc"}]}}}}}}
        r = requests.post(f"{self.idx}/wazuh-monitoring-*/_search", json=q,
                          auth=self.idx_auth, verify=self.verify, timeout=TIMEOUT)
        r.raise_for_status()
        b = {}
        for ag in r.json()["aggregations"]["ag"]["buckets"]:
            st = ag["last"]["hits"]["hits"][0]["_source"].get("status", "unknown")
            b[st] = b.get(st, 0) + 1
        out = {k: b.get(k, 0) for k in ("active", "disconnected", "never_connected", "pending")}
        out["total"] = sum(b.values())
        out["fuente"] = f"indexer ({last[:16]})"
        return out

    def alerts_24h(self, min_level: int = 10) -> dict:
        query = {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"timestamp": {"gte": "now-24h"}}},
                {"range": {"rule.level": {"gte": min_level}}},
            ]}},
            "aggs": {
                "top_rules": {"terms": {"field": "rule.description", "size": 10}},
                "top_agents": {"terms": {"field": "agent.name", "size": 10}},
                "por_hora": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h",
                                                "min_doc_count": 0,
                                                "extended_bounds": {"min": "now-24h", "max": "now"}}},
                "por_nivel": {"terms": {"field": "rule.level", "size": 10}},
            },
        }
        r = requests.post(f"{self.idx}/wazuh-alerts-*/_search", json=query,
                          auth=self.idx_auth, verify=self.verify, timeout=TIMEOUT)
        r.raise_for_status()
        d = r.json()
        return {
            "total": d["hits"]["total"]["value"],
            "top_rules": [(b["key"], b["doc_count"]) for b in d["aggregations"]["top_rules"]["buckets"]],
            "top_agents": [(b["key"], b["doc_count"]) for b in d["aggregations"]["top_agents"]["buckets"]],
            "por_hora": [(b["key_as_string"][:13], b["doc_count"]) for b in d["aggregations"]["por_hora"]["buckets"]],
            "por_nivel": sorted([(int(b["key"]), b["doc_count"]) for b in d["aggregations"]["por_nivel"]["buckets"]], reverse=True),
        }

    # ------------------------------------------------------------ panel ampliado
    RANGES = {"24h": ("now-24h", "1h"), "7d": ("now-7d", "6h"), "30d": ("now-30d", "1d")}

    def _search(self, index: str, body: dict) -> dict:
        r = requests.post(f"{self.idx}/{index}/_search", json=body,
                          auth=self.idx_auth, verify=self.verify, timeout=TIMEOUT)
        if r.status_code == 400:  # el indexer explica el motivo (campo no agregable, consulta inválida…)
            try:
                rc = (r.json().get("error") or {}).get("root_cause") or [{}]
                reason = rc[0].get("reason") or r.json()["error"].get("reason")
            except Exception:
                reason = r.text[:200]
            raise requests.HTTPError(f"400 del indexer en {index}: {reason}", response=r)
        r.raise_for_status()
        return r.json()

    def threats(self, rng: str = "24h", min_level: int = 10) -> dict:
        """Alertas, niveles, MITRE, IPs de origen, países y mapa de calor para el rango elegido."""
        since, interval = self.RANGES.get(rng, self.RANGES["24h"])
        flt = [{"range": {"timestamp": {"gte": since}}}, {"range": {"rule.level": {"gte": min_level}}}]
        terms = lambda f, n=10: {"terms": {"field": f, "size": n}}
        core = {
            "hist": {"date_histogram": {"field": "timestamp", "fixed_interval": interval, "min_doc_count": 0,
                                        "extended_bounds": {"min": since, "max": "now"}}},
            "niveles": terms("rule.level", 16),
            "reglas": {"terms": {"field": "rule.id", "size": 10},
                       "aggs": {"d": {"terms": {"field": "rule.description", "size": 1}},
                                "lv": {"max": {"field": "rule.level"}}}},
            "agentes": terms("agent.name"),
        }
        extra = {
            "tacticas": terms("rule.mitre.tactic", 14),
            "tecnicas": {"terms": {"field": "rule.mitre.id", "size": 10},
                         "aggs": {"n": {"terms": {"field": "rule.mitre.technique", "size": 1}}}},
            "ips": terms("data.srcip"),
            "paises": terms("GeoLocation.country_name"),
            "grupos": terms("rule.groups", 12),
            "calor": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h", "min_doc_count": 1}},
        }
        # Las agregaciones se calculan sobre min_level; la lista "recientes" solo con nivel >= 12
        body = {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": flt}},
                "aggs": {**core, **extra,
                         "recientes": {"filter": {"range": {"rule.level": {"gte": max(min_level, 12)}}},
                                       "aggs": {"h": {"top_hits": {"size": 12, "sort": [{"timestamp": "desc"}],
                                                                   "_source": ["timestamp", "agent.name", "rule.id", "rule.level",
                                                                               "rule.description", "data.srcip"]}}}}}}
        try:
            d = self._search("wazuh-alerts-*", body)
        except requests.HTTPError:
            # algún campo opcional no existe con ese tipo: se repite sin los extras
            body["aggs"] = {**core, "recientes": body["aggs"]["recientes"]}
            d = self._search("wazuh-alerts-*", body)
        ag = d["aggregations"]
        kv = lambda k: [(b["key"], b["doc_count"]) for b in ag.get(k, {}).get("buckets", [])]
        return {
            "rango": rng, "min_level": min_level, "total": d["hits"]["total"]["value"],
            "hist": [(b["key"], b["doc_count"]) for b in ag["hist"]["buckets"]],
            "niveles": sorted([(int(k), v) for k, v in kv("niveles")], reverse=True),
            "reglas": [{"id": b["key"], "desc": (b["d"]["buckets"] or [{"key": ""}])[0]["key"],
                        "nivel": int(b["lv"]["value"] or 0), "n": b["doc_count"]} for b in ag["reglas"]["buckets"]],
            "agentes": kv("agentes"), "tacticas": kv("tacticas"), "ips": kv("ips"),
            "paises": kv("paises"), "grupos": kv("grupos"),
            "tecnicas": [{"id": b["key"], "nombre": (b["n"]["buckets"] or [{"key": ""}])[0]["key"], "n": b["doc_count"]}
                         for b in ag.get("tecnicas", {}).get("buckets", [])],
            "calor": [(b["key"], b["doc_count"]) for b in ag.get("calor", {}).get("buckets", [])],
            "recientes": [h["_source"] for h in ag["recientes"]["h"]["hits"]["hits"]],
        }

    ALERT_FIELDS = {"rule.id", "agent.name", "rule.mitre.tactic", "rule.mitre.id", "data.srcip",
                    "GeoLocation.country_name", "rule.level", "rule.groups"}

    def alerts_by(self, field: str, value: str, rng: str = "24h", min_level: int = 10) -> list:
        """Últimas alertas para un filtro (al pulsar un elemento del panel)."""
        if field not in self.ALERT_FIELDS:
            raise ValueError("campo no permitido")
        since = self.RANGES.get(rng, self.RANGES["24h"])[0]
        body = {"size": 25, "sort": [{"timestamp": "desc"}],
                "_source": ["timestamp", "agent.name", "rule.id", "rule.level", "rule.description",
                            "data.srcip", "rule.mitre.tactic", "full_log"],
                "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": since}}},
                                              {"range": {"rule.level": {"gte": min_level}}},
                                              {"term": {field: value}}]}}}
        return [h["_source"] for h in self._search("wazuh-alerts-*", body)["hits"]["hits"]]

    def agents_detail(self) -> dict:
        """Última foto de cada agente en wazuh-monitoring-*: reparto por estado, SO, versión y grupo."""
        last = self._search("wazuh-monitoring-*", {"size": 0, "aggs": {"m": {"max": {"field": "timestamp"}}}}
                            )["aggregations"]["m"].get("value_as_string")
        if not last:
            raise RuntimeError("wazuh-monitoring-* sin datos")
        body = {"size": 0, "query": {"range": {"timestamp": {"gte": f"{last}||-14m", "lte": last}}},
                "aggs": {"ag": {"terms": {"field": "id", "size": 20000},
                                "aggs": {"t": {"top_hits": {"size": 1, "sort": [{"timestamp": "desc"}],
                                                            "_source": ["id", "name", "ip", "status", "os.name", "os.platform",
                                                                        "os.version", "version", "group", "lastKeepAlive",
                                                                        "dateAdd"]}}}}}}
        rows = [b["t"]["hits"]["hits"][0]["_source"] for b in self._search("wazuh-monitoring-*", body)["aggregations"]["ag"]["buckets"]]
        count = lambda f: sorted(_counter(f(r) for r in rows).items(), key=lambda x: -x[1])
        grp = _counter(g for r in rows for g in (r.get("group") or ["(sin grupo)"]))
        return {
            "foto": last[:16], "total": len(rows),
            "estados": count(lambda r: r.get("status", "unknown")),
            "so": count(lambda r: (r.get("os") or {}).get("name") or (r.get("os") or {}).get("platform") or "Desconocido")[:10],
            "versiones": count(lambda r: r.get("version") or "—")[:10],
            "grupos": sorted(grp.items(), key=lambda x: -x[1])[:12],
            "lista": sorted([{"id": r.get("id"), "name": r.get("name"), "ip": r.get("ip"), "status": r.get("status"),
                              "os": ((r.get("os") or {}).get("name") or "") + " " + ((r.get("os") or {}).get("version") or ""),
                              "version": r.get("version"), "group": ", ".join(r.get("group") or []),
                              "last": r.get("lastKeepAlive") or ""} for r in rows],
                            key=lambda r: (r["status"] == "active", r["last"] or "")),
        }

    def search_ioc(self, value: str, days: int = 30) -> dict:
        fields = ["data.srcip", "data.dstip", "data.src_ip", "data.dest_ip", "data.url", "data.hostname",
                  "data.win.eventdata.queryName", "syscheck.sha256_after", "syscheck.md5_after",
                  "syscheck.sha1_after", "data.misp.value", "agent.ip", "full_log"]
        body = {"size": 10, "sort": [{"timestamp": "desc"}], "track_total_hits": True,
                "_source": ["timestamp", "agent.name", "rule.id", "rule.level", "rule.description"],
                "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{days}d"}}},
                                              {"multi_match": {"query": value, "type": "phrase",
                                                               "fields": fields, "lenient": True}}]}},
                "aggs": {"agentes": {"terms": {"field": "agent.name", "size": 8}}}}
        d = self._search("wazuh-alerts-*", body)
        return {"total": d["hits"]["total"]["value"], "alertas": [h["_source"] for h in d["hits"]["hits"]],
                "agentes": [(b["key"], b["doc_count"]) for b in d["aggregations"]["agentes"]["buckets"]]}

    # ------------------------------------------------------------ vulnerabilidades
    # Wazuh 4.8+ guarda el inventario en wazuh-states-vulnerabilities-*; versiones anteriores
    # solo generan alertas (grupo vulnerability-detector) en wazuh-alerts-*.
    VULN_SRC = {
        "states": {"index": "wazuh-states-vulnerabilities-*", "flt": [],
                   "cve": "vulnerability.id", "sev": "vulnerability.severity", "score": "vulnerability.score.base",
                   "pkg": "package.name", "ver": "package.version", "agent": "agent.name", "date": "vulnerability.detected_at"},
        "alerts": {"index": "wazuh-alerts-*", "flt": [{"term": {"rule.groups": "vulnerability-detector"}},
                                                      {"range": {"timestamp": {"gte": "now-30d"}}}],
                   "cve": "data.vulnerability.cve", "sev": "data.vulnerability.severity",
                   "score": "data.vulnerability.cvss.cvss3.base_score", "pkg": "data.vulnerability.package.name",
                   "ver": "data.vulnerability.package.version", "agent": "agent.name", "date": "timestamp",
                   "score_kw": True},  # en wazuh-alerts la puntuación CVSS es keyword (texto)
    }

    def _vsrc(self):
        if getattr(self, "_vs", None):
            return self._vs
        r = requests.get(f"{self.idx}/wazuh-states-vulnerabilities-*/_count", auth=self.idx_auth,
                         verify=self.verify, timeout=TIMEOUT)
        self._vs = "states" if r.ok and r.json().get("count", 0) > 0 else "alerts"
        return self._vs

    def vulns(self, severity: str = "", agent: str = "", q: str = "") -> dict:
        src = self._vsrc(); F = self.VULN_SRC[src]
        flt = list(F["flt"])
        if severity:
            flt.append({"term": {F["sev"]: severity}})
        if agent:
            flt.append({"term": {F["agent"]: agent}})
        if q:
            flt.append({"bool": {"should": [{"wildcard": {F["cve"]: {"value": f"*{q.upper()}*"}}},
                                            {"wildcard": {F["pkg"]: {"value": f"*{q.lower()}*"}}}]}})
        kw = F.get("score_kw")
        score_agg = {"terms": {"field": F["score"], "size": 5}} if kw else {"max": {"field": F["score"]}}
        order = [{"_count": "desc"}] if kw else [{"score": "desc"}, {"_count": "desc"}]
        body = {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": flt}}, "aggs": {
            "sev": {"terms": {"field": F["sev"], "size": 6}},
            "agentes_n": {"cardinality": {"field": F["agent"]}},
            "cves_n": {"cardinality": {"field": F["cve"]}},
            "agentes": {"terms": {"field": F["agent"], "size": 10}},
            "paquetes": {"terms": {"field": F["pkg"], "size": 10}},
            "cves": {"terms": {"field": F["cve"], "size": 60, "order": order},
                     "aggs": {"score": score_agg, "agents": {"cardinality": {"field": F["agent"]}},
                              "sev": {"terms": {"field": F["sev"], "size": 1}}, "pkg": {"terms": {"field": F["pkg"], "size": 3}}}},
        }}
        d = self._search(F["index"], body); ag = d["aggregations"]
        kv = lambda k: [(b["key"], b["doc_count"]) for b in ag[k]["buckets"]]

        def score(b):
            if not kw:
                return b["score"]["value"]
            vals = []
            for x in b["score"]["buckets"]:
                try:
                    vals.append(float(x["key"]))
                except (TypeError, ValueError):
                    pass
            return max(vals) if vals else None
        cves = [{"cve": b["key"], "n": b["doc_count"], "agentes": b["agents"]["value"], "score": score(b),
                 "sev": (b["sev"]["buckets"] or [{"key": ""}])[0]["key"],
                 "paquetes": [x["key"] for x in b["pkg"]["buckets"]]} for b in ag["cves"]["buckets"]]
        if kw:
            cves.sort(key=lambda c: (-(c["score"] or 0), -c["n"]))
        return {"fuente": src, "total": d["hits"]["total"]["value"], "cves_n": ag["cves_n"]["value"],
                "agentes_n": ag["agentes_n"]["value"], "severidad": kv("sev"), "agentes": kv("agentes"),
                "paquetes": kv("paquetes"),
                "cves": cves}

    def vuln_detail(self, cve: str) -> list:
        F = self.VULN_SRC[self._vsrc()]
        body = {"size": 500, "query": {"bool": {"filter": F["flt"] + [{"term": {F["cve"]: cve}}]}},
                "collapse": {"field": F["agent"]}}
        out = []
        for h in self._search(F["index"], body)["hits"]["hits"]:
            src = h["_source"]
            g = lambda path: _get(src, path)
            out.append({"agent": g(F["agent"]), "agent_id": _get(src, "agent.id"), "package": g(F["pkg"]),
                        "version": g(F["ver"]), "severity": g(F["sev"]), "score": g(F["score"]), "date": g(F["date"]),
                        "reference": _get(src, "vulnerability.reference") or _get(src, "data.vulnerability.reference"),
                        "description": _get(src, "vulnerability.description") or _get(src, "data.vulnerability.title")})
        return out

    # ------------------------------------------------------------ MITRE / OWASP
    def mitre_counts(self, days: int = 30) -> dict:
        body = {"size": 0, "query": {"range": {"timestamp": {"gte": f"now-{days}d"}}},
                "aggs": {"t": {"terms": {"field": "rule.mitre.id", "size": 1500}}}}
        return {b["key"]: b["doc_count"] for b in self._search("wazuh-alerts-*", body)["aggregations"]["t"]["buckets"]}

    def mitre_rules(self, tid: str, days: int = 30) -> dict:
        body = {"size": 5, "sort": [{"timestamp": "desc"}], "track_total_hits": True,
                "_source": ["timestamp", "agent.name", "rule.id", "rule.level", "rule.description", "rule.mitre.id"],
                "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{days}d"}}}],
                                   "should": [{"term": {"rule.mitre.id": tid}}, {"prefix": {"rule.mitre.id": tid + "."}}],
                                   "minimum_should_match": 1}},
                "aggs": {"r": {"terms": {"field": "rule.id", "size": 10}, "aggs": {"d": {"terms": {"field": "rule.description", "size": 1}},
                                                                               "lv": {"max": {"field": "rule.level"}}}},
                         "a": {"terms": {"field": "agent.name", "size": 8}}}}
        d = self._search("wazuh-alerts-*", body)
        ag = d["aggregations"]
        return {"total": d["hits"]["total"]["value"], "recientes": [h["_source"] for h in d["hits"]["hits"]],
                "reglas": [{"id": b["key"], "desc": (b["d"]["buckets"] or [{"key": ""}])[0]["key"], "nivel": int(b["lv"]["value"] or 0),
                            "n": b["doc_count"]} for b in ag["r"]["buckets"]],
                "agentes": [(b["key"], b["doc_count"]) for b in ag["a"]["buckets"]]}

    def web_attacks(self, days: int = 30) -> list:
        body = {"size": 0, "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": f"now-{days}d"}}},
                                                         {"terms": {"rule.groups": ["web", "attack", "accesslog", "ids"]}}]}},
                "aggs": {"r": {"terms": {"field": "rule.description", "size": 60}, "aggs": {"ip": {"cardinality": {"field": "data.srcip"}}}}}}
        return [{"desc": b["key"], "n": b["doc_count"], "ips": b["ip"]["value"]}
                for b in self._search("wazuh-alerts-*", body)["aggregations"]["r"]["buckets"]]

    def misp_hits_24h(self) -> list:
        query = {
            "size": 20, "sort": [{"timestamp": "desc"}],
            "_source": ["timestamp", "agent.name", "data.misp"],
            "query": {"bool": {"filter": [
                {"range": {"timestamp": {"gte": "now-24h"}}},
                {"term": {"rule.id": "100622"}},
            ]}},
        }
        r = requests.post(f"{self.idx}/wazuh-alerts-*/_search", json=query,
                          auth=self.idx_auth, verify=self.verify, timeout=TIMEOUT)
        r.raise_for_status()
        return [h["_source"] for h in r.json()["hits"]["hits"]]


# ----------------------------------------------------------------- MISP
class MISP:
    def __init__(self):
        self.url = os.environ["MISP_BASE_URL"].rstrip("/")
        self.h = {"Authorization": os.environ["MISP_API_KEY"],
                  "Accept": "application/json", "Content-Type": "application/json"}
        self.verify = _bool("MISP_VERIFY_TLS", "false")

    def recent_events(self, days: int = 7) -> list:
        body = {"returnFormat": "json", "last": f"{days}d", "metadata": True, "limit": 15}
        r = requests.post(f"{self.url}/events/restSearch", headers=self.h, json=body,
                          verify=self.verify, timeout=TIMEOUT)
        r.raise_for_status()
        out = []
        for e in r.json().get("response", []):
            ev = e.get("Event", {})
            out.append({"id": ev.get("id"), "info": ev.get("info"), "date": ev.get("date"),
                        "threat_level_id": ev.get("threat_level_id"),
                        "attribute_count": ev.get("attribute_count")})
        return out

    def ioc_count(self, days: int = 1) -> int:
        return self.ioc_stats(days)["total"]

    def ioc_stats(self, days: int = 1) -> dict:
        body = {"returnFormat": "json", "last": f"{days}d", "to_ids": 1, "limit": 10000,
                "includeContext": 0}
        r = requests.post(f"{self.url}/attributes/restSearch", headers=self.h, json=body,
                          verify=self.verify, timeout=60)
        r.raise_for_status()
        attrs = r.json().get("response", {}).get("Attribute", [])
        return {"total": len(attrs),
                "tipos": sorted(_counter(a.get("type", "?") for a in attrs).items(), key=lambda x: -x[1])[:10]}

    TLP_TAGS = {"white": "tlp:white", "clear": "tlp:clear", "green": "tlp:green", "amber": "tlp:amber", "red": "tlp:red"}
    CATEGORY = {"ip-dst": "Network activity", "ip-src": "Network activity", "domain": "Network activity",
                "hostname": "Network activity", "url": "Network activity", "email-src": "Payload delivery",
                "md5": "Payload delivery", "sha1": "Payload delivery", "sha256": "Payload delivery"}

    def add_event(self, info: str, iocs: list, tlp: str = "amber", to_ids: bool = True, comment: str = "") -> str:
        """Crea un evento con los IoC como atributos. Necesita una API key con permiso de escritura
        (MISP_WRITE_API_KEY); la clave de solo lectura del panel no sirve para esto."""
        key = os.getenv("MISP_WRITE_API_KEY") or os.environ["MISP_API_KEY"]
        h = {**self.h, "Authorization": key}
        ev = {"Event": {"info": info, "distribution": 0, "threat_level_id": 2, "analysis": 1,
                        "Tag": [{"name": self.TLP_TAGS.get(tlp, "tlp:amber")}, {"name": "source:portal-soc"}],
                        "Attribute": [{"type": i["type"], "category": self.CATEGORY.get(i["type"], "Other"),
                                       "value": i["value"], "to_ids": bool(to_ids), "comment": comment[:250]} for i in iocs]}}
        r = requests.post(f"{self.url}/events/add", headers=h, json=ev, verify=self.verify, timeout=TIMEOUT)
        if r.status_code == 403:
            raise RuntimeError("la API key de MISP no tiene permiso de escritura (define MISP_WRITE_API_KEY)")
        r.raise_for_status()
        return str(r.json()["Event"]["id"])

    def search(self, value: str) -> list:
        body = {"returnFormat": "json", "value": value, "limit": 20, "includeEventTags": 1}
        r = requests.post(f"{self.url}/attributes/restSearch", headers=self.h, json=body,
                          verify=self.verify, timeout=TIMEOUT)
        r.raise_for_status()
        out = []
        for a in r.json().get("response", {}).get("Attribute", []):
            ev = a.get("Event", {})
            out.append({"event_id": a.get("event_id"), "event": ev.get("info"), "type": a.get("type"),
                        "category": a.get("category"), "to_ids": a.get("to_ids"), "value": a.get("value"),
                        "date": ev.get("date") or "",
                        "tags": [t.get("name") for t in (a.get("Tag") or []) + (ev.get("Tag") or [])][:6]})
        return out


# ----------------------------------------------------------------- Shuffle
class Shuffle:
    def __init__(self):
        self.url = os.environ["SHUFFLE_URL"].rstrip("/")
        self.h = {"Authorization": f"Bearer {os.environ['SHUFFLE_API_KEY']}"}

    def workflows(self) -> list:
        r = requests.get(f"{self.url}/api/v1/workflows", headers=self.h, timeout=TIMEOUT)
        r.raise_for_status()
        return [{"id": w.get("id"), "name": w.get("name"),
                 "valid": w.get("is_valid", True),
                 "triggers": sorted({t.get("trigger_type", "") for t in (w.get("triggers") or [])} - {""})}
                for w in r.json()]

    def executions(self, per_workflow: int = 10) -> dict:
        """Últimas ejecuciones de cada workflow y su resultado."""
        runs = []
        for w in self.workflows():
            data = None
            for url in (f"{self.url}/api/v2/workflows/{w['id']}/executions?top={per_workflow}",
                        f"{self.url}/api/v1/workflows/{w['id']}/executions"):
                try:
                    r = requests.get(url, headers=self.h, timeout=TIMEOUT)
                    if r.ok:
                        data = r.json()
                        break
                except requests.RequestException:
                    continue
            if isinstance(data, dict):
                data = data.get("executions") or []
            for e in (data or [])[:per_workflow]:
                runs.append({"workflow": w["name"], "workflow_id": w["id"], "id": e.get("execution_id"),
                             "status": e.get("status", "?"), "started": e.get("started_at") or 0,
                             "completed": e.get("completed_at") or 0})
        runs.sort(key=lambda x: -int(x["started"] or 0))
        return {"recientes": runs[:15], "estados": sorted(_counter(r["status"] for r in runs).items(), key=lambda x: -x[1])}


# ----------------------------------------------------------------- Wiki.js 2.x (GraphQL)
class WikiJS:
    def __init__(self):
        self.url = os.environ["WIKI_URL"].rstrip("/") + "/graphql"
        self.h = {"Authorization": f"Bearer {os.environ['WIKI_API_KEY']}",
                  "Content-Type": "application/json"}
        self.locale = os.getenv("WIKI_LOCALE", "es")

    def gql(self, query: str, variables: dict | None = None) -> dict:
        r = requests.post(self.url, headers=self.h, timeout=TIMEOUT,
                          json={"query": query, "variables": variables or {}})
        r.raise_for_status()
        data = r.json()
        if "errors" in data:
            raise RuntimeError(data["errors"])
        return data["data"]

    def list_pages(self) -> list:
        q = """{ pages { list(orderBy: PATH, limit: 5000) {
                 id path locale title description isPublished tags updatedAt } } }"""
        return self.gql(q)["pages"]["list"]

    def page_id(self, path: str) -> int | None:
        for p in self.list_pages():
            if p["path"] == path and p["locale"] == self.locale:
                return p["id"]
        return None

    def upsert(self, path: str, title: str, content: str, description: str = "",
               tags: list | None = None) -> str:
        tags = tags or ["soc"]
        pid = self.page_id(path)
        if pid is None:
            q = """mutation ($c:String!,$d:String!,$l:String!,$p:String!,$t:[String]!,$ti:String!) {
              pages { create(content:$c, description:$d, editor:"markdown", isPublished:true,
                isPrivate:false, locale:$l, path:$p, tags:$t, title:$ti) {
                responseResult { succeeded message } } } }"""
            res = self.gql(q, {"c": content, "d": description, "l": self.locale,
                               "p": path, "t": tags, "ti": title})["pages"]["create"]
        else:
            q = """mutation ($id:Int!,$c:String!,$d:String!,$t:[String]!,$ti:String!) {
              pages { update(id:$id, content:$c, description:$d, tags:$t, title:$ti,
                isPublished:true) { responseResult { succeeded message } } } }"""
            res = self.gql(q, {"id": pid, "c": content, "d": description,
                               "t": tags, "ti": title})["pages"]["update"]
        rr = res["responseResult"]
        if not rr["succeeded"]:
            raise RuntimeError(rr["message"])
        return "creada" if pid is None else "actualizada"


def now_str() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")
