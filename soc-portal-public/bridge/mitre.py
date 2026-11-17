"""MITRE ATT&CK Enterprise para el portal: matriz, técnicas, alertas de Wazuh por técnica y cobertura.

Datos: se descarga el STIX oficial (attack-stix-data) y se guarda una versión compacta en /data/mitre-enterprise.json.
Sin conexión, se usa una lista básica con las técnicas más frecuentes y las de los runbooks.
"""
import json
import logging
import os
import pathlib
import threading
import time

import requests

log = logging.getLogger("soc-bridge.mitre")
STIX_URL = os.getenv("MITRE_STIX_URL",
                     "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json")
REFRESH_DAYS = int(os.getenv("MITRE_REFRESH_DAYS", "14"))

# 15 tácticas de ATT&CK Enterprise v20 (Defense Evasion se dividió en Stealth y Defense Impairment)
TACTICS = [
    ("TA0043", "reconnaissance", "Reconnaissance", "Reconocimiento"),
    ("TA0042", "resource-development", "Resource Development", "Desarrollo de recursos"),
    ("TA0001", "initial-access", "Initial Access", "Acceso inicial"),
    ("TA0002", "execution", "Execution", "Ejecución"),
    ("TA0003", "persistence", "Persistence", "Persistencia"),
    ("TA0004", "privilege-escalation", "Privilege Escalation", "Escalada de privilegios"),
    ("TA0005", "stealth", "Stealth", "Sigilo"),
    ("TA0112", "defense-impairment", "Defense Impairment", "Debilitamiento de defensas"),
    ("TA0006", "credential-access", "Credential Access", "Acceso a credenciales"),
    ("TA0007", "discovery", "Discovery", "Descubrimiento"),
    ("TA0008", "lateral-movement", "Lateral Movement", "Movimiento lateral"),
    ("TA0009", "collection", "Collection", "Recolección"),
    ("TA0011", "command-and-control", "Command and Control", "Comando y control"),
    ("TA0010", "exfiltration", "Exfiltration", "Exfiltración"),
    ("TA0040", "impact", "Impact", "Impacto"),
]
# Nombres antiguos que todavía usan las reglas de Wazuh
OLD_TACTIC = {"defense-evasion": ["stealth", "defense-impairment"]}

_B = lambda *t: list(t)
FALLBACK = {  # id: (nombre, [tácticas])  — lista básica sin conexión
    "T1595": ("Active Scanning", _B("reconnaissance")), "T1589": ("Gather Victim Identity Information", _B("reconnaissance")),
    "T1598": ("Phishing for Information", _B("reconnaissance")), "T1583": ("Acquire Infrastructure", _B("resource-development")),
    "T1585": ("Establish Accounts", _B("resource-development")), "T1588": ("Obtain Capabilities", _B("resource-development")),
    "T1190": ("Exploit Public-Facing Application", _B("initial-access")), "T1133": ("External Remote Services", _B("initial-access", "persistence")),
    "T1566": ("Phishing", _B("initial-access")), "T1078": ("Valid Accounts", _B("initial-access", "persistence", "privilege-escalation", "stealth")),
    "T1091": ("Replication Through Removable Media", _B("initial-access", "lateral-movement")), "T1195": ("Supply Chain Compromise", _B("initial-access")),
    "T1199": ("Trusted Relationship", _B("initial-access")), "T1189": ("Drive-by Compromise", _B("initial-access")),
    "T1059": ("Command and Scripting Interpreter", _B("execution")), "T1204": ("User Execution", _B("execution")),
    "T1047": ("Windows Management Instrumentation", _B("execution")), "T1053": ("Scheduled Task/Job", _B("execution", "persistence", "privilege-escalation")),
    "T1072": ("Software Deployment Tools", _B("execution", "lateral-movement")), "T1203": ("Exploitation for Client Execution", _B("execution")),
    "T1569": ("System Services", _B("execution")), "T1543": ("Create or Modify System Process", _B("persistence", "privilege-escalation")),
    "T1547": ("Boot or Logon Autostart Execution", _B("persistence", "privilege-escalation")), "T1546": ("Event Triggered Execution", _B("persistence", "privilege-escalation")),
    "T1136": ("Create Account", _B("persistence")), "T1098": ("Account Manipulation", _B("persistence", "privilege-escalation")),
    "T1505": ("Server Software Component", _B("persistence")), "T1542": ("Pre-OS Boot", _B("persistence", "stealth")),
    "T1068": ("Exploitation for Privilege Escalation", _B("privilege-escalation")), "T1548": ("Abuse Elevation Control Mechanism", _B("privilege-escalation", "stealth")),
    "T1484": ("Domain or Tenant Policy Modification", _B("privilege-escalation", "defense-impairment")),
    "T1027": ("Obfuscated Files or Information", _B("stealth")), "T1036": ("Masquerading", _B("stealth")), "T1218": ("System Binary Proxy Execution", _B("stealth")),
    "T1564": ("Hide Artifacts", _B("stealth")), "T1014": ("Rootkit", _B("stealth")), "T1055": ("Process Injection", _B("stealth", "privilege-escalation")),
    "T1140": ("Deobfuscate/Decode Files or Information", _B("stealth")), "T1497": ("Virtualization/Sandbox Evasion", _B("stealth", "discovery")),
    "T1207": ("Rogue Domain Controller", _B("stealth")), "T1550": ("Use Alternate Authentication Material", _B("stealth", "lateral-movement")),
    "T1562": ("Impair Defenses", _B("defense-impairment")), "T1070": ("Indicator Removal", _B("defense-impairment", "stealth")),
    "T1112": ("Modify Registry", _B("stealth", "defense-impairment")), "T1601": ("Modify System Image", _B("defense-impairment")),
    "T1110": ("Brute Force", _B("credential-access")), "T1003": ("OS Credential Dumping", _B("credential-access")),
    "T1555": ("Credentials from Password Stores", _B("credential-access")), "T1552": ("Unsecured Credentials", _B("credential-access")),
    "T1558": ("Steal or Forge Kerberos Tickets", _B("credential-access")), "T1621": ("Multi-Factor Authentication Request Generation", _B("credential-access")),
    "T1528": ("Steal Application Access Token", _B("credential-access")), "T1056": ("Input Capture", _B("credential-access", "collection")),
    "T1046": ("Network Service Discovery", _B("discovery")), "T1087": ("Account Discovery", _B("discovery")), "T1082": ("System Information Discovery", _B("discovery")),
    "T1018": ("Remote System Discovery", _B("discovery")), "T1083": ("File and Directory Discovery", _B("discovery")), "T1069": ("Permission Groups Discovery", _B("discovery")),
    "T1021": ("Remote Services", _B("lateral-movement")), "T1570": ("Lateral Tool Transfer", _B("lateral-movement")), "T1534": ("Internal Spearphishing", _B("lateral-movement")),
    "T1114": ("Email Collection", _B("collection")), "T1560": ("Archive Collected Data", _B("collection")), "T1213": ("Data from Information Repositories", _B("collection")),
    "T1530": ("Data from Cloud Storage", _B("collection")), "T1005": ("Data from Local System", _B("collection")),
    "T1071": ("Application Layer Protocol", _B("command-and-control")), "T1573": ("Encrypted Channel", _B("command-and-control")),
    "T1095": ("Non-Application Layer Protocol", _B("command-and-control")), "T1105": ("Ingress Tool Transfer", _B("command-and-control")),
    "T1219": ("Remote Access Tools", _B("command-and-control")), "T1572": ("Protocol Tunneling", _B("command-and-control")),
    "T1041": ("Exfiltration Over C2 Channel", _B("exfiltration")), "T1048": ("Exfiltration Over Alternative Protocol", _B("exfiltration")),
    "T1052": ("Exfiltration Over Physical Medium", _B("exfiltration")), "T1567": ("Exfiltration Over Web Service", _B("exfiltration")),
    "T1486": ("Data Encrypted for Impact", _B("impact")), "T1490": ("Inhibit System Recovery", _B("impact")), "T1489": ("Service Stop", _B("impact")),
    "T1485": ("Data Destruction", _B("impact")), "T1491": ("Defacement", _B("impact")), "T1496": ("Resource Hijacking", _B("impact")),
    "T1498": ("Network Denial of Service", _B("impact")), "T1499": ("Endpoint Denial of Service", _B("impact")), "T1657": ("Financial Theft", _B("impact")),
    "T1656": ("Impersonation", _B("stealth")),
}


class Mitre:
    def __init__(self, data_dir: str):
        self.path = pathlib.Path(data_dir) / "mitre-enterprise.json"
        self.data = None
        self._lock = threading.Lock()
        self.status = ""
        self._load()
        if not self.data or time.time() - self.data.get("fetched", 0) > REFRESH_DAYS * 86400:
            threading.Thread(target=self.refresh, daemon=True).start()

    def _load(self):
        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            self.data = None

    def refresh(self):
        """Descarga el STIX oficial (~50 MB) y guarda solo lo necesario."""
        with self._lock:
            try:
                self.status = "descargando"
                r = requests.get(STIX_URL, timeout=(20, 300))
                r.raise_for_status()
                objs = r.json()["objects"]
                version = next((o.get("x_mitre_version") for o in objs if o.get("type") == "x-mitre-collection"), "")
                techs = {}
                for o in objs:
                    if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
                        continue
                    ref = next((e for e in o.get("external_references", []) if e.get("source_name") == "mitre-attack"), None)
                    if not ref:
                        continue
                    techs[ref["external_id"]] = {
                        "id": ref["external_id"], "name": o.get("name", ""), "url": ref.get("url", ""),
                        "tactics": [k["phase_name"] for k in o.get("kill_chain_phases", []) if k.get("kill_chain_name") == "mitre-attack"],
                        "platforms": o.get("x_mitre_platforms", []), "sub": bool(o.get("x_mitre_is_subtechnique")),
                        "desc": (o.get("description") or "")[:1500], "detection": (o.get("x_mitre_detection") or "")[:1200]}
                out = {"version": version, "fetched": int(time.time()), "techniques": techs}
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
                tmp.replace(self.path)
                self.data = out
                self.status = f"actualizado (v{version}, {len(techs)} técnicas)"
                log.info("MITRE ATT&CK %s", self.status)
            except Exception as exc:
                self.status = f"sin conexión: {str(exc)[:120]}"
                log.warning("MITRE ATT&CK no se pudo descargar: %s", exc)

    def techniques(self):
        if self.data:
            return self.data["techniques"], "stix", self.data.get("version", "")
        t = {k: {"id": k, "name": n, "tactics": tac, "url": f"https://attack.mitre.org/techniques/{k}/", "platforms": [],
                 "sub": False, "desc": "", "detection": ""} for k, (n, tac) in FALLBACK.items()}
        return t, "basica", ""

    def matrix(self, alerts: dict, runbooks: dict, marks: dict):
        """alerts: {Txxxx[.yyy]: n}; runbooks: {Txxxx: [runbook]}; marks: {Txxxx: {status, note}}."""
        techs, src, ver = self.techniques()
        par = lambda t: t.split(".")[0]
        a_par, rb_par = {}, {}
        for k, n in alerts.items():
            a_par[par(k)] = a_par.get(par(k), 0) + n
        for k, lst in runbooks.items():
            rb_par.setdefault(par(k), []).extend(x for x in lst if x not in rb_par.get(par(k), []))
        subs = {}
        for t in techs.values():
            if t["sub"]:
                subs.setdefault(par(t["id"]), 0)
                subs[par(t["id"])] += 1
        cols = []
        for tid, short, name, name_es in TACTICS:
            items = []
            for t in techs.values():
                if t["sub"]:
                    continue
                tacs = [x for tac in t["tactics"] for x in OLD_TACTIC.get(tac, [tac])]
                if short in tacs:
                    m = marks.get(t["id"], {})
                    items.append({"id": t["id"], "name": t["name"], "subs": subs.get(t["id"], 0), "alerts": a_par.get(t["id"], 0),
                                  "runbooks": rb_par.get(t["id"], []), "mark": m.get("status", "")})
            items.sort(key=lambda x: (-x["alerts"], -len(x["runbooks"]), x["name"]))
            cols.append({"id": tid, "short": short, "name": name, "name_es": name_es, "techniques": items,
                         "alerts": sum(x["alerts"] for x in items)})
        parents = {t["id"] for t in techs.values() if not t["sub"]}
        return {"source": src, "version": ver, "status": self.status, "tactics": cols,
                "stats": {"tecnicas": len(parents), "con_alertas": sum(1 for p in parents if a_par.get(p)),
                          "con_runbook": sum(1 for p in parents if rb_par.get(p)),
                          "detectadas": sum(1 for p in parents if marks.get(p, {}).get("status") == "detectada"),
                          "parciales": sum(1 for p in parents if marks.get(p, {}).get("status") == "parcial"),
                          "sin_cobertura": sum(1 for p in parents if marks.get(p, {}).get("status") == "sin_cobertura"),
                          "alertas": sum(a_par.values())}}

    def detail(self, tid: str):
        techs, src, _ = self.techniques()
        t = techs.get(tid)
        if not t:
            return None
        names = {k: v["tactics"] for k, v in techs.items()}
        tac_es = {s: es for _, s, _, es in TACTICS}
        return {**t, "tactics_es": [tac_es.get(x, x) for tac in names[tid] for x in OLD_TACTIC.get(tac, [tac])],
                "subtechniques": sorted([{"id": k, "name": v["name"]} for k, v in techs.items() if k.startswith(tid + ".")], key=lambda x: x["id"]),
                "source": src}
