"""Pruebas de la auditoría y del lector de informes de Pentera.   cd bridge && python3 -m pytest tests -q"""
import json
import pathlib
import sqlite3
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent))

import audit  # noqa: E402
import pentera  # noqa: E402


def test_redact_oculta_secretos_y_recorta():
    r = audit.redact({"password": "x", "api_key": "y", "auth_header": "Auth-Key: z", "title": "ok", "ext_key": "k",
                      "nested": {"client_secret": "s"}, "long": "a" * 500})
    assert r["password"] == r["api_key"] == r["auth_header"] == r["nested"]["client_secret"] == "••••"
    assert r["title"] == "ok" and r["ext_key"] == "k" and r["long"].endswith("(500 caracteres)")


def test_redact_estricto_en_cuentas():
    r = audit.redact({"username": "ana", "current": "Clave1", "new": "Clave2", "whatever": "z"}, strict=True)
    assert r == {"username": "ana", "current": "••••", "new": "••••", "whatever": "••••"}


def test_describe_rutas():
    assert audit.describe("POST", "/portal/api/vulns/pentera/3/import") == ("Vulnerabilidades · Pentera", "Importar", "Informe #3")
    assert audit.describe("DELETE", "/portal/api/incidents/INC-2026-001") == ("Incidentes", "Eliminar", "INC-2026-001")
    assert audit.describe("POST", "/portal/api/sophos/actions/4/approve")[1:] == ("Aprobar", "Acción #4")


def test_cadena_de_hashes_detecta_manipulacion(tmp_path):
    a = audit.Audit(str(tmp_path / "a.db"))
    for i in range(5):
        a.record(user="ana", method="POST", path=f"/x/{i}", status=200)
    assert a.verify()["ok"]
    db = sqlite3.connect(tmp_path / "a.db")
    db.execute("UPDATE changes SET user = 'otro' WHERE id = 3"); db.commit()
    v = a.verify()
    assert not v["ok"] and v["alterado"] == 3


def test_purge_conserva_la_cadena(tmp_path):
    a = audit.Audit(str(tmp_path / "a.db"))
    for i in range(4):
        a.record(user="ana", method="POST", path=f"/x/{i}", status=200, ts=1000 + i)  # registros «antiguos»
    a.record(user="ana", method="POST", path="/x/nuevo", status=200)
    assert a.purge(1) == 4
    assert a.verify() == {"ok": True, "registros": 1, "mensaje": "Cadena íntegra: 1 registros verificados"}


def test_pentera_severidad():
    assert [pentera.sev_from_score(x) for x in (10, 7.5, 7.4, 5, 2.5, 2.4, 0)] == [
        "Critical", "Critical", "High", "High", "Medium", "Low", None]


def test_pentera_pdf_bloques():
    r = pentera.parse((HERE / "pentera_bloques.pdf").read_bytes(), "x.pdf")
    t = {i["title"]: i for i in r["items"]}
    assert r["estrategia"] == "bloques" and len(t) == 5  # el informativo (0) se omite
    assert t["SMB Signing Not Required"]["asset"] == "10.0.1.10, 10.0.1.11, 10.0.5.21"
    assert t["SMB Signing Not Required"]["port"] == "445"
    assert "CVE-2021-44228" in next(i["cve"] for k, i in t.items() if "Log4j" in k)
    assert t["LLMNR Enabled"]["severity"] == "High"


def test_pentera_pdf_tabla():
    r = pentera.parse((HERE / "pentera_tabla.pdf").read_bytes(), "x.pdf")
    assert r["estrategia"] == "tabla"
    assert [(i["title"], i["severity"]) for i in r["items"]][:2] == [
        ("Credenciales en texto claro en scripts", "Critical"), ("Kerberoasting de cuentas de servicio", "Critical")]


def test_pentera_json_y_csv():
    j = {"vulnerabilities": [{"name": "SMB Signing", "severity": 8.6, "targets": [{"ip": "10.0.1.10"}], "port": 445},
                             {"name": "Info", "severity": 0}],
         "achievements": [{"name": "Domain Admin", "severity": 9.8, "target_id": "DC01"}]}
    r = pentera.parse(json.dumps(j).encode(), "p.json")
    assert [(i["title"], i["asset"]) for i in r["items"]] == [("SMB Signing", "10.0.1.10"), ("Logro de Pentera: Domain Admin", "DC01")]
    c = b"Name,Severity,Target,Port\nLLMNR Enabled,5.2,10.0.9.77;10.0.9.78,\n"
    assert pentera.parse(c, "p.csv")["items"][0]["asset"] == "10.0.9.77, 10.0.9.78"


def test_pentera_pdf_sin_texto():
    import io
    import pytest
    canvas = pytest.importorskip("reportlab.pdfgen.canvas")  # PDF sin texto (como un escaneo)
    b = io.BytesIO(); cv = canvas.Canvas(b); cv.rect(10, 10, 100, 100); cv.save()
    r = pentera.parse(b.getvalue(), "scan.pdf")
    assert not r["items"] and "escaneo" in r["aviso"]
