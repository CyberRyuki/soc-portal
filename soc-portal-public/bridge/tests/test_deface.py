"""Pruebas de la detección de desfiguración y de la importación de portales.   python3 -m pytest tests -q"""
import io
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import deface  # noqa: E402
import feeds  # noqa: E402

U = "https://municipio.example/"


def page(body="", title="Ayuntamiento | Inicio", extra=""):
    news = "".join(f"<article><h3>Noticia {i}</h3><p>El ayuntamiento informa sobre la jornada {i} de limpieza, servicios "
                   f"y obras en el sector {i} del municipio.</p></article>" for i in range(6))
    return (f"<html><head><title>{title}</title><script src='/js/app.js'></script>{extra}</head><body><nav>Inicio "
            f"Transparencia Servicios</nav><h1>Ayuntamiento Municipal</h1>{news}{body}<footer>Aviso legal · Visitas 1234"
            f"</footer></body></html>")


BASE = deface.snapshot(page(), U)


def level(html):
    return deface.compare(BASE, deface.snapshot(html, U), 40)["nivel"]


def test_cambios_legitimos_no_alertan():
    assert level(page().replace("1234", "99999")) == "ok"  # contadores y fechas
    assert level(page().replace("Noticia 0", "Entrega de útiles escolares")) == "ok"  # una noticia nueva


def test_defacement_clasico():
    v = deface.compare(BASE, deface.snapshot("<title>Hacked by X</title><h1>HACKED BY X</h1><p>Greetz</p>", U))
    assert v["nivel"] == "defacement" and v["cambio_pct"] == 100


def test_firma_ya_presente_en_la_base_no_alerta():
    base = deface.snapshot(page("<p>Noticia: el sitio de otro país fue hacked by un grupo</p>"), U)
    v = deface.compare(base, deface.snapshot(page("<p>Noticia: el sitio de otro país fue hacked by un grupo</p>"), U))
    assert v["nivel"] == "ok"


def test_inyecciones():
    assert level(page("<div style='display:none'>slot gacor maxwin</div>")) == "sospecha"
    assert level(page(extra="<script src='https://cdn-evil.top/x.js'></script>")) == "sospecha"
    assert level(page(extra="<script>window.location='https://evil.ru/'</script>")) == "sospecha"
    assert level(page(extra="<script src='https://cdn.municipio.example/x.js'></script>")) == "ok"  # mismo dominio


def test_pagina_vaciada_y_titulo():
    assert level("<title>Ayuntamiento | Inicio</title><p>En mantenimiento</p>") == "sospecha"
    assert level(page(title="Otro título")) == "cambio"


def test_base_domain():
    assert deface.base_domain("www.acme.example") == "acme.example"
    assert deface.base_domain("cdn.jsdelivr.net") == "jsdelivr.net"


def test_diff():
    d = deface.diff("a\nb\nc", "a\nX\nc")
    assert d == {"quitado": ["b"], "añadido": ["X"]}


def test_import_csv_y_xlsx():
    csv = b"Portal,Plan,Estado,IP publica,Servidor\nacme.example,Enterprise,Bypass,1.2.3.4,SRV1\nwww.acme.example/,,,,\n"
    rows = feeds.parse_sites_file(csv, "p.csv")
    assert rows == [{"name": "acme.example", "url": "https://acme.example/", "waf": "bypass", "plan": "Enterprise",
                     "public_ip": "1.2.3.4", "backend_ip": "", "server": "SRV1", "vs": "", "grp": ""}]
    import pytest
    openpyxl = pytest.importorskip("openpyxl")
    wb = openpyxl.Workbook()
    ws = wb.active; ws.title = "Pasan por WAF"; ws.append(["#", "Portal", "Plan"]); ws.append([1, "a.example", "Free"])
    ws2 = wb.create_sheet("NO pasan por WAF"); ws2.append(["#", "Portal", "Estado"]); ws2.append([1, "b.example", "Backend directo"])
    b = io.BytesIO(); wb.save(b)
    got = {r["name"]: r["waf"] for r in feeds.parse_sites_file(b.getvalue(), "x.xlsx")}
    assert got == {"a.example": "waf", "b.example": "directo"}


def test_sugerencias_se_agrupan(tmp_path):
    import store as S
    st = S.Store(str(tmp_path / "s.db"), tmp_path)
    a = st.suggest_incident({"title": "Portal caído: x", "severity": "High"}, "monitor", "site-down-1")
    b = st.suggest_incident({"title": "Portal caído: x", "severity": "Critical"}, "monitor", "site-down-1")
    assert a == b
    rows = st.suggestions()
    assert len(rows) == 1 and rows[0]["n"] == 2 and rows[0]["severity"] == "Critical"
    assert st.decide_suggestion(a, "dismissed", "ana") == 1
    assert st.decide_suggestion(a, "dismissed", "ana") == 0  # ya decidida
    assert st.suggestions() == [] and len(st.incidents()) == 0


def test_hora_local_de_fechas_utc():
    import datetime
    import re
    src = (pathlib.Path(__file__).parent.parent / "app.py").read_text()
    ns = {"datetime": datetime, "re": re}
    exec(src[src.index("def _local("):src.index("_ES = [")], ns)
    exec(src[src.index("_ES = ["):src.index("def _since")], ns)
    utc = datetime.datetime(2026, 11, 17, 18, 0, tzinfo=datetime.timezone.utc)
    assert ns["_local"]("2026-11-17T18:00:00.000Z") == utc.astimezone().strftime("%Y-%m-%d %H:%M")
    assert ns["_local"]("2026-11-17 14:07:33") == "2026-11-17 14:07"
    assert ns["_es"]("Status: Open → Closed") == "Estado: Abierto → Cerrado"
