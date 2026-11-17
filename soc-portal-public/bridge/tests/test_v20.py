"""Pruebas v20: alteraciones fuera del texto, comparación visual y alcance del módulo de exposición."""
import datetime
import io
import ipaddress
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import deface  # noqa: E402
import exposure  # noqa: E402
import screens  # noqa: E402
from test_deface import BASE, U, page  # noqa: E402


def cmp(base_extra, snap_extra, scope=None):
    b = {**BASE, **base_extra}
    s = {**deface.snapshot(page(), U), **snap_extra}
    return deface.compare(b, s, 40, scope=scope)


def test_formulario_contrasena_es_sospecha():
    s = deface.snapshot(page(body="<form><input type='password' name='p'></form>"), U)
    r = deface.compare(BASE, s, 40)
    assert r["nivel"] in ("sospecha", "defacement")
    assert any("contraseña" in m["motivo"] for m in r["motivos"])


def test_cabeceras_y_servidor():
    r = cmp({"headers": {"security": ["strict-transport-security", "content-security-policy"], "server": "nginx"}},
            {"headers": {"security": ["content-security-policy"], "server": "Apache/2.2"}})
    assert r["nivel"] == "cambio"
    assert any("HSTS" in m["motivo"] for m in r["motivos"])


def test_dns_fuera_de_alcance_es_sospecha():
    nets = [ipaddress.ip_network("5.180.20.0/23")]
    r = cmp({"dns": ["5.180.20.10"]}, {"dns": ["185.1.2.3"]}, scope=nets)
    assert r["nivel"] == "sospecha"
    r2 = cmp({"dns": ["5.180.20.10"]}, {"dns": ["5.180.21.20"]}, scope=nets)
    assert r2["nivel"] == "cambio"


def test_script_modificado_vs_despliegue():
    base = {f"/js/{i}.js": "a" for i in range(6)}
    one = dict(base, **{"/js/0.js": "b"})
    assert cmp({"assets": base}, {"assets": one})["nivel"] == "sospecha"
    many = {k: "z" for k in base}
    assert cmp({"assets": base}, {"assets": many})["nivel"] == "cambio"


def test_bases_antiguas_no_alertan():
    s = {**deface.snapshot(page(), U), "headers": {"security": []}, "dns": ["1.1.1.1"], "assets": {"/a.js": "x"}}
    assert deface.compare(BASE, s, 40)["nivel"] == "ok"


def _img(color, box=None):
    from PIL import Image, ImageDraw
    im = Image.new("RGB", (1280, 840), color)
    if box:
        ImageDraw.Draw(im).rectangle(box, fill=(0, 0, 0))
    b = io.BytesIO()
    im.save(b, "JPEG")
    return b.getvalue()


def test_comparacion_visual():
    a = _img((255, 255, 255))
    assert screens.compare(a, a)[0] == 0
    pct, diff = screens.compare(a, _img((0, 0, 0)))
    assert pct > 90 and diff[:2] == b"\xff\xd8"
    small, _ = screens.compare(a, _img((255, 255, 255), (0, 0, 100, 20)))
    assert small < 5
    assert screens.level(small) == "ok" and screens.level(45) == "cambio" and screens.level(80) == "sospecha"


@pytest.fixture
def exp(tmp_path, monkeypatch):
    monkeypatch.delenv("EXPOSURE_ALLOW_PRIVATE", raising=False)
    return exposure.Exposure(str(tmp_path / "exposure.db"))


def test_alcance_validacion(exp):
    with pytest.raises(exposure.ScopeError):
        exp.save_config({"rangos": ["10.0.0.0/8"]}, "admin")
    with pytest.raises(exposure.ScopeError):
        exp.save_config({"rangos": ["45.0.0.0/8"]}, "admin")
    with pytest.raises(exposure.ScopeError):
        exp.save_config({"dominios": ["no es dominio"]}, "admin")
    c = exp.save_config({"dominios": ["*.ACME.example"], "rangos": ["5.180.20.0/23"], "excluidos": ["5.180.20.1"]}, "admin")
    assert c["dominios"] == ["acme.example"]
    assert exp.in_scope_ip("5.180.21.7") and not exp.in_scope_ip("5.180.20.1") and not exp.in_scope_ip("8.8.8.8")
    assert exp.in_scope_host("portal.acme.example") and not exp.in_scope_host("acme.example.evil.com")


def test_autorizacion(exp):
    assert exp.authorized()[0] is False
    ayer = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    exp.save_config({"autorizacion": {"por": "Dir", "referencia": "Memo 1", "hasta": ayer}}, "admin")
    ok, msg = exp.authorized()
    assert not ok and "venció" in msg
    exp.save_config({"autorizacion": {"por": "Dir", "referencia": "Memo 1", "hasta": "2099-01-01"}}, "admin")
    assert exp.authorized()[0] is True
    assert exp.config()["autorizacion"]["registrado_por"] == "admin"


def test_activo_sin_autorizacion_rechazado(exp):
    exp.save_config({"rangos": ["5.180.20.0/24"]}, "admin")
    with pytest.raises(Exception):
        exp.start("completo", "admin", {"hosts": set(), "ips": set()})
