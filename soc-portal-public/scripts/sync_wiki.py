#!/usr/bin/env python3
"""
Sincroniza el contenido del portal (wiki-content/) con Wiki.js.
  - Crea o actualiza cada página (etiqueta "managed").
  - Borra páginas gestionadas que ya no existen en wiki-content/ (nunca toca incidentes
    ni páginas sin la etiqueta "managed").
  - Borra las páginas antiguas en español (--prune-legacy).
  - Aplica el estilo visual theme.css (--theme).
Uso:  set -a; source .env; set +a; export WIKI_URL=http://$HOST_IP:3000
      python3 scripts/sync_wiki.py --prune-legacy --theme
"""
import os, pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bridge"))
from connectors import WikiJS  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent / "wiki-content"
AUTO = {"soc/status", "soc/inventory"}            # páginas que genera el sistema
LEGACY = ["soc", "soc/automatizacion", "soc/incidentes", "soc/inteligencia", "soc/monitorizacion",
          "soc/plantillas/incidente", "soc/runbooks", "soc/runbooks/alerta-critica",
          "soc/runbooks/ioc-misp", "soc/runbooks/phishing", "soc/estado", "soc/inventario"]
SUBS = {
    "PORTAL_URL": os.getenv("PORTAL_PUBLIC_URL", f"http://{os.getenv('HOST_IP', 'HOST_IP')}:8088/portal/"),
    "WAZUH_HOST": os.getenv("WAZUH_HOST", "WAZUH_HOST"),
    "HOST_IP": os.getenv("HOST_IP", "HOST_IP"),
}


def parse(md):
    meta, body = {}, md
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", md, re.S)
    if m:
        for line in m.group(1).splitlines():
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip().strip('"')
        body = m.group(2)
    for k, v in SUBS.items():
        body = body.replace(k, v)
    tags = [t.strip() for t in meta.get("tags", "soc").split(",") if t.strip()]
    if "managed" not in tags:
        tags.append("managed")
    return meta.get("title", "Untitled"), meta.get("description", ""), tags, body


def to_path(f):
    rel = f.relative_to(ROOT).with_suffix("").as_posix()
    if rel == "home":
        return "soc"
    if rel.endswith("/index"):
        rel = rel[: -len("/index")]
    return f"soc/{rel}"


def delete(wiki, pid):
    q = "mutation ($id:Int!){ pages { delete(id:$id) { responseResult { succeeded message } } } }"
    return wiki.gql(q, {"id": pid})["pages"]["delete"]["responseResult"]["succeeded"]


def apply_theme(wiki, css):
    cfg = wiki.gql("{ theming { config { theme iconset darkMode injectHead injectBody } } }")["theming"]["config"]
    q = """mutation ($t:String!,$i:String!,$d:Boolean!,$c:String,$h:String,$b:String){
      theming { setConfig(theme:$t, iconset:$i, darkMode:$d, injectCSS:$c, injectHead:$h, injectBody:$b) {
        responseResult { succeeded message } } } }"""
    r = wiki.gql(q, {"t": cfg["theme"], "i": cfg["iconset"], "d": cfg["darkMode"], "c": css,
                     "h": cfg.get("injectHead") or "", "b": cfg.get("injectBody") or ""})
    return r["theming"]["setConfig"]["responseResult"]


def main():
    wiki = WikiJS()
    managed = set()
    print(f"Idioma de la Wiki: {wiki.locale}\n== Páginas")
    for f in sorted(ROOT.rglob("*.md")):
        title, desc, tags, body = parse(f.read_text(encoding="utf-8"))
        path = to_path(f)
        managed.add(path)
        print(f"   {path:<32} {wiki.upsert(path, title, body, desc, tags)}")

    pages = wiki.list_pages()
    print("== Limpieza")
    for p in pages:
        tags = p.get("tags") or []
        same_locale = p["locale"] == wiki.locale
        if same_locale and "managed" in tags and p["path"] not in managed | AUTO:
            print(f"   borrada (ya no existe en wiki-content): {p['locale']}/{p['path']}", delete(wiki, p["id"]))
        elif "--prune-legacy" in sys.argv and p["path"] in LEGACY and \
                (not same_locale or p["path"] not in managed):
            print(f"   borrada (antigua): {p['locale']}/{p['path']}", delete(wiki, p["id"]))

    if "--theme" in sys.argv:
        print("== Estilo")
        try:
            r = apply_theme(wiki, (ROOT / "theme.css").read_text(encoding="utf-8"))
            print("   aplicado" if r["succeeded"] else f"   no aplicado: {r['message']}")
        except Exception as e:
            print(f"   no se pudo aplicar por API ({e}).\n   Pégalo a mano en Admin → Theme → Code Injection → CSS Override:"
                  f" {ROOT / 'theme.css'}")
    print("\nListo.")


if __name__ == "__main__":
    main()
