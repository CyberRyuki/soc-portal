#!/usr/bin/env python3
"""
Inventario completo de Wiki.js: lista TODAS las páginas (ruta, título, idioma,
etiquetas, publicada, última actualización).
  - Exporta inventario_wiki.csv
  - Publica/actualiza la página /soc/inventario (desactivar con --no-publish)
Uso: set -a; source .env; set +a; WIKI_URL=http://HOST_IP:3000 python3 scripts/inventario_wiki.py
"""
import csv
import pathlib
import sys
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bridge"))
from connectors import WikiJS, now_str  # noqa: E402


def main():
    wiki = WikiJS()
    pages = wiki.list_pages()

    with open("inventario_wiki.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "ruta", "idioma", "titulo", "publicada", "etiquetas", "actualizada"])
        for p in pages:
            w.writerow([p["id"], p["path"], p["locale"], p["title"], p["isPublished"],
                        ";".join(p.get("tags") or []), p["updatedAt"]])
    print(f"{len(pages)} páginas -> inventario_wiki.csv")

    if "--no-publish" in sys.argv:
        return

    secciones = Counter(p["path"].split("/")[0] for p in pages)
    L = ["# Wiki inventory", f"> Generated **{now_str()}** · {len(pages)} pages · run `scripts/inventario_wiki.py` to refresh", "{.is-info}", "",
         "## By section", "| Section | Pages |", "|---|---|"]
    L += [f"| `{s}` | {n} |" for s, n in sorted(secciones.items())]
    L += ["", "## All pages", "| Page | Path | Locale | Tags | Published | Updated |",
          "|---|---|---|---|---|---|"]
    for p in pages:
        t = (p["title"] or "").replace("|", "\\|")
        L.append(f"| [{t}](/{p['path']}) | `{p['path']}` | {p['locale']} | "
                 f"{', '.join(p.get('tags') or [])} | {'✅' if p['isPublished'] else '—'} | "
                 f"{(p['updatedAt'] or '')[:10]} |")
    print("soc/inventory", wiki.upsert("soc/inventory", "Wiki inventory", "\n".join(L) + "\n",
                                     "Automatic list of every page", ["soc", "inventory", "auto"]))


if __name__ == "__main__":
    main()
