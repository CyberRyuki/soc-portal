#!/usr/bin/env python3
"""
Crea un incidente nuevo en la Wiki a partir de la plantilla, con el siguiente número libre.
  soc/incidents/<año>/INC-<año>-NNN
Uso:  set -a; source .env; set +a; export WIKI_URL=http://$HOST_IP:3000
      python3 scripts/new_incident.py "Brute force on srv-dc01" --severity High
"""
import argparse, datetime, os, pathlib, re, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bridge"))
from connectors import WikiJS  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("title", help="Título corto del incidente")
ap.add_argument("--severity", default="High", choices=["Critical", "High", "Medium", "Low"])
ap.add_argument("--owner", default="")
a = ap.parse_args()

wiki = WikiJS()
year = datetime.date.today().year
prefix = f"soc/incidents/{year}/INC-{year}-"
nums = [int(m.group(1)) for p in wiki.list_pages()
        if p["locale"] == wiki.locale and (m := re.match(re.escape(prefix) + r"(\d+)$", p["path"]))]
num = max(nums, default=0) + 1
inc = f"INC-{year}-{num:03d}"
path = f"soc/incidents/{year}/{inc}"

tpl = (ROOT / "wiki-content/templates/incident.md").read_text(encoding="utf-8")
body = re.sub(r"^---\n.*?\n---\n", "", tpl, flags=re.S)
body = body.replace("# INC-YYYY-NNN — Title", f"# {inc} — {a.title}")
body = re.sub(r"> Copy this page.*?\n\{\.is-info\}\n", "", body, flags=re.S)
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
body = body.replace("| Detected | |", f"| Detected | {now} |")
body = body.replace("| Severity | Critical / High / Medium / Low |", f"| Severity | {a.severity} |")
body = body.replace("| Status | Open / Contained / Closed |", "| Status | Open |")
body = body.replace("| Owner | |", f"| Owner | {a.owner} |")

r = wiki.upsert(path, f"{inc} — {a.title}", body, f"{a.severity} · Open", ["soc", "incident", a.severity.lower()])
host = os.getenv("WIKI_PUBLIC_URL", os.getenv("WIKI_URL", "")).rstrip("/")
print(f"{inc} {r}: {host}/{path}")
