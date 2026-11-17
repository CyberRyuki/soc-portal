"""Repositorio interno de herramientas del SOC: archivos subidos y sincronización con GitHub."""
import hashlib
import os
import re
from pathlib import Path

import requests

from store import now

GH_API = "https://api.github.com"
GH_RAW = "https://raw.githubusercontent.com"
MAX_FILE = int(os.getenv("TOOLS_MAX_FILE_MB", "50")) * 1024 * 1024
VIEW_MAX = 3 * 1024 * 1024  # el visor muestra archivos de texto de hasta 3 MB
TEXT_EXT = {".py", ".sh", ".ps1", ".psm1", ".bat", ".cmd", ".js", ".ts", ".go", ".rb", ".pl", ".php", ".c", ".h", ".cpp",
            ".rs", ".java", ".cs", ".md", ".txt", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".xml",
            ".html", ".css", ".sql", ".csv", ".rules", ".yar", ".yara", ".sigma", ".env", ".dockerfile", ""}
LANG = {".py": "python", ".sh": "bash", ".ps1": "powershell", ".psm1": "powershell", ".bat": "batch", ".cmd": "batch",
        ".js": "javascript", ".ts": "javascript", ".go": "go", ".rb": "ruby", ".php": "php", ".c": "c", ".h": "c",
        ".cpp": "c", ".rs": "rust", ".java": "java", ".cs": "csharp", ".md": "markdown", ".json": "json",
        ".yml": "yaml", ".yaml": "yaml", ".xml": "xml", ".html": "xml", ".sql": "sql", ".yar": "yara", ".yara": "yara"}


def _gh_headers():
    h = {"Accept": "application/vnd.github+json", "User-Agent": "SOC-ACME-portal"}
    if os.getenv("GITHUB_TOKEN"):
        h["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    return h


def parse_repo(url: str):
    m = re.match(r"^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/|$)", (url or "").strip())
    return (m.group(1), m.group(2)) if m else None


def safe_path(p: str) -> str:
    """Ruta relativa segura (sin .., sin rutas absolutas)."""
    parts = [x for x in re.split(r"[\\/]+", p or "") if x not in ("", ".", "..")]
    clean = "/".join(re.sub(r"[^\w.\- ]", "_", x)[:120] for x in parts)
    if not clean:
        raise ValueError("Nombre de archivo no válido")
    return clean[:400]


def lang_of(path: str) -> str:
    name = path.rsplit("/", 1)[-1].lower()
    if name in ("dockerfile", "makefile"):
        return "bash"
    ext = os.path.splitext(name)[1]
    return LANG.get(ext, "python" if ext == "" else "text")


class ToolFiles:
    def __init__(self, root: str, store):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.store = store

    def _disk(self, tid: int, path: str) -> Path:
        p = (self.root / str(tid) / path).resolve()
        if not str(p).startswith(str((self.root / str(tid)).resolve())):
            raise ValueError("Ruta no permitida")
        return p

    def save(self, tid, path, chunks, user, source="upload"):
        path = safe_path(path)
        dst = self._disk(tid, path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        h, size, tmp = hashlib.sha256(), 0, dst.with_suffix(dst.suffix + ".part")
        with open(tmp, "wb") as fh:
            for c in chunks:
                size += len(c)
                if size > MAX_FILE:
                    fh.close(); tmp.unlink(missing_ok=True)
                    raise ValueError(f"Archivo mayor de {MAX_FILE // 1048576} MB")
                h.update(c)
                fh.write(c)
        tmp.replace(dst)
        return self.store.tool_file_upsert(tid, path, size, h.hexdigest(), source, 1, user)

    def read(self, tool, f):
        """Devuelve (bytes, desde_caché). Los archivos de GitHub se descargan la primera vez que se abren."""
        p = self._disk(tool["id"], f["path"])
        if p.exists():
            return p.read_bytes(), True
        if f["source"] != "github":
            raise FileNotFoundError("El archivo ya no está en el servidor")
        repo = parse_repo(tool["repo_url"])
        r = requests.get(f"{GH_RAW}/{repo[0]}/{repo[1]}/{tool['gh_branch'] or 'main'}/{f['path']}",
                         headers={"User-Agent": "SOC-ACME-portal"}, timeout=60)
        r.raise_for_status()
        data = r.content
        self.save(tool["id"], f["path"], [data], f.get("uploaded_by") or "github", source="github")
        return data, False

    def remove(self, tid, path):
        p = self._disk(tid, path)
        if p.exists():
            p.unlink()

    def remove_all(self, tid):
        import shutil
        shutil.rmtree(self.root / str(tid), ignore_errors=True)

    @staticmethod
    def as_text(data: bytes):
        if len(data) > VIEW_MAX or b"\x00" in data[:8000]:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return data.decode("latin-1")
            except Exception:
                return None

    def github_sync(self, tool, user):
        """Lee del repositorio público: descripción, lenguaje, licencia, estrellas, README y árbol de archivos.
        Los archivos no se descargan hasta que alguien los abre (o se pulsa «Descargar copia local»)."""
        repo = parse_repo(tool["repo_url"])
        if not repo:
            raise ValueError("La URL no es de un repositorio de GitHub (https://github.com/usuario/repositorio)")
        o, n = repo
        r = requests.get(f"{GH_API}/repos/{o}/{n}", headers=_gh_headers(), timeout=30)
        if r.status_code == 404:
            raise ValueError("Repositorio no encontrado o privado (para privados define GITHUB_TOKEN)")
        r.raise_for_status()
        meta = r.json()
        branch = meta.get("default_branch") or "main"
        readme = ""
        rr = requests.get(f"{GH_API}/repos/{o}/{n}/readme", headers={**_gh_headers(), "Accept": "application/vnd.github.raw"}, timeout=30)
        if rr.ok:
            readme = rr.text[:400000]
        tr = requests.get(f"{GH_API}/repos/{o}/{n}/git/trees/{branch}?recursive=1", headers=_gh_headers(), timeout=60)
        tr.raise_for_status()
        files = [x for x in tr.json().get("tree", []) if x.get("type") == "blob"][:2000]
        existing = {f["path"]: f for f in self.store.tool(tool["id"])["files"]}
        for x in files:
            path = safe_path(x["path"])
            old = existing.get(path)
            if old and old["source"] == "upload":
                continue  # no se pisa un archivo subido a mano con el mismo nombre
            changed = not old or old["size"] != x.get("size")
            if changed and old:
                self.remove(tool["id"], path)  # la copia local quedó vieja: se volverá a descargar
            self.store.tool_file_upsert(tool["id"], path, x.get("size"), None, "github", 0 if changed or not old else old["cached"], user)
        lic = (meta.get("license") or {}).get("spdx_id") or ""
        upd = {"gh_branch": branch, "stars": meta.get("stargazers_count"), "gh_synced": now()}
        for k, v in (("description", meta.get("description")), ("language", meta.get("language")),
                     ("license", "" if lic == "NOASSERTION" else lic), ("readme", readme)):
            if v and not tool.get(k):
                upd[k] = v  # solo se rellenan los campos vacíos: no se pisa lo que escribió el equipo
        self.store.tool_meta(tool["id"], **upd)
        self.store.tool_log(tool["id"], user, f"Sincronizado con GitHub ({len(files)} archivos, rama {branch})")
        return {"archivos": len(files), "rama": branch}

    def cache_all(self, tool, user, limit_mb=200):
        """Descarga copia local de todos los archivos de GitHub (por si el repositorio desaparece)."""
        got, total = 0, 0
        for f in self.store.tool(tool["id"])["files"]:
            if f["source"] == "github" and not f["cached"]:
                total += f["size"] or 0
                if total > limit_mb * 1048576:
                    break
                self.read(tool, f)
                got += 1
        self.store.tool_log(tool["id"], user, f"Copia local de {got} archivos de GitHub")
        return got


SEED = [{
    "name": "Crawler-Scanner",
    "category": "Monitoreo de filtraciones",
    "repo_url": "https://github.com/CyberRyuki/Crawler-Scanner",
    "language": "Python",
    "platform": "Linux",
    "owner": "ryuki",
    "status": "En evaluación",
    "requires_auth": 1,
    "tags": "tor, leak sites, ransomware, palabras clave, osint",
    "description": "Rastreador de sitios de filtraciones de grupos de ransomware (vía Tor) que busca menciones de palabras clave en el HTML y en archivos JSON publicados.",
    "auth_note": "Uso exclusivamente defensivo: buscar menciones de ACME y de instituciones del Estado en sitios de filtración. "
                 "Requiere aprobación del responsable de seguridad antes de cada uso, ejecutarse en una máquina aislada y no descargar "
                 "ni redistribuir datos filtrados de terceros.",
    "usage": """## Requisitos
- Python 3 y un cliente **Tor** en la misma máquina (puerto SOCKS 9050 o 9150; el script lo detecta solo).
- Obligatorias: `pip install requests urllib3 beautifulsoup4`
- Opcionales (el script funciona sin ellas): `spacy` (modelo `es_core_news_sm`), `pandas`, `selenium`, `playwright`, `redis`, `celery`, `kafka-python`, `ray`, `scrapy`, `nltk`.

## Antes de usarla
1. **Cambia las palabras clave del código** (`keywords_list`): ahora tiene términos de prueba de otra organización. Pon las de ACME y las instituciones que se monitorean.
2. Revisa la lista de sitios (`domain_groups`), los tiempos de espera y el número de procesos.
3. Ejecútala en una **VM aislada** del SOC, nunca en servidores de producción.

## Ejecución
```bash
sudo systemctl start tor          # o abre Tor Browser (puerto 9150)
python3 Crawler
```
Los resultados se guardan en una base SQLite (tablas de ataques, dominios y entidades).

## Qué hacer con un hallazgo
Si aparece una mención de una institución: abre un incidente en el portal (runbook *Cuenta comprometida* o *Coincidencia de IoC*), avisa al responsable de seguridad y no descargues el contenido filtrado.""",
}]
