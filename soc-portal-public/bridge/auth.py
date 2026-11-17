"""Autenticación del portal SOC: cuentas locales y de Active Directory (LDAP), roles, MFA (TOTP),
bloqueo por intentos fallidos, sesiones con caducidad y registro de accesos."""
import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import ssl
import struct
import threading
import time
from urllib.parse import quote

log = logging.getLogger("soc-bridge.auth")
ROLES = {"admin": "Administrador", "analyst": "Analista", "viewer": "Solo lectura"}
_env = lambda k, d: os.getenv(k, d)
MAX_FAILS = int(_env("AUTH_MAX_FAILS", "5"))          # intentos fallidos seguidos antes de bloquear (0 = no bloquear)
LOCK_MIN = int(_env("AUTH_LOCK_MIN", "15"))            # minutos de bloqueo
IDLE_MIN = int(_env("AUTH_IDLE_MIN", "30"))            # cierre por inactividad
MAX_HOURS = int(_env("AUTH_MAX_HOURS", "12"))          # duración máxima de una sesión
REQUIRE_MFA = [r.strip() for r in _env("AUTH_REQUIRE_MFA", "admin").split(",") if r.strip()]  # roles con MFA obligatorio
ISSUER = _env("AUTH_MFA_ISSUER", "SOC ACME")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL COLLATE NOCASE, display TEXT DEFAULT '',
  email TEXT DEFAULT '', source TEXT NOT NULL DEFAULT 'local', pw_hash TEXT, role TEXT NOT NULL DEFAULT 'analyst',
  enabled INTEGER DEFAULT 1, must_change INTEGER DEFAULT 0, mfa_secret TEXT, mfa_enabled INTEGER DEFAULT 0,
  mfa_last INTEGER DEFAULT 0, recovery TEXT DEFAULT '[]', failed INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0,
  last_login TEXT, last_ip TEXT, created_at TEXT, created_by TEXT, pw_changed TEXT);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created INTEGER, last_seen INTEGER, ip TEXT, ua TEXT);
CREATE TABLE IF NOT EXISTS auth_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, ts INTEGER, username TEXT, ip TEXT, event TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_auth_log_ts ON auth_log(ts);
"""
EVENTS = {"login": "Inicio de sesión", "login_fail": "Contraseña incorrecta", "mfa_fail": "Código MFA incorrecto",
          "locked": "Cuenta bloqueada", "blocked": "Intento con cuenta bloqueada", "disabled": "Intento con cuenta desactivada",
          "unknown": "Usuario inexistente", "logout": "Cierre de sesión", "expired": "Sesión caducada",
          "pw_change": "Cambio de contraseña", "mfa_on": "MFA activado", "mfa_off": "MFA desactivado", "recovery": "Código de recuperación usado",
          "ldap_down": "AD no disponible", "ldap_nogroup": "Usuario de AD sin grupo del SOC", "admin": "Cambio de administración",
          "ip_block": "IP bloqueada por exceso de intentos", "incident_delete": "Incidente eliminado",
          "sophos_action": "Acción en Sophos Central", "m365_action": "Acción en Microsoft 365",
          "exposure_scan": "Escaneo de exposición"}


def now_s():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------ contraseñas (scrypt, librería estándar)
def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def check_pw(pw: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(h))
    except Exception:
        return False


def pw_policy(pw: str, username: str = "") -> str:
    """Devuelve el motivo si la contraseña no cumple la política; cadena vacía si es válida."""
    if len(pw) < 12:
        return "Debe tener al menos 12 caracteres"
    if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"\d", pw) and re.search(r"[^\w\s]|_", pw)):
        return "Debe combinar mayúsculas, minúsculas, números y símbolos"
    if username and username.lower() in pw.lower():
        return "No puede contener el nombre de usuario"
    return ""


def temp_password() -> str:
    alpha = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alpha) for _ in range(10)) + secrets.choice("!#$%*+-?@") + secrets.choice("23456789")


# ------------------------------------------------------------ TOTP (RFC 6238)
def totp_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    h = hmac.new(key, struct.pack(">Q", counter), "sha1").digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


def totp_check(secret: str, code: str, last: int = 0):
    """Devuelve el contador usado (para impedir reutilizar el mismo código) o None."""
    code = re.sub(r"\D", "", code or "")
    if len(code) != 6:
        return None
    c = int(time.time() // 30)
    for k in (c - 1, c, c + 1):  # ±30 s de margen por desfase de reloj
        if k > last and hmac.compare_digest(totp_at(secret, k), code):
            return k
    return None


def qr_svg(text: str) -> str:
    try:
        import qrcode
        import qrcode.image.svg
        img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
        return img.to_string(encoding="unicode")
    except Exception as exc:
        log.warning("QR no disponible: %s", exc)
        return ""


# ------------------------------------------------------------ Active Directory (LDAP)
class LdapDown(Exception):
    pass


def ldap_conf():
    on = _env("LDAP_ENABLED", "false").lower() in ("1", "true", "yes")
    return {"on": on and bool(_env("LDAP_URL", "")), "url": _env("LDAP_URL", ""), "suffix": _env("LDAP_UPN_SUFFIX", ""),
            "base": _env("LDAP_BASE_DN", ""), "starttls": _env("LDAP_STARTTLS", "false").lower() in ("1", "true", "yes"),
            "verify": _env("LDAP_VERIFY_TLS", "false").lower() in ("1", "true", "yes"),
            "timeout": int(_env("LDAP_TIMEOUT", "8")),
            "groups": [("admin", _env("LDAP_GROUP_ADMIN", "")), ("analyst", _env("LDAP_GROUP_ANALYST", "")),
                       ("viewer", _env("LDAP_GROUP_VIEWER", ""))]}


def ldap_login(username: str, password: str):
    """Valida contra AD con la propia cuenta del usuario. Devuelve {role, display, email} o None.
    El rol sale del primer grupo del SOC al que pertenece (también grupos anidados)."""
    from ldap3 import Connection, Server, Tls
    from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError
    from ldap3.utils.conv import escape_filter_chars
    c = ldap_conf()
    if not password:
        return None  # una clave vacía haría un bind anónimo «correcto»
    try:
        tls = Tls(validate=ssl.CERT_REQUIRED if c["verify"] else ssl.CERT_NONE)
        srv = Server(c["url"], use_ssl=c["url"].lower().startswith("ldaps"), tls=tls, connect_timeout=c["timeout"])
        user = username if "@" in username or "\\" in username else f"{username}@{c['suffix']}" if c["suffix"] else username
        conn = Connection(srv, user=user, password=password, receive_timeout=c["timeout"], raise_exceptions=False)
        conn.open()
        if c["starttls"]:
            conn.start_tls()
        if not conn.bind():
            return None
        sam = escape_filter_chars(username.split("@")[0].split("\\")[-1])
        conn.search(c["base"], f"(&(objectClass=user)(sAMAccountName={sam}))", attributes=["displayName", "mail"])
        info = conn.entries[0] if conn.entries else None
        role = None
        for r, dn in c["groups"]:
            if dn and conn.search(c["base"], f"(&(sAMAccountName={sam})(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(dn)}))",
                                  attributes=["sAMAccountName"]) and conn.entries:
                role = r
                break
        conn.unbind()
        return {"role": role, "display": str(info.displayName) if info and info.displayName else username,
                "email": str(info.mail) if info and info.mail else ""}
    except LDAPSocketOpenError as exc:
        raise LdapDown(str(exc)[:150])
    except LDAPException as exc:
        raise LdapDown(str(exc)[:150])


# ------------------------------------------------------------ servicio
class Auth:
    def __init__(self, store):
        self.s = store
        self.s.db.executescript(SCHEMA)
        self.s.db.commit()
        self.tickets = {}   # pasos intermedios (MFA) de 5 minutos
        self.ipfails = {}   # ip -> [timestamps]
        self._lock = threading.Lock()

    # utilidades
    def q(self, sql, a=(), one=False):
        return self.s._q(sql, a, one)

    def x(self, sql, a=()):
        return self.s._x(sql, a)

    def audit(self, username, ip, event, detail=""):
        self.x("INSERT INTO auth_log(at, ts, username, ip, event, detail) VALUES(?,?,?,?,?,?)",
               (now_s(), int(time.time()), username, ip, event, detail[:300]))

    def user(self, username=None, uid=None):
        if uid is not None:
            return self.q("SELECT * FROM users WHERE id = ?", (uid,), one=True)
        return self.q("SELECT * FROM users WHERE username = ?", (username,), one=True)

    @staticmethod
    def public(u):
        return {k: u[k] for k in ("id", "username", "display", "email", "source", "role", "enabled", "must_change",
                                   "mfa_enabled", "failed", "locked_until", "last_login", "last_ip", "created_at", "pw_changed")} | {
            "locked": (u["locked_until"] or 0) > time.time(), "role_name": ROLES.get(u["role"], u["role"]),
            "mfa_required": u["role"] in REQUIRE_MFA, "recovery_left": len(json.loads(u["recovery"] or "[]"))}

    def bootstrap(self, legacy: dict):
        """Primera ejecución: migra PORTAL_USERS (el primero como administrador) o crea un admin con clave temporal."""
        if self.q("SELECT 1 FROM users LIMIT 1", one=True):
            return None
        if legacy:
            for i, (u, pw) in enumerate(legacy.items()):
                self.x("INSERT INTO users(username, display, source, pw_hash, role, created_at, created_by, pw_changed) VALUES(?,?,?,?,?,?,?,?)",
                       (u, u, "local", hash_pw(pw), "admin" if i == 0 else "analyst", now_s(), "migración", now_s()))
            log.info("Usuarios migrados desde PORTAL_USERS: %s (el primero es administrador)", ", ".join(legacy))
            return None
        pw = temp_password()
        self.x("INSERT INTO users(username, display, source, pw_hash, role, must_change, created_at, created_by) VALUES(?,?,?,?,?,?,?,?)",
               ("admin", "Administrador", "local", hash_pw(pw), "admin", 1, now_s(), "sistema"))
        log.warning("=" * 60 + "\nUsuario inicial: admin   Contraseña temporal: %s\n(se pedirá cambiarla al entrar)\n" + "=" * 60, pw)
        return pw

    # control de intentos por IP (evita fuerza bruta repartida entre muchos usuarios)
    def ip_blocked(self, ip):
        with self._lock:
            lst = [t for t in self.ipfails.get(ip, []) if t > time.time() - 600]
            self.ipfails[ip] = lst
            lim = int(_env("AUTH_IP_MAX_FAILS", "20"))  # 0 = sin bloqueo por IP
            return lim > 0 and len(lst) >= lim

    def ip_fail(self, ip):
        with self._lock:
            self.ipfails.setdefault(ip, []).append(time.time())

    def _fail(self, u, ip, event):
        self.ip_fail(ip)
        if not u:
            return
        failed = (u["failed"] or 0) + 1
        locked = int(time.time()) + LOCK_MIN * 60 if MAX_FAILS > 0 and LOCK_MIN > 0 and failed >= MAX_FAILS else 0
        self.x("UPDATE users SET failed = ?, locked_until = ? WHERE id = ?", (failed if not locked else 0, locked, u["id"]))
        self.audit(u["username"], ip, event, f"intento {failed} de {MAX_FAILS}" if MAX_FAILS > 0 else f"intento {failed} (sin bloqueo)")
        if locked:
            self.audit(u["username"], ip, "locked", f"{LOCK_MIN} minutos tras {MAX_FAILS} intentos fallidos")

    # ---------------------------------------------------------- inicio de sesión
    def login(self, username, password, ip, ua):
        """Devuelve {"ok": token} | {"mfa": ticket} | {"error": mensaje}."""
        username = (username or "").strip()
        generic = "Usuario o contraseña incorrectos"
        if self.ip_blocked(ip):
            self.audit(username, ip, "ip_block")
            return {"error": "Demasiados intentos desde esta dirección. Espera unos minutos."}
        if not username or not password:
            return {"error": generic}
        u = self.user(username)
        if u and (u["locked_until"] or 0) > time.time():
            self.audit(username, ip, "blocked")
            mins = int((u["locked_until"] - time.time()) // 60) + 1
            return {"error": f"Cuenta bloqueada temporalmente por intentos fallidos. Inténtalo en {mins} min o pide a un administrador que la desbloquee."}
        if u and not u["enabled"]:
            self.audit(username, ip, "disabled")
            return {"error": generic}
        if u and u["source"] == "local":
            if not check_pw(password, u["pw_hash"] or ""):
                self._fail(u, ip, "login_fail")
                return {"error": generic}
        elif ldap_conf()["on"]:
            try:
                info = ldap_login(username, password)
            except LdapDown as exc:
                self.audit(username, ip, "ldap_down", str(exc))
                return {"error": "No se puede contactar con el Active Directory. Usa una cuenta local de emergencia."}
            if info is None:
                self._fail(u, ip, "login_fail") if u else (self.ip_fail(ip), self.audit(username, ip, "login_fail", "AD"))
                return {"error": generic}
            if not info["role"]:
                self.audit(username, ip, "ldap_nogroup")
                return {"error": "Tu cuenta del dominio no pertenece a ningún grupo del SOC."}
            uname = username.split("@")[0].split("\\")[-1]
            u = self.user(uname)
            if not u:
                self.x("INSERT INTO users(username, display, email, source, role, created_at, created_by) VALUES(?,?,?,?,?,?,?)",
                       (uname, info["display"], info["email"], "ldap", info["role"], now_s(), "AD"))
            else:
                if not u["enabled"]:
                    self.audit(uname, ip, "disabled")
                    return {"error": generic}
                self.x("UPDATE users SET display = ?, email = ?, role = ? WHERE id = ?", (info["display"], info["email"], info["role"], u["id"]))
            u = self.user(uname)
        else:
            self.ip_fail(ip)
            self.audit(username, ip, "unknown")
            check_pw(password, hash_pw("x"))  # mismo tiempo de respuesta que con un usuario real
            return {"error": generic}
        if u["mfa_enabled"]:
            t = secrets.token_urlsafe(24)
            self.tickets[t] = (u["id"], time.time() + 300, ua)
            return {"mfa": t}
        return {"ok": self._session(u, ip, ua)}

    def login_mfa(self, ticket, code, ip, ua):
        tk = self.tickets.get(ticket)
        if not tk or tk[1] < time.time():
            self.tickets.pop(ticket, None)
            return {"error": "El paso de verificación caducó. Vuelve a introducir tu contraseña."}
        u = self.user(uid=tk[0])
        if (u["locked_until"] or 0) > time.time():
            return {"error": "Cuenta bloqueada temporalmente."}
        k = totp_check(u["mfa_secret"], code, u["mfa_last"] or 0)
        if k:
            self.x("UPDATE users SET mfa_last = ? WHERE id = ?", (k, u["id"]))
        elif self._use_recovery(u, code):
            self.audit(u["username"], ip, "recovery")
        else:
            self._fail(u, ip, "mfa_fail")
            return {"error": "Código incorrecto"}
        self.tickets.pop(ticket, None)
        return {"ok": self._session(u, ip, ua)}

    def _use_recovery(self, u, code):
        c = re.sub(r"[^A-Za-z0-9]", "", code or "").upper()
        if len(c) != 10:
            return False
        lst = json.loads(u["recovery"] or "[]")
        h = hashlib.sha256(c.encode()).hexdigest()
        if h in lst:
            lst.remove(h)
            self.x("UPDATE users SET recovery = ? WHERE id = ?", (json.dumps(lst), u["id"]))
            return True
        return False

    def _session(self, u, ip, ua):
        token = secrets.token_urlsafe(32)
        t = int(time.time())
        self.x("INSERT INTO sessions(token, user_id, created, last_seen, ip, ua) VALUES(?,?,?,?,?,?)",
               (hashlib.sha256(token.encode()).hexdigest(), u["id"], t, t, ip, (ua or "")[:200]))
        self.x("UPDATE users SET failed = 0, locked_until = 0, last_login = ?, last_ip = ? WHERE id = ?", (now_s(), ip, u["id"]))
        self.audit(u["username"], ip, "login", f"{'AD' if u['source'] == 'ldap' else 'local'}{' + MFA' if u['mfa_enabled'] else ''}")
        return token

    def check(self, token, ip, background=False):
        """Valida la cookie. Devuelve (usuario, sesión) o (None, motivo)."""
        if not token:
            return None, "sin sesión"
        th = hashlib.sha256(token.encode()).hexdigest()
        s = self.q("SELECT * FROM sessions WHERE token = ?", (th,), one=True)
        if not s:
            return None, "sin sesión"
        u = self.user(uid=s["user_id"])
        t = int(time.time())
        idle = IDLE_MIN * 60 if u and u["role"] != "viewer" else 24 * 3600  # la pantalla NOC (solo lectura) no caduca por inactividad
        if not u or not u["enabled"] or t - s["created"] > MAX_HOURS * 3600 or t - s["last_seen"] > idle:
            self.x("DELETE FROM sessions WHERE token = ?", (th,))
            if u:
                self.audit(u["username"], ip, "expired", "inactividad" if t - s["last_seen"] > idle else "duración máxima")
            return None, "sesión caducada"
        if not background and t - s["last_seen"] > 30:
            self.x("UPDATE sessions SET last_seen = ? WHERE token = ?", (t, th))
        return u, s

    def logout(self, token, ip):
        th = hashlib.sha256((token or "").encode()).hexdigest()
        s = self.q("SELECT user_id FROM sessions WHERE token = ?", (th,), one=True)
        if s:
            u = self.user(uid=s["user_id"])
            self.audit(u["username"] if u else "?", ip, "logout")
        self.x("DELETE FROM sessions WHERE token = ?", (th,))

    def state(self, u):
        """Pasos obligatorios antes de usar el portal."""
        if u["source"] == "local" and u["must_change"]:
            return "change_password"
        if u["role"] in REQUIRE_MFA and not u["mfa_enabled"]:
            return "setup_mfa"
        return "ok"

    # ---------------------------------------------------------- cuenta propia
    def change_password(self, u, current, new, ip):
        if u["source"] != "local":
            return "Las cuentas del dominio cambian la contraseña en Windows / Active Directory"
        if not check_pw(current or "", u["pw_hash"] or ""):
            self._fail(u, ip, "login_fail")
            return "La contraseña actual no es correcta"
        err = pw_policy(new or "", u["username"])
        if err:
            return err
        if check_pw(new, u["pw_hash"]):
            return "La nueva contraseña debe ser distinta de la actual"
        self.x("UPDATE users SET pw_hash = ?, must_change = 0, pw_changed = ? WHERE id = ?", (hash_pw(new), now_s(), u["id"]))
        self.audit(u["username"], ip, "pw_change")
        return ""

    def mfa_setup(self, u):
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        self.x("UPDATE users SET mfa_secret = ? WHERE id = ? AND mfa_enabled = 0", (secret, u["id"]))
        uri = f"otpauth://totp/{quote(ISSUER)}:{quote(u['username'])}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits=6&period=30"
        return {"secret": " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)), "uri": uri, "qr": qr_svg(uri)}

    def mfa_enable(self, u, code, ip):
        u = self.user(uid=u["id"])
        if not u["mfa_secret"]:
            return None, "Primero genera el código QR"
        k = totp_check(u["mfa_secret"], code, 0)
        if not k:
            return None, "Código incorrecto. Comprueba que la hora del teléfono es correcta."
        codes = ["".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(10)) for _ in range(8)]
        self.x("UPDATE users SET mfa_enabled = 1, mfa_last = ?, recovery = ? WHERE id = ?",
               (k, json.dumps([hashlib.sha256(c.encode()).hexdigest() for c in codes]), u["id"]))
        self.audit(u["username"], ip, "mfa_on")
        return [c[:5] + "-" + c[5:] for c in codes], ""

    def mfa_disable(self, u, code, ip):
        if u["role"] in REQUIRE_MFA:
            return "Tu rol exige MFA; pide a un administrador que lo restablezca si cambias de teléfono"
        if not (totp_check(u["mfa_secret"], code, 0) or self._use_recovery(u, code)):
            return "Código incorrecto"
        self.x("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, recovery = '[]' WHERE id = ?", (u["id"],))
        self.audit(u["username"], ip, "mfa_off")
        return ""

    def sessions_of(self, uid, current=None):
        rows = self.q("SELECT token, created, last_seen, ip, ua FROM sessions WHERE user_id = ? ORDER BY last_seen DESC", (uid,))
        return [{"id": r["token"][:16], "current": r["token"] == current, "ip": r["ip"], "ua": r["ua"],
                 "created": datetime.datetime.fromtimestamp(r["created"]).strftime("%Y-%m-%d %H:%M"),
                 "last_seen": datetime.datetime.fromtimestamp(r["last_seen"]).strftime("%Y-%m-%d %H:%M")} for r in rows]

    def revoke(self, uid, sid_prefix=None, keep=None):
        for r in self.q("SELECT token FROM sessions WHERE user_id = ?", (uid,)):
            if (sid_prefix is None or r["token"].startswith(sid_prefix)) and r["token"] != keep:
                self.x("DELETE FROM sessions WHERE token = ?", (r["token"],))

    # ---------------------------------------------------------- administración
    def users(self):
        rows = self.q("SELECT * FROM users ORDER BY username")
        act = {r["user_id"]: r["n"] for r in self.q("SELECT user_id, COUNT(*) n FROM sessions GROUP BY user_id")}
        return [self.public(u) | {"sessions": act.get(u["id"], 0)} for u in rows]

    def create_user(self, data, admin, ip):
        un = (data.get("username") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{2,40}", un):
            return None, "Usuario no válido (letras, números, punto, guion; 2-40 caracteres)"
        if self.user(un):
            return None, "Ya existe ese usuario"
        role = data.get("role") if data.get("role") in ROLES else "analyst"
        src = "ldap" if data.get("source") == "ldap" else "local"
        pw = None
        if src == "local":
            pw = data.get("password") or temp_password()
            err = pw_policy(pw, un)
            if err:
                return None, err
        self.x("""INSERT INTO users(username, display, email, source, pw_hash, role, must_change, created_at, created_by)
                  VALUES(?,?,?,?,?,?,?,?,?)""", (un, data.get("display") or un, data.get("email") or "", src,
                                                hash_pw(pw) if pw else None, role, 1 if src == "local" else 0, now_s(), admin["username"]))
        self.audit(admin["username"], ip, "admin", f"Crea el usuario {un} ({ROLES[role]}, {src})")
        return {"username": un, "password": pw}, ""

    def update_user(self, uid, data, admin, ip):
        u = self.user(uid=uid)
        if not u:
            return None, "Usuario no encontrado"
        changes, out = [], {}
        if "role" in data and data["role"] in ROLES and data["role"] != u["role"]:
            if u["id"] == admin["id"] and data["role"] != "admin":
                return None, "No puedes quitarte a ti mismo el rol de administrador"
            self.x("UPDATE users SET role = ? WHERE id = ?", (data["role"], uid)); changes.append(f"rol → {ROLES[data['role']]}")
        if "enabled" in data:
            en = 1 if data["enabled"] else 0
            if u["id"] == admin["id"] and not en:
                return None, "No puedes desactivar tu propia cuenta"
            if en != u["enabled"]:
                self.x("UPDATE users SET enabled = ? WHERE id = ?", (en, uid)); changes.append("activada" if en else "desactivada")
                if not en:
                    self.revoke(uid)
        for k in ("display", "email"):
            if k in data and data[k] != u[k]:
                self.x(f"UPDATE users SET {k} = ? WHERE id = ?", (data[k], uid))
        if data.get("unlock"):
            self.x("UPDATE users SET failed = 0, locked_until = 0 WHERE id = ?", (uid,)); changes.append("desbloqueada")
        if data.get("reset_password"):
            if u["source"] != "local":
                return None, "Las cuentas del dominio cambian la contraseña en Active Directory"
            pw = temp_password()
            self.x("UPDATE users SET pw_hash = ?, must_change = 1, failed = 0, locked_until = 0 WHERE id = ?", (hash_pw(pw), uid))
            self.revoke(uid)
            out["password"] = pw; changes.append("contraseña restablecida")
        if data.get("reset_mfa"):
            self.x("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, recovery = '[]' WHERE id = ?", (uid,))
            self.revoke(uid); changes.append("MFA restablecido")
        if data.get("logout"):
            self.revoke(uid); changes.append("sesiones cerradas")
        if changes:
            self.audit(admin["username"], ip, "admin", f"{u['username']}: " + ", ".join(changes))
        return out, ""

    def delete_user(self, uid, admin, ip):
        u = self.user(uid=uid)
        if not u or u["id"] == admin["id"]:
            return "No puedes eliminar tu propia cuenta"
        if u["role"] == "admin" and self.q("SELECT COUNT(*) n FROM users WHERE role = 'admin' AND enabled = 1", one=True)["n"] <= 1:
            return "Debe quedar al menos un administrador"
        self.revoke(uid)
        self.x("DELETE FROM users WHERE id = ?", (uid,))
        self.audit(admin["username"], ip, "admin", f"Elimina el usuario {u['username']}")
        return ""

    def log(self, q="", event="", days=7, limit=500):
        sql, a = "SELECT * FROM auth_log WHERE ts >= ?", [int(time.time()) - days * 86400]
        if q:
            sql += " AND (username LIKE ? OR ip LIKE ?)"; a += [f"%{q}%"] * 2
        if event:
            sql += " AND event = ?"; a.append(event)
        rows = self.q(sql + " ORDER BY id DESC LIMIT ?", a + [limit])
        return [r | {"event_name": EVENTS.get(r["event"], r["event"])} for r in rows]

    def stats(self):
        d1 = int(time.time()) - 86400
        ev = {r["event"]: r["n"] for r in self.q("SELECT event, COUNT(*) n FROM auth_log WHERE ts >= ? GROUP BY event", (d1,))}
        us = self.q("SELECT role, mfa_enabled, enabled, locked_until FROM users")
        return {"logins_24h": ev.get("login", 0),
                "fallos_24h": sum(ev.get(k, 0) for k in ("login_fail", "mfa_fail", "unknown", "blocked", "ip_block")),
                "bloqueados": sum(1 for u in us if (u["locked_until"] or 0) > time.time()),
                "sin_mfa": sum(1 for u in us if u["enabled"] and not u["mfa_enabled"]), "usuarios": len(us),
                "sesiones": self.q("SELECT COUNT(*) n FROM sessions", one=True)["n"],
                "ldap": ldap_conf()["on"], "politica": {"max_fails": MAX_FAILS, "lock_min": LOCK_MIN, "idle_min": IDLE_MIN,
                                                        "max_hours": MAX_HOURS, "mfa_roles": REQUIRE_MFA}}

    def cleanup(self):
        t = int(time.time())
        self.x("DELETE FROM sessions WHERE created < ?", (t - MAX_HOURS * 3600,))
        self.x("DELETE FROM auth_log WHERE ts < ?", (t - int(_env("AUTH_LOG_DAYS", "365")) * 86400,))
        for k, v in list(self.tickets.items()):
            if v[1] < time.time():
                self.tickets.pop(k, None)
