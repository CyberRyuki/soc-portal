<div align="center">

# 🛡️ SOC Portal

**Consola unificada para un Centro de Operaciones de Seguridad (SOC)**

Wazuh · MISP · Shuffle SOAR · Sophos Central · Microsoft 365 Defender · Wiki.js · IA local

![Versión](https://img.shields.io/badge/versión-20.0.0-2563eb)
![Python](https://img.shields.io/badge/Python-3.12-3776ab?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-19-61dafb?logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-compose-2496ed?logo=docker&logoColor=white)

</div>

---

Un solo portal para **ver, investigar y responder**. Reúne en una misma interfaz las alertas del SIEM, la inteligencia
de amenazas, el estado de los endpoints y de Microsoft 365, la vigilancia de los portales web y la superficie expuesta
a Internet. Toda acción que cambia algo pasa por **aprobación humana** y queda en una **auditoría a prueba de manipulación**.

> [!NOTE]
> Los nombres, dominios (`acme.example`) y direcciones IP de este repositorio son **ficticios**.
> Adapta `.env` a tu entorno y no subas nunca `.env` ni la carpeta `data/`.

## ✨ Funcionalidades

| Módulo | Qué hace |
|---|---|
| **Resumen** | Mapa de riesgo, línea de tiempo, estado de todas las integraciones y tarjetas por fuente, con refresco automático configurable. |
| **Amenazas y agentes** | Alertas de Wazuh por nivel, regla, táctica MITRE ATT&CK, IP y país; inventario de agentes; vista NOC para pantallas. |
| **Incidentes** | Tablero con SLA, runbooks y asistente de IA. Las detecciones generan **sugerencias** que un analista confirma o descarta. |
| **IoC e inteligencia** | Feeds abiertos y MISP, búsqueda de indicadores, correlación con las alertas de Wazuh y carga de IoC a MISP. |
| **Vulnerabilidades** | Vulnerabilidades de Wazuh y seguimiento con vencimientos; importación de informes **Pentera** (PDF, JSON o CSV). |
| **Portales** | Disponibilidad, certificados, cobertura WAF y **detección de desfiguración**: texto, captura visual, scripts modificados, redirecciones, formularios de phishing, cabeceras de seguridad y cambios de DNS. |
| **Exposición / Shadow IT** | Descubrimiento pasivo (certificados públicos, DNS, Shodan InternetDB) y escaneo activo **autorizado** de puertos y rutas sensibles. Encuentra lo publicado que no está inventariado. |
| **Sophos Central** | Alertas, salud de equipos y respuesta (aislar, escanear, bloquear IoC) con cola de aprobación. |
| **Microsoft 365** | Defender XDR, inicios de sesión de riesgo, reglas de correo sospechosas, Secure Score y acciones sobre cuentas con aprobación. |
| **Auditoría** | Quién cambió qué, cuándo y desde dónde, en una cadena de hashes verificable y exportable a CSV. |
| **Asistente IA** | Investigación guiada sobre los datos del SOC con un modelo **local** (Ollama, vLLM o compatible con OpenAI). |

## 🏗️ Arquitectura

```
                         Analistas (navegador)
                                 │  :8088
                    ┌────────────▼────────────┐
                    │  soc-web (nginx + React) │
                    └────────────┬────────────┘
                                 │ red interna Docker
   ┌──────────────┐     ┌────────▼────────┐     ┌──────────────────────────┐
   │ soc-screens  │◄────┤   soc-bridge    ├────►│ Wazuh API / Indexer      │
   │ Chromium     │     │ FastAPI+SQLite  ├────►│ MISP · Shuffle · Wiki.js │
   │ (aislado)    │     └───────┬─────────┘     │ Sophos · Microsoft Graph │
   └──────────────┘             │               │ Ollama (IA local)        │
                           /data (volumen)      └──────────────────────────┘
```

- **soc-web**: interfaz React 19 + TypeScript servida por nginx.
- **soc-bridge**: API FastAPI. Contenedor de solo lectura, sin privilegios, con los datos en SQLite (`/data`).
- **soc-screens**: Chromium headless aislado (sin `.env`, sin capacidades, con token) para las capturas de los portales.

## 🚀 Inicio rápido

```bash
git clone https://github.com/CyberRyuki/soc-portal.git
cd soc-portal
cp .env.example .env            # edita IP, URLs y credenciales de tus servicios
echo "SCREENS_TOKEN=$(openssl rand -hex 24)" >> .env
docker compose --env-file .env -f bridge/docker-compose.yml up -d --build
```

Abre `http://<servidor>:8088/portal/` y entra con un usuario de `PORTAL_USERS`. En el primer acceso se te pedirá
cambiar la contraseña.

La instalación completa (Wazuh, MISP, Shuffle y Wiki.js, credenciales de solo lectura y reglas de firewall) está en
**[docs/instalacion.md](docs/instalacion.md)**.

## 🔐 Seguridad por diseño

- **Humano en el bucle**: aislar equipos, bloquear IoC o deshabilitar cuentas requiere un motivo y una aprobación
  desde el portal. Opcionalmente, regla de cuatro ojos.
- **Incidentes no automáticos**: las detecciones proponen y el analista decide.
- **Auditoría encadenada** con hashes y secretos redactados.
- **Login endurecido**: MFA TOTP por rol, bloqueo por intentos, caducidad de sesión, LDAP/Active Directory opcional.
- **Escaneos acotados**: solo dentro del alcance definido, con autorización registrada y vigente; rangos privados bloqueados.
- **Contenedores mínimos**: `read_only`, `cap_drop: ALL`, `no-new-privileges` y usuarios sin root.
- **Integraciones de solo lectura** siempre que es posible (Wazuh, MISP, Sophos y Microsoft 365 en modo lectura).

## 📚 Documentación

| Documento | Contenido |
|---|---|
| [docs/instalacion.md](docs/instalacion.md) | Instalación completa y operación |
| [docs/exposicion.md](docs/exposicion.md) | Exposición y Shadow IT: alcance, autorización y perfiles |
| [docs/sophos.md](docs/sophos.md) | Integración con Sophos Central |
| [docs/m365.md](docs/m365.md) | Integración con Microsoft 365 / Entra ID |
| [docs/seguridad.md](docs/seguridad.md) | Endurecimiento y copias de seguridad |
| [web/README.md](web/README.md) | Desarrollo de la interfaz web |

## 🧪 Pruebas

```bash
cd bridge && python3 -m pytest tests -q          # backend
cd web && npm ci && npm test && npm run build    # interfaz
```

## 🗂️ Estructura

```
bridge/        API soc-bridge (FastAPI) y docker-compose del portal
web/           Interfaz React + TypeScript
screens/       Servicio de capturas (Chromium + Playwright)
wazuh/         Integraciones y reglas para el servidor Wazuh
misp/ shuffle/ wikijs/   Despliegue de cada servicio
wiki-content/  Páginas, runbooks y plantillas de la Wiki
docs/          Guías
```

## ⚠️ Aviso

Las herramientas de escaneo y respuesta de este proyecto son para uso **defensivo**, solo sobre sistemas propios o con
autorización expresa. Avisa a tu equipo de red antes de lanzar un escaneo activo.
