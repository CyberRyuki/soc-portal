# Portal SOC — frontend web (v14)

Interfaz del Portal SOC de ACME: React 19 + TypeScript estricto, servida por un contenedor **nginx** (`soc-web`)
que también hace de proxy inverso hacia la API de `soc-bridge` (FastAPI).

```
Navegador ──► soc-web (nginx :8088) ──┬─► /portal/*          SPA estática (este proyecto)
                                      └─► /portal/api|auth|data, /feeds, /health, /api/soc
                                                              ──► soc-bridge:8088 (red interna)
```

## Stack

| Área                 | Elección                                                                                |
| -------------------- | --------------------------------------------------------------------------------------- |
| Base                 | Vite 8, React 19, TypeScript 5.9 (`strict`, `noUncheckedIndexedAccess`)                 |
| Estilos              | Tailwind CSS v4, componentes estilo shadcn/ui sobre Radix UI, iconos Lucide             |
| Temas                | claro, oscuro y XR (tokens CSS en `src/index.css`, `data-theme` en `<html>`)            |
| Rutas                | React Router 7 (`basename /portal`), páginas con carga diferida (`lazy`)                |
| Datos                | TanStack Query 5 (caché, reintentos, invalidación); estado de UI con Zustand            |
| Formularios          | React Hook Form + Zod                                                                   |
| Gráficos / animación | Recharts, GSAP (respeta `prefers-reduced-motion`)                                       |
| Markdown             | marked + DOMPurify (todo HTML se sanea antes de pintarse)                               |
| Calidad              | ESLint (typescript-eslint, react-hooks), Prettier, Vitest + Testing Library, Playwright |

## Estructura

```
src/
  app/          App, router (lazy + guardas RequireAuth/RequireAdmin), queryClient
  components/
    ui/         primitivas (button, dialog, tabs, table…) — estilo shadcn
    shared/     piezas del SOC (Kpi, Panel, SevPill, HBars, Markdown…)
    charts/     gráficos Recharts con colores del tema
    layout/     Sidebar, AppShell
  hooks/        useAuth (sesión y roles), useConfirm, useSearchParam, usePageEnter
  lib/          api (cliente HTTP), format, markdown (saneado), constants, utils
  services/     hooks de datos por dominio (incidents, threats, iocs, ai, tools…)
  pages/        una carpeta por sección (home, threats, incidents, iocs, ai, mitre, tools, admin…)
  store/        Zustand (tema, modo NOC, barra lateral)
  types/        contrato de la API de soc-bridge
e2e/            pruebas Playwright
docker/         nginx.conf del contenedor soc-web
```

## Integraciones y módulos

- **Auditoría** (`/portal/audit`, solo admin): todo POST/PUT/PATCH/DELETE queda registrado (usuario o integración,
  IP, módulo, objeto, resultado y datos enviados con los secretos ocultos), también los intentos rechazados. Cadena de
  hashes verificable, exportación CSV y registro del sistema en vivo. Conservación: `AUDIT_DAYS`.
- **Pentera** (`/portal/vulns?view=pentera`): sube el PDF del informe (o la exportación JSON/CSV), revisa y corrige los
  hallazgos y se importan a Seguimiento. El original queda guardado y descargable.

- **Sophos Central** (`/portal/sophos`): alertas, equipos, bloqueos y cola de acciones con aprobación humana.
  Configuración y uso desde Shuffle en [`../docs/sophos.md`](../docs/sophos.md).

## Desarrollo

Requisitos: Node 22+, un `soc-bridge` accesible.

```bash
cd web
npm ci
cp .env.example .env.local        # ajusta VITE_API_PROXY al bridge (p. ej. http://10.10.10.101:8088)
npm run dev                       # http://localhost:5173/portal/
```

Vite reenvía las rutas de API al bridge, así que la cookie de sesión funciona igual que en producción.

### Scripts

| Comando                           | Qué hace                                       |
| --------------------------------- | ---------------------------------------------- |
| `npm run dev`                     | servidor de desarrollo con recarga en caliente |
| `npm run build`                   | `tsc -b` + build de producción en `dist/`      |
| `npm run preview`                 | sirve `dist/` localmente                       |
| `npm run typecheck`               | comprobación de tipos sin emitir               |
| `npm run lint`                    | ESLint                                         |
| `npm run format` / `format:check` | Prettier                                       |
| `npm test`                        | pruebas unitarias (Vitest)                     |
| `npm run test:e2e`                | pruebas end-to-end (Playwright)                |

## Pruebas

**Unitarias** (`src/**/__tests__`): formato de datos, cliente API (CSRF, errores, 401), saneado de Markdown
contra XSS, protección contra redirecciones abiertas en el login, reglas de contraseña, resaltado de código,
componentes compartidos y tablero Kanban.

**End-to-end** (`e2e/`): login y redirección, credenciales erróneas, cierre de sesión, navegación por todas las
secciones sin errores de consola, cambio de tema persistente, creación de incidente y tablero.

```bash
# contra el entorno de desarrollo (arranca npm run dev automáticamente)
E2E_USER=e2e E2E_PASS='…' VITE_API_PROXY=http://127.0.0.1:8088 npm run test:e2e
# contra un portal desplegado
E2E_BASE_URL=http://10.10.10.101:8088 E2E_USER=e2e E2E_PASS='…' npm run test:e2e
```

Usa un usuario `analyst` **sin MFA** dedicado a pruebas (las e2e crean incidentes de prueba). La primera vez:
`npx playwright install chromium`.

## Seguridad

- **Sin secretos en el frontend.** La sesión es una cookie `HttpOnly`, `SameSite=Strict` emitida por soc-bridge;
  el JavaScript nunca ve tokens. Las variables `VITE_*` son públicas: no se usan para claves.
- **CSRF:** todas las peticiones llevan `X-SOC: 1`; el bridge rechaza las mutaciones sin esa cabecera.
- **XSS:** React escapa por defecto; el único HTML dinámico (Markdown de runbooks, respuestas de la IA, QR de MFA)
  pasa por DOMPurify. El visor de código genera nodos React, no HTML.
- **CSP estricta** en nginx (`script-src 'self'`, sin `eval`, sin orígenes externos), `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy`, `Permissions-Policy`. Las fuentes se sirven como archivos, no `data:`.
- **RBAC:** la UI oculta acciones según rol (`viewer` / `analyst` / `admin`), pero **la autorización real la hace el
  backend** en cada endpoint.
- **Redirecciones:** `?next=` solo acepta rutas internas de `/portal`.
- Las respuestas 401 llevan al login conservando la ruta; 428 obliga a cambiar contraseña o activar MFA.

## Despliegue

El `bridge/docker-compose.yml` construye los dos contenedores:

```bash
cd /opt/soc-portal
docker compose --env-file .env -f bridge/docker-compose.yml up -d --build --force-recreate
```

- `soc-web` publica el puerto **8088** (mismo que antes, sin cambios para los usuarios).
- `soc-bridge` ya **no** se publica: solo es accesible por la red interna `soc-net`.
- El build (`web/Dockerfile`) es multi-etapa: `node:22-alpine` compila y `nginx:1.27-alpine` sirve. El primer
  build necesita acceso al registro npm desde el servidor.
- Contenedor de solo lectura, `no-new-privileges`, recursos estáticos con caché inmutable e `index.html` sin caché.

### Variables de entorno

| Variable                                                 | Dónde                       | Uso                                                     |
| -------------------------------------------------------- | --------------------------- | ------------------------------------------------------- |
| `VITE_API_PROXY`                                         | `web/.env.local` (solo dev) | backend al que Vite reenvía la API                      |
| `E2E_BASE_URL`, `E2E_USER`, `E2E_PASS`, `PW_CHROMIUM`    | entorno (solo pruebas)      | ver «Pruebas»                                           |
| `AUTH_TRUST_PROXY`                                       | fijada a `true` en compose  | el bridge toma la IP real de `X-Forwarded-For` de nginx |
| `AUTH_COOKIE_SECURE`                                     | `.env`                      | `true` cuando el portal se publique por HTTPS           |
| resto (`AUTH_*`, `AI_*`, `WAZUH_*`, `MISP_*`, `LDAP_*`…) | `.env`                      | backend — ver `../.env.example`                         |

El frontend no necesita ninguna variable en producción.
