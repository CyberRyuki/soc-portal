import { defineConfig, devices } from '@playwright/test';

/**
 * Pruebas end-to-end. Necesitan un backend soc-bridge accesible:
 *  - E2E_BASE_URL: URL del portal ya desplegado (p. ej. http://localhost:8088). Si no se define,
 *    se arranca `npm run dev` y Vite reenvía la API a VITE_API_PROXY.
 *  - E2E_USER / E2E_PASS: usuario de pruebas con rol analyst o admin, SIN MFA.
 */
const baseURL = process.env.E2E_BASE_URL ?? 'http://127.0.0.1:5173';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL,
    trace: 'retain-on-failure',
    locale: 'es-DO',
    // Permite usar un Chromium ya instalado (p. ej. en CI o en un servidor sin descarga).
    launchOptions: process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM } : {},
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: process.env.E2E_BASE_URL
    ? undefined
    : {
        command: 'npm run dev -- --port 5173 --strictPort',
        url: `${baseURL}/portal/login`,
        reuseExistingServer: true,
      },
});
