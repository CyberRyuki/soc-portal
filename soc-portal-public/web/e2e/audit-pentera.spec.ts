import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test, type Page } from '@playwright/test';

/** Requieren un administrador sin MFA: E2E_ADMIN_USER / E2E_ADMIN_PASS. */
const ADMIN = process.env.E2E_ADMIN_USER ?? '';
const ADMIN_PASS = process.env.E2E_ADMIN_PASS ?? '';
const here = path.dirname(fileURLToPath(import.meta.url));

test.skip(!ADMIN || !ADMIN_PASS, 'Define E2E_ADMIN_USER y E2E_ADMIN_PASS');

async function loginAdmin(page: Page, next: string) {
  await page.goto(`/portal/login?next=${encodeURIComponent(next)}`);
  await page.getByLabel('Usuario').fill(ADMIN);
  await page.getByLabel('Contraseña').fill(ADMIN_PASS);
  await page.getByRole('button', { name: /entrar/i }).click();
  await expect(page.getByRole('navigation')).toBeVisible();
}

test('subir un PDF de Pentera, revisar y importar; queda en la auditoría', async ({ page }) => {
  await loginAdmin(page, '/portal/vulns?view=pentera');
  await page.setInputFiles('#pt-file', path.join(here, 'fixtures', 'pentera_ejemplo.pdf'));
  await page.getByRole('button', { name: /Leer informe/ }).click();
  await expect(page.getByText(/Revisión ·/)).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole('textbox', { name: 'Título' }).first()).toHaveValue('SMB Signing Not Required');
  await page.getByRole('checkbox', { name: /Incluir TLS 1.0/ }).click();
  await page.getByRole('button', { name: /^Importar 4/ }).click();
  await expect(page.getByText(/nuevas y \d+ actualizadas/)).toBeVisible();

  await page.goto('/portal/audit?module=Vulnerabilidades');
  await expect(page.getByRole('cell', { name: 'Importar' }).first()).toBeVisible();
  await page.getByRole('button', { name: /Verificar integridad/ }).click();
  await expect(page.getByText(/Cadena íntegra/)).toBeVisible();
});

test('el registro del sistema se puede filtrar', async ({ page }) => {
  await loginAdmin(page, '/portal/audit?view=sistema');
  await expect(page.getByText('Registro del sistema').first()).toBeVisible();
  await page.getByRole('button', { name: 'Solo errores' }).click();
  await expect(page.locator('main')).toBeVisible();
});
