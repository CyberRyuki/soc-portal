import { expect, test } from '@playwright/test';
import { login, PASS } from './helpers';

test.skip(!PASS, 'Define E2E_PASS para ejecutar las pruebas e2e');

test('la página de Sophos carga sus pestañas sin errores', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await login(page, '/sophos');
  await expect(page.getByRole('heading', { name: 'Sophos Central', exact: true })).toBeVisible();
  const configured = await page
    .getByRole('button', { name: 'Equipos' })
    .waitFor({ timeout: 5000 })
    .then(() => true)
    .catch(() => false);
  test.skip(!configured, 'Sophos Central no está configurado en este entorno');
  for (const tab of ['Equipos', 'Bloqueos', /^Acciones( \(\d+\))?$/, 'Alertas']) {
    await page.getByRole('button', { name: tab }).click();
    await expect(page.locator('main table, main [role=status], main .card').first()).toBeVisible();
  }
  expect(errors).toEqual([]);
});

test('una acción de Sophos exige motivo antes de confirmar', async ({ page }) => {
  await login(page, '/sophos?view=equipos');
  const menu = page.getByRole('button', { name: /^Acciones de / }).first();
  const has = await menu
    .waitFor({ timeout: 5000 })
    .then(() => true)
    .catch(() => false);
  test.skip(!has, 'Sin equipos de Sophos (o Sophos no configurado)');
  await menu.click();
  await page.getByRole('menuitem', { name: /Escanear/ }).click();
  const dlg = page.getByRole('dialog');
  const ok = dlg.getByRole('button', { name: /Confirmar|Solicitar/ });
  await expect(ok).toBeDisabled();
  await dlg.getByLabel(/Motivo/).fill('Escaneo de comprobación e2e');
  await expect(ok).toBeEnabled();
  await dlg.getByRole('button', { name: 'Cancelar' }).click();
});
