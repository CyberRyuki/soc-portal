import { expect, test } from '@playwright/test';
import { login, PASS } from './helpers';

test.skip(!PASS, 'Define E2E_PASS para ejecutar las pruebas e2e');

test('Microsoft 365: todas las pestañas cargan sin errores', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await login(page, '/m365');
  await expect(page.getByRole('heading', { name: 'Microsoft 365', exact: true })).toBeVisible();
  const configured = await page
    .getByRole('button', { name: 'Secure Score' })
    .waitFor({ timeout: 5000 })
    .then(() => true)
    .catch(() => false);
  test.skip(!configured, 'Microsoft 365 no está configurado en este entorno');
  for (const tab of [
    'Inicios de sesión',
    'Usuarios en riesgo',
    'Correo',
    'Auditoría',
    'Secure Score',
    /^Acciones/,
    'Alertas',
  ]) {
    await page.getByRole('button', { name: tab }).click();
    await expect(page.locator('main .card').first()).toBeVisible();
  }
  expect(errors).toEqual([]);
});

test('una sugerencia de incidente se puede convertir en incidente', async ({ page }) => {
  await login(page, '/incidents');
  const create = page.getByRole('button', { name: 'Crear incidente' }).first();
  const has = await create
    .waitFor({ timeout: 5000 })
    .then(() => true)
    .catch(() => false);
  test.skip(!has, 'No hay sugerencias pendientes en este entorno');
  await create.click();
  const dlg = page.getByRole('dialog');
  await expect(dlg.getByLabel(/Título/)).not.toHaveValue('');
  await dlg.getByRole('button', { name: /crear/i }).click();
  await expect(page).toHaveURL(/\/portal\/incidents\/INC-/);
});
