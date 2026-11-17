import { expect, test } from '@playwright/test';
import { login, PASS, USER } from './helpers';

test.skip(!PASS, 'Define E2E_PASS para ejecutar las pruebas e2e');

test('una ruta protegida redirige al login y vuelve tras entrar', async ({ page }) => {
  await page.goto('/portal/incidents');
  await expect(page).toHaveURL(/\/portal\/login\?next=/);
  await page.getByLabel('Usuario').fill(USER);
  await page.getByLabel('Contraseña').fill(PASS);
  await page.getByRole('button', { name: /entrar/i }).click();
  await expect(page).toHaveURL(/\/portal\/incidents/);
});

test('credenciales incorrectas muestran un error', async ({ page }) => {
  await page.goto('/portal/login');
  await page.getByLabel('Usuario').fill(USER);
  await page.getByLabel('Contraseña').fill('incorrecta-' + Date.now());
  await page.getByRole('button', { name: /entrar/i }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('alert')).not.toHaveText(/caducada/i);
  await expect(page).toHaveURL(/\/portal\/login/);
});

test('cerrar sesión vuelve al login', async ({ page }) => {
  await login(page);
  await page.getByRole('button', { name: 'Menú de usuario' }).click();
  await page.getByRole('menuitem', { name: /cerrar sesión/i }).click();
  await expect(page).toHaveURL(/\/portal\/login/);
});
