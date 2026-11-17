import { expect, test } from '@playwright/test';
import { login, PASS } from './helpers';

test.skip(!PASS, 'Define E2E_PASS para ejecutar las pruebas e2e');

test('crear un incidente y abrir su ficha', async ({ page }) => {
  const title = `E2E prueba ${Date.now()}`;
  await login(page);
  await page
    .getByRole('button', { name: /incidente/i })
    .first()
    .click();
  const dlg = page.getByRole('dialog');
  await dlg.getByLabel(/Título/).fill(title);
  await dlg.getByRole('button', { name: /crear/i }).click();
  await expect(page).toHaveURL(/\/portal\/incidents\/INC-/);
  await expect(page.getByRole('heading', { name: title })).toBeVisible();
});

test('el tablero muestra las cuatro columnas', async ({ page }) => {
  await login(page, '/incidents?view=board');
  for (const l of ['Abierto', 'En investigación', 'Contenido', 'Cerrado'])
    await expect(page.getByLabel(`Columna ${l}`)).toBeVisible();
});

test('cerrar un incidente con su resolución y reabrirlo', async ({ page }) => {
  const title = `E2E cierre ${Date.now()}`;
  await login(page);
  await page
    .getByRole('button', { name: /incidente/i })
    .first()
    .click();
  await page
    .getByRole('dialog')
    .getByLabel(/Título/)
    .fill(title);
  await page.getByRole('dialog').getByRole('button', { name: /crear/i }).click();
  await expect(page.getByRole('heading', { name: title })).toBeVisible();

  await page.getByRole('button', { name: 'Cerrar incidente' }).click();
  const dlg = page.getByRole('dialog');
  await dlg.getByRole('button', { name: /cerrar incidente/i }).click();
  await expect(dlg.getByText(/cómo se resolvió/i)).toBeVisible(); // la resolución es obligatoria
  await dlg.getByLabel(/Resolución/).fill('Se bloqueó la IP en el firewall y se rotaron credenciales');
  await dlg.getByRole('button', { name: /cerrar incidente/i }).click();
  await expect(page.getByText('Cerrado', { exact: true }).first()).toBeVisible();
  await expect(page.getByText(/✔ Cierre: Se bloqueó la IP/)).toBeVisible();

  await page.getByRole('button', { name: 'Reabrir' }).click();
  await expect(page.getByRole('button', { name: 'Cerrar incidente' })).toBeVisible();
});

test('un analista no ve la opción de eliminar', async ({ page }) => {
  test.skip(!!process.env.E2E_ADMIN, 'El usuario de pruebas es administrador');
  await login(page, '/incidents?status=');
  await expect(page.getByRole('button', { name: /^Acciones de / }).first()).toBeVisible();
  await page
    .getByRole('button', { name: /^Acciones de / })
    .first()
    .click();
  await expect(page.getByRole('menuitem', { name: /eliminar/i })).toHaveCount(0);
});
