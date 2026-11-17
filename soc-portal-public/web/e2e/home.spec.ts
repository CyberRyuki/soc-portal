import { expect, test } from '@playwright/test';
import { login, PASS } from './helpers';

test.skip(!PASS, 'Define E2E_PASS para ejecutar las pruebas e2e');

test('el Resumen muestra riesgo, integraciones y línea de tiempo, y recuerda el intervalo', async ({
  page,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await login(page);
  await expect(page.getByLabel(/Riesgo del SOC: \d+ de 100/)).toBeVisible();
  await expect(page.getByText('Estado de las integraciones')).toBeVisible();
  await expect(page.getByText('Línea de tiempo')).toBeVisible();
  const sel = page.getByRole('combobox', { name: 'Intervalo de actualización' });
  await sel.selectOption('60000');
  await page.reload();
  await expect(sel).toHaveValue('60000');
  await page.getByRole('button', { name: 'Actualizar ahora' }).click();
  await expect(page.getByText(/Actualizado hace|Actualizando/)).toBeVisible();
  expect(errors).toEqual([]);
});
