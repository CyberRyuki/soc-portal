import { expect, test } from '@playwright/test';
import { login, PASS } from './helpers';

test.skip(!PASS, 'Define E2E_PASS para ejecutar las pruebas e2e');

const PAGES: [RegExp, RegExp][] = [
  [/^Amenazas/, /\/threats/],
  [/^Agentes/, /\/agents/],
  [/^IoC/, /\/iocs/],
  [/^Inteligencia/, /\/intel/],
  [/^Asistente IA/, /\/ai$/],
  [/^Vulnerabilidades/, /\/vulns/],
  [/^Portales/, /\/sites/],
  [/^Incidentes/, /\/incidents/],
  [/^Runbooks/, /\/runbooks/],
  [/^ATT&CK/, /\/mitre/],
  [/^Herramientas/, /\/tools/],
  [/^Contactos/, /\/contacts/],
  [/^Resumen/, /\/portal\/?$/],
];

test('todas las secciones cargan sin errores de consola', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  await login(page);
  for (const [name, url] of PAGES) {
    await page.getByRole('navigation').getByRole('link', { name }).click();
    await expect(page).toHaveURL(url);
    await expect(page.locator('main h1')).toBeVisible();
  }
  expect(errors).toEqual([]);
});

test('el tema se puede cambiar y se recuerda', async ({ page }) => {
  await login(page);
  const html = page.locator('html');
  const before = await html.getAttribute('data-theme');
  await page.getByRole('button', { name: 'Cambiar tema' }).click();
  await expect(html).not.toHaveAttribute('data-theme', before ?? '');
  const after = await html.getAttribute('data-theme');
  await page.reload();
  await expect(html).toHaveAttribute('data-theme', after ?? '');
});
