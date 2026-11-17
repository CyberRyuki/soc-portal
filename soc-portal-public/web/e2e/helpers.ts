import { expect, type Page } from '@playwright/test';

export const USER = process.env.E2E_USER ?? 'ana';
export const PASS = process.env.E2E_PASS ?? '';

export async function login(page: Page, next = '') {
  await page.goto(`/portal/login${next ? `?next=${encodeURIComponent(next)}` : ''}`);
  await page.getByLabel('Usuario').fill(USER);
  await page.getByLabel('Contraseña').fill(PASS);
  await page.getByRole('button', { name: /entrar/i }).click();
  await expect(page.getByRole('navigation')).toBeVisible();
}
