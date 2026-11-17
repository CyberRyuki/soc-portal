import { describe, expect, it } from 'vitest';
import { safeNext } from '../LoginPage';

describe('safeNext (sin redirecciones abiertas)', () => {
  it('acepta rutas internas con o sin prefijo /portal', () => {
    expect(safeNext('?next=/portal/incidents')).toBe('/portal/incidents');
    expect(safeNext('?next=' + encodeURIComponent('/incidents?view=board'))).toBe(
      '/portal/incidents?view=board',
    );
  });
  it('rechaza destinos externos', () => {
    for (const bad of ['//evil.com', 'https://evil.com', '/\\evil.com', 'javascript:alert(1)', ''])
      expect(safeNext('?next=' + encodeURIComponent(bad))).toBe('/portal/');
  });
});
