import { describe, expect, it } from 'vitest';
import { passwordRules } from '../AccountPage';

describe('passwordRules', () => {
  it('exige longitud, mayúsculas, números, símbolos y no contener el usuario', () => {
    expect(passwordRules('corta', 'ana').filter(([ok]) => ok)).toHaveLength(1);
    expect(passwordRules('Segura.Clave.2026', 'ana').every(([ok]) => ok)).toBe(true);
    expect(passwordRules('Ana.Clave.2026!', 'ana').find(([, t]) => t.includes('usuario'))?.[0]).toBe(false);
  });
});
