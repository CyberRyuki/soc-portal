import { describe, expect, it } from 'vitest';
import { tokenize } from '../CodeView';

describe('tokenize (resaltado de código)', () => {
  it('reconoce comentarios, cadenas y palabras clave de Python', () => {
    const t = tokenize('def f():\n  # hola\n  return "x"', 'python');
    expect(t.find((x) => x.t === 'def')?.c).toBe('k');
    expect(t.find((x) => x.t === '# hola')?.c).toBe('c');
    expect(t.find((x) => x.t === '"x"')?.c).toBe('s');
  });
  it('conserva el texto original completo', () => {
    const src = 'const a = 1; // fin\nlet b = `t`;';
    expect(
      tokenize(src, 'javascript')
        .map((x) => x.t)
        .join(''),
    ).toBe(src);
  });
});
