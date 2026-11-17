import { describe, expect, it } from 'vitest';
import { renderMarkdown } from '../markdown';

describe('renderMarkdown (prevención de XSS)', () => {
  it('renderiza markdown básico', () => {
    expect(renderMarkdown('# Título\n\n**negrita**')).toContain('<strong>negrita</strong>');
  });
  it('elimina scripts y manejadores de eventos', () => {
    const html = renderMarkdown(
      '<img src=x onerror="alert(1)"><script>alert(2)</script>[x](javascript:alert(3))',
    );
    expect(html).not.toMatch(/onerror|<script|javascript:/i);
  });
});
