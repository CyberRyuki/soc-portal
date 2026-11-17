import { marked } from 'marked';
import DOMPurify from 'dompurify';

marked.setOptions({ gfm: true, breaks: false });

/** Markdown → HTML saneado (defensa XSS: solo etiquetas y atributos seguros). */
export function renderMarkdown(src: string | null | undefined): string {
  const html = marked.parse(src ?? '', { async: false });
  return DOMPurify.sanitize(html, { USE_PROFILES: { html: true }, ADD_ATTR: ['target', 'rel'] });
}
