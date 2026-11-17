import { useMemo } from 'react';

const KW = new Set(
  'def class import from return if elif else for while try except finally with as in is not and or None True False async await lambda yield pass break continue raise global nonlocal del assert function const let var new this typeof instanceof switch case default echo fi then do done esac local export param begin process end foreach select where'.split(
    ' ',
  ),
);
type Tok = { t: string; c?: 'c' | 's' | 'k' | 'n' };
const CLS: Record<string, string> = {
  c: 'text-[#5c8a5c] italic',
  s: 'text-[#b5651d]',
  k: 'text-[#7a3ecf] font-semibold',
  n: 'text-[#1b6fa8]',
};

/** Resaltado ligero por expresiones regulares (comentarios, cadenas, palabras clave, números). Devuelve nodos React, nunca HTML. */
export function tokenize(src: string, lang: string): Tok[] {
  if (lang === 'text' || src.length > 1_500_000) return [{ t: src }];
  const hashC = ['python', 'bash', 'powershell', 'ruby', 'yaml'].includes(lang);
  const slashC = !['python', 'bash', 'yaml', 'powershell'].includes(lang);
  const re = new RegExp(
    [
      hashC ? '(#[^\\n]*)' : '(\\b\\B)',
      slashC ? '(\\/\\/[^\\n]*|\\/\\*[\\s\\S]*?\\*\\/)' : '(\\b\\B)',
      `("""[\\s\\S]*?"""|'''[\\s\\S]*?'''|"(?:\\\\.|[^"\\\\\\n])*"|'(?:\\\\.|[^'\\\\\\n])*'|\`(?:\\\\.|[^\`\\\\])*\`)`,
      '\\b([A-Za-z_][A-Za-z0-9_]*)\\b',
      '\\b(\\d+(?:\\.\\d+)?)\\b',
    ].join('|'),
    'g',
  );
  const out: Tok[] = [];
  let last = 0,
    m: RegExpExecArray | null;
  while ((m = re.exec(src))) {
    if (!m[0]) {
      re.lastIndex++;
      continue;
    }
    if (m.index > last) out.push({ t: src.slice(last, m.index) });
    const t = m[0];
    if (m[1] || m[2]) out.push({ t, c: 'c' });
    else if (m[3]) out.push({ t, c: 's' });
    else if (m[4])
      out.push(KW.has(t) ? { t, c: 'k' } : /^[A-Z][A-Z0-9_]{2,}$/.test(t) ? { t, c: 'n' } : { t });
    else out.push({ t, c: 'n' });
    last = re.lastIndex;
  }
  if (last < src.length) out.push({ t: src.slice(last) });
  return out;
}

export function CodeView({ src, lang, lines }: { src: string; lang: string; lines: number | null }) {
  const toks = useMemo(() => tokenize(src, lang), [src, lang]);
  const n = lines ?? src.split('\n').length;
  return (
    <div className="flex overflow-auto rounded-xl border border-line bg-grid font-mono text-[12.5px] leading-[1.55] scroll-thin">
      <pre className="select-none border-r border-line px-2.5 py-3 text-right text-muted" aria-hidden="true">
        {Array.from({ length: n }, (_, i) => i + 1).join('\n')}
      </pre>
      <pre className="flex-1 whitespace-pre px-3 py-3">
        {toks.map((x, i) =>
          x.c ? (
            <span key={i} className={CLS[x.c]}>
              {x.t}
            </span>
          ) : (
            x.t
          ),
        )}
      </pre>
    </div>
  );
}
