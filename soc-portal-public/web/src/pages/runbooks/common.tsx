import { Link } from 'react-router-dom';
import { Badge } from '@/components/ui/badge';

export const LEVELS = ['Básico', 'Intermedio', 'Avanzado', 'Referencia'] as const;
export const LEVEL_VARIANT: Record<string, 'ok' | 'warn' | 'bad' | 'gray'> = {
  Básico: 'ok',
  Intermedio: 'warn',
  Avanzado: 'bad',
  Referencia: 'gray',
};
export const LevelPill = ({ v }: { v: string }) =>
  v ? <Badge variant={LEVEL_VARIANT[v] ?? 'gray'}>{v}</Badge> : null;
export const splitList = (s: string | null | undefined) =>
  (s ?? '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
export const MitreChips = ({ s, max = 4 }: { s: string | null | undefined; max?: number }) => (
  <>
    {splitList(s)
      .slice(0, max)
      .map((t) => (
        <Link key={t} to={`/mitre?t=${encodeURIComponent(t)}`} onClick={(e) => e.stopPropagation()}>
          <Badge variant="info" className="font-mono">
            {t}
          </Badge>
        </Link>
      ))}
  </>
);
export const OwaspChips = ({ s }: { s: string | null | undefined }) => (
  <>
    {splitList(s).map((o) => (
      <Link key={o} to={`/owasp?a=${encodeURIComponent(o)}`} onClick={(e) => e.stopPropagation()}>
        <Badge variant="warn">{o.split(':')[0]}</Badge>
      </Link>
    ))}
  </>
);
