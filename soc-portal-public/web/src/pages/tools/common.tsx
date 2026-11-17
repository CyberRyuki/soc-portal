import { Badge } from '@/components/ui/badge';
import type { FindingSeverity } from '@/types/api';

export const STATUS_VARIANT: Record<string, 'ok' | 'warn' | 'gray'> = {
  Aprobada: 'ok',
  'En evaluación': 'warn',
  Obsoleta: 'gray',
};
export const PLAT_ICON: Record<string, string> = {
  Kali: '🐉',
  Windows: '🪟',
  Linux: '🐧',
  Multiplataforma: '🌐',
};
export const LANG_COLOR: Record<string, string> = {
  Python: '#3572A5',
  Shell: '#89e051',
  Bash: '#89e051',
  PowerShell: '#012456',
  JavaScript: '#f1e05a',
  TypeScript: '#3178c6',
  Go: '#00ADD8',
  C: '#555555',
  'C++': '#f34b7d',
  Rust: '#dea584',
  YARA: '#220000',
  Ruby: '#701516',
  'C#': '#178600',
  Java: '#b07219',
};
export const FSEV: Record<FindingSeverity, [string, string]> = {
  critical: ['Crítica', 'var(--st-crit)'],
  high: ['Alta', 'var(--st-serious)'],
  medium: ['Media', 'var(--st-warn)'],
  low: ['Baja', 'var(--s-neutral)'],
  informational: ['Info', 'var(--s-neutral)'],
};
export const ccnColor = (c: number) =>
  c > 25
    ? 'var(--st-crit)'
    : c > 15
      ? 'var(--st-serious)'
      : c > 10
        ? 'var(--st-warn)'
        : c > 5
          ? 'var(--q4)'
          : 'var(--q2)';

export const LangDot = ({ l }: { l: string }) =>
  l ? (
    <span className="inline-flex items-center gap-1.5">
      <i
        className="inline-block size-2.5 rounded-full"
        style={{ background: LANG_COLOR[l] ?? 'var(--s-neutral)' }}
      />
      {l}
    </span>
  ) : null;
export const FindingSev = ({ s }: { s: FindingSeverity | null }) =>
  s ? (
    <Badge style={{ background: `color-mix(in srgb, ${FSEV[s][1]} 18%, transparent)`, color: FSEV[s][1] }}>
      {FSEV[s][0]}
    </Badge>
  ) : (
    <Badge variant="gray">Por validar</Badge>
  );
export const tagList = (s: string | null | undefined) =>
  (s ?? '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
