import { useNavigate } from 'react-router-dom';
import { Compass, Globe } from 'lucide-react';
import { Chips } from '@/components/shared';

export const MARK_COLOR: Record<string, string> = {
  detectada: 'var(--st-good)',
  parcial: 'var(--st-warn)',
  sin_cobertura: 'var(--st-crit)',
  no_aplica: 'var(--s-neutral)',
};
export const OW_VARIANT: Record<string, 'ok' | 'warn' | 'bad' | 'gray'> = {
  cumple: 'ok',
  parcial: 'warn',
  no_cumple: 'bad',
  no_aplica: 'gray',
};
export const stripCitations = (s: string) => s.replace(/\(Citation:[^)]*\)/g, '');

export function FrameworkNav({ cur }: { cur: 'mitre' | 'owasp' }) {
  const nav = useNavigate();
  return (
    <Chips
      options={[
        [
          'mitre',
          <>
            <Compass className="size-3.5" /> MITRE ATT&CK
          </>,
        ],
        [
          'owasp',
          <>
            <Globe className="size-3.5" /> OWASP Top 10
          </>,
        ],
      ]}
      value={cur}
      onChange={(v) => nav(`/${v}`)}
    />
  );
}
