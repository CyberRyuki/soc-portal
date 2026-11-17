import { Badge } from '@/components/ui/badge';
import { Empty } from '@/components/shared';
import { nf } from '@/lib/format';
import type { IntelJob, IntelSourceHit } from '@/types/api';

export const KIND_LABEL: Record<string, string> = { feed: 'Feed', misp: 'MISP', manual: 'Carga' };
export const TLP_VARIANT: Record<string, 'bad' | 'warn' | 'ok' | 'gray'> = {
  red: 'bad',
  amber: 'warn',
  green: 'ok',
  clear: 'gray',
  white: 'gray',
};
export const JOB_KIND: Record<string, string> = {
  feed: 'Descarga',
  misp: 'MISP',
  upload: 'Archivo',
  retro: 'Retrobúsqueda',
  delete: 'Borrado',
};

export const SourcePills = ({ f, max = 4 }: { f: IntelSourceHit[] | undefined; max?: number }) => {
  const list = f ?? [];
  if (!list.length) return <span className="text-muted">—</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {list.slice(0, max).map((x) => (
        <Badge
          key={x.id}
          variant={x.weight >= 80 ? 'bad' : x.weight >= 60 ? 'warn' : 'gray'}
          title={`Confianza ${x.weight}${x.ref ? ` · ${x.ref}` : ''}${x.via && x.via !== (x as { value?: string }).value ? ` · vía ${x.via}` : ''}`}
        >
          {x.name}
        </Badge>
      ))}
      {list.length > max && <span className="text-xs text-muted">+{list.length - max}</span>}
    </span>
  );
};

export function JobsList({ jobs }: { jobs: IntelJob[] }) {
  if (!jobs.length) return <Empty className="py-3">Sin trabajos todavía.</Empty>;
  return (
    <ul className="space-y-2">
      {jobs.map((j) => (
        <li key={j.id} className="flex items-start gap-2 text-[13px]">
          <Badge variant={j.status === 'done' ? 'ok' : j.status === 'error' ? 'bad' : 'warn'}>
            {j.status === 'running'
              ? '⏳ En curso'
              : j.status === 'queued'
                ? 'En cola'
                : j.status === 'done'
                  ? 'Listo'
                  : 'Error'}
          </Badge>
          <div className="min-w-0 flex-1">
            <b>{JOB_KIND[j.kind] ?? j.kind}</b> {j.source}
            <div className="truncate text-xs text-muted">
              {j.status === 'running' ? `${nf(j.done)} procesados…` : j.msg}
            </div>
          </div>
          <span className="whitespace-nowrap text-xs text-muted">
            {(j.finished || j.started || '').slice(5)}
          </span>
        </li>
      ))}
    </ul>
  );
}
