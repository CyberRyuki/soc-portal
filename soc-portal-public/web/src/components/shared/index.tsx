/* Componentes compartidos del portal: KPI, paneles, estados, píldoras, filtros. */
import * as React from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, Inbox, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { initials, nf, pct } from '@/lib/format';
import { Card, CardContent, CardHeader, CardHint, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { SEV_LABEL, STATUS_LABEL, levelColor, type Severity, type IncidentStatus } from '@/lib/constants';

/* ---------- KPI ---------- */
export interface KpiProps {
  title: React.ReactNode;
  value: React.ReactNode;
  hint?: React.ReactNode;
  to?: string;
  onClick?: () => void;
  alert?: boolean;
  className?: string;
}
export function Kpi({ title, value, hint, to, onClick, alert, className }: KpiProps) {
  const body = (
    <>
      <div className="flex items-center gap-1.5 text-[12.5px] text-muted">{title}</div>
      <div className={cn('mt-1 text-[26px] font-bold leading-none tracking-tight', alert && 'text-bad')}>
        {value}
      </div>
      {hint !== undefined && <div className="mt-1.5 truncate text-xs text-muted">{hint}</div>}
    </>
  );
  const cls = cn(
    'card block px-4 py-3.5 transition-transform duration-150',
    (to || onClick) && 'hover:-translate-y-0.5 hover:shadow-lg cursor-pointer',
    alert && 'border-bad/50',
    className,
  );
  if (to)
    return (
      <Link to={to} className={cls}>
        {body}
      </Link>
    );
  if (onClick)
    return (
      <button type="button" onClick={onClick} className={cn(cls, 'w-full text-left')}>
        {body}
      </button>
    );
  return <div className={cls}>{body}</div>;
}
export const KpiGrid = ({
  className,
  children,
  cols,
}: {
  className?: string;
  children: React.ReactNode;
  cols?: 5;
}) => (
  <div
    className={cn(
      'grid gap-3',
      cols === 5 ? 'grid-cols-2 lg:grid-cols-5' : 'grid-cols-[repeat(auto-fit,minmax(150px,1fr))]',
      className,
    )}
  >
    {children}
  </div>
);

/* ---------- Panel ---------- */
export function Panel({
  title,
  hint,
  children,
  className,
  bodyClassName,
  actions,
}: {
  title: React.ReactNode;
  hint?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
  actions?: React.ReactNode;
}) {
  return (
    <Card className={cn('min-w-0', className)}>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {actions ?? (hint ? <CardHint>{hint}</CardHint> : null)}
      </CardHeader>
      <CardContent className={bodyClassName}>{children}</CardContent>
    </Card>
  );
}

/* ---------- Encabezado de página ---------- */
export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-[22px] font-bold leading-tight tracking-tight">{title}</h1>
        {subtitle && <p className="mt-0.5 text-[13.5px] text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/* ---------- Estados ---------- */
export function Empty({
  children,
  icon: Icon = Inbox,
  className,
}: {
  children: React.ReactNode;
  icon?: React.ComponentType<{ className?: string }>;
  className?: string;
}) {
  return (
    <div
      className={cn('flex flex-col items-center gap-2 py-8 text-center text-[13.5px] text-muted', className)}
    >
      <Icon className="size-6 opacity-60" />
      <div>{children}</div>
    </div>
  );
}
export function ErrorState({
  error,
  onRetry,
  compact,
}: {
  error: unknown;
  onRetry?: () => void;
  compact?: boolean;
}) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div
      className={cn('flex flex-col items-center gap-2 text-center text-[13.5px]', compact ? 'py-4' : 'py-8')}
      role="alert"
    >
      <AlertTriangle className="size-6 text-bad" />
      <div className="text-bad">No disponible: {msg}</div>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          <RefreshCw /> Reintentar
        </Button>
      )}
    </div>
  );
}
export function Loading({ rows = 3, h = 'h-40' }: { rows?: number; h?: string }) {
  return (
    <div className="space-y-3" aria-busy="true" aria-label="Cargando">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className={cn(i === 0 ? 'h-24' : h)} />
      ))}
    </div>
  );
}

/* ---------- Píldoras ---------- */
const SEV_VARIANT: Record<Severity, 'bad' | 'warn' | 'info' | 'gray'> = {
  Critical: 'bad',
  High: 'warn',
  Medium: 'info',
  Low: 'gray',
};
export const SevPill = ({ v }: { v: Severity | string }) => (
  <Badge variant={SEV_VARIANT[v as Severity] ?? 'gray'}>{SEV_LABEL[v as Severity] ?? v}</Badge>
);
const ST_VARIANT: Record<IncidentStatus, 'bad' | 'warn' | 'info' | 'ok'> = {
  Open: 'bad',
  Investigating: 'warn',
  Contained: 'info',
  Closed: 'ok',
};
export const StatusPill = ({ v }: { v: IncidentStatus | string }) => (
  <Badge variant={ST_VARIANT[v as IncidentStatus] ?? 'gray'}>{STATUS_LABEL[v as IncidentStatus] ?? v}</Badge>
);
export const Level = ({ l }: { l: number | undefined }) => (
  <span
    className="inline-grid size-6 place-items-center rounded-md text-[11.5px] font-bold text-white"
    style={{ background: levelColor(l ?? 0) }}
    title={`Nivel ${l ?? '—'}`}
  >
    {l ?? '—'}
  </span>
);
export const Risk = ({ s }: { s: number }) => (
  <span
    className="inline-grid min-w-7 place-items-center rounded-md px-1 text-[11.5px] font-bold text-white"
    style={{
      background:
        s >= 80
          ? 'var(--st-crit)'
          : s >= 50
            ? 'var(--st-serious)'
            : s > 0
              ? 'var(--st-warn)'
              : 'var(--s-neutral)',
    }}
    title="Puntuación de riesgo combinando la confianza de las fuentes"
  >
    {s}
  </span>
);
export const Avatar = ({ name, className }: { name: string | null | undefined; className?: string }) => (
  <span
    className={cn(
      'inline-grid size-7 shrink-0 place-items-center rounded-lg bg-gradient-to-br from-[#2f5bea] to-[#7a5af8] text-[11px] font-bold text-white',
      className,
    )}
    aria-hidden="true"
  >
    {initials(name)}
  </span>
);
export const Dot = ({ ok, className }: { ok: boolean | 'warn'; className?: string }) => (
  <span
    className={cn(
      'inline-block size-2 rounded-full',
      ok === 'warn' ? 'bg-st-warn' : ok ? 'bg-st-good' : 'bg-st-crit',
      className,
    )}
  />
);

/* ---------- Chips (filtro segmentado) ---------- */
export function Chips<T extends string | number>({
  options,
  value,
  onChange,
  className,
}: {
  options: [T, React.ReactNode][];
  value: T;
  onChange: (v: T) => void;
  className?: string;
}) {
  return (
    <div
      className={cn('inline-flex flex-wrap rounded-xl border border-line bg-card p-0.5', className)}
      role="group"
    >
      {options.map(([v, label]) => (
        <button
          key={String(v)}
          type="button"
          aria-pressed={v === value}
          onClick={() => onChange(v)}
          className={cn(
            'cursor-pointer rounded-[10px] px-3 py-1.5 text-[13px] font-semibold text-muted transition-colors hover:text-ink',
            v === value && 'bg-brand-soft text-brand',
          )}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

/* ---------- Listas con barras ---------- */
export interface BarRow {
  label: React.ReactNode;
  value: number;
  color?: string;
  sub?: React.ReactNode;
  onClick?: () => void;
  key?: string;
}
export function HBars({
  rows,
  empty = 'Sin datos',
  max = 8,
}: {
  rows: BarRow[];
  empty?: string;
  max?: number;
}) {
  const list = rows.slice(0, max);
  if (!list.length) return <Empty>{empty}</Empty>;
  const top = Math.max(1, ...list.map((r) => r.value));
  return (
    <ul className="space-y-2">
      {list.map((r, i) => (
        <li key={r.key ?? i}>
          <button
            type="button"
            onClick={r.onClick}
            disabled={!r.onClick}
            className={cn(
              'block w-full text-left',
              r.onClick && 'cursor-pointer rounded-md hover:bg-grid/70',
            )}
          >
            <div className="flex items-baseline justify-between gap-3 text-[13px]">
              <span className="min-w-0 truncate">{r.label}</span>
              <b className="shrink-0">{nf(r.value)}</b>
            </div>
            <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-grid">
              <div
                className="h-full rounded-full"
                style={{ width: `${pct(r.value, top)}%`, background: r.color ?? 'var(--s1)' }}
              />
            </div>
          </button>
        </li>
      ))}
    </ul>
  );
}
export function Rank({
  rows,
  total,
  empty = 'Sin datos',
  max = 7,
}: {
  rows: BarRow[];
  total: number;
  empty?: string;
  max?: number;
}) {
  const list = rows.slice(0, max);
  if (!list.length) return <Empty>{empty}</Empty>;
  const top = Math.max(1, ...list.map((r) => r.value));
  return (
    <ol className="space-y-1">
      {list.map((r, i) => (
        <li key={r.key ?? i}>
          <button
            type="button"
            onClick={r.onClick}
            disabled={!r.onClick}
            className={cn(
              'flex w-full items-center gap-3 rounded-lg px-1 py-1.5 text-left',
              r.onClick && 'cursor-pointer hover:bg-grid/70',
            )}
          >
            <span
              className={cn(
                'grid size-7 shrink-0 place-items-center rounded-lg text-xs font-bold',
                i < 3 ? 'bg-brand text-brand-ink' : 'bg-grid text-muted',
              )}
            >
              {i + 1}
            </span>
            <span className="min-w-0 flex-1">
              <span className="flex items-baseline justify-between gap-2 text-[13.5px]">
                <span className="min-w-0 truncate font-semibold">{r.label}</span>
                <b className="shrink-0">{nf(r.value)}</b>
              </span>
              <span className="flex items-center gap-2 text-xs text-muted">
                <span className="min-w-0 truncate">{r.sub}</span>
                <span className="ml-auto shrink-0">{pct(r.value, total)} %</span>
              </span>
              <span className="mt-1 block h-1 overflow-hidden rounded-full bg-grid">
                <span
                  className="block h-full rounded-full"
                  style={{ width: `${pct(r.value, top)}%`, background: r.color ?? 'var(--s1)' }}
                />
              </span>
            </span>
          </button>
        </li>
      ))}
    </ol>
  );
}

/* ---------- Markdown ---------- */
import { renderMarkdown } from '@/lib/markdown';
export const Markdown = ({ src, className }: { src: string | null | undefined; className?: string }) => (
  <div className={cn('md', className)} dangerouslySetInnerHTML={{ __html: renderMarkdown(src) }} />
);

/* ---------- Mensaje de error de formulario ---------- */
export const FieldError = ({ msg }: { msg?: string }) =>
  msg ? <p className="mt-1 text-xs text-bad">{msg}</p> : null;
