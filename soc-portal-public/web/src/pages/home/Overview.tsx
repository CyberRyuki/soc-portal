import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  Bug,
  Cloud,
  Globe,
  Lightbulb,
  Pause,
  RefreshCw,
  ShieldCheck,
  Siren,
  type LucideIcon,
  Radar,
} from 'lucide-react';
import { Empty, Panel } from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Select } from '@/components/ui/input';
import { nf } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { Overview } from '@/types/api';

// ---------------------------------------------------------------- refresco elegible
const KEY = 'soc-home-refresh';
export const REFRESH_OPTIONS: [number, string][] = [
  [15_000, 'cada 15 s'],
  [30_000, 'cada 30 s'],
  [60_000, 'cada 1 min'],
  [300_000, 'cada 5 min'],
  [0, 'en pausa'],
];
/** Intervalo de refresco del Resumen, recordado en este navegador. */
export function useRefreshInterval(): [number, (v: number) => void] {
  const [v, setV] = useState<number>(() => {
    try {
      const s = localStorage.getItem(KEY);
      return s != null && REFRESH_OPTIONS.some(([n]) => String(n) === s) ? Number(s) : 30_000;
    } catch {
      return 30_000;
    }
  });
  const set = (n: number) => {
    setV(n);
    try {
      localStorage.setItem(KEY, String(n));
    } catch {
      /* navegador sin almacenamiento */
    }
  };
  return [v, set];
}

/** «Actualizado hace X s», selector de intervalo y botón para refrescar ahora. */
export function RefreshControl({
  every,
  onChange,
  updatedAt,
  fetching,
}: {
  every: number;
  onChange: (n: number) => void;
  updatedAt: number;
  fetching: boolean;
}) {
  const qc = useQueryClient();
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  const secs = updatedAt ? Math.max(0, Math.round((now - updatedAt) / 1000)) : null;
  const ago =
    secs == null
      ? '—'
      : secs < 60
        ? `hace ${secs} s`
        : secs < 3600
          ? `hace ${Math.floor(secs / 60)} min`
          : 'hace más de 1 h';
  return (
    <div
      className="flex flex-wrap items-center gap-2 text-[12.5px]"
      role="group"
      aria-label="Actualización del resumen"
    >
      <span className={cn('flex items-center gap-1.5 text-muted', fetching && 'text-brand')}>
        {every ? (
          <i className={cn('size-2 rounded-full', fetching ? 'animate-pulse bg-brand' : 'bg-st-good')} />
        ) : (
          <Pause className="size-3.5" />
        )}
        {fetching ? 'Actualizando…' : `Actualizado ${ago}`}
      </span>
      <Select
        value={every}
        onChange={(e) => onChange(Number(e.target.value))}
        aria-label="Intervalo de actualización"
        className="h-8 w-auto text-[12.5px]"
      >
        {REFRESH_OPTIONS.map(([n, l]) => (
          <option key={n} value={n}>
            {l}
          </option>
        ))}
      </Select>
      <Button
        size="sm"
        variant="secondary"
        aria-label="Actualizar ahora"
        disabled={fetching}
        onClick={() => {
          for (const k of ['home', 'overview', 'threats']) void qc.invalidateQueries({ queryKey: [k] });
        }}
      >
        <RefreshCw className={cn(fetching && 'animate-spin')} />
      </Button>
    </div>
  );
}

// ---------------------------------------------------------------- puntuación de riesgo
const LEVEL: Record<string, { color: string; text: string }> = {
  Bajo: { color: 'var(--st-good)', text: 'text-ok' },
  Moderado: { color: 'var(--st-warn)', text: 'text-warn' },
  Alto: { color: 'var(--sev-high, #e8590c)', text: 'text-warn' },
  Crítico: { color: 'var(--st-crit)', text: 'text-bad' },
};

export function RiskGauge({ r }: { r: Overview['riesgo'] }) {
  const L = LEVEL[r.nivel] ?? LEVEL.Bajo!;
  const R = 52;
  const C = 2 * Math.PI * R;
  const arc = (C * 0.75 * r.puntuacion) / 100; // 270º
  return (
    <section className="card p-4" aria-label={`Riesgo del SOC: ${r.puntuacion} de 100, ${r.nivel}`}>
      <div className="flex flex-wrap items-center gap-5">
        <div className="relative size-[132px] shrink-0">
          <svg viewBox="0 0 120 120" className="size-full -rotate-[225deg]" aria-hidden>
            <circle
              cx="60"
              cy="60"
              r={R}
              fill="none"
              stroke="var(--grid)"
              strokeWidth="11"
              strokeLinecap="round"
              strokeDasharray={`${C * 0.75} ${C}`}
            />
            <circle
              cx="60"
              cy="60"
              r={R}
              fill="none"
              stroke={L.color}
              strokeWidth="11"
              strokeLinecap="round"
              strokeDasharray={`${arc} ${C}`}
              className="transition-[stroke-dasharray] duration-700"
            />
          </svg>
          <div className="absolute inset-0 grid place-items-center text-center">
            <div>
              <div className="text-[34px] font-bold leading-none tracking-tight">{r.puntuacion}</div>
              <div className={cn('mt-0.5 text-[12.5px] font-semibold', L.text)}>{r.nivel}</div>
            </div>
          </div>
        </div>
        <div className="min-w-[220px] flex-1">
          <h2 className="flex items-center gap-2 text-[15px] font-semibold">
            <Siren className="size-4 text-brand" /> Riesgo del SOC
          </h2>
          <p className="mb-2 text-xs text-muted">
            0 = tranquilo · 100 = crítico. Pulsa un factor para ir a él.
          </p>
          {r.factores.length ? (
            <ul className="space-y-1">
              {r.factores.slice(0, 6).map((f) => {
                const inner = (
                  <>
                    <span className="flex-1 truncate">
                      {f.factor} <span className="text-muted">({nf(f.n)})</span>
                    </span>
                    <b className="tabular-nums">+{f.puntos}</b>
                  </>
                );
                return (
                  <li key={f.factor}>
                    {f.to ? (
                      <Link
                        to={f.to}
                        className="flex items-center gap-2 rounded-md px-1.5 py-0.5 text-[13px] hover:bg-grid"
                      >
                        {inner}
                      </Link>
                    ) : (
                      <div className="flex items-center gap-2 px-1.5 py-0.5 text-[13px]">{inner}</div>
                    )}
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="text-[13px] text-ok">Sin factores de riesgo activos.</p>
          )}
        </div>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------- tarjetas por fuente
function SourceCard({
  icon: Icon,
  title,
  to,
  alert,
  off,
  lines,
  foot,
}: {
  icon: LucideIcon;
  title: string;
  to: string;
  alert?: boolean;
  off?: string;
  lines: [string, number | string | null | undefined, boolean?][];
  foot?: string;
}) {
  return (
    <Link
      to={to}
      className={cn(
        'card block p-4 transition-colors hover:border-brand/50',
        alert && 'border-bad/50 bg-bad/[0.03]',
        off && 'opacity-70',
      )}
    >
      <div className="mb-2 flex items-center gap-2">
        <span
          className={cn(
            'grid size-8 place-items-center rounded-lg bg-brand-soft text-brand',
            alert && 'bg-bad/15 text-bad',
          )}
        >
          <Icon className="size-4" />
        </span>
        <b className="text-[14px]">{title}</b>
      </div>
      {off ? (
        <p className="text-xs text-muted">{off}</p>
      ) : (
        <dl className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-0.5 text-[13px]">
          {lines.map(([k, v, bad]) => (
            <div key={k} className="contents">
              <dt className="text-muted">{k}</dt>
              <dd className={cn('text-right font-semibold tabular-nums', bad && v ? 'text-bad' : '')}>
                {v == null ? '—' : typeof v === 'number' ? nf(v) : v}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {foot && <p className="mt-2 truncate text-[11.5px] text-muted">{foot}</p>}
    </Link>
  );
}

export function SourceCards({ o }: { o: Overview }) {
  const p = o.portales;
  const s = o.sophos;
  const m = o.m365;
  const v = o.vulns;
  const e = o.exposicion;
  return (
    <div className="grid gap-3.5 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6" data-enter="">
      <SourceCard
        icon={Lightbulb}
        title="Por revisar"
        to="/incidents"
        alert={o.sugerencias.criticas > 0}
        lines={[
          ['Sugerencias de incidente', o.sugerencias.pendientes, o.sugerencias.pendientes > 0],
          ['Críticas', o.sugerencias.criticas, true],
          ['Acciones por aprobar', o.acciones_pendientes, o.acciones_pendientes > 0],
          ['Incidentes abiertos', o.incidentes.abiertos],
          ['SLA vencidos', o.incidentes.sla_vencidos, true],
        ]}
        foot={o.sugerencias.top[0]?.title}
      />
      <SourceCard
        icon={Globe}
        title="Portales"
        to="/sites"
        alert={p.desfigurados > 0 || p.caidos > 0}
        off={p.total ? undefined : 'Sin portales: impórtalos desde Excel en Portales.'}
        lines={[
          ['En línea', `${nf(p.en_linea)} / ${nf(p.activos)}`],
          ['Caídos', p.caidos, true],
          ['Desfigurados', p.desfigurados, true],
          ['Sospecha de inyección', p.sospecha, true],
          ['Sin WAF con problema', p.sin_waf_con_problema, true],
        ]}
        foot={
          p.alertas.map((x) => x.name).join(', ') ||
          `${nf(p.sin_waf)} portales sin WAF · SSL ≤ 30 d: ${nf(p.ssl30)}`
        }
      />
      <SourceCard
        icon={ShieldCheck}
        title="Sophos"
        to="/sophos"
        alert={!!s.altas_24h}
        off={s.configurado ? undefined : 'No configurado (SOPHOS_CLIENT_ID).'}
        lines={[
          ['Alertas 24 h', s.alertas_24h],
          ['Altas 24 h', s.altas_24h, true],
          ['Equipos', s.equipos],
          ['Salud mala', s.salud_mala, true],
          ['Aislados', s.aislados],
        ]}
        foot={s.ultima_sync ? `Sincronizado ${s.ultima_sync}` : undefined}
      />
      <SourceCard
        icon={Cloud}
        title="Microsoft 365"
        to="/m365"
        alert={!!m.altas}
        off={m.configurado ? undefined : 'No configurado (M365_TENANT_ID).'}
        lines={[
          ['Alertas abiertas · 7 d', m.abiertas],
          ['Altas', m.altas, true],
          ['Usuarios en riesgo', m.usuarios_riesgo, true],
          ['Reglas de correo sospechosas', m.reglas_sospechosas, true],
        ]}
        foot={m.ultima_sync ? `Sincronizado ${m.ultima_sync}` : undefined}
      />
      <SourceCard
        icon={Bug}
        title="Vulnerabilidades"
        to="/vulns?view=track"
        alert={v.criticas > 0}
        lines={[
          ['Críticas abiertas', v.criticas, true],
          ['Altas abiertas', v.altas],
          ['Vencidas', v.vencidas, true],
          ['De Pentera abiertas', v.pentera_abiertas],
        ]}
        foot={
          v.ultimo_informe
            ? `Último Pentera: ${v.ultimo_informe.name} · ${v.ultimo_informe.at.slice(0, 10)}`
            : 'Sin informes de Pentera'
        }
      />
      <SourceCard
        icon={Radar}
        title="Exposición"
        to="/exposure"
        alert={!!e?.criticos}
        off={e?.configurado ? undefined : 'Sin alcance: defínelo en Exposición › Alcance.'}
        lines={[
          ['Hallazgos críticos', e?.criticos ?? 0, true],
          ['Hallazgos altos', e?.altos ?? 0, true],
          ['Shadow IT', e?.shadow ?? 0, (e?.shadow ?? 0) > 0],
          ['Servicios expuestos', e?.servicios ?? 0],
          ['IP con CVE', e?.con_cve ?? 0, true],
        ]}
        foot={e?.ultimo ? `Último escaneo: ${e.ultimo}` : 'Nunca escaneado'}
      />
    </div>
  );
}

// ---------------------------------------------------------------- integraciones
const EST: Record<string, [string, string]> = {
  ok: ['En línea', 'bg-st-good'],
  aviso: ['Con avisos', 'bg-st-warn'],
  error: ['Error', 'bg-st-crit'],
  off: ['No configurado', 'bg-line'],
};
export function Integrations({ items }: { items: Overview['integraciones'] }) {
  return (
    <Panel title="Estado de las integraciones" hint="se actualiza con el resumen">
      <ul className="divide-y divide-line">
        {items.map((i) => {
          const [l, c] = EST[i.estado] ?? EST.off!;
          const body = (
            <>
              <i className={cn('mt-1.5 size-2.5 shrink-0 rounded-full', c)} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-2">
                  <b className="text-[13.5px]">{i.name}</b>
                  <span
                    className={cn('text-xs', i.estado === 'error' ? 'font-semibold text-bad' : 'text-muted')}
                  >
                    {l}
                  </span>
                </div>
                <div
                  className={cn('truncate text-xs', i.estado === 'error' ? 'text-bad' : 'text-muted')}
                  title={i.detalle}
                >
                  {i.detalle}
                  {i.ultima && ` · ${i.ultima.slice(5, 16)}`}
                </div>
              </div>
            </>
          );
          return (
            <li key={i.name}>
              {i.to ? (
                <Link to={i.to} className="-mx-1.5 flex gap-2.5 rounded-md px-1.5 py-2 hover:bg-grid">
                  {body}
                </Link>
              ) : (
                <div className="flex gap-2.5 py-2">{body}</div>
              )}
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

// ---------------------------------------------------------------- línea de tiempo
const SRC: Record<string, [LucideIcon, string]> = {
  Portales: [Globe, 'text-s1'],
  Incidentes: [Activity, 'text-brand'],
  Sugerencias: [Lightbulb, 'text-warn'],
  Sophos: [ShieldCheck, 'text-ok'],
  'Microsoft 365': [Cloud, 'text-s2'],
  IoC: [Siren, 'text-bad'],
};
const HOT = new Set(['deface', 'down', 'high', 'Critical', 'High', 'coincidencia', 'defacement']);

export function Timeline({ items }: { items: Overview['timeline'] }) {
  const [src, setSrc] = useState('');
  const sources = [...new Set(items.map((x) => x.fuente))];
  const rows = items.filter((x) => !src || x.fuente === src);
  return (
    <Panel
      title="Línea de tiempo"
      hint="últimos eventos de todas las fuentes"
      actions={
        <Select
          value={src}
          onChange={(e) => setSrc(e.target.value)}
          aria-label="Fuente"
          className="h-8 w-auto text-[12.5px]"
        >
          <option value="">Todas las fuentes</option>
          {sources.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Select>
      }
    >
      {rows.length ? (
        <ol className="relative max-h-[460px] space-y-0.5 overflow-auto pr-1">
          {rows.map((t, i) => {
            const [Icon, color] = SRC[t.fuente] ?? [Activity, 'text-muted'];
            return (
              <li key={`${t.at}-${i}`}>
                <Link
                  to={t.to || '/'}
                  className="flex items-start gap-2.5 rounded-md px-1.5 py-1.5 hover:bg-grid"
                >
                  <Icon className={cn('mt-0.5 size-4 shrink-0', color)} />
                  <div className="min-w-0 flex-1">
                    <div className={cn('text-[13px] leading-snug', HOT.has(t.tipo) && 'font-semibold')}>
                      {t.texto}
                    </div>
                    <div className="text-[11.5px] text-muted">
                      {t.at.slice(5)} · {t.fuente}
                      {HOT.has(t.tipo) && (
                        <Badge variant="bad" className="ml-1.5 px-1.5 py-0 text-[10.5px]">
                          atención
                        </Badge>
                      )}
                    </div>
                  </div>
                </Link>
              </li>
            );
          })}
        </ol>
      ) : (
        <Empty>Sin eventos todavía.</Empty>
      )}
    </Panel>
  );
}
