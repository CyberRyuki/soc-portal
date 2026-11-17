/* Gráficas del portal sobre Recharts, con la paleta de tokens (claro/oscuro/XR). */
import { useMemo } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { nf, pct, short, toDate } from '@/lib/format';
import { SEQ_RAMP } from '@/lib/constants';
import { cn } from '@/lib/utils';

const TIP_STYLE = {
  background: 'var(--card)',
  border: '1px solid var(--line)',
  borderRadius: 10,
  fontSize: 12.5,
  color: 'var(--ink)',
  boxShadow: 'var(--shadow)',
};
const AXIS = { fontSize: 11, fill: 'var(--muted)' };

function fmtTick(span: number): (t: number) => string {
  if (span <= 36 * 3600e3)
    return (t) => toDate(t).toLocaleTimeString('es-DO', { hour: '2-digit', minute: '2-digit' });
  return (t) => toDate(t).toLocaleDateString('es-DO', { day: '2-digit', month: 'short' });
}

/** Barras por tiempo: pts = [[timestamp|iso, valor]]. */
export function TimeBars({
  pts,
  h = 180,
  unit = 'alertas',
  color = 'var(--s1)',
}: {
  pts: [string | number, number][];
  h?: number;
  unit?: string;
  color?: string;
}) {
  const data = useMemo(
    () => pts.map(([t, v]) => ({ t: toDate(t).getTime(), v })).filter((d) => !Number.isNaN(d.t)),
    [pts],
  );
  if (!data.length) return <div className="py-8 text-center text-[13px] text-muted">Sin datos</div>;
  const span = (data[data.length - 1]?.t ?? 0) - (data[0]?.t ?? 0);
  const tick = fmtTick(span);
  return (
    <ResponsiveContainer width="100%" height={h}>
      <BarChart data={data} margin={{ top: 6, right: 6, left: -18, bottom: 0 }} barCategoryGap={2}>
        <CartesianGrid vertical={false} stroke="var(--grid)" />
        <XAxis
          dataKey="t"
          tickFormatter={tick}
          tick={AXIS}
          axisLine={false}
          tickLine={false}
          minTickGap={28}
        />
        <YAxis
          tick={AXIS}
          axisLine={false}
          tickLine={false}
          tickFormatter={(v: number) => short(v)}
          width={56}
        />
        <Tooltip
          cursor={{ fill: 'var(--grid)' }}
          contentStyle={TIP_STYLE}
          labelFormatter={(t) =>
            toDate(Number(t)).toLocaleString('es-DO', {
              day: '2-digit',
              month: '2-digit',
              hour: '2-digit',
              minute: '2-digit',
            })
          }
          formatter={(v) => [nf(Number(v)), unit]}
        />
        <Bar dataKey="v" fill={color} radius={[4, 4, 0, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Líneas con etiquetas de categoría (fechas ISO). */
export function Lines({
  labels,
  series,
  h = 220,
}: {
  labels: string[];
  series: { name: string; color: string; values: number[] }[];
  h?: number;
}) {
  const data = labels.map((l, i) =>
    Object.fromEntries([['x', l], ...series.map((s) => [s.name, s.values[i] ?? 0])]),
  );
  return (
    <div>
      <ResponsiveContainer width="100%" height={h}>
        <LineChart data={data} margin={{ top: 6, right: 8, left: -22, bottom: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--grid)" />
          <XAxis
            dataKey="x"
            tick={AXIS}
            axisLine={false}
            tickLine={false}
            minTickGap={24}
            tickFormatter={(s: string) => s.slice(5)}
          />
          <YAxis tick={AXIS} axisLine={false} tickLine={false} allowDecimals={false} width={56} />
          <Tooltip contentStyle={TIP_STYLE} />
          {series.map((s) => (
            <Line
              key={s.name}
              type="monotone"
              dataKey={s.name}
              stroke={s.color}
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
      <div className="mt-1 flex flex-wrap gap-3 text-xs text-muted">
        {series.map((s) => (
          <span key={s.name} className="inline-flex items-center gap-1.5">
            <i className="inline-block size-2.5 rounded-sm" style={{ background: s.color }} />
            {s.name} <b className="text-ink">{nf(s.values.reduce((a, b) => a + b, 0))}</b>
          </span>
        ))}
      </div>
    </div>
  );
}

export interface DonutItem {
  label: string;
  value: number;
  color: string;
  onClick?: () => void;
}
/** Anillo con leyenda a la derecha y total en el centro. */
export function Donut({ items, center = '', h = 170 }: { items: DonutItem[]; center?: string; h?: number }) {
  const total = items.reduce((a, b) => a + b.value, 0);
  if (!total) return <div className="py-8 text-center text-[13px] text-muted">Sin datos</div>;
  return (
    <div className="grid grid-cols-[150px_1fr] items-center gap-3 max-sm:grid-cols-1">
      <div className="relative" style={{ height: h }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={items}
              dataKey="value"
              nameKey="label"
              innerRadius="68%"
              outerRadius="100%"
              paddingAngle={1}
              stroke="none"
              isAnimationActive={false}
            >
              {items.map((it) => (
                <Cell key={it.label} fill={it.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={TIP_STYLE}
              formatter={(v, n) => [`${nf(Number(v))} (${pct(Number(v), total)} %)`, String(n)]}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
          <div>
            <div className="text-[22px] font-bold leading-none">{short(total)}</div>
            <div className="text-[11px] text-muted">{center}</div>
          </div>
        </div>
      </div>
      <ul className="space-y-1.5 text-[13px]">
        {items.map((it) => (
          <li key={it.label}>
            <button
              type="button"
              onClick={it.onClick}
              disabled={!it.onClick}
              className={cn(
                'flex w-full items-center gap-2 rounded-md px-1 text-left',
                it.onClick && 'cursor-pointer hover:bg-grid/70',
              )}
            >
              <i className="inline-block size-2.5 shrink-0 rounded-sm" style={{ background: it.color }} />
              <span className="min-w-0 flex-1 truncate">{it.label}</span>
              <b>{nf(it.value)}</b>
              <span className="w-10 text-right text-muted">{pct(it.value, total)} %</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

const DAYS = ['Lun', 'Mar', 'Mié', 'Jue', 'Vie', 'Sáb', 'Dom'];
/** Mapa de calor día × hora. */
export function Heatmap({ pts }: { pts: [string | number, number][] }) {
  const m = useMemo(() => {
    const g = DAYS.map(() => Array<number>(24).fill(0));
    for (const [t, n] of pts) {
      const d = toDate(t);
      if (!Number.isNaN(d.getTime())) {
        const row = g[(d.getDay() + 6) % 7];
        if (row) row[d.getHours()] = (row[d.getHours()] ?? 0) + n;
      }
    }
    return g;
  }, [pts]);
  const max = Math.max(1, ...m.flat());
  const col = (v: number) =>
    v ? SEQ_RAMP[Math.min(6, Math.floor(Math.sqrt(v / max) * 6.99))] : 'var(--grid)';
  return (
    <div>
      <div
        className="grid gap-[3px] text-[10.5px] text-muted"
        style={{ gridTemplateColumns: '34px repeat(24, 1fr)' }}
      >
        <span />
        {Array.from({ length: 24 }, (_, h) => (
          <span key={h} className="text-center">
            {h % 3 ? '' : h}
          </span>
        ))}
        {m.map((row, d) => (
          <div key={d} className="contents">
            <span className="leading-[18px]">{DAYS[d]}</span>
            {row.map((v, h) => (
              <div
                key={h}
                className="h-[18px] rounded-[3px]"
                style={{ background: col(v) }}
                title={`${nf(v)} alertas · ${DAYS[d]} ${h}:00–${h}:59`}
              />
            ))}
          </div>
        ))}
      </div>
      <div className="mt-2 flex items-center justify-end gap-1 text-[11px] text-muted">
        Menos{' '}
        {SEQ_RAMP.map((q) => (
          <i key={q} className="inline-block size-2.5 rounded-sm" style={{ background: q }} />
        ))}{' '}
        Más
      </div>
    </div>
  );
}
