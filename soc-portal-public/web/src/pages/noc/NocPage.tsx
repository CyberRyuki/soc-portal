import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Maximize, X } from 'lucide-react';
import { Donut, TimeBars } from '@/components/charts';
import {
  Dot,
  Empty,
  ErrorState,
  HBars,
  Kpi,
  Level,
  Loading,
  Panel,
  SevPill,
  StatusPill,
} from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useUi } from '@/store/ui';
import { useHome, useThreats } from '@/services/threats';
import { levelItems } from '@/pages/home/HomePage';
import { AGENT_COLOR, AGENT_LABEL, type AgentStatus } from '@/lib/constants';
import { dur, fdt, nf, short } from '@/lib/format';
import { cn } from '@/lib/utils';

/** Vista para la pantalla de la sala: tema XR, sin menú, refresco automático cada minuto. */
export default function NocPage() {
  const { enterNoc, leaveNoc } = useUi();
  const home = useHome(true);
  const thr = useThreats('24h', 10);
  const [clock, setClock] = useState(new Date());
  useEffect(() => {
    enterNoc();
    document.title = 'SOC ACME · Operación en vivo';
    const t = setInterval(() => setClock(new Date()), 1000);
    return () => {
      clearInterval(t);
      leaveNoc();
      if (document.fullscreenElement) void document.exitFullscreen().catch(() => undefined);
    };
  }, [enterNoc, leaveNoc]);
  const d = home.data;
  const s = d?.summary;
  const a = s?.agentes;
  const al = s?.alertas;
  const M = d?.metrics;
  const hits = s?.misp_hits ?? [];
  const crit = (al?.por_nivel ?? []).filter(([l]) => l >= 13).reduce((x, [, c]) => x + c, 0);
  const down = (d?.sites ?? []).filter((x) => x.enabled && x.state === 'down');
  const big = 'text-[38px]';
  return (
    <div className="min-h-screen p-5">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">SOC ACME · Operación en vivo</h1>
          <div className="mt-1.5 flex gap-2">
            {s &&
              (
                [
                  ['Wazuh', !s.err_alertas],
                  ['MISP', !s.err_misp_eventos],
                  ['Shuffle', !s.err_workflows],
                ] as [string, boolean][]
              ).map(([n, ok]) => (
                <Badge key={n} variant="outline" className="bg-card">
                  <Dot ok={ok} /> {n}
                </Badge>
              ))}
          </div>
        </div>
        <div className="text-right">
          <div className="font-mono text-[34px] font-bold leading-none tabular-nums">
            {clock.toLocaleTimeString('es-DO')}
          </div>
          <div className="mt-1 text-xs text-muted">
            {s ? `Datos de ${s.generado} · se actualiza cada minuto` : ''}
          </div>
          <div className="mt-2 flex justify-end gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() =>
                document.fullscreenElement
                  ? void document.exitFullscreen()
                  : void document.documentElement.requestFullscreen()
              }
            >
              <Maximize /> Pantalla completa
            </Button>
            <Button variant="secondary" size="sm" asChild>
              <Link to="/">
                <X /> Salir
              </Link>
            </Button>
          </div>
        </div>
      </div>
      {home.isPending ? (
        <Loading rows={3} h="h-64" />
      ) : home.error || !d || !a || !al || !M ? (
        <ErrorState error={home.error} onRetry={() => void home.refetch()} />
      ) : (
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
            <Kpi
              title="Críticas 13–15 · 24 h"
              value={<span className={big}>{nf(crit)}</span>}
              alert={crit > 0}
            />
            <Kpi title="Alertas ≥ 10 · 24 h" value={<span className={big}>{short(al.total)}</span>} />
            <Kpi
              title="Agentes activos"
              value={
                <span className={big}>
                  {nf(a.active)}
                  <span className="text-xl text-muted"> / {nf(a.total)}</span>
                </span>
              }
              hint={`${nf(a.disconnected)} desconectados`}
            />
            <Kpi
              title="Coincidencias MISP"
              value={<span className={big}>{nf(hits.length)}</span>}
              hint="24 h"
              alert={hits.length > 0}
            />
            <Kpi
              title="Incidentes abiertos"
              value={<span className={big}>{nf(d.incidents.stats.open)}</span>}
              hint={`${nf(d.incidents.stats.critical_open)} críticos`}
              alert={d.incidents.stats.critical_open > 0}
            />
            <Kpi
              title="SLA vencidos"
              value={<span className={big}>{nf(M.vencidos.length)}</span>}
              alert={M.vencidos.length > 0}
            />
            <Kpi
              title="Portales caídos"
              value={<span className={big}>{nf(down.length)}</span>}
              hint={down
                .map((x) => x.name)
                .join(', ')
                .slice(0, 40)}
              alert={down.length > 0}
            />
          </div>
          <Panel className="col-span-12 xl:col-span-8" title="Alertas ≥ 10 por hora · 24 h">
            <TimeBars h={230} pts={al.por_hora.map(([k, n]) => [k.length <= 13 ? `${k}:00:00Z` : k, n])} />
          </Panel>
          <Panel className="col-span-12 md:col-span-6 xl:col-span-4" title="Por nivel">
            <Donut items={levelItems(al.por_nivel, 10)} center="alertas" />
          </Panel>
          <Panel className="col-span-12 md:col-span-6 xl:col-span-4" title="Agentes">
            <Donut
              center="agentes"
              items={(Object.keys(AGENT_LABEL) as AgentStatus[]).map((k) => ({
                label: AGENT_LABEL[k],
                value: a[k] ?? 0,
                color: AGENT_COLOR[k],
              }))}
            />
          </Panel>
          <Panel className="col-span-12 md:col-span-6 xl:col-span-4" title="Tácticas MITRE · 24 h">
            {thr.data ? (
              <HBars rows={thr.data.tacticas.map(([k, v]) => ({ key: k, label: k, value: v }))} max={6} />
            ) : thr.error ? (
              <ErrorState error={thr.error} compact />
            ) : (
              <Loading rows={1} h="h-20" />
            )}
          </Panel>
          <Panel className="col-span-12 md:col-span-6 xl:col-span-4" title="Incidentes abiertos">
            {M.abiertos.length ? (
              <ul className="space-y-2">
                {M.abiertos.slice(0, 6).map((i) => (
                  <li key={i.code} className="flex items-center gap-2 text-[14px]">
                    <SevPill v={i.severity} />
                    <div className="min-w-0 flex-1">
                      <b>{i.code}</b> {i.title}
                      <div className="flex items-center gap-1 text-xs text-muted">
                        {i.owner || 'sin responsable'} · <StatusPill v={i.status} />
                      </div>
                    </div>
                    <span
                      className={cn(
                        'whitespace-nowrap text-[12.5px]',
                        !i.respondido && i.edad_min > i.sla_min && 'font-bold text-bad',
                      )}
                    >
                      {dur(i.edad_min)}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty>Sin incidentes abiertos</Empty>
            )}
          </Panel>
          <Panel className="col-span-12 xl:col-span-7" title="Últimas alertas críticas">
            {thr.data?.recientes.length ? (
              <ul className="divide-y divide-line">
                {thr.data.recientes.slice(0, 8).map((x, i) => (
                  <li key={i} className="flex items-center gap-3 py-1.5 text-[14px]">
                    <Level l={x.rule?.level} />
                    <div className="min-w-0 flex-1 truncate">
                      {x.rule?.description}
                      <div className="text-xs text-muted">{x.agent?.name}</div>
                    </div>
                    <span className="text-xs text-muted">{fdt(x.timestamp)}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty>Sin alertas ≥ 12</Empty>
            )}
          </Panel>
          <Panel className="col-span-12 xl:col-span-5" title="Coincidencias MISP · 24 h">
            {hits.length ? (
              <ul className="divide-y divide-line">
                {hits.slice(0, 8).map((h, i) => (
                  <li key={i} className="flex items-center gap-3 py-1.5 text-[14px]">
                    <Badge variant="bad">{h.data?.misp?.type}</Badge>
                    <div className="mono min-w-0 flex-1 truncate">
                      {h.data?.misp?.value}
                      <div className="font-sans text-xs text-muted">{h.agent?.name}</div>
                    </div>
                    <span className="text-xs text-muted">{fdt(h.timestamp)}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty>Sin coincidencias</Empty>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
