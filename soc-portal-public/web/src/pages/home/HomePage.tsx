import { useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { BookOpen, Radar, Shield, Workflow } from 'lucide-react';
import { usePageEnter } from '@/components/layout/AppShell';
import { Donut, TimeBars } from '@/components/charts';
import {
  Empty,
  ErrorState,
  HBars,
  Kpi,
  KpiGrid,
  Level,
  Loading,
  Panel,
  Rank,
  SevPill,
  StatusPill,
} from '@/components/shared';
import { Table, TableBody, TableCell, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { useHome, useOverview, useThreats } from '@/services/threats';
import {
  Integrations,
  RefreshControl,
  RiskGauge,
  SourceCards,
  Timeline,
  useRefreshInterval,
} from './Overview';
import { useDrill } from '@/pages/threats/DrillDialog';
import {
  AGENT_COLOR,
  AGENT_LABEL,
  LEVEL_GROUPS,
  SEV_COLOR,
  SEV_LABEL,
  levelColor,
  type AgentStatus,
  type Severity,
} from '@/lib/constants';
import { dur, fdt, nf, short } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { Pair } from '@/types/api';

export function levelItems(niveles: Pair<number>[] | undefined, min = 0) {
  return LEVEL_GROUPS.filter((g) => g[2] >= min).map(([label, a, b, color]) => ({
    label,
    color,
    value: (niveles ?? []).filter(([l]) => l >= a && l <= b).reduce((t, [, c]) => t + c, 0),
  }));
}

export default function HomePage() {
  const ref = usePageEnter('home');
  const [every, setEvery] = useRefreshInterval();
  const home = useHome(true, every);
  const ov = useOverview(every);
  const thr = useThreats('24h', 10, every);
  const drill = useDrill();
  const nav = useNavigate();
  useEffect(() => {
    document.title = 'Portal SOC · Resumen';
  }, []);
  if (home.isPending) return <Loading rows={4} />;
  if (home.error) return <ErrorState error={home.error} onRetry={() => void home.refetch()} />;
  const d = home.data;
  const s = d.summary;
  const a = s.agentes;
  const al = s.alertas;
  const IS = d.incidents.stats;
  const M = d.metrics;
  const crit = (al?.por_nivel ?? []).filter(([l]) => l >= 13).reduce((t, [, c]) => t + c, 0);
  const hits = s.misp_hits ?? [];
  const sitesOn = d.sites.filter((x) => x.enabled);
  const sitesDown = sitesOn.filter((x) => x.state === 'down');
  const vcrit = d.vulns.por_severidad.find((x) => x[0] === 'Critical')?.[1] ?? 0;
  const o = ov.data;
  const attn = [
    o?.portales.desfigurados && `${nf(o.portales.desfigurados)} portal(es) desfigurado(s)`,
    o?.sugerencias.criticas && `${nf(o.sugerencias.criticas)} sugerencias críticas sin revisar`,
    crit && `${nf(crit)} alertas críticas`,
    M.vencidos.length && `${nf(M.vencidos.length)} SLA vencidos`,
    sitesDown.length && 'portales caídos',
    (s.err_alertas || s.err_misp_eventos || s.err_workflows) && 'servicios sin conexión',
  ].filter(Boolean);
  const services: [string, boolean][] = [
    ['Wazuh', !s.err_alertas],
    ['MISP', !s.err_misp_eventos],
    ['Shuffle', !s.err_workflows],
    ['Portal', true],
  ];
  const rules = thr.data?.reglas;
  const agents = thr.data?.agentes ?? al?.top_agents ?? [];

  return (
    <div ref={ref} className="space-y-4">
      <section className="card relative overflow-hidden p-6">
        <div className="absolute -right-10 -top-16 size-64 rounded-full bg-[radial-gradient(circle,var(--glow-a),transparent_70%)] blur-2xl" />
        <div className="relative flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="flex items-center gap-3 text-2xl font-bold tracking-tight">
              <span className="grid size-11 place-items-center rounded-xl bg-brand-soft text-brand">
                <Shield className="size-6" />
              </span>
              Centro de Operaciones de Seguridad
            </h1>
            <p className="mt-1.5 text-[13.5px] text-muted">
              ACME · monitoreo, inteligencia de amenazas y respuesta · datos de {s.generado}
            </p>
            <Badge variant={attn.length ? 'bad' : 'ok'} className="mt-3 px-3 py-1 text-[12.5px]">
              {attn.length ? `⚠ Requiere atención: ${attn.join(' · ')}` : '✓ Operación normal'}
            </Badge>
          </div>
          <div className="flex flex-col items-end gap-2">
            <RefreshControl
              every={every}
              onChange={setEvery}
              updatedAt={Math.max(home.dataUpdatedAt, ov.dataUpdatedAt)}
              fetching={home.isFetching || ov.isFetching}
            />
            <div className="flex flex-wrap justify-end gap-2">
              {services.map(([n, ok]) => (
                <Badge key={n} variant="outline" className="bg-card px-2.5 py-1 text-[12.5px]">
                  <i className={cn('size-2 rounded-full', ok ? 'bg-st-good' : 'bg-st-crit')} /> {n}
                </Badge>
              ))}
            </div>
          </div>
        </div>
      </section>

      {o && (
        <>
          <div className="grid gap-4 lg:grid-cols-[1.35fr_1fr]" data-enter="">
            <RiskGauge r={o.riesgo} />
            <Integrations items={o.integraciones} />
          </div>
          <SourceCards o={o} />
        </>
      )}

      <KpiGrid cols={5} data-enter="">
        <Kpi
          title="Agentes activos"
          value={
            <>
              {nf(a.active)}
              <span className="text-[15px] font-medium text-muted"> / {nf(a.total)}</span>
            </>
          }
          hint={`${nf(a.disconnected)} desconectados`}
          to="/agents"
        />
        <Kpi title="Alertas ≥ 10 · 24 h" value={short(al?.total ?? 0)} hint="Wazuh" to="/threats" />
        <Kpi
          title="Críticas 13–15 · 24 h"
          value={nf(crit)}
          hint={crit ? 'Revisar ahora' : 'Sin críticas'}
          to="/threats?lv=13"
          alert={crit > 0}
        />
        <Kpi
          title="Coincidencias MISP"
          value={nf(hits.length)}
          hint="IoC vistos en alertas · 24 h"
          to="/intel"
        />
        <Kpi title="IoC nuevos · 24 h" value={nf(s.misp_ioc_24h)} hint="MISP (to_ids)" to="/intel" />
        <Kpi
          title="Incidentes abiertos"
          value={nf(IS.open)}
          hint={`${nf(IS.critical_open)} críticos`}
          to="/incidents"
          alert={IS.critical_open > 0}
        />
        <Kpi
          title="SLA vencidos"
          value={nf(M.vencidos.length)}
          hint="Sin primera respuesta a tiempo"
          to="/incidents"
          alert={M.vencidos.length > 0}
        />
        <Kpi
          title="Vulnerabilidades críticas"
          value={nf(vcrit)}
          hint={`${nf(d.vulns.activas)} abiertas · ${nf(d.vulns.vencidas)} vencidas`}
          to="/vulns?view=track&severity=Critical"
          alert={vcrit > 0 || d.vulns.vencidas > 0}
        />
        <Kpi
          title="Portales caídos"
          value={
            <>
              {nf(sitesDown.length)}
              <span className="text-[15px] font-medium text-muted"> / {nf(sitesOn.length)}</span>
            </>
          }
          hint={
            sitesDown
              .map((x) => x.name)
              .join(', ')
              .slice(0, 50) || 'Todos en línea'
          }
          to="/sites"
          alert={sitesDown.length > 0}
        />
        <Kpi
          title="Coincidencias IoC · 24 h"
          value={nf(d.iocs.vistos)}
          hint={`${short(d.iocs.activos)} IoC en la base`}
          to="/iocs?view=coincidencias&days=1"
          alert={d.iocs.vistos > 0}
        />
      </KpiGrid>

      <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
        <Panel title="Alertas ≥ 10 por hora" hint="últimas 24 h · pasa el ratón por las barras">
          <TimeBars pts={(al?.por_hora ?? []).map(([k, n]) => [k.length <= 13 ? `${k}:00:00Z` : k, n])} />
        </Panel>
        <Panel title="Alertas por nivel" hint="24 h">
          <Donut items={levelItems(al?.por_nivel, 10)} center="alertas" />
        </Panel>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Panel
          title="Reglas que más alertan"
          actions={
            <span className="text-xs text-muted">
              24 h · nivel ≥ 10 ·{' '}
              <Link className="text-brand" to="/threats">
                Ver amenazas →
              </Link>
            </span>
          }
        >
          <Rank
            total={thr.data?.total ?? al?.total ?? 0}
            empty="Sin alertas"
            rows={
              rules
                ? rules.map((r) => ({
                    key: r.id,
                    label: r.desc,
                    value: r.n,
                    color: levelColor(r.nivel),
                    sub: (
                      <span className="inline-flex items-center gap-1.5">
                        <Level l={r.nivel} /> <span className="mono">regla {r.id}</span>
                      </span>
                    ),
                    onClick: () => drill.open('rule.id', r.id),
                  }))
                : (al?.top_rules ?? []).map(([k, v]) => ({ key: k, label: k, value: v }))
            }
          />
        </Panel>
        <Panel title="Equipos con más alertas" hint="24 h · pulsa para ver sus alertas">
          <Rank
            total={thr.data?.total ?? al?.total ?? 0}
            empty="Sin alertas"
            rows={agents.map(([k, v]) => ({
              key: k,
              label: k,
              value: v,
              sub: '🖥 equipo',
              onClick: () => drill.open('agent.name', k),
            }))}
          />
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Estado de los agentes" hint={a.fuente ?? ''}>
          <Donut
            center="agentes"
            items={(Object.keys(AGENT_LABEL) as AgentStatus[]).map((k) => ({
              label: AGENT_LABEL[k],
              value: a[k] ?? 0,
              color: AGENT_COLOR[k],
            }))}
          />
        </Panel>
        <Panel
          title="Incidentes abiertos por severidad"
          hint={`MTTA ${dur(M.mtta_min)} · MTTR ${dur(M.mttr_min)}`}
        >
          <HBars
            empty="Sin incidentes abiertos"
            rows={M.por_severidad.map(([k, v]) => ({
              key: k,
              label: SEV_LABEL[k as Severity] ?? k,
              value: v,
              color: SEV_COLOR[k as Severity],
            }))}
          />
          {M.vencidos.length > 0 && (
            <div className="mt-3">
              <b className="text-[13px] text-bad">⚠ SLA vencido</b>
              {M.vencidos.slice(0, 4).map((v) => (
                <Link
                  key={v.code}
                  to={`/incidents/${v.code}`}
                  className="flex items-center justify-between gap-2 py-1 text-[13px] hover:text-brand"
                >
                  <span className="truncate">
                    <b>{v.code}</b> {v.title}
                  </span>
                  <SevPill v={v.severity} />
                </Link>
              ))}
            </div>
          )}
        </Panel>
        <Panel title="Coincidencias con MISP" hint="24 h">
          {hits.length ? (
            <ul className="space-y-2">
              {hits.slice(0, 6).map((h, i) => {
                const m = h.data?.misp;
                return (
                  <li key={i} className="flex items-start gap-2 text-[13px]">
                    <Badge variant="bad">{m?.type}</Badge>
                    <div className="min-w-0 flex-1">
                      <Link className="mono text-brand" to={`/intel?q=${encodeURIComponent(m?.value ?? '')}`}>
                        {m?.value}
                      </Link>
                      <div className="truncate text-xs text-muted">
                        {h.agent?.name} · {m?.event_info}
                      </div>
                    </div>
                    <span className="text-xs text-muted">{fdt(h.timestamp)}</span>
                  </li>
                );
              })}
            </ul>
          ) : (
            <Empty>
              Sin coincidencias en 24 h. Que no haya coincidencias no garantiza que un indicador sea seguro.
            </Empty>
          )}
        </Panel>
      </div>

      {o && <Timeline items={o.timeline} />}

      <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
        <Panel
          title="Incidentes recientes"
          actions={
            <Link className="text-xs text-brand" to="/incidents">
              Ver todos →
            </Link>
          }
          bodyClassName="px-2 pb-2"
        >
          {d.incidents.recent.length ? (
            <Table>
              <TableBody>
                {d.incidents.recent.map((x) => (
                  <TableRow key={x.code} clickable onClick={() => nav(`/incidents/${x.code}`)}>
                    <TableCell>
                      <Link to={`/incidents/${x.code}`} className="font-bold">
                        {x.code}
                      </Link>
                    </TableCell>
                    <TableCell>{x.title}</TableCell>
                    <TableCell>
                      <SevPill v={x.severity} />
                    </TableCell>
                    <TableCell>
                      <StatusPill v={x.status} />
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-muted">{x.updated_at}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <Empty>Aún no hay incidentes.</Empty>
          )}
        </Panel>
        <Panel title="Accesos">
          <div className="grid gap-2.5">
            {[
              ['Wazuh', 'SIEM / XDR', d.links.wazuh, Shield],
              ['MISP', 'Inteligencia de amenazas', d.links.misp, Radar],
              ['Shuffle', `SOAR · ${nf((s.workflows ?? []).length)} workflows`, d.links.shuffle, Workflow],
              ['Runbooks', `${d.runbooks.length} procedimientos`, '/runbooks', BookOpen],
            ].map(([t, p, h, Icon]) => {
              const I = Icon as React.ComponentType<{ className?: string }>;
              const inner = (
                <>
                  <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-brand-soft text-brand">
                    <I className="size-5" />
                  </span>
                  <span>
                    <b className="block text-[13.5px]">{t as string}</b>
                    <small className="text-muted">{p as string}</small>
                  </span>
                </>
              );
              const cls =
                'flex items-center gap-3 rounded-xl border border-line bg-card p-2.5 transition-colors hover:border-brand/50 hover:bg-brand-soft/40';
              return String(h).startsWith('/') ? (
                <Link key={t as string} to={h as string} className={cls}>
                  {inner}
                </Link>
              ) : (
                <a
                  key={t as string}
                  href={h as string}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={cls}
                >
                  {inner}
                </a>
              );
            })}
          </div>
        </Panel>
      </div>
    </div>
  );
}
