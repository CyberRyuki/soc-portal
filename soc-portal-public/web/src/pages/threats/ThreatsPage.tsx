import { useEffect } from 'react';
import { RefreshCw } from 'lucide-react';
import { usePageEnter } from '@/components/layout/AppShell';
import { Donut, Heatmap, TimeBars } from '@/components/charts';
import {
  Chips,
  Empty,
  ErrorState,
  HBars,
  Kpi,
  KpiGrid,
  Level,
  Loading,
  PageHeader,
  Panel,
  Rank,
} from '@/components/shared';
import { Button } from '@/components/ui/button';
import { useSearchParam } from '@/hooks/useSearchParam';
import { useThreats } from '@/services/threats';
import { useDrill } from './DrillDialog';
import { levelItems } from '@/pages/home/HomePage';
import { levelColor } from '@/lib/constants';
import { fdt, nf, pct, short } from '@/lib/format';
import type { Pair, ThreatRange } from '@/types/api';

const RANGES: [ThreatRange, string][] = [
  ['24h', '24 h'],
  ['7d', '7 días'],
  ['30d', '30 días'],
];
const LEVELS: [number, string][] = [
  [7, 'Nivel ≥ 7'],
  [10, '≥ 10'],
  [12, '≥ 12'],
  [13, 'Críticas'],
];

export default function ThreatsPage() {
  const ref = usePageEnter('threats');
  const [rangeS, setRange] = useSearchParam('range', '24h');
  const [lvS, setLv] = useSearchParam('lv', '10');
  const range = (RANGES.some(([r]) => r === rangeS) ? rangeS : '24h') as ThreatRange;
  const lv = Number(lvS) || 10;
  const q = useThreats(range, lv);
  const drill = useDrill();
  useEffect(() => {
    document.title = 'Portal SOC · Amenazas';
  }, []);
  const rows = (list: Pair[], field: string) =>
    list.map(([k, v]) => ({
      key: k,
      label: k,
      value: v,
      onClick: () => drill.open(field, String(k), range, lv),
    }));
  const t = q.data;
  const crit = t?.niveles.filter(([l]) => l >= 13).reduce((a, [, c]) => a + c, 0) ?? 0;
  const plus = (n: number) => nf(n) + (n >= 10 ? '+' : '');
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Amenazas"
        subtitle="Alertas de Wazuh con MITRE ATT&CK, origen y reglas. Pulsa cualquier elemento para ver sus alertas."
        actions={
          <>
            <Chips options={RANGES} value={range} onChange={setRange} />
            <Chips options={LEVELS} value={lv} onChange={(v) => setLv(String(v))} />
            <Button variant="secondary" size="icon" onClick={() => void q.refetch()} aria-label="Actualizar">
              <RefreshCw className={q.isFetching ? 'animate-spin' : ''} />
            </Button>
          </>
        }
      />
      {q.isPending ? (
        <>
          <Loading rows={3} />
          <p className="text-center text-[13px] text-muted">
            Consultando el indexer de Wazuh… los rangos largos pueden tardar.
          </p>
        </>
      ) : q.error || !t ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : (
        <>
          <KpiGrid data-enter="">
            <Kpi title={`Alertas nivel ≥ ${lv}`} value={short(t.total)} hint={`rango ${range}`} />
            <Kpi
              title="Críticas 13–15"
              value={nf(crit)}
              hint={`${pct(crit, t.total)} % del total`}
              alert={crit > 0}
            />
            <Kpi
              title="Tácticas MITRE"
              value={nf(t.tacticas.length)}
              hint={t.tacticas[0] ? `Principal: ${t.tacticas[0][0]}` : '—'}
            />
            <Kpi
              title="IPs de origen"
              value={plus(t.ips.length)}
              hint={t.ips[0] ? `Top: ${t.ips[0][0]}` : '—'}
            />
            <Kpi
              title="Países"
              value={plus(t.paises.length)}
              hint={t.paises[0] ? `Top: ${t.paises[0][0]}` : '—'}
            />
            <Kpi
              title="Agentes afectados"
              value={plus(t.agentes.length)}
              hint={t.agentes[0] ? `Top: ${t.agentes[0][0]}` : '—'}
            />
          </KpiGrid>
          <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
            <Panel title="Evolución de alertas" hint={`nivel ≥ ${lv}`}>
              <TimeBars pts={t.hist} />
            </Panel>
            <Panel title="Por nivel">
              <Donut items={levelItems(t.niveles, lv)} center="alertas" />
            </Panel>
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            <Panel title="Tácticas MITRE ATT&CK">
              <HBars
                rows={rows(t.tacticas, 'rule.mitre.tactic')}
                empty="Sin datos MITRE en este rango"
                max={10}
              />
            </Panel>
            <Panel title="Técnicas MITRE">
              <HBars
                rows={t.tecnicas.map((x) => ({
                  key: x.id,
                  label: `${x.id} · ${x.nombre}`,
                  value: x.n,
                  onClick: () => drill.open('rule.mitre.id', x.id, range, lv),
                }))}
                empty="Sin técnicas"
                max={10}
              />
            </Panel>
            <Panel title="Equipos con más alertas">
              <Rank
                total={t.total}
                rows={t.agentes.map(([k, v]) => ({
                  key: k,
                  label: k,
                  value: v,
                  sub: '🖥 equipo',
                  onClick: () => drill.open('agent.name', k, range, lv),
                }))}
                empty="Sin alertas"
                max={10}
              />
            </Panel>
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            <Panel title="IPs de origen" hint="pulsa para ver alertas">
              <HBars rows={rows(t.ips, 'data.srcip')} empty="Sin IPs de origen" max={10} />
            </Panel>
            <Panel title="Países de origen">
              <HBars
                rows={rows(t.paises, 'GeoLocation.country_name')}
                empty="Sin geolocalización (GeoIP)"
                max={10}
              />
            </Panel>
            <Panel title="Grupos de reglas">
              <HBars rows={rows(t.grupos, 'rule.groups')} empty="Sin datos" max={10} />
            </Panel>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <Panel title="Reglas más frecuentes" hint="pulsa para ver sus alertas">
              <Rank
                total={t.total}
                max={10}
                empty="Sin alertas"
                rows={t.reglas.map((r) => ({
                  key: r.id,
                  label: r.desc,
                  value: r.n,
                  color: levelColor(r.nivel),
                  sub: (
                    <span className="inline-flex items-center gap-1.5">
                      <Level l={r.nivel} />
                      <span className="mono">regla {r.id}</span>
                    </span>
                  ),
                  onClick: () => drill.open('rule.id', r.id, range, lv),
                }))}
              />
            </Panel>
            <Panel title="Mapa de calor" hint="día y hora local">
              <Heatmap pts={t.calor} />
            </Panel>
          </div>
          <Panel title={`Últimas alertas nivel ≥ ${Math.max(lv, 12)}`}>
            {t.recientes.length ? (
              <ul className="divide-y divide-line">
                {t.recientes.map((a, i) => (
                  <li key={i} className="flex items-center gap-3 py-2 text-[13.5px]">
                    <Level l={a.rule?.level} />
                    <button
                      type="button"
                      className="min-w-0 flex-1 cursor-pointer text-left hover:text-brand"
                      onClick={() => drill.open('rule.id', String(a.rule?.id ?? ''), range, lv)}
                    >
                      <div className="truncate">{a.rule?.description}</div>
                      <div className="text-xs text-muted">
                        {a.agent?.name}
                        {a.data?.srcip ? ` · origen ${a.data.srcip}` : ''}
                      </div>
                    </button>
                    <span className="whitespace-nowrap text-xs text-muted">{fdt(a.timestamp)}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty>Sin alertas de ese nivel.</Empty>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
