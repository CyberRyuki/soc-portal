import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Download, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { usePageEnter } from '@/components/layout/AppShell';
import { Donut } from '@/components/charts';
import {
  Chips,
  Empty,
  ErrorState,
  Kpi,
  KpiGrid,
  Loading,
  PageHeader,
  Panel,
  Rank,
  Risk,
} from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Input, Select, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Bar } from '@/components/ui/progress';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import { useConfirm } from '@/hooks/useConfirm';
import { useSearchParam } from '@/hooks/useSearchParam';
import { IOC_TYPE_LABEL, SEQ_RAMP } from '@/lib/constants';
import { csvDownload, nf, short } from '@/lib/format';
import { cn } from '@/lib/utils';
import {
  useAddCatalog,
  useAddIocs,
  useBulkCheck,
  useCatalog,
  useDeleteSource,
  useIntelJobs,
  useIntelOverlap,
  useIntelOverview,
  useParseIocs,
  useRetro,
  useRunSource,
  useSightings,
  useSources,
} from '@/services/intel';
import { useNewIncident } from '@/pages/incidents/NewIncidentDialog';
import { useDrill } from '@/pages/threats/DrillDialog';
import { useIocDetail } from './IocDetailDialog';
import { SourceDialog } from './SourceDialog';
import { JobsList, KIND_LABEL, SourcePills, TLP_VARIANT } from './common';
import type { IntelSource } from '@/types/api';

const VIEWS: [string, string][] = [
  ['resumen', 'Resumen'],
  ['coincidencias', 'Coincidencias'],
  ['comprobar', 'Comprobar'],
  ['fuentes', 'Fuentes'],
  ['cargar', 'Cargar'],
  ['integrar', 'Integrar'],
];
const TYPE_COLORS = [
  'var(--s1)',
  'var(--s2)',
  '#1baf7a',
  '#eda100',
  '#e87ba4',
  '#6250d6',
  '#008300',
  '#98a2b3',
];

export default function IocsPage() {
  const ref = usePageEnter('iocs');
  const [view, setView] = useSearchParam('view', 'resumen');
  useEffect(() => {
    document.title = 'Portal SOC · IoC';
  }, []);
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Inteligencia de amenazas · IoC"
        subtitle="Millones de indicadores de varias fuentes, cruzados automáticamente con las alertas de Wazuh y con MISP."
        actions={<Chips options={VIEWS} value={view} onChange={setView} />}
      />
      {view === 'coincidencias' ? (
        <SightingsView />
      ) : view === 'comprobar' ? (
        <CheckView />
      ) : view === 'fuentes' ? (
        <SourcesView />
      ) : view === 'cargar' ? (
        <LoadView />
      ) : view === 'integrar' ? (
        <IntegrateView />
      ) : (
        <OverviewView />
      )}
    </div>
  );
}

function RetroButton({ small }: { small?: boolean }) {
  const retro = useRetro();
  const [open, setOpen] = useState(false);
  const [days, setDays] = useState('7');
  const run = async () => {
    const d = Math.max(1, Math.min(90, Number(days) || 7));
    try {
      const r = await retro.mutateAsync(d);
      toast(r.encolado ? `Retrobúsqueda de ${d} días en marcha` : 'Ya hay una retrobúsqueda en curso');
      setOpen(false);
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  };
  return (
    <>
      <Button variant="secondary" size={small ? 'sm' : 'default'} onClick={() => setOpen(true)}>
        Retrobúsqueda
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent
          title="Retrobúsqueda en Wazuh"
          description="Revisa las alertas pasadas en busca de los IoC cargados."
        >
          <Label htmlFor="rd">¿Cuántos días hacia atrás? (1-90)</Label>
          <Input
            id="rd"
            type="number"
            min={1}
            max={90}
            value={days}
            onChange={(e) => setDays(e.target.value)}
          />
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setOpen(false)}>
              Cancelar
            </Button>
            <Button onClick={run} disabled={retro.isPending}>
              Iniciar
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

function OverviewView() {
  const d = useIntelOverview();
  const recent = useSightings(7);
  const ovl = useIntelOverlap();
  const jobs = useIntelJobs();
  const detail = useIocDetail();
  if (d.isPending) return <Loading />;
  if (d.error || !d.data) return <ErrorState error={d.error} onRetry={() => void d.refetch()} />;
  const x = d.data;
  const on = x.fuentes.filter((f) => f.enabled);
  const list = jobs.data?.jobs ?? x.jobs;
  const O = ovl.data;
  const M: Record<string, number> = {};
  O?.pares.forEach(([a, b, n]) => {
    M[`${a}-${b}`] = n;
    M[`${b}-${a}`] = n;
  });
  const mx = Math.max(1, ...(O?.pares.map((p) => p[2]) ?? [1]));
  const F = O?.fuentes.slice(0, 8) ?? [];
  const col = (n: number) =>
    n ? SEQ_RAMP[Math.min(6, Math.floor(Math.sqrt(n / mx) * 6.99))] : 'var(--grid)';
  return (
    <>
      <KpiGrid data-enter="">
        <Kpi title="IoC en la base" value={short(x.unicos)} hint={`${nf(on.length)} fuentes activas`} />
        <Kpi title="En varias fuentes" value={short(x.multi)} hint="más confianza (coinciden ≥ 2)" />
        <Kpi
          title="Coincidencias 24 h"
          value={nf(x.coincidencias_24h)}
          hint="IoC vistos en alertas de Wazuh"
          to="/iocs?view=coincidencias&days=1"
          alert={x.coincidencias_24h > 0}
        />
        <Kpi
          title="IoC vistos · 7 días"
          value={nf(x.iocs_vistos_7d)}
          hint={`${nf(x.equipos_7d)} equipos afectados`}
          to="/iocs?view=coincidencias"
          alert={x.iocs_vistos_7d > 0}
        />
        <Kpi
          title="Correlación con Wazuh"
          value={x.correlacion ? 'Activa' : '—'}
          hint={
            x.correlacion ? `cada 5 min · última ${x.correlacion.slice(11)}` : 'esperando la primera ventana'
          }
        />
      </KpiGrid>
      {!x.fuentes.length && (
        <Panel title="Empieza añadiendo fuentes" className="bg-brand-soft">
          <p className="mb-3 text-[13.5px]">
            Activa feeds públicos de inteligencia (abuse.ch, Spamhaus, Emerging Threats…) y tu MISP, o carga
            tus propias listas.
          </p>
          <div className="flex gap-2">
            <Button asChild>
              <Link to="/iocs?view=fuentes">Añadir fuentes →</Link>
            </Button>
            <Button variant="secondary" asChild>
              <Link to="/iocs?view=cargar">Cargar una lista</Link>
            </Button>
          </div>
        </Panel>
      )}
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="IoC por tipo">
          <Donut
            center="IoC"
            items={x.por_tipo.map(([k, n], i) => ({
              label: IOC_TYPE_LABEL[k] ?? k,
              value: n,
              color: TYPE_COLORS[i % 8] ?? 'var(--s1)',
            }))}
          />
        </Panel>
        <Panel title="IoC por fuente">
          <Rank
            total={x.fuentes.reduce((a, f) => a + (f.n || 0), 0)}
            max={6}
            empty="Sin fuentes con datos"
            rows={x.fuentes
              .filter((f) => f.n)
              .map((f) => ({
                key: String(f.id),
                label: f.name,
                value: f.n,
                sub: `${KIND_LABEL[f.kind] ?? f.kind} · confianza ${f.weight}`,
              }))}
          />
        </Panel>
        <Panel title="Trabajos" actions={<RetroButton small />}>
          <JobsList jobs={list.slice(0, 8)} />
        </Panel>
      </div>
      <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
        <Panel
          title="Últimas coincidencias con Wazuh"
          actions={
            <Link className="text-xs text-brand" to="/iocs?view=coincidencias">
              Ver todas →
            </Link>
          }
        >
          {recent.data?.length ? (
            <ul className="space-y-2">
              {recent.data.slice(0, 8).map((s) => (
                <li key={s.value} className="flex items-start gap-2 text-[13px]">
                  <Risk s={s.score} />
                  <button
                    type="button"
                    className="min-w-0 flex-1 cursor-pointer text-left"
                    onClick={() => detail.open(s.value)}
                  >
                    <span className="mono mr-1">{s.value}</span>
                    <SourcePills f={s.fuentes} />
                    <div className="truncate text-xs text-muted">
                      {s.agents
                        .slice(0, 3)
                        .map(([a, n]) => `${a} (${nf(n)})`)
                        .join(', ')}{' '}
                      · {s.rule}
                    </div>
                  </button>
                  <span className="whitespace-nowrap text-xs text-muted">{s.last_seen.slice(5, 16)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <Empty>
              Sin coincidencias en 7 días.{' '}
              {x.fuentes.length ? 'La correlación revisa las alertas nuevas cada 5 minutos.' : ''}
            </Empty>
          )}
        </Panel>
        <Panel title="Solapamiento entre fuentes" hint="IoC compartidos">
          {ovl.isPending ? (
            <Loading rows={1} h="h-28" />
          ) : !O || O.fuentes.length < 2 ? (
            <Empty className="py-3">Necesitas al menos dos fuentes con datos.</Empty>
          ) : (
            <div className="overflow-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr>
                    <th />
                    {F.map((f, i) => (
                      <th key={f.id} title={f.name} className="px-1 text-center">
                        {i + 1}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {F.map((a, i) => (
                    <tr key={a.id}>
                      <td className="max-w-[190px] truncate whitespace-nowrap py-0.5 pr-1" title={a.name}>
                        <b>{i + 1}</b> {a.name}
                      </td>
                      {F.map((b) => {
                        const n = M[`${a.id}-${b.id}`] ?? 0;
                        return (
                          <td
                            key={b.id}
                            className={cn(
                              'h-7 w-8 rounded text-center',
                              n / mx > 0.25 && 'font-semibold text-white',
                            )}
                            style={{ background: a.id === b.id ? 'var(--grid)' : col(n) }}
                            title={`${nf(n)} IoC en común · ${a.name} / ${b.name}`}
                          >
                            {n ? short(n) : ''}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
      {x.correlacion_msg && <p className="text-xs text-muted">{x.correlacion_msg}</p>}
    </>
  );
}

function SightingsView() {
  const [daysS, setDays] = useSearchParam('days', '7');
  const [minS, setMin] = useSearchParam('min', '0');
  const [q, setQ] = useSearchParam('q', '');
  const [draft, setDraft] = useState(q);
  const days = Number(daysS) || 7,
    min = Number(minS) || 0;
  const s = useSightings(days, q, min);
  const detail = useIocDetail();
  const drill = useDrill();
  const newInc = useNewIncident();
  const { canWrite } = useAuth();
  const rows = s.data ?? [];
  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <Chips
          options={[
            [1, '24 h'],
            [7, '7 días'],
            [30, '30 días'],
            [90, '90 días'],
          ]}
          value={days}
          onChange={(v) => setDays(String(v))}
        />
        <Chips
          options={[
            [0, 'Todo riesgo'],
            [50, '≥ 50'],
            [80, 'Alto ≥ 80'],
          ]}
          value={min}
          onChange={(v) => setMin(String(v))}
        />
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && setQ(draft)}
          placeholder="Buscar IoC, equipo o regla… (Enter)"
          className="min-w-[200px] flex-1"
          aria-label="Buscar"
        />
        <RetroButton />
        <Button
          variant="secondary"
          onClick={() =>
            csvDownload(
              'coincidencias.csv',
              rows.map((x) => ({
                ...x,
                fuentes: x.fuentes.map((f) => f.name).join(' | '),
                agents: x.agents.map((a) => a[0]).join(' | '),
              })),
              ['value', 'type', 'score', 'fuentes', 'agents', 'n', 'first_seen', 'last_seen', 'rule'],
            )
          }
        >
          <Download /> CSV
        </Button>
      </div>
      {s.isPending ? (
        <Loading />
      ) : s.error ? (
        <ErrorState error={s.error} />
      ) : (
        <Panel title="" className="[&>div:first-child]:hidden" bodyClassName="px-0 pb-0">
          {rows.length ? (
            <div className="max-h-[680px] overflow-auto scroll-thin">
              <Table>
                <TableHeader className="sticky top-0 bg-card">
                  <TableRow>
                    <TableHead>Riesgo</TableHead>
                    <TableHead>Indicador visto</TableHead>
                    <TableHead>Fuentes</TableHead>
                    <TableHead>Equipos</TableHead>
                    <TableHead className="text-right">Alertas</TableHead>
                    <TableHead>Última vez</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((x) => (
                    <TableRow key={x.value}>
                      <TableCell>
                        <Risk s={x.score} />
                      </TableCell>
                      <TableCell>
                        <span className="mono break-all">{x.value}</span>{' '}
                        <Badge variant="gray">{IOC_TYPE_LABEL[x.type] ?? x.type}</Badge>
                        <div className="text-xs text-muted">
                          {x.rule}
                          {x.matched && x.matched !== x.value && (
                            <>
                              {' '}
                              · coincide con <span className="mono">{x.matched}</span>
                            </>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <SourcePills f={x.fuentes} />
                      </TableCell>
                      <TableCell className="text-[13px]">
                        {x.agents.slice(0, 3).map(([a, n]) => (
                          <div key={a}>
                            {a} <span className="text-muted">{nf(n)}</span>
                          </div>
                        ))}
                        {x.agents.length > 3 && (
                          <span className="text-muted">+{x.agents.length - 3} más</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right font-bold">{nf(x.n)}</TableCell>
                      <TableCell className="whitespace-nowrap text-[13px]">
                        {x.last_seen.slice(0, 16)}
                        <div className="text-xs text-muted">desde {x.first_seen.slice(5, 16)}</div>
                      </TableCell>
                      <TableCell className="whitespace-nowrap">
                        <Button variant="secondary" size="sm" onClick={() => detail.open(x.value)}>
                          Detalle
                        </Button>
                        {x.fields.includes('data.srcip') && (
                          <Button
                            variant="secondary"
                            size="sm"
                            className="ml-1"
                            onClick={() => drill.open('data.srcip', x.value)}
                          >
                            Alertas
                          </Button>
                        )}
                        {canWrite && (
                          <Button
                            size="sm"
                            className="ml-1"
                            aria-label="Crear incidente"
                            onClick={() =>
                              newInc.open({
                                title: `IoC visto en Wazuh: ${x.value}`,
                                iocs: x.value,
                                assets: x.agents.map((a) => a[0]).join(', '),
                                detected_by: 'Motor de inteligencia',
                                runbook: 'misp-ioc-match',
                                severity: x.score >= 90 ? 'Critical' : 'High',
                              })
                            }
                          >
                            <Plus />
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <Empty>
              Ningún IoC de tus fuentes aparece en las alertas de Wazuh en este periodo. Prueba una
              retrobúsqueda tras cargar fuentes nuevas.
            </Empty>
          )}
        </Panel>
      )}
      <p className="text-xs text-muted">
        Campos revisados: IPs de origen y destino (también Sysmon, AWS y Office 365), consultas DNS, URLs y
        hashes de FIM y VirusTotal. Un subdominio coincide con su dominio padre; una IP coincide con las redes
        CIDR (p. ej. Spamhaus).
      </p>
    </>
  );
}

function CheckView() {
  const [text, setText] = useState('');
  const [one, setOne] = useState('');
  const check = useBulkCheck();
  const detail = useIocDetail();
  const { meta } = useAuth();
  const rows = useMemo(
    () =>
      [...(check.data?.resultados ?? [])].sort(
        (a, b) => b.score - a.score || (b.wazuh ?? 0) - (a.wazuh ?? 0),
      ),
    [check.data],
  );
  const bad = rows.filter(
    (x) => x.score || x.wazuh || (Array.isArray(x.misp) ? x.misp.length : x.misp),
  ).length;
  return (
    <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
      <Panel title="Comprobar indicadores" hint="hasta 1000 a la vez">
        <Textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          className="min-h-[160px] font-mono text-[12.5px]"
          placeholder="Pega IPs, dominios, URLs o hashes (también el texto de un aviso)…"
          aria-label="Indicadores"
        />
        <div className="mt-2.5 flex items-center justify-between gap-2">
          <span className="text-xs text-muted">
            Se busca en todas tus fuentes, en las alertas de Wazuh (30 días) y en MISP, en una sola consulta.
          </span>
          <Button onClick={() => text.trim() && check.mutate(text)} disabled={check.isPending}>
            Comprobar
          </Button>
        </div>
        {check.isPending && <Loading rows={1} h="h-24" />}
        {check.error && <ErrorState error={check.error} compact />}
        {check.data && (
          <div className="mt-4">
            <div className="mb-2 flex items-center justify-between">
              <b>
                {nf(rows.length)} indicadores ·{' '}
                <span className={bad ? 'text-bad' : 'text-ok'}>{nf(bad)} con coincidencias</span>
              </b>
              <Button
                variant="secondary"
                size="sm"
                onClick={() =>
                  csvDownload(
                    'comprobacion.csv',
                    rows.map((x) => ({
                      ...x,
                      fuentes: x.fuentes.map((f) => f.name).join(' | '),
                      misp: Array.isArray(x.misp) ? x.misp.join(' ') : x.misp,
                    })),
                    ['value', 'type', 'score', 'fuentes', 'wazuh', 'misp'],
                  )
                }
              >
                <Download /> CSV
              </Button>
            </div>
            <div className="max-h-[520px] overflow-auto scroll-thin">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Riesgo</TableHead>
                    <TableHead>Indicador</TableHead>
                    <TableHead>Fuentes</TableHead>
                    <TableHead className="text-right">Wazuh 30 d</TableHead>
                    <TableHead>MISP</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((x) => {
                    const mispIds = Array.isArray(x.misp) ? (x.misp as (string | number)[]) : [];
                    return (
                      <TableRow key={x.value}>
                        <TableCell>
                          <Risk s={x.score} />
                        </TableCell>
                        <TableCell className="mono break-all">
                          {x.value} <Badge variant="gray">{IOC_TYPE_LABEL[x.type] ?? x.type}</Badge>
                        </TableCell>
                        <TableCell>
                          <SourcePills f={x.fuentes} />
                        </TableCell>
                        <TableCell className="text-right">
                          {x.wazuh == null ? '?' : x.wazuh ? <b className="text-bad">{nf(x.wazuh)}</b> : '0'}
                        </TableCell>
                        <TableCell>
                          {x.misp == null
                            ? '?'
                            : mispIds.length
                              ? mispIds.slice(0, 3).map((e) => (
                                  <a
                                    key={String(e)}
                                    className="mr-1 text-brand"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    href={`${meta?.links.misp ?? ''}/events/view/${encodeURIComponent(String(e))}`}
                                  >
                                    #{String(e)}
                                  </a>
                                ))
                              : '—'}
                        </TableCell>
                        <TableCell>
                          <Button variant="secondary" size="sm" onClick={() => detail.open(x.value)}>
                            Detalle
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </div>
        )}
      </Panel>
      <Panel title="Análisis a fondo de un indicador">
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (one.trim()) detail.open(one);
          }}
        >
          <Input
            value={one}
            onChange={(e) => setOne(e.target.value)}
            placeholder="185.220.101.1 · malo.xyz · hash…"
            aria-label="Indicador"
          />
          <Button type="submit">Analizar</Button>
        </form>
        <p className="mt-3 text-xs text-muted">
          Añade enriquecimiento externo: Shodan InternetDB (gratis) y, si configuras sus claves, AbuseIPDB,
          VirusTotal, AlienVault OTX y ThreatFox.
        </p>
      </Panel>
    </div>
  );
}

function SourcesView() {
  const src = useSources();
  const cat = useCatalog();
  const jobs = useIntelJobs();
  const add = useAddCatalog();
  const run = useRunSource();
  const del = useDeleteSource();
  const { canWrite } = useAuth();
  const [confirm, dialog] = useConfirm();
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [edit, setEdit] = useState<{ open: boolean; source: IntelSource | null; kind: 'feed' | 'misp' }>({
    open: false,
    source: null,
    kind: 'feed',
  });
  if (src.isPending || cat.isPending) return <Loading />;
  if (src.error || cat.error) return <ErrorState error={src.error ?? cat.error} />;
  const rows = src.data ?? [];
  const remove = async (s: IntelSource) => {
    if (
      !(await confirm({
        title: `¿Eliminar «${s.name}» y todos sus IoC?`,
        confirmText: 'Eliminar',
        destructive: true,
      }))
    )
      return;
    await del.mutateAsync(s.id);
    toast('Eliminando en segundo plano');
  };
  return (
    <>
      <Panel
        title={
          <>
            Fuentes configuradas <span className="text-xs font-normal text-muted">{rows.length}</span>
          </>
        }
        actions={
          canWrite && (
            <div className="flex gap-2">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setEdit({ open: true, source: null, kind: 'misp' })}
              >
                <Plus /> Mi MISP
              </Button>
              <Button size="sm" onClick={() => setEdit({ open: true, source: null, kind: 'feed' })}>
                <Plus /> Feed por URL
              </Button>
            </div>
          )
        }
        bodyClassName="px-0 pb-0"
      >
        {rows.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Fuente</TableHead>
                <TableHead>Tipo</TableHead>
                <TableHead className="text-right">Confianza</TableHead>
                <TableHead className="text-right">IoC</TableHead>
                <TableHead>Actualiza</TableHead>
                <TableHead>Última ejecución</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((s) => (
                <TableRow key={s.id} className={cn(!s.enabled && 'opacity-55')}>
                  <TableCell>
                    <b>{s.name}</b>
                    {s.url && (
                      <div className="mono max-w-[330px] truncate text-[11px] text-muted">{s.url}</div>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge variant={s.kind === 'misp' ? 'info' : s.kind === 'feed' ? 'default' : 'gray'}>
                      {KIND_LABEL[s.kind] ?? s.kind}
                    </Badge>{' '}
                    <Badge variant={TLP_VARIANT[s.tlp] ?? 'gray'}>TLP:{String(s.tlp).toUpperCase()}</Badge>
                  </TableCell>
                  <TableCell className="text-right font-bold">{s.weight}</TableCell>
                  <TableCell className="text-right">
                    <b>{short(s.n || 0)}</b>
                    {s.last_added > 0 && (
                      <div className="text-[11.5px] text-muted">+{short(s.last_added)}</div>
                    )}
                  </TableCell>
                  <TableCell className="text-[13px]">
                    {s.kind === 'manual' ? '—' : `cada ${s.interval_h} h`}
                    <div className="text-[11.5px] text-muted">
                      {s.retention_days ? `caduca a los ${s.retention_days} d` : 'no caduca'}
                    </div>
                  </TableCell>
                  <TableCell className="max-w-[260px] text-[12.5px]">
                    {s.last_run || 'pendiente'}
                    <div
                      className={cn(
                        'text-xs',
                        String(s.last_status).startsWith('Error') ? 'text-bad' : 'text-muted',
                      )}
                    >
                      {s.last_status}
                    </div>
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    {canWrite && (
                      <>
                        {s.kind !== 'manual' && (
                          <Button
                            variant="secondary"
                            size="icon-sm"
                            title="Actualizar ahora"
                            onClick={() =>
                              run.mutate(s.id, { onSuccess: () => toast('Actualización en cola') })
                            }
                          >
                            <RefreshCw />
                          </Button>
                        )}
                        <Button
                          variant="secondary"
                          size="icon-sm"
                          className="ml-1"
                          title="Editar"
                          onClick={() => setEdit({ open: true, source: s, kind: s.kind as 'feed' | 'misp' })}
                        >
                          <Pencil />
                        </Button>
                        <Button
                          variant="secondary"
                          size="icon-sm"
                          className="ml-1"
                          title="Eliminar la fuente y sus IoC"
                          onClick={() => remove(s)}
                        >
                          <Trash2 />
                        </Button>
                      </>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty>Aún no hay fuentes. Elige feeds del catálogo de abajo o conecta tu MISP.</Empty>
        )}
      </Panel>
      <Panel
        title="Catálogo de feeds públicos"
        actions={
          canWrite && (
            <Button
              size="sm"
              disabled={!sel.size || add.isPending}
              onClick={async () => {
                await add.mutateAsync([...sel]);
                toast.success(`${sel.size} fuentes añadidas; descargando…`);
                setSel(new Set());
              }}
            >
              Añadir seleccionados
            </Button>
          )
        }
      >
        <p className="mb-3 text-xs text-muted">
          Feeds gratuitos y reconocidos. La <b>confianza</b> (1-100) pesa en la puntuación de riesgo: un IoC
          que está en varias fuentes fiables puntúa alto. Revisa las condiciones de uso de cada proveedor.
        </p>
        <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
          {(cat.data ?? []).map((c) => (
            <label
              key={c.key}
              className={cn(
                'flex cursor-pointer items-start gap-2.5 rounded-xl border border-line p-3',
                c.added && 'opacity-55',
              )}
            >
              <Checkbox
                className="mt-0.5"
                disabled={c.added || !canWrite}
                checked={c.added || sel.has(c.key)}
                onCheckedChange={(v) =>
                  setSel((s) => {
                    const n = new Set(s);
                    if (v === true) n.add(c.key);
                    else n.delete(c.key);
                    return n;
                  })
                }
              />
              <span>
                <b className="text-[13.5px]">{c.name}</b>
                <div className="text-xs text-muted">
                  {IOC_TYPE_LABEL[c.ioc_type] ?? 'Varios'} · confianza {c.weight} · cada {c.interval_h} h
                  {c.added && ' · ya añadida'}
                </div>
              </span>
            </label>
          ))}
        </div>
      </Panel>
      <Panel title="Trabajos recientes">
        <JobsList jobs={(jobs.data?.jobs ?? []).slice(0, 8)} />
      </Panel>
      <SourceDialog
        open={edit.open}
        source={edit.source}
        kind={edit.kind}
        onClose={() => setEdit((e) => ({ ...e, open: false }))}
      />
      {dialog}
    </>
  );
}

function LoadView() {
  const { meta } = useAuth();
  const jobs = useIntelJobs();
  const parse = useParseIocs();
  const addIocs = useAddIocs();
  const [text, setText] = useState('');
  const [form, setForm] = useState({
    source: '',
    weight: '80',
    description: '',
    misp: false,
    to_ids: true,
    retro: true,
  });
  const timer = useRef<number>(0);
  const [up, setUp] = useState<{ pct: number; msg: React.ReactNode; busy: boolean }>({
    pct: 0,
    msg: '',
    busy: false,
  });
  const fileForm = useRef<HTMLFormElement>(null);
  useEffect(() => {
    clearTimeout(timer.current);
    if (!text.trim()) return;
    timer.current = window.setTimeout(() => parse.mutate(text), 500);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text]);
  const preview = parse.data;
  const by: Record<string, number> = {};
  preview?.iocs.forEach((i) => (by[i.type] = (by[i.type] ?? 0) + 1));

  const upload = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = e.currentTarget;
    const file = (f.elements.namedItem('file') as HTMLInputElement).files?.[0];
    if (!file) return;
    const fd = new FormData(f);
    const p = new URLSearchParams();
    for (const k of ['name', 'weight', 'ioc_type', 'mode', 'expires_days', 'tlp', 'retro'])
      p.set(k, String(fd.get(k) ?? ''));
    const x = new XMLHttpRequest();
    setUp({ pct: 0, msg: 'Subiendo…', busy: true });
    x.upload.onprogress = (ev) =>
      ev.lengthComputable &&
      setUp({
        pct: (ev.loaded / ev.total) * 100,
        msg: `Subiendo ${(ev.loaded / 1048576).toFixed(0)} de ${(ev.total / 1048576).toFixed(0)} MB…`,
        busy: true,
      });
    x.onload = () => {
      if (x.status < 300) {
        setUp({
          pct: 100,
          msg: (
            <b className="text-ok">
              Archivo recibido. Se está cargando en segundo plano; mira el avance en «Trabajos».
            </b>
          ),
          busy: false,
        });
        void jobs.refetch();
        fileForm.current?.reset();
      } else {
        let m = String(x.status);
        try {
          m = JSON.parse(x.responseText).detail;
        } catch {
          /* texto plano */
        }
        setUp({ pct: 0, msg: <span className="text-bad">Error: {m}</span>, busy: false });
      }
    };
    x.onerror = () =>
      setUp({ pct: 0, msg: <span className="text-bad">Error de red al subir el archivo</span>, busy: false });
    x.open('POST', `/portal/api/intel/upload?${p}`);
    x.setRequestHeader('Content-Type', 'application/octet-stream');
    x.setRequestHeader('X-SOC', '1');
    x.send(file);
  };
  const load = async () => {
    if (!text.trim()) return toast.error('Pega algún indicador');
    try {
      await addIocs.mutateAsync({ ...form, weight: Number(form.weight) || 80, text });
      setText('');
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  };
  const r = addIocs.data;
  return (
    <>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Archivo grande" hint="TXT, CSV o .gz · hasta millones de IoC">
          <form ref={fileForm} onSubmit={upload} className="grid gap-3 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <Label htmlFor="up-file">Archivo *</Label>
              <Input
                id="up-file"
                name="file"
                type="file"
                required
                accept=".txt,.csv,.gz,.log,.lst"
                className="pt-1.5"
              />
            </div>
            <div>
              <Label htmlFor="up-name">Nombre de la fuente *</Label>
              <Input id="up-name" name="name" required placeholder="p. ej. Lista CSIRT nacional 2026" />
            </div>
            <div>
              <Label htmlFor="up-w">Confianza (1-100)</Label>
              <Input id="up-w" name="weight" type="number" min={1} max={100} defaultValue={70} />
            </div>
            <div>
              <Label htmlFor="up-t">Tipo de IoC</Label>
              <Select id="up-t" name="ioc_type">
                <option value="auto">Detectar solo</option>
                {Object.entries(IOC_TYPE_LABEL).map(([v, t]) => (
                  <option key={v} value={v}>
                    {t}
                  </option>
                ))}
              </Select>
            </div>
            <div>
              <Label htmlFor="up-m">De cada línea tomar</Label>
              <Select id="up-m" name="mode">
                <option value="first">El primer indicador</option>
                <option value="all">Todos los indicadores</option>
              </Select>
            </div>
            <div>
              <Label htmlFor="up-e">Caduca</Label>
              <Select id="up-e" name="expires_days" defaultValue="90">
                <option value="0">Nunca</option>
                <option value="30">30 días</option>
                <option value="90">90 días</option>
                <option value="365">1 año</option>
              </Select>
            </div>
            <div>
              <Label htmlFor="up-tlp">TLP</Label>
              <Select id="up-tlp" name="tlp" defaultValue="amber">
                <option value="clear">CLEAR</option>
                <option value="green">GREEN</option>
                <option value="amber">AMBER</option>
                <option value="red">RED</option>
              </Select>
            </div>
            <div className="sm:col-span-2">
              <Label htmlFor="up-r">Retrobúsqueda en Wazuh al terminar</Label>
              <Select id="up-r" name="retro" defaultValue="7">
                <option value="0">No</option>
                <option value="1">Último día</option>
                <option value="7">Últimos 7 días</option>
                <option value="30">Últimos 30 días</option>
              </Select>
            </div>
            {(up.busy || up.msg) && (
              <div className="sm:col-span-2">
                {up.busy && <Bar value={up.pct} />}
                <div className="mt-1.5 text-xs text-muted">{up.msg}</div>
              </div>
            )}
            <div className="text-right sm:col-span-2">
              <Button type="submit" disabled={up.busy}>
                Subir y cargar
              </Button>
            </div>
          </form>
          <p className="mt-3 text-xs text-muted">
            Ritmo aproximado: 1 millón de IoC cada 30 s. Los IoC repetidos solo actualizan su fecha. Para
            enviar a MISP listas de este tamaño, usa el feed de la pestaña{' '}
            <Link className="text-brand" to="/iocs?view=integrar">
              Integrar
            </Link>{' '}
            en vez de crear un evento.
          </p>
        </Panel>
        <Panel title="Pegar indicadores" hint="hasta 50 000 líneas">
          <Textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="min-h-[140px] font-mono text-[12.5px]"
            placeholder={'185.220.101[.]1\nhxxp://malo[.]xyz/login.php\n…o el texto completo de un aviso'}
            aria-label="Indicadores"
          />
          <div className="my-1.5 text-xs text-muted">
            {preview && text.trim() ? (
              <>
                <b className="text-ink">{nf(preview.iocs.length)} válidos:</b>{' '}
                {Object.entries(by).map(([k, n]) => (
                  <Badge key={k} variant="info" className="mr-1">
                    {k} · {n}
                  </Badge>
                ))}
                {preview.ignorados.length > 0 && ` · se ignoran ${preview.ignorados.length}`}
              </>
            ) : (
              'Se corrigen los «defanged» (hxxp, [.]) y se ignoran IPs privadas y dominios propios.'
            )}
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label htmlFor="ld-s">Fuente</Label>
              <Input
                id="ld-s"
                value={form.source}
                onChange={(e) => setForm({ ...form, source: e.target.value })}
                placeholder="CSIRT nacional, análisis propio…"
              />
            </div>
            <div>
              <Label htmlFor="ld-w">Confianza</Label>
              <Input
                id="ld-w"
                type="number"
                min={1}
                max={100}
                value={form.weight}
                onChange={(e) => setForm({ ...form, weight: e.target.value })}
              />
            </div>
            <div className="sm:col-span-2">
              <Label htmlFor="ld-d">Descripción (título del evento en MISP)</Label>
              <Input
                id="ld-d"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
            </div>
            <div className="flex flex-wrap gap-4 text-[13.5px] sm:col-span-2">
              <label className="flex items-center gap-2">
                <Checkbox
                  checked={form.misp}
                  onCheckedChange={(v) => setForm({ ...form, misp: v === true })}
                />{' '}
                Enviar a MISP
              </label>
              <label className="flex items-center gap-2">
                <Checkbox
                  checked={form.to_ids}
                  onCheckedChange={(v) => setForm({ ...form, to_ids: v === true })}
                />{' '}
                to_ids
              </label>
              <label className="flex items-center gap-2">
                <Checkbox
                  checked={form.retro}
                  onCheckedChange={(v) => setForm({ ...form, retro: v === true })}
                />{' '}
                Retrobúsqueda 7 días
              </label>
            </div>
            <div className="text-right sm:col-span-2">
              <Button onClick={load} disabled={addIocs.isPending}>
                Cargar
              </Button>
            </div>
          </div>
          {addIocs.error && <ErrorState error={addIocs.error} compact />}
          {r && (
            <div className="mt-3 rounded-xl bg-st-good/10 p-3 text-[13.5px]">
              <b>
                {nf(r.leidos)} leídos · {nf(r.añadidos)} nuevos
              </b>{' '}
              · {nf(r.ya_conocidos)} ya estaban en otras fuentes
              {r.misp_event && (
                <div>
                  Evento MISP{' '}
                  <a
                    className="text-brand"
                    target="_blank"
                    rel="noopener noreferrer"
                    href={`${meta?.links.misp ?? ''}/events/view/${encodeURIComponent(String(r.misp_event))}`}
                  >
                    #{String(r.misp_event)}
                  </a>{' '}
                  creado.
                </div>
              )}
              {r.misp_error && <div className="text-bad">MISP: {r.misp_error}</div>}
            </div>
          )}
        </Panel>
      </div>
      <Panel title="Trabajos">
        <JobsList jobs={(jobs.data?.jobs ?? []).slice(0, 8)} />
      </Panel>
    </>
  );
}

const Code = ({ t }: { t: string }) => (
  <pre className="mono my-1.5 overflow-auto rounded-xl bg-grid px-3 py-2.5 text-[12px]">{t}</pre>
);
const Tok = () => <span className="mono">X-API-Key: &lt;BRIDGE_TOKEN&gt;</span>;

function IntegrateView() {
  const d = useIntelOverview();
  const base = location.origin;
  return (
    <>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="MISP consume tus IoC (feed)">
          <p className="text-[13.5px]">
            En MISP: <i>Sync Actions → Feeds → Add Feed</i>, tipo <b>Freetext Parsed Feed</b>, «Lookup
            visible» y cabecera <Tok />. MISP los correlaciona con sus eventos sin crear millones de
            atributos.
          </p>
          <Code
            t={['ip', 'domain', 'url', 'hash']
              .map((k) => `${base}/feeds/misp/${k}.txt?min_weight=60`)
              .join('\n')}
          />
          <p className="text-xs text-muted">Se excluye lo que vino del propio MISP para no crear bucles.</p>
        </Panel>
        <Panel title="Wazuh detecta en tiempo real (listas CDB)">
          <p className="text-[13.5px]">
            El script <span className="mono">wazuh/actualizar_listas_ioc.sh</span> del proyecto descarga estas
            listas en el servidor de Wazuh, las compara y reinicia el manager solo si cambiaron. Las reglas
            están en <span className="mono">wazuh/rules/ioc_portal_rules.xml</span>.
          </p>
          <Code
            t={['ip', 'domain', 'hash'].map((k) => `${base}/feeds/wazuh/${k}.cdb?min_weight=75`).join('\n')}
          />
          <p className="text-xs text-muted">
            Solo fuentes con confianza ≥ 75 para que las listas no sean enormes. La correlación del portal
            (cada 5 min) revisa además todas las fuentes.
          </p>
        </Panel>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Servicios de enriquecimiento">
          {d.data?.providers ? (
            <ul className="divide-y divide-line text-[13.5px]">
              {d.data.providers.map((p) => (
                <li key={p.name} className="flex justify-between py-1.5">
                  <b>{p.name}</b>
                  {p.on ? <Badge variant="ok">Activo</Badge> : <Badge variant="gray">Sin clave</Badge>}
                </li>
              ))}
            </ul>
          ) : (
            <Loading rows={1} h="h-20" />
          )}
          <p className="mt-2 text-xs text-muted">
            Las claves van en el <span className="mono">.env</span>:{' '}
            <span className="mono">ABUSEIPDB_KEY</span>, <span className="mono">VT_API_KEY</span>,{' '}
            <span className="mono">OTX_API_KEY</span>, <span className="mono">ABUSECH_AUTH_KEY</span>. Solo se
            usan al analizar un indicador (con caché de 24 h), nunca en masa.
          </p>
        </Panel>
        <Panel title="Shuffle">
          <p className="text-[13.5px]">
            Shuffle puede cargar IoC y comprobarlos con <Tok />:
          </p>
          <Code
            t={`POST ${base}/portal/api/iocs\n{"text": "1.2.3.4\\nmalo.xyz", "source": "Shuffle", "weight": 80, "misp": false}`}
          />
          <p className="text-xs text-muted">
            Con <span className="mono">INTEL_AUTO_INCIDENT_SCORE=80</span> en el{' '}
            <span className="mono">.env</span>, cada IoC nuevo visto en Wazuh con riesgo ≥ 80 abre un
            incidente automáticamente.
          </p>
        </Panel>
      </div>
    </>
  );
}
