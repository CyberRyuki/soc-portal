import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Ban, CheckCircle2, Globe, Plus, Radar, ScanSearch, ShieldAlert, Square, Undo2 } from 'lucide-react';
import { toast } from 'sonner';
import { usePageEnter } from '@/components/layout/AppShell';
import {
  Chips,
  Empty,
  ErrorState,
  HBars,
  Kpi,
  KpiGrid,
  Loading,
  PageHeader,
  Panel,
} from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input, Select, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import { useConfirm } from '@/hooks/useConfirm';
import { useSearchParam } from '@/hooks/useSearchParam';
import { nf } from '@/lib/format';
import { cn } from '@/lib/utils';
import { useNewIncident } from '@/pages/incidents/NewIncidentDialog';
import {
  useExpAssetSet,
  useExpAssets,
  useExpConfig,
  useExpFindingSet,
  useExpFindings,
  useExpJobs,
  useExpSaveConfig,
  useExpScan,
  useExpServices,
  useExpStop,
  useExpSummary,
  useExpToPortal,
} from '@/services/exposure';
import type { ExpConfig, ExpFinding, ExpSeverity } from '@/types/api';

const VIEWS: [string, string][] = [
  ['resumen', 'Resumen'],
  ['hallazgos', 'Hallazgos'],
  ['shadow', 'Shadow IT'],
  ['activos', 'Activos'],
  ['servicios', 'Servicios'],
  ['escaneos', 'Escaneos'],
  ['alcance', 'Alcance'],
];
const SEV: Record<ExpSeverity, [string, 'bad' | 'warn' | 'info' | 'gray']> = {
  critical: ['Crítica', 'bad'],
  high: ['Alta', 'bad'],
  medium: ['Media', 'warn'],
  low: ['Baja', 'info'],
  info: ['Info', 'gray'],
};
const CAT: Record<string, string> = {
  shadow: 'Shadow IT',
  puerto: 'Puerto expuesto',
  web: 'Web',
  cve: 'CVE conocidos',
  tls: 'Certificado',
};
const PERFIL: Record<string, string> = {
  pasivo: 'Pasivo (sin tocar servidores)',
  estandar: 'Estándar (~70 puertos clave)',
  amplio: 'Amplio (1–1024 + comunes)',
  completo: 'Completo (65 535 puertos)',
};

export default function ExposurePage() {
  const ref = usePageEnter('exposure');
  const [view, setView] = useSearchParam('view', 'resumen');
  const S = useExpSummary();
  useEffect(() => {
    document.title = 'Portal SOC · Exposición';
  }, []);
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Exposición y Shadow IT"
        subtitle="Superficie de ataque de ACME: subdominios y servidores (inventariados o no), puertos y servicios expuestos, rutas sensibles y CVE conocidos."
        actions={<Chips options={VIEWS} value={view} onChange={setView} />}
      />
      <ScanBar />
      {S.isPending ? (
        <Loading rows={2} />
      ) : S.error || !S.data ? (
        <ErrorState error={S.error} onRetry={() => void S.refetch()} />
      ) : view === 'hallazgos' ? (
        <FindingsView />
      ) : view === 'shadow' ? (
        <AssetsView only="shadow" />
      ) : view === 'activos' ? (
        <AssetsView only="" />
      ) : view === 'servicios' ? (
        <ServicesView />
      ) : view === 'escaneos' ? (
        <JobsView />
      ) : view === 'alcance' ? (
        <ScopeView />
      ) : (
        <SummaryView />
      )}
    </div>
  );
}

// ---------------------------------------------------------------- barra de escaneo
function ScanBar() {
  const { canWrite, isAdmin } = useAuth();
  const S = useExpSummary();
  const J = useExpJobs();
  const scan = useExpScan();
  const stop = useExpStop();
  const [confirm, dialog] = useConfirm();
  const s = S.data;
  const j = J.data?.items[0];
  const running = !!J.data?.en_curso && j?.status === 'running';
  const pct = j && j.total ? Math.round((j.done / j.total) * 100) : 0;
  if (!s) return null;
  const noScope = !s.alcance.dominios && !s.alcance.rangos.length;
  const run = async (kind: 'pasivo' | 'completo') => {
    if (
      kind === 'completo' &&
      !(await confirm({
        title: '¿Lanzar el escaneo activo?',
        description: `Se escanearán los puertos de ${s.alcance.rangos.join(', ')} (perfil ${s.alcance.perfil}) y se probarán rutas sensibles en los servicios web. Puede disparar alertas del firewall, del WAF y de Wazuh: avisa al equipo de red.`,
        confirmText: 'Escanear',
        destructive: true,
      }))
    )
      return;
    scan.mutate(kind, {
      onSuccess: () =>
        toast.success(kind === 'completo' ? 'Escaneo activo en curso' : 'Descubrimiento pasivo en curso'),
      onError: (e) => toast.error(e.message),
    });
  };
  return (
    <div className="card flex flex-wrap items-center gap-3 px-4 py-2.5 text-[13px]">
      <Radar className={cn('size-4', running ? 'animate-pulse text-brand' : 'text-muted')} />
      {running && j ? (
        <>
          <span>
            Escaneo <b>{j.kind}</b> #{j.id} · {j.phase} · {nf(j.done)} / {nf(j.total)}
          </span>
          <div className="h-2 min-w-[160px] flex-1 overflow-hidden rounded-full bg-grid">
            <div
              className="h-full rounded-full bg-brand transition-[width] duration-500"
              style={{ width: `${pct}%` }}
            />
          </div>
          {canWrite && (
            <Button size="sm" variant="secondary" onClick={() => stop.mutate()}>
              <Square /> Detener
            </Button>
          )}
        </>
      ) : (
        <>
          <span className="text-muted">
            {noScope ? (
              <>
                Sin alcance definido.{' '}
                {isAdmin ? (
                  <Link className="text-brand" to="/exposure?view=alcance">
                    Configúralo
                  </Link>
                ) : (
                  'Un administrador debe configurarlo.'
                )}
              </>
            ) : (
              <>
                Alcance: {s.alcance.dominios} dominio(s) · {s.alcance.rangos.join(', ') || 'sin rangos'} ·
                último:{' '}
                {s.ultimo
                  ? `${s.ultimo.kind} ${s.ultimo.finished?.slice(5, 16) || ''} · ${s.ultimo.msg}`
                  : 'nunca'}
              </>
            )}
          </span>
          <span className="flex-1" />
          {!s.alcance.autorizado && s.alcance.rangos.length > 0 && (
            <Badge variant="warn" title={s.alcance.motivo}>
              Activo sin autorización
            </Badge>
          )}
          {canWrite && (
            <Button
              size="sm"
              variant="secondary"
              disabled={noScope || scan.isPending}
              onClick={() => void run('pasivo')}
            >
              <Globe /> Descubrimiento pasivo
            </Button>
          )}
          {isAdmin && (
            <Button
              size="sm"
              variant="destructive"
              disabled={!s.alcance.autorizado || !s.alcance.rangos.length || scan.isPending}
              title={s.alcance.autorizado ? undefined : s.alcance.motivo}
              onClick={() => void run('completo')}
            >
              <ScanSearch /> Escaneo activo
            </Button>
          )}
        </>
      )}
      {dialog}
    </div>
  );
}

// ---------------------------------------------------------------- resumen
function SummaryView() {
  const S = useExpSummary();
  const s = S.data!;
  const h = s.hallazgos;
  return (
    <>
      <KpiGrid>
        <Kpi
          title="Hallazgos críticos"
          value={nf(h.critical ?? 0)}
          alert={(h.critical ?? 0) > 0}
          to="/exposure?view=hallazgos"
        />
        <Kpi
          title="Hallazgos altos"
          value={nf(h.high ?? 0)}
          alert={(h.high ?? 0) > 0}
          to="/exposure?view=hallazgos"
        />
        <Kpi
          title="Shadow IT"
          value={nf(s.shadow)}
          hint="activos no inventariados"
          alert={s.shadow > 0}
          to="/exposure?view=shadow"
        />
        <Kpi
          title="Servicios expuestos"
          value={nf(s.servicios)}
          hint={`${nf(s.activos)} activos conocidos`}
          to="/exposure?view=servicios"
        />
        <Kpi title="IP con CVE conocidos" value={nf(s.con_cve)} hint="según Shodan" alert={s.con_cve > 0} />
      </KpiGrid>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Hallazgos abiertos por tipo">
          <HBars
            rows={s.categorias.map(([k, v]) => ({ label: CAT[k] ?? k, value: v }))}
            empty="Sin hallazgos abiertos"
          />
        </Panel>
        <Panel title="Puertos más vistos">
          <HBars rows={s.puertos.map(([k, v]) => ({ label: k, value: v }))} empty="Aún no hay servicios" />
        </Panel>
      </div>
      <TopFindings />
    </>
  );
}

function TopFindings() {
  const F = useExpFindings({ status: 'open', severity: '', category: '', q: '' });
  const rows = (F.data ?? []).filter((f) => f.severity === 'critical' || f.severity === 'high').slice(0, 10);
  return (
    <Panel title="Lo más urgente" bodyClassName="px-0 pb-0">
      {rows.length ? (
        <FindingsTable rows={rows} compact />
      ) : (
        <Empty>Sin hallazgos críticos ni altos abiertos.</Empty>
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------- hallazgos
function FindingsView() {
  const [status, setStatus] = useState('open');
  const [severity, setSeverity] = useSearchParam('severity', '');
  const [category, setCategory] = useState('');
  const [draft, setDraft] = useState('');
  const [q, setQ] = useState('');
  const F = useExpFindings({ status, severity, category, q });
  return (
    <Panel
      title={`Hallazgos · ${nf(F.data?.length ?? 0)}`}
      bodyClassName="px-0 pb-0"
      actions={
        <div className="flex flex-wrap gap-2">
          <Chips
            options={[
              ['open', 'Abiertos'],
              ['accepted', 'Aceptados'],
              ['fixed', 'Corregidos'],
              ['', 'Todos'],
            ]}
            value={status}
            onChange={setStatus}
          />
          <Select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            aria-label="Severidad"
            className="w-auto"
          >
            <option value="">Toda severidad</option>
            {Object.entries(SEV).map(([k, [l]]) => (
              <option key={k} value={k}>
                {l}
              </option>
            ))}
          </Select>
          <Select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            aria-label="Tipo"
            className="w-auto"
          >
            <option value="">Todo tipo</option>
            {Object.entries(CAT).map(([k, l]) => (
              <option key={k} value={k}>
                {l}
              </option>
            ))}
          </Select>
          <Input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && setQ(draft)}
            placeholder="IP, dominio, texto… (Enter)"
            className="w-52"
            aria-label="Buscar hallazgos"
          />
        </div>
      }
    >
      {F.isPending ? (
        <Loading rows={2} />
      ) : F.error ? (
        <ErrorState error={F.error} compact />
      ) : F.data?.length ? (
        <FindingsTable rows={F.data} />
      ) : (
        <Empty>Sin hallazgos con estos filtros.</Empty>
      )}
    </Panel>
  );
}

function FindingsTable({ rows, compact }: { rows: ExpFinding[]; compact?: boolean }) {
  const { canWrite } = useAuth();
  const set = useExpFindingSet();
  const newInc = useNewIncident();
  const act = (f: ExpFinding, status: string, msg: string) =>
    set.mutate(
      { key: f.key, status },
      { onSuccess: () => toast.success(msg), onError: (e) => toast.error(e.message) },
    );
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Severidad</TableHead>
          <TableHead>Hallazgo</TableHead>
          <TableHead>Activo</TableHead>
          {!compact && <TableHead>Visto</TableHead>}
          {canWrite && <TableHead className="w-32" />}
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((f) => (
          <TableRow key={f.key} className={cn(f.status !== 'open' && 'opacity-60')}>
            <TableCell>
              <Badge variant={SEV[f.severity]?.[1] ?? 'gray'}>{SEV[f.severity]?.[0] ?? f.severity}</Badge>
            </TableCell>
            <TableCell className="max-w-[520px]">
              <b className="text-[13.5px]">{f.title}</b>
              <div className="text-xs text-muted">
                {CAT[f.category] ?? f.category} · {f.detail}
              </div>
              {f.evidence && <div className="truncate font-mono text-[11px] text-muted">{f.evidence}</div>}
              {f.status !== 'open' && (
                <div className="text-xs text-muted">
                  {f.status === 'accepted' ? 'Aceptado' : 'Corregido'} {f.decided_by && `por ${f.decided_by}`}{' '}
                  {f.note && `· ${f.note}`}
                </div>
              )}
            </TableCell>
            <TableCell className="max-w-[240px] break-all font-mono text-xs">
              {f.asset.replace(/^(ip|host):/, '')}
            </TableCell>
            {!compact && (
              <TableCell className="whitespace-nowrap text-xs text-muted">
                {f.last_seen.slice(5, 16)}
                <div>desde {f.first_seen.slice(5, 10)}</div>
              </TableCell>
            )}
            {canWrite && (
              <TableCell>
                <div className="flex justify-end gap-1">
                  {f.status === 'open' ? (
                    <>
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label={`Crear incidente: ${f.title}`}
                        title="Crear incidente"
                        onClick={() =>
                          newInc.open({
                            title: `Exposición: ${f.title}`.slice(0, 200),
                            severity:
                              f.severity === 'critical'
                                ? 'Critical'
                                : f.severity === 'high'
                                  ? 'High'
                                  : 'Medium',
                            detected_by: 'Exposición / Shadow IT',
                            assets: f.asset.replace(/^(ip|host):/, ''),
                            summary: `${f.detail}\n\n${f.evidence}`.trim(),
                          })
                        }
                      >
                        <Plus />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label="Marcar corregido"
                        title="Marcar corregido"
                        onClick={() => act(f, 'fixed', 'Marcado como corregido')}
                      >
                        <CheckCircle2 />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label="Aceptar el riesgo"
                        title="Aceptar el riesgo (se esperaba)"
                        onClick={() => act(f, 'accepted', 'Riesgo aceptado')}
                      >
                        <Ban />
                      </Button>
                    </>
                  ) : (
                    <Button
                      size="icon"
                      variant="ghost"
                      aria-label="Reabrir"
                      title="Reabrir"
                      onClick={() => act(f, 'open', 'Reabierto')}
                    >
                      <Undo2 />
                    </Button>
                  )}
                </div>
              </TableCell>
            )}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

// ---------------------------------------------------------------- activos y Shadow IT
function AssetsView({ only }: { only: '' | 'shadow' }) {
  const { canWrite } = useAuth();
  const [draft, setDraft] = useState('');
  const [q, setQ] = useState('');
  const A = useExpAssets({ only, q });
  const set = useExpAssetSet();
  const toPortal = useExpToPortal();
  return (
    <Panel
      title={
        only === 'shadow'
          ? `Shadow IT · ${nf(A.data?.length ?? 0)} activos no inventariados`
          : `Activos · ${nf(A.data?.length ?? 0)}`
      }
      hint={
        only === 'shadow'
          ? 'Subdominios y servidores de ACME que no están en Portales. Añádelos al inventario, márcalos como conocidos o ignóralos.'
          : 'Todo lo descubierto: inventariado, en alcance o visto fuera de él.'
      }
      bodyClassName="px-0 pb-0"
      actions={
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && setQ(draft)}
          placeholder="Dominio o IP… (Enter)"
          className="w-52"
          aria-label="Buscar activos"
        />
      }
    >
      {A.isPending ? (
        <Loading rows={2} />
      ) : A.error ? (
        <ErrorState error={A.error} compact />
      ) : A.data?.length ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Activo</TableHead>
              <TableHead>IP</TableHead>
              <TableHead>Responde</TableHead>
              <TableHead>Puertos</TableHead>
              <TableHead>Origen</TableHead>
              <TableHead>Estado</TableHead>
              {canWrite && <TableHead className="w-10" />}
            </TableRow>
          </TableHeader>
          <TableBody>
            {A.data.map((a) => {
              const web = Object.entries(a.web).find(([, w]) => w.status);
              const hits = Object.values(a.web).flatMap((w) => w.hits ?? []);
              return (
                <TableRow key={a.key}>
                  <TableCell className="max-w-[260px]">
                    <b className="break-all">{a.value}</b>
                    <div className="text-xs text-muted">
                      {a.type === 'host' ? 'subdominio' : 'servidor'}
                      {a.hallazgos > 0 && <b className="text-bad"> · {a.hallazgos} hallazgos</b>}
                      {!!hits.length && <b className="text-bad"> · {hits.map((h) => h.path).join(', ')}</b>}
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{a.ips.slice(0, 3).join(', ') || '—'}</TableCell>
                  <TableCell className="max-w-[220px] text-xs">
                    {web ? (
                      <>
                        <Badge variant="gray">{web[1].status}</Badge> {web[1].title || web[1].server || ''}
                        {web[1].login && <span className="text-warn"> · pide contraseña</span>}
                      </>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </TableCell>
                  <TableCell className="max-w-[160px] font-mono text-xs">
                    {[...new Set([...a.servicios, ...(a.idb.ports ?? [])])].slice(0, 8).join(', ') || '—'}
                    {!!a.idb.vulns?.length && <div className="text-bad">{a.idb.vulns.length} CVE</div>}
                  </TableCell>
                  <TableCell className="text-xs text-muted">{a.sources.join(', ')}</TableCell>
                  <TableCell>
                    {a.inventoried ? (
                      <Badge variant="ok">Inventariado</Badge>
                    ) : a.status === 'conocido' ? (
                      <Badge variant="info">Conocido</Badge>
                    ) : a.status === 'ignorado' ? (
                      <Badge variant="gray">Ignorado</Badge>
                    ) : a.in_scope ? (
                      <Badge variant="warn">No inventariado</Badge>
                    ) : (
                      <Badge variant="gray">Fuera de alcance</Badge>
                    )}
                  </TableCell>
                  {canWrite && (
                    <TableCell>
                      {!a.inventoried && a.in_scope ? (
                        <div className="flex justify-end gap-1">
                          {a.type === 'host' && (
                            <Button
                              size="sm"
                              variant="secondary"
                              disabled={toPortal.isPending}
                              onClick={() =>
                                toPortal.mutate(a.key, {
                                  onSuccess: () => toast.success(`${a.value} añadido a Portales`),
                                  onError: (e) => toast.error(e.message),
                                })
                              }
                            >
                              <Plus /> A Portales
                            </Button>
                          )}
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => set.mutate({ key: a.key, status: 'conocido' })}
                          >
                            Conocido
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => set.mutate({ key: a.key, status: 'ignorado' })}
                          >
                            Ignorar
                          </Button>
                        </div>
                      ) : null}
                    </TableCell>
                  )}
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      ) : (
        <Empty>
          {only === 'shadow'
            ? 'No se encontraron activos sin inventariar (o aún no se ha escaneado).'
            : 'Aún no hay activos: lanza un escaneo.'}
        </Empty>
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------- servicios
function ServicesView() {
  const [draft, setDraft] = useState('');
  const [q, setQ] = useState('');
  const S = useExpServices(q);
  return (
    <Panel
      title={`Servicios expuestos · ${nf(S.data?.length ?? 0)}`}
      bodyClassName="px-0 pb-0"
      actions={
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && setQ(draft)}
          placeholder="IP, puerto o servicio… (Enter)"
          className="w-56"
          aria-label="Buscar servicios"
        />
      }
    >
      {S.isPending ? (
        <Loading rows={2} />
      ) : S.error ? (
        <ErrorState error={S.error} compact />
      ) : S.data?.length ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>IP : puerto</TableHead>
              <TableHead>Servicio</TableHead>
              <TableHead>Banner</TableHead>
              <TableHead>Certificado</TableHead>
              <TableHead>Origen</TableHead>
              <TableHead>Visto</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {S.data.map((s) => (
              <TableRow key={`${s.ip}:${s.port}`}>
                <TableCell className="whitespace-nowrap font-mono text-[13px]">
                  {s.ip}:<b>{s.port}</b>
                </TableCell>
                <TableCell>
                  {s.service || '—'}{' '}
                  {s.riesgo && (
                    <Badge variant={SEV[s.riesgo as ExpSeverity]?.[1] ?? 'gray'}>
                      {SEV[s.riesgo as ExpSeverity]?.[0]}
                    </Badge>
                  )}
                </TableCell>
                <TableCell
                  className="max-w-[260px] truncate font-mono text-[11.5px] text-muted"
                  title={s.banner}
                >
                  {s.banner || '—'}
                </TableCell>
                <TableCell className="text-xs">
                  {s.tls.expiry ? (
                    <span className={cn((s.tls.expired || (s.tls.days ?? 99) <= 30) && 'text-bad')}>
                      {s.tls.expired ? 'caducado' : `${s.tls.days} d`} {s.tls.self_signed && '· autofirmado'}
                    </span>
                  ) : (
                    '—'
                  )}
                </TableCell>
                <TableCell className="text-xs text-muted">{s.source}</TableCell>
                <TableCell className="whitespace-nowrap text-xs text-muted">
                  {s.last_seen.slice(5, 16)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : (
        <Empty>Aún no hay servicios: lanza un escaneo.</Empty>
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------- escaneos
function JobsView() {
  const J = useExpJobs();
  const ST: Record<string, ['ok' | 'bad' | 'warn' | 'gray' | 'info', string]> = {
    running: ['info', 'En curso'],
    done: ['ok', 'Terminado'],
    failed: ['bad', 'Error'],
    cancelled: ['gray', 'Cancelado'],
  };
  return (
    <Panel title="Historial de escaneos" bodyClassName="px-0 pb-0">
      {J.data?.items.length ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>#</TableHead>
              <TableHead>Inicio</TableHead>
              <TableHead>Tipo</TableHead>
              <TableHead>Lanzado por</TableHead>
              <TableHead>Estado</TableHead>
              <TableHead>Resultado</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {J.data.items.map((j) => (
              <TableRow key={j.id}>
                <TableCell className="text-muted">{j.id}</TableCell>
                <TableCell className="whitespace-nowrap text-[13px]">{j.at.slice(0, 16)}</TableCell>
                <TableCell>
                  <Badge variant={j.kind === 'completo' ? 'warn' : 'gray'}>
                    {j.kind === 'completo' ? 'Activo' : 'Pasivo'}
                  </Badge>
                </TableCell>
                <TableCell className="text-[13px]">{j.by}</TableCell>
                <TableCell>
                  <Badge variant={ST[j.status]?.[0] ?? 'gray'}>{ST[j.status]?.[1] ?? j.status}</Badge>
                  {j.status === 'running' && <div className="text-xs text-muted">{j.phase}</div>}
                </TableCell>
                <TableCell className="max-w-[420px] text-xs text-muted">
                  {j.msg}
                  {j.finished && <div>terminó {j.finished.slice(5, 16)}</div>}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : (
        <Empty>Todavía no se ha lanzado ningún escaneo.</Empty>
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------- alcance y autorización (solo administradores)
function ScopeView() {
  const C = useExpConfig();
  if (C.isPending) return <Loading rows={2} />;
  if (C.error || !C.data) return <ErrorState error={C.error} onRetry={() => void C.refetch()} />;
  return <ScopeForm key={JSON.stringify(C.data)} c={C.data} />;
}

function ScopeForm({ c }: { c: ExpConfig }) {
  const { isAdmin } = useAuth();
  const save = useExpSaveConfig();
  const [dom, setDom] = useState(c.dominios.join('\n'));
  const [ran, setRan] = useState(c.rangos.join('\n'));
  const [exc, setExc] = useState(c.excluidos.join('\n'));
  const [perfil, setPerfil] = useState(c.perfil);
  const [vel, setVel] = useState(c.velocidad);
  const [conc, setConc] = useState(c.concurrencia);
  const [rutas, setRutas] = useState(c.rutas_web);
  const [prog, setProg] = useState(c.programado_dias);
  const [por, setPor] = useState(c.autorizacion.por);
  const [ref, setRef] = useState(c.autorizacion.referencia);
  const [hasta, setHasta] = useState(c.autorizacion.hasta);
  const lines = (t: string) =>
    t
      .split(/[\s,;]+/)
      .map((x) => x.trim())
      .filter(Boolean);
  const submit = () =>
    save.mutate(
      {
        dominios: lines(dom),
        rangos: lines(ran),
        excluidos: lines(exc),
        perfil,
        velocidad: vel,
        concurrencia: conc,
        rutas_web: rutas,
        programado_dias: prog,
        autorizacion: { por, referencia: ref, hasta, registrado_por: '', registrado_at: '' },
      },
      { onSuccess: () => toast.success('Alcance guardado'), onError: (e) => toast.error(e.message) },
    );
  const ro = !isAdmin;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel title="Qué es de ACME" hint="Solo se escanea lo que está aquí; nunca fuera de los rangos.">
        <fieldset disabled={ro} className="space-y-3">
          <div>
            <Label htmlFor="sc-d">Dominios raíz (uno por línea)</Label>
            <Textarea
              id="sc-d"
              rows={4}
              value={dom}
              onChange={(e) => setDom(e.target.value)}
              placeholder={'acme.example\nmunicipios.example'}
              className="font-mono text-[12.5px]"
            />
            <p className="mt-1 text-xs text-muted">
              Se buscan sus subdominios en los certificados públicos (crt.sh).
            </p>
          </div>
          <div>
            <Label htmlFor="sc-r">Rangos de IP públicas (CIDR)</Label>
            <Textarea
              id="sc-r"
              rows={3}
              value={ran}
              onChange={(e) => setRan(e.target.value)}
              placeholder={'5.180.20.0/23'}
              className="font-mono text-[12.5px]"
            />
            <p className="mt-1 text-xs text-muted">
              Máximo {nf(c.max_ips)} direcciones en total. No se admiten rangos privados.
            </p>
          </div>
          <div>
            <Label htmlFor="sc-e">Excluir (IP o rangos que no se deben tocar)</Label>
            <Textarea
              id="sc-e"
              rows={2}
              value={exc}
              onChange={(e) => setExc(e.target.value)}
              placeholder={'5.180.20.1/32'}
              className="font-mono text-[12.5px]"
            />
          </div>
        </fieldset>
      </Panel>
      <div className="space-y-4">
        <Panel
          title="Autorización del escaneo activo"
          hint="Obligatoria: sin ella solo se permite el descubrimiento pasivo."
        >
          <fieldset disabled={ro} className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label htmlFor="sc-p">Autorizado por</Label>
              <Input
                id="sc-p"
                value={por}
                onChange={(e) => setPor(e.target.value)}
                placeholder="Director de Seguridad TIC"
              />
            </div>
            <div>
              <Label htmlFor="sc-h">Vigente hasta</Label>
              <Input id="sc-h" type="date" value={hasta} onChange={(e) => setHasta(e.target.value)} />
            </div>
            <div className="sm:col-span-2">
              <Label htmlFor="sc-ref">Referencia del documento</Label>
              <Input
                id="sc-ref"
                value={ref}
                onChange={(e) => setRef(e.target.value)}
                placeholder="Memo ACME-SEG-2026-114"
              />
            </div>
            {c.autorizacion.registrado_por && (
              <p className="text-xs text-muted sm:col-span-2">
                Registrada por {c.autorizacion.registrado_por} el {c.autorizacion.registrado_at}.
              </p>
            )}
          </fieldset>
        </Panel>
        <Panel title="Cómo escanear">
          <fieldset disabled={ro} className="grid gap-3 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <Label htmlFor="sc-pf">Perfil de puertos</Label>
              <Select
                id="sc-pf"
                value={perfil}
                onChange={(e) => setPerfil(e.target.value as ExpConfig['perfil'])}
              >
                {Object.entries(PERFIL).map(([k, l]) => (
                  <option key={k} value={k}>
                    {l}
                  </option>
                ))}
              </Select>
            </div>
            <div>
              <Label htmlFor="sc-v">Conexiones por segundo</Label>
              <Input
                id="sc-v"
                type="number"
                min={10}
                max={5000}
                value={vel}
                onChange={(e) => setVel(Number(e.target.value))}
              />
            </div>
            <div>
              <Label htmlFor="sc-c">Simultáneas</Label>
              <Input
                id="sc-c"
                type="number"
                min={10}
                max={2000}
                value={conc}
                onChange={(e) => setConc(Number(e.target.value))}
              />
            </div>
            <div>
              <Label htmlFor="sc-pr">Repetir cada (días, 0 = manual)</Label>
              <Input
                id="sc-pr"
                type="number"
                min={0}
                max={90}
                value={prog}
                onChange={(e) => setProg(Number(e.target.value))}
              />
            </div>
            <label className="flex items-end gap-2 pb-2 text-[13.5px]">
              <Checkbox checked={rutas} onCheckedChange={(v) => setRutas(v === true)} /> Probar rutas
              sensibles (/.git, /.env…)
            </label>
            {perfil === 'completo' && (
              <p className="flex gap-2 rounded-lg border border-st-warn/40 bg-st-warn/10 p-2 text-xs sm:col-span-2">
                <ShieldAlert className="size-4 shrink-0 text-warn" />
                Perfil completo: con {nf(vel)} conexiones/s, un /23 tarda unas{' '}
                {Math.ceil((512 * 65535) / vel / 3600)} h. Avisa al equipo de red y al proveedor: el firewall
                y el WAF lo verán como un escaneo.
              </p>
            )}
          </fieldset>
        </Panel>
        {isAdmin ? (
          <div className="flex justify-end">
            <Button disabled={save.isPending} onClick={submit}>
              Guardar alcance
            </Button>
          </div>
        ) : (
          <p className="text-right text-xs text-muted">Solo un administrador puede cambiar el alcance.</p>
        )}
      </div>
    </div>
  );
}
