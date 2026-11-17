import { PenteraImport } from './PenteraImport';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Download, Plus, X } from 'lucide-react';
import { toast } from 'sonner';
import { usePageEnter } from '@/components/layout/AppShell';
import { Donut } from '@/components/charts';
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
  SevPill,
} from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Input, Select, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import { useSearchParam } from '@/hooks/useSearchParam';
import { SEVERITIES, SEV_COLOR, SEV_LABEL, VULN_STATUS_LABEL, type Severity } from '@/lib/constants';
import { csvDownload, fdt, nf, short } from '@/lib/format';
import { cn } from '@/lib/utils';
import { useImportScan, useTrackCve, useVulns, useWazuhVulnHosts, useWazuhVulns } from '@/services/vulns';
import { VulnDialog } from './VulnDialog';
import type { Vuln } from '@/types/api';

const normSev = (v: string): Severity =>
  (({ critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }) as Record<string, Severity>)[
    String(v).toLowerCase()
  ] ?? (v as Severity);
const Nvd = ({ c }: { c: string }) =>
  c ? (
    <>
      {c.split(/,\s*/).map((x) => (
        <a
          key={x}
          className="mono text-brand hover:underline"
          target="_blank"
          rel="noopener noreferrer"
          href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(x)}`}
        >
          {x}
        </a>
      ))}
    </>
  ) : null;
const VST_VARIANT: Record<string, 'bad' | 'warn' | 'info' | 'gray' | 'ok'> = {
  Open: 'bad',
  Remediating: 'warn',
  Mitigated: 'info',
  Accepted: 'gray',
  Closed: 'ok',
};

export default function VulnsPage() {
  const ref = usePageEnter('vulns');
  const { canWrite } = useAuth();
  const [view, setView] = useSearchParam('view', 'wazuh');
  const [editing, setEditing] = useState<{ open: boolean; v: Vuln | null }>({ open: false, v: null });
  useEffect(() => {
    document.title = 'Portal SOC · Vulnerabilidades';
  }, []);
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Vulnerabilidades"
        subtitle="Detección automática de Wazuh, resultados de escáneres y registro manual, con seguimiento hasta su cierre."
        actions={
          <>
            <Chips
              options={[
                ['wazuh', 'Detectadas por Wazuh'],
                ['track', 'Seguimiento'],
                ['import', 'Importar escáner'],
                ['pentera', 'Pentera'],
              ]}
              value={view}
              onChange={setView}
            />
            {canWrite && (
              <Button size="sm" onClick={() => setEditing({ open: true, v: null })}>
                <Plus /> Registrar
              </Button>
            )}
          </>
        }
      />
      {view === 'track' ? (
        <TrackView onEdit={(v) => setEditing({ open: true, v })} />
      ) : view === 'import' ? (
        <ImportView />
      ) : view === 'pentera' ? (
        <PenteraImport />
      ) : (
        <WazuhView />
      )}
      <VulnDialog
        vuln={editing.v}
        open={editing.open}
        onClose={(saved) => {
          setEditing({ open: false, v: null });
          if (saved && view !== 'track') setView('track');
        }}
      />
    </div>
  );
}

function WazuhView() {
  const [severity, setSeverity] = useSearchParam('severity', '');
  const [agent, setAgent] = useSearchParam('agent', '');
  const [q, setQ] = useSearchParam('q', '');
  const [draft, setDraft] = useState(q);
  const [hosts, setHosts] = useState('');
  const { canWrite } = useAuth();
  const d = useWazuhVulns({ severity, agent, q });
  const track = useTrackCve();
  const doTrack = async (cve: string, sev?: string) => {
    try {
      const r = await track.mutateAsync({ cve, severity: sev });
      setHosts('');
      toast.success(
        r.nuevo ? `${cve} en seguimiento` : `${cve} ya estaba en seguimiento; equipos actualizados`,
      );
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  };
  if (d.isPending) return <Loading />;
  if (d.error || !d.data)
    return (
      <>
        <ErrorState error={d.error} onRetry={() => void d.refetch()} />
        <p className="text-center text-[13px] text-muted">
          Si dice 403, el rol <span className="mono">soc_bridge_read</span> del indexer necesita lectura sobre{' '}
          <span className="mono">wazuh-states-vulnerabilities-*</span>.
        </p>
      </>
    );
  const x = d.data;
  const S = Object.fromEntries(x.severidad.map(([k, n]) => [normSev(k), n])) as Partial<
    Record<Severity, number>
  >;
  return (
    <>
      <KpiGrid data-enter="">
        <Kpi
          title="Detecciones"
          value={short(x.total)}
          hint={x.fuente === 'states' ? 'inventario actual de Wazuh' : 'alertas de los últimos 30 días'}
        />
        <Kpi title="CVE distintos" value={nf(x.cves_n)} />
        <Kpi title="Equipos afectados" value={nf(x.agentes_n)} />
        <Kpi
          title="Críticas"
          value={nf(S.Critical)}
          hint="detecciones"
          onClick={() => setSeverity('Critical')}
          alert={(S.Critical ?? 0) > 0}
        />
        <Kpi title="Altas" value={nf(S.High)} hint="detecciones" onClick={() => setSeverity('High')} />
      </KpiGrid>
      <div className="flex flex-wrap items-center gap-2">
        <Chips
          options={[
            ['', 'Todas'],
            ['Critical', 'Críticas'],
            ['High', 'Altas'],
            ['Medium', 'Medias'],
            ['Low', 'Bajas'],
          ]}
          value={severity}
          onChange={setSeverity}
        />
        {agent && (
          <Badge variant="info">
            Equipo: {agent}{' '}
            <button type="button" onClick={() => setAgent('')} aria-label="Quitar filtro">
              <X className="size-3" />
            </button>
          </Badge>
        )}
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && setQ(draft)}
          placeholder="Buscar CVE o paquete… (Enter)"
          className="min-w-[200px] flex-1"
          aria-label="Buscar"
        />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Por severidad">
          <Donut
            center="detecciones"
            items={SEVERITIES.map((k) => ({
              label: SEV_LABEL[k],
              value: S[k] ?? 0,
              color: SEV_COLOR[k],
              onClick: () => setSeverity(k),
            }))}
          />
        </Panel>
        <Panel title="Equipos con más vulnerabilidades" hint="pulsa para filtrar">
          <HBars
            rows={x.agentes.map(([k, n]) => ({ key: k, label: k, value: n, onClick: () => setAgent(k) }))}
          />
        </Panel>
        <Panel title="Paquetes más afectados">
          <HBars
            rows={x.paquetes.map(([k, n]) => ({
              key: k,
              label: k,
              value: n,
              onClick: () => {
                setDraft(k);
                setQ(k);
              },
            }))}
          />
        </Panel>
      </div>
      <Panel title="CVE con mayor puntuación" hint="se muestran los 60 primeros" bodyClassName="px-0 pb-0">
        <div className="max-h-[620px] overflow-auto scroll-thin">
          {x.cves.length ? (
            <Table>
              <TableHeader className="sticky top-0 bg-card">
                <TableRow>
                  <TableHead>CVE</TableHead>
                  <TableHead>Severidad</TableHead>
                  <TableHead className="text-right">CVSS</TableHead>
                  <TableHead>Paquete</TableHead>
                  <TableHead className="text-right">Equipos</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {x.cves.map((c) => (
                  <TableRow key={c.cve}>
                    <TableCell>
                      <Nvd c={c.cve} />
                    </TableCell>
                    <TableCell>
                      <SevPill v={normSev(c.sev)} />
                    </TableCell>
                    <TableCell className="text-right">
                      {c.score != null ? Number(c.score).toFixed(1) : '—'}
                    </TableCell>
                    <TableCell>{c.paquetes.join(', ')}</TableCell>
                    <TableCell className="text-right font-bold">{nf(c.agentes)}</TableCell>
                    <TableCell className="whitespace-nowrap text-right">
                      <Button variant="secondary" size="sm" onClick={() => setHosts(c.cve)}>
                        Equipos
                      </Button>
                      {canWrite && (
                        <Button size="sm" className="ml-1" onClick={() => doTrack(c.cve, normSev(c.sev))}>
                          Seguir
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <Empty>Sin vulnerabilidades con estos filtros.</Empty>
          )}
        </div>
      </Panel>
      <p className="text-xs text-muted">
        <b>Seguir</b> crea un registro en Seguimiento con todos los equipos afectados y fecha límite según la
        severidad.
      </p>
      <HostsDialog
        cve={hosts}
        onClose={() => setHosts('')}
        onTrack={canWrite ? (cve) => doTrack(cve) : undefined}
      />
    </>
  );
}

function HostsDialog({
  cve,
  onClose,
  onTrack,
}: {
  cve: string;
  onClose: () => void;
  onTrack?: (cve: string) => void;
}) {
  const q = useWazuhVulnHosts(cve);
  return (
    <Dialog open={!!cve} onOpenChange={(o) => !o && onClose()}>
      <DialogContent wide title={`${cve} · equipos afectados`}>
        {q.isPending ? (
          <Loading rows={1} />
        ) : q.error ? (
          <ErrorState error={q.error} compact />
        ) : (
          <>
            {q.data[0]?.description && (
              <p className="mb-3 text-[13px] text-muted">{q.data[0].description.slice(0, 600)}</p>
            )}
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Equipo</TableHead>
                  <TableHead>Paquete</TableHead>
                  <TableHead>Versión</TableHead>
                  <TableHead>Severidad</TableHead>
                  <TableHead>Detectado</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {q.data.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <b>{r.agent}</b> <span className="mono text-muted">{r.agent_id}</span>
                    </TableCell>
                    <TableCell>{r.package}</TableCell>
                    <TableCell className="mono">{r.version}</TableCell>
                    <TableCell>
                      <SevPill v={normSev(r.severity)} />
                    </TableCell>
                    <TableCell>{fdt(r.date)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {onTrack && (
              <div className="mt-3 text-right">
                <Button onClick={() => onTrack(cve)}>Pasar a seguimiento</Button>
              </div>
            )}
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function TrackView({ onEdit }: { onEdit: (v: Vuln) => void }) {
  const [status, setStatus] = useSearchParam('status', 'active');
  const [severity, setSeverity] = useSearchParam('severity', '');
  const [source, setSource] = useSearchParam('source', '');
  const [q, setQ] = useSearchParam('q', '');
  const [draft, setDraft] = useState(q);
  const d = useVulns({ status, severity, source, q });
  if (d.isPending) return <Loading />;
  if (d.error || !d.data) return <ErrorState error={d.error} onRetry={() => void d.refetch()} />;
  const { rows, stats: S, today } = d.data;
  return (
    <>
      <KpiGrid data-enter="">
        <Kpi title="Abiertas" value={nf(S.activas)} hint={`${nf(S.total)} registradas en total`} />
        <Kpi
          title="Fecha límite vencida"
          value={nf(S.vencidas)}
          hint="sin remediar a tiempo"
          alert={S.vencidas > 0}
        />
        {S.por_severidad.map(([k, n]) => (
          <Kpi
            key={k}
            title={`${SEV_LABEL[k as Severity] ?? k}s abiertas`}
            value={nf(n)}
            hint={`plazo ${S.sla_dias[k as Severity]} días`}
            onClick={() => setSeverity(k)}
            alert={k === 'Critical' && n > 0}
          />
        ))}
      </KpiGrid>
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Por estado">
          <HBars
            rows={S.por_estado.map(([k, n]) => ({
              key: k,
              label: VULN_STATUS_LABEL[k] ?? k,
              value: n,
              onClick: () => setStatus(k),
            }))}
          />
        </Panel>
        <Panel title="Por origen">
          <HBars
            rows={S.por_origen.map(([k, n]) => ({ key: k, label: k, value: n, onClick: () => setSource(k) }))}
            empty="Aún no hay registros"
          />
        </Panel>
        <Panel title="Plazos de remediación">
          <ul className="space-y-1.5 text-[13.5px]">
            {(Object.entries(S.sla_dias) as [Severity, number][]).map(([k, n]) => (
              <li key={k} className="flex items-center justify-between">
                <SevPill v={k} />
                <b>{n} días</b>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-muted">
            Se calculan al registrar. Se cambian en <span className="mono">store.py</span> (VULN_SLA_DAYS).
          </p>
        </Panel>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="w-auto"
          aria-label="Estado"
        >
          <option value="active">Activas (abiertas o en remediación)</option>
          <option value="">Todas</option>
          {Object.entries(VULN_STATUS_LABEL).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </Select>
        <Select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="w-auto"
          aria-label="Severidad"
        >
          <option value="">Todas las severidades</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEV_LABEL[s]}
            </option>
          ))}
        </Select>
        {source && (
          <Badge variant="info">
            Origen: {source}{' '}
            <button type="button" onClick={() => setSource('')} aria-label="Quitar filtro">
              <X className="size-3" />
            </button>
          </Badge>
        )}
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && setQ(draft)}
          placeholder="Buscar CVE, título, activo o paquete… (Enter)"
          className="min-w-[200px] flex-1"
          aria-label="Buscar"
        />
        <Button
          variant="secondary"
          onClick={() =>
            csvDownload('vulnerabilidades.csv', rows as unknown as Record<string, unknown>[], [
              'cve',
              'title',
              'severity',
              'cvss',
              'asset',
              'package',
              'port',
              'status',
              'owner',
              'due_date',
              'source',
              'first_seen',
              'last_seen',
            ])
          }
        >
          <Download /> Exportar CSV
        </Button>
      </div>
      <Panel title="" className="[&>div:first-child]:hidden" bodyClassName="px-0 pb-0">
        {rows.length ? (
          <div className="max-h-[640px] overflow-auto scroll-thin">
            <Table>
              <TableHeader className="sticky top-0 bg-card">
                <TableRow>
                  <TableHead>Vulnerabilidad</TableHead>
                  <TableHead>Severidad</TableHead>
                  <TableHead>Activo</TableHead>
                  <TableHead>Estado</TableHead>
                  <TableHead>Responsable</TableHead>
                  <TableHead>Fecha límite</TableHead>
                  <TableHead>Origen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => {
                  const late =
                    !!r.due_date && r.due_date < today && ['Open', 'Remediating'].includes(r.status);
                  return (
                    <TableRow key={r.id} clickable onClick={() => onEdit(r)}>
                      <TableCell>
                        <b>{r.title}</b>
                        <div className="text-xs">
                          <Nvd c={r.cve} />{' '}
                          {r.cvss != null && (
                            <span className="text-muted">CVSS {Number(r.cvss).toFixed(1)}</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <SevPill v={r.severity} />
                      </TableCell>
                      <TableCell className="max-w-[240px] truncate" title={r.asset}>
                        {r.asset}
                        {r.port && <span className="text-muted">:{r.port}</span>}
                      </TableCell>
                      <TableCell>
                        <Badge variant={VST_VARIANT[r.status] ?? 'gray'}>
                          {VULN_STATUS_LABEL[r.status] ?? r.status}
                        </Badge>
                      </TableCell>
                      <TableCell>{r.owner || <span className="text-muted">—</span>}</TableCell>
                      <TableCell className={cn('whitespace-nowrap', late && 'font-bold text-bad')}>
                        {r.due_date || '—'}
                        {late && ' ⚠'}
                      </TableCell>
                      <TableCell>
                        <Badge variant="gray">{r.source}</Badge>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        ) : (
          <Empty>
            No hay vulnerabilidades con estos filtros. Puedes pasarlas desde{' '}
            <Link className="text-brand" to="/vulns?view=wazuh">
              Wazuh
            </Link>
            ,{' '}
            <Link className="text-brand" to="/vulns?view=import">
              importar un escáner
            </Link>{' '}
            o registrarlas a mano.
          </Empty>
        )}
      </Panel>
    </>
  );
}

function ImportView() {
  const [scanner, setScanner] = useState('nessus');
  const [text, setText] = useState('');
  const imp = useImportScan();
  const run = (preview: boolean) => {
    if (!text.trim()) return toast.error('Pega o selecciona un CSV');
    imp.mutate({ text, scanner, preview });
  };
  const onFile = (f: File | undefined) => {
    if (!f) return;
    if (f.size > 15e6) return toast.error('Archivo demasiado grande (máx. 15 MB)');
    const r = new FileReader();
    r.onload = () => {
      setText(String(r.result));
      toast.success(`${f.name} cargado`);
    };
    r.readAsText(f);
  };
  const r = imp.data;
  return (
    <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
      <Panel title="Importar resultados de un escáner">
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="scn">Escáner</Label>
            <Select id="scn" value={scanner} onChange={(e) => setScanner(e.target.value)}>
              <option value="nessus">Nessus / Tenable</option>
              <option value="openvas">OpenVAS / Greenbone</option>
              <option value="qualys">Qualys</option>
              <option value="pentest">Pentest / informe</option>
              <option value="csv">Otro CSV</option>
            </Select>
          </div>
          <div>
            <Label htmlFor="scf">Archivo CSV</Label>
            <Input
              id="scf"
              type="file"
              accept=".csv,.txt"
              className="pt-1.5"
              onChange={(e) => onFile(e.target.files?.[0])}
            />
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="sct">…o pega el contenido</Label>
            <Textarea
              id="sct"
              value={text}
              onChange={(e) => setText(e.target.value)}
              className="min-h-[220px] font-mono text-[12px]"
              placeholder={'Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Solution\n...'}
            />
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 sm:col-span-2">
            <span className="text-xs text-muted">
              Se omiten los hallazgos informativos. Reimportar el mismo escaneo actualiza en lugar de
              duplicar.
            </span>
            <span className="flex gap-2">
              <Button variant="secondary" onClick={() => run(true)} disabled={imp.isPending}>
                Vista previa
              </Button>
              <Button onClick={() => run(false)} disabled={imp.isPending}>
                Importar
              </Button>
            </span>
          </div>
        </div>
        {imp.error && (
          <div className="mt-3">
            <ErrorState error={imp.error} compact />
          </div>
        )}
        {r && r.muestra && (
          <div className="mt-4 text-[13.5px]">
            <b>{nf(r.total ?? 0)}</b> vulnerabilidades a importar · {nf(r.omitidos)} omitidas (informativas)
            <div className="my-1.5 flex flex-wrap gap-1 text-xs">
              {Object.entries(r.columnas ?? {}).map(([k, c]) => (
                <Badge key={k} variant="gray">
                  {k} ← {c}
                </Badge>
              ))}
            </div>
            <Table>
              <TableBody>
                {r.muestra.map((x, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <SevPill v={x.severity ?? 'Medium'} />
                    </TableCell>
                    <TableCell>
                      {x.title} <Nvd c={x.cve ?? ''} />
                    </TableCell>
                    <TableCell>
                      {x.asset}
                      {x.port ? `:${x.port}` : ''}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        {r && r.nuevas != null && (
          <div className="mt-4 rounded-xl bg-st-good/10 p-4 text-[13.5px]">
            <b>Importación completada:</b> {nf(r.nuevas)} nuevas · {nf(r.actualizadas ?? 0)} actualizadas ·{' '}
            {nf(r.omitidos)} omitidas.{' '}
            <Link className="text-brand" to="/vulns?view=track">
              Ver seguimiento →
            </Link>
          </div>
        )}
      </Panel>
      <Panel title="Cómo exportar el CSV">
        <div className="space-y-2 text-[13.5px] leading-relaxed">
          <p>
            <b>Nessus:</b> abre el escaneo → <i>Report</i> → <i>CSV</i> → marca todas las columnas.
          </p>
          <p>
            <b>OpenVAS / Greenbone:</b> <i>Scans → Reports</i> → abre el informe → descarga con el formato{' '}
            <i>CSV Results</i>.
          </p>
          <p>
            <b>Qualys:</b> <i>Reports</i> → <i>Scan report</i> → formato CSV.
          </p>
          <p>
            <b>Otro / pentest:</b> un CSV con cabeceras como{' '}
            <span className="mono">title, cve, severity, cvss, host, port, solution</span> (también en
            español).
          </p>
          <p className="text-muted">
            El estado, el responsable y las notas que pongas en el portal se conservan al reimportar.
          </p>
        </div>
      </Panel>
    </div>
  );
}
