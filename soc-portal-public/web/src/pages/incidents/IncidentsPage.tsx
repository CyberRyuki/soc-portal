import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  CheckCircle2,
  Download,
  LayoutGrid,
  List,
  MoreHorizontal,
  Plus,
  RotateCcw,
  Trash2,
  X,
} from 'lucide-react';
import { usePageEnter } from '@/components/layout/AppShell';
import { Lines } from '@/components/charts';
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
  StatusPill,
} from '@/components/shared';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input, Select } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import { useSearchParam } from '@/hooks/useSearchParam';
import { useIncidents, useMetrics, useMoveIncident } from '@/services/incidents';
import { CloseIncidentDialog, DeleteIncidentDialog, type Target } from './IncidentActions';
import { toast } from 'sonner';
import type { Incident } from '@/types/api';
import { useNewIncident } from './NewIncidentDialog';
import { KanbanBoard } from './KanbanBoard';
import { SuggestionsPanel } from './SuggestionsPanel';
import { SEVERITIES, SEV_COLOR, SEV_LABEL, STATUSES, STATUS_LABEL, type Severity } from '@/lib/constants';
import { dur, nf } from '@/lib/format';

export default function IncidentsPage() {
  const ref = usePageEnter('incidents');
  const nav = useNavigate();
  const { meta, canWrite, isAdmin } = useAuth();
  const newInc = useNewIncident();
  const move = useMoveIncident();
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [closing, setClosing] = useState<Target[]>([]);
  const [deleting, setDeleting] = useState<Target[]>([]);
  const [status, setStatus] = useSearchParam('status', 'active');
  const [severity, setSeverity] = useSearchParam('severity', '');
  const [q, setQ] = useSearchParam('q', '');
  const [view, setView] = useSearchParam('view', localStorage.getItem('soc-incview') ?? 'list');
  const [text, setText] = useState(q);
  const board = view === 'board';
  useEffect(() => {
    document.title = 'Portal SOC · Incidentes';
  }, []);
  useEffect(() => {
    try {
      localStorage.setItem('soc-incview', view);
    } catch {
      /* ignorar */
    }
  }, [view]);
  const list = useIncidents({ status: board ? '' : status, severity, q });
  const M = useMetrics();
  const rbTitle = (s: string) => meta?.runbooks.find((r) => r.slug === s)?.title ?? s;
  if (M.isPending || list.isPending) return <Loading rows={3} />;
  if (M.error || !M.data) return <ErrorState error={M.error} onRetry={() => void M.refetch()} />;
  const m = M.data;
  const rows = list.data ?? [];
  const visible = new Set(rows.map((r) => r.code));
  const picked = rows.filter((r) => sel.has(r.code));
  const toggle = (code: string, on: boolean) =>
    setSel((p) => {
      const n = new Set([...p].filter((c) => visible.has(c)));
      if (on) n.add(code);
      else n.delete(code);
      return n;
    });
  const allOn = rows.length > 0 && picked.length === rows.length;
  const clear = () => setSel(new Set());
  const reopen = async (x: Incident) => {
    try {
      await move.mutateAsync({ code: x.code, status: 'Investigating' });
      toast.success(`${x.code} reabierto`);
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  };
  const critOpen = m.por_severidad.find((x) => x[0] === 'Critical')?.[1] ?? 0;
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Incidentes"
        subtitle={`Registro, métricas de respuesta y SLA. Primera respuesta: Crítica ${m.sla.Critical} min · Alta ${m.sla.High} min · Media ${m.sla.Medium / 60} h · Baja ${m.sla.Low / 60} h.`}
      />
      <SuggestionsPanel />
      <KpiGrid data-enter="">
        <Kpi
          title="Abiertos"
          value={nf(m.por_severidad.reduce((a, [, v]) => a + v, 0))}
          hint={`${nf(m.total)} en total`}
        />
        <Kpi
          title="Críticos abiertos"
          value={nf(critOpen)}
          onClick={() => setSeverity('Critical')}
          alert={critOpen > 0}
        />
        <Kpi
          title="MTTA (mediana)"
          value={dur(m.mtta_min)}
          hint={`tiempo a primera respuesta · ${m.n_tta} casos`}
        />
        <Kpi
          title="MTTR (mediana)"
          value={dur(m.mttr_min)}
          hint={`tiempo hasta el cierre · ${m.n_ttr} casos`}
        />
        <Kpi
          title="SLA vencidos"
          value={nf(m.vencidos.length)}
          hint="abiertos sin respuesta a tiempo"
          alert={m.vencidos.length > 0}
        />
      </KpiGrid>
      <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
        <Panel title="Creados y cerrados por día" hint="últimos 30 días">
          <Lines
            labels={m.dias}
            series={[
              { name: 'Creados', color: 'var(--s1)', values: m.creados },
              { name: 'Cerrados', color: 'var(--s2)', values: m.cerrados },
            ]}
            h={300}
          />
        </Panel>
        <div className="grid gap-4">
          <Panel title="Abiertos por severidad">
            <HBars
              empty="Sin incidentes abiertos"
              rows={m.por_severidad.map(([k, v]) => ({
                key: k,
                label: SEV_LABEL[k as Severity] ?? k,
                value: v,
                color: SEV_COLOR[k as Severity],
                onClick: () => setSeverity(k),
              }))}
            />
          </Panel>
          <Panel title="Por runbook">
            <HBars
              empty="Ningún incidente vinculado a runbook"
              max={5}
              rows={m.por_runbook.map(([k, v]) => ({
                key: k,
                label: rbTitle(k),
                value: v,
                onClick: () => nav(`/runbooks/${k}`),
              }))}
            />
          </Panel>
        </div>
      </div>
      {m.vencidos.length > 0 && (
        <Panel
          title={<span className="text-bad">⚠ SLA de primera respuesta vencido</span>}
          className="border-bad/50"
          bodyClassName="px-2 pb-2"
        >
          <Table>
            <TableBody>
              {m.vencidos.map((v) => (
                <TableRow key={v.code} clickable onClick={() => nav(`/incidents/${v.code}`)}>
                  <TableCell className="font-bold">{v.code}</TableCell>
                  <TableCell>{v.title}</TableCell>
                  <TableCell>
                    <SevPill v={v.severity} />
                  </TableCell>
                  <TableCell>{v.owner || 'sin responsable'}</TableCell>
                  <TableCell className="text-right font-bold text-bad">
                    {dur(v.edad_min)} <span className="font-normal text-muted">/ SLA {dur(v.sla_min)}</span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-base font-bold">{board ? 'Tablero' : 'Listado'}</h2>
        <Chips
          options={[
            [
              'list',
              <>
                <List className="size-3.5" /> Lista
              </>,
            ],
            [
              'board',
              <>
                <LayoutGrid className="size-3.5" /> Tablero
              </>,
            ],
          ]}
          value={view}
          onChange={setView}
        />
        <span className="text-xs text-muted">
          {board
            ? 'arrastra una tarjeta para cambiar su estado · clic para abrirla'
            : `${rows.length} mostrados`}
        </span>
        <span className="flex-1" />
        {!board && (
          <Select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="w-auto"
            aria-label="Estado"
          >
            <option value="active">Activos (no cerrados)</option>
            <option value="">Todos</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {STATUS_LABEL[s]}
              </option>
            ))}
          </Select>
        )}
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
        <Input
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && setQ(text)}
          placeholder="Buscar código, título, activo o IoC… (Enter)"
          className="w-72"
          aria-label="Buscar"
        />
        {canWrite && (
          <Button onClick={() => newInc.open()}>
            <Plus /> Nuevo incidente
          </Button>
        )}
        <Button variant="secondary" asChild>
          <a href="/portal/api/export">
            <Download /> Exportar
          </a>
        </Button>
      </div>
      <CloseIncidentDialog targets={closing} onOpenChange={(o) => !o && setClosing([])} onDone={clear} />
      <DeleteIncidentDialog targets={deleting} onOpenChange={(o) => !o && setDeleting([])} onDone={clear} />
      {!board && picked.length > 0 && (
        <div
          role="toolbar"
          aria-label="Acciones sobre la selección"
          className="glass sticky top-2 z-10 flex flex-wrap items-center gap-2 rounded-xl px-3 py-2"
        >
          <b className="text-[13px]">{picked.length} seleccionados</b>
          <span className="flex-1" />
          <Button
            size="sm"
            variant="secondary"
            onClick={() => setClosing(picked.filter((x) => x.status !== 'Closed'))}
            disabled={!picked.some((x) => x.status !== 'Closed')}
          >
            <CheckCircle2 /> Cerrar
          </Button>
          {isAdmin && (
            <Button size="sm" variant="destructive" onClick={() => setDeleting(picked)}>
              <Trash2 /> Eliminar
            </Button>
          )}
          <Button size="sm" variant="ghost" onClick={clear} aria-label="Quitar selección">
            <X />
          </Button>
        </div>
      )}
      {list.error ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : board ? (
        <KanbanBoard rows={rows} open={m.abiertos} />
      ) : (
        <Panel title="" bodyClassName="px-0 pb-0" className="[&>div:first-child]:hidden">
          {rows.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  {canWrite && (
                    <TableHead className="w-8">
                      <Checkbox
                        aria-label="Seleccionar todos"
                        checked={allOn ? true : picked.length ? 'indeterminate' : false}
                        onCheckedChange={(v) =>
                          setSel(v === true ? new Set(rows.map((r) => r.code)) : new Set())
                        }
                      />
                    </TableHead>
                  )}
                  <TableHead>Código</TableHead>
                  <TableHead>Título</TableHead>
                  <TableHead>Severidad</TableHead>
                  <TableHead>Estado</TableHead>
                  <TableHead>Responsable</TableHead>
                  <TableHead>Runbook</TableHead>
                  <TableHead>Actualizado</TableHead>
                  {canWrite && <TableHead className="w-10" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((x) => (
                  <TableRow key={x.code} clickable onClick={() => nav(`/incidents/${x.code}`)}>
                    {canWrite && (
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          aria-label={`Seleccionar ${x.code}`}
                          checked={sel.has(x.code)}
                          onCheckedChange={(v) => toggle(x.code, v === true)}
                        />
                      </TableCell>
                    )}
                    <TableCell className="whitespace-nowrap">
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
                    <TableCell>{x.owner}</TableCell>
                    <TableCell className="text-muted">
                      {x.runbook ? `📘 ${rbTitle(x.runbook)}` : ''}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-muted">{x.updated_at}</TableCell>
                    {canWrite && (
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button size="icon" variant="ghost" aria-label={`Acciones de ${x.code}`}>
                              <MoreHorizontal />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            {x.status === 'Closed' ? (
                              <DropdownMenuItem onSelect={() => void reopen(x)}>
                                <RotateCcw /> Reabrir
                              </DropdownMenuItem>
                            ) : (
                              <DropdownMenuItem onSelect={() => setClosing([x])}>
                                <CheckCircle2 /> Cerrar incidente
                              </DropdownMenuItem>
                            )}
                            {isAdmin && (
                              <>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem className="text-bad" onSelect={() => setDeleting([x])}>
                                  <Trash2 /> Eliminar
                                </DropdownMenuItem>
                              </>
                            )}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <Empty>Ningún incidente coincide con estos filtros.</Empty>
          )}
        </Panel>
      )}
    </div>
  );
}
