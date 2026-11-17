import { useDeferredValue, useEffect, useMemo, useState } from 'react';
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
} from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useSearchParam } from '@/hooks/useSearchParam';
import { useAgents } from '@/services/threats';
import { AGENT_COLOR, AGENT_LABEL, type AgentStatus } from '@/lib/constants';
import { fdt, nf, pct, since } from '@/lib/format';

const ONE: Record<string, string> = {
  active: 'Activo',
  disconnected: 'Desconectado',
  never_connected: 'Nunca conectado',
  pending: 'Pendiente',
};
const MAX_ROWS = 300;

export default function AgentsPage() {
  const ref = usePageEnter('agents');
  const q = useAgents();
  const [status, setStatus] = useSearchParam('status', '');
  const [text, setText] = useState('');
  const f = useDeferredValue(text.trim().toLowerCase());
  useEffect(() => {
    document.title = 'Portal SOC · Agentes';
  }, []);
  const d = q.data;
  const rows = useMemo(
    () =>
      (d?.lista ?? []).filter(
        (r) =>
          (!status || r.status === status) &&
          (!f || [r.name, r.ip, r.os, r.group, r.id].join(' ').toLowerCase().includes(f)),
      ),
    [d, status, f],
  );
  if (q.isPending) return <Loading rows={3} />;
  if (q.error || !d) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const S = Object.fromEntries(d.estados) as Partial<Record<AgentStatus, number>>;
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Agentes"
        subtitle={
          <>
            Estado de los agentes de Wazuh según la última foto de{' '}
            <span className="mono">wazuh-monitoring</span> (se renueva cada ~15 min).
          </>
        }
      />
      <KpiGrid data-enter="">
        <Kpi title="Total" value={nf(d.total)} hint={`foto ${fdt(d.foto + 'Z')}`} />
        <Kpi
          title="Activos"
          value={nf(S.active)}
          hint={`${pct(S.active ?? 0, d.total)} %`}
          onClick={() => setStatus('active')}
        />
        <Kpi
          title="Desconectados"
          value={nf(S.disconnected)}
          hint="Revisar conectividad"
          onClick={() => setStatus('disconnected')}
          alert={(S.disconnected ?? 0) > 0}
        />
        <Kpi
          title="Nunca conectados"
          value={nf(S.never_connected)}
          hint="Registrados sin conexión"
          onClick={() => setStatus('never_connected')}
        />
      </KpiGrid>
      <div className="grid gap-4 lg:grid-cols-4">
        <Panel title="Estado" className="lg:col-span-2">
          <Donut
            center="agentes"
            items={(Object.keys(AGENT_LABEL) as AgentStatus[]).map((k) => ({
              label: AGENT_LABEL[k],
              value: S[k] ?? 0,
              color: AGENT_COLOR[k],
              onClick: () => setStatus(k),
            }))}
          />
        </Panel>
        <Panel title="Sistema operativo">
          <HBars rows={d.so.map(([k, v]) => ({ key: k, label: k, value: v }))} />
        </Panel>
        <Panel title="Versión del agente">
          <HBars rows={d.versiones.map(([k, v]) => ({ key: k, label: k, value: v }))} />
        </Panel>
      </div>
      <Panel title="Grupos">
        <HBars
          rows={d.grupos.map(([k, v]) => ({ key: k, label: k, value: v }))}
          empty="Sin grupos"
          max={12}
        />
      </Panel>
      <Panel
        title={
          <>
            Listado <span className="text-xs font-normal text-muted">{nf(rows.length)} agentes</span>
          </>
        }
        bodyClassName="px-0 pb-0"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Chips
              options={[['', 'Todos'], ...(Object.entries(AGENT_LABEL) as [AgentStatus, string][])]}
              value={status}
              onChange={setStatus}
            />
            <Input
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Buscar por nombre, IP, SO o grupo…"
              className="w-64"
              aria-label="Buscar agente"
            />
          </div>
        }
      >
        <div className="max-h-[560px] overflow-auto scroll-thin">
          {rows.length ? (
            <Table>
              <TableHeader className="sticky top-0 bg-card">
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Nombre</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Estado</TableHead>
                  <TableHead>SO</TableHead>
                  <TableHead>Versión</TableHead>
                  <TableHead>Grupo</TableHead>
                  <TableHead>Última conexión</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.slice(0, MAX_ROWS).map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="mono">{r.id}</TableCell>
                    <TableCell className="font-bold">{r.name}</TableCell>
                    <TableCell className="mono">{r.ip}</TableCell>
                    <TableCell>
                      <Badge
                        variant={r.status === 'active' ? 'ok' : r.status === 'disconnected' ? 'bad' : 'gray'}
                      >
                        {ONE[r.status] ?? r.status}
                      </Badge>
                    </TableCell>
                    <TableCell>{r.os}</TableCell>
                    <TableCell className="mono">{r.version}</TableCell>
                    <TableCell>{r.group}</TableCell>
                    <TableCell className="whitespace-nowrap">
                      {r.last ? (
                        <>
                          {fdt(r.last)} <span className="text-muted">· hace {since(r.last)}</span>
                        </>
                      ) : (
                        '—'
                      )}
                    </TableCell>
                  </TableRow>
                ))}
                {rows.length > MAX_ROWS && (
                  <TableRow>
                    <TableCell colSpan={8} className="text-muted">
                      Mostrando {MAX_ROWS} de {nf(rows.length)}. Usa el buscador para acotar.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          ) : (
            <Empty>Ningún agente coincide.</Empty>
          )}
        </div>
      </Panel>
    </div>
  );
}
