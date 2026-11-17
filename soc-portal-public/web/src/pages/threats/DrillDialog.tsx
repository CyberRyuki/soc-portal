import { create } from 'zustand';
import { Plus } from 'lucide-react';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Empty, ErrorState, Level, Loading } from '@/components/shared';
import { useAuth } from '@/hooks/useAuth';
import { FIELD_NAMES } from '@/lib/constants';
import { fdt } from '@/lib/format';
import { useAlerts } from '@/services/threats';
import { useNewIncident } from '@/pages/incidents/NewIncidentDialog';
import type { ThreatRange } from '@/types/api';

interface DrillState {
  field: string;
  value: string;
  range: ThreatRange;
  minLevel: number;
  open: (field: string, value: string, range?: ThreatRange, minLevel?: number) => void;
  close: () => void;
}
/** Al pulsar una regla, agente, IP… se abren sus últimas alertas. */
export const useDrill = create<DrillState>((set) => ({
  field: '',
  value: '',
  range: '24h',
  minLevel: 10,
  open: (field, value, range = '24h', minLevel = 10) => set({ field, value, range, minLevel }),
  close: () => set({ field: '', value: '' }),
}));

export function DrillDialog() {
  const { field, value, range, minLevel, close } = useDrill();
  const { canWrite } = useAuth();
  const newInc = useNewIncident();
  const q = useAlerts(field, value, range, minLevel);
  const rows = q.data ?? [];
  const agents = [...new Set(rows.map((a) => a.agent?.name).filter(Boolean))] as string[];
  const ips = [...new Set(rows.map((a) => a.data?.srcip).filter(Boolean))] as string[];
  return (
    <Dialog open={!!field} onOpenChange={(o) => !o && close()}>
      <DialogContent
        wide
        title={`${FIELD_NAMES[field] ?? field}: ${value}`}
        description={`Últimas 25 alertas · rango ${range} · nivel ≥ ${minLevel}`}
      >
        {q.isPending ? (
          <Loading rows={2} />
        ) : q.error ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
        ) : rows.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Fecha</TableHead>
                <TableHead>Nivel</TableHead>
                <TableHead>Agente</TableHead>
                <TableHead>Regla</TableHead>
                <TableHead>Origen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((a, i) => (
                <TableRow key={i}>
                  <TableCell className="whitespace-nowrap text-muted">{fdt(a.timestamp)}</TableCell>
                  <TableCell>
                    <Level l={a.rule?.level} />
                  </TableCell>
                  <TableCell>{a.agent?.name}</TableCell>
                  <TableCell>
                    <div>{a.rule?.description}</div>
                    <div className="mono text-muted">regla {a.rule?.id}</div>
                    {a.full_log && (
                      <div className="mono mt-1 max-w-[560px] truncate text-muted" title={a.full_log}>
                        {a.full_log}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="mono">{a.data?.srcip ?? ''}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty>Sin alertas para este filtro en el rango.</Empty>
        )}
        {canWrite && rows.length > 0 && (
          <div className="mt-4 flex justify-end">
            <Button
              onClick={() => {
                close();
                newInc.open({
                  title: `${FIELD_NAMES[field] ?? field} ${value}`.slice(0, 200),
                  detected_by: `Wazuh · ${rows[0]?.rule?.description ?? ''}`.slice(0, 200),
                  assets: agents.join(', '),
                  iocs: ips.join('\n'),
                  severity: (rows[0]?.rule?.level ?? 0) >= 13 ? 'Critical' : 'High',
                });
              }}
            >
              <Plus /> Crear incidente con estas alertas
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
