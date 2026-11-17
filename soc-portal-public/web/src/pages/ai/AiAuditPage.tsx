import { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { usePageEnter } from '@/components/layout/AppShell';
import { Empty, ErrorState, Kpi, KpiGrid, Loading, PageHeader } from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { nf, pct, short } from '@/lib/format';
import { useAiAudit } from '@/services/ai';
import { TOOL_NAME, VERDICT } from './common';

export default function AiAuditPage() {
  const ref = usePageEnter('ai-audit');
  const q = useAiAudit();
  useEffect(() => {
    document.title = 'Portal SOC · Registro del asistente';
  }, []);
  if (q.isPending) return <Loading />;
  if (q.error || !q.data) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const rows = q.data;
  const tot = rows.reduce((a, r) => a + (r.tokens_in || 0) + (r.tokens_out || 0), 0);
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Registro de uso del asistente"
        actions={
          <Button variant="secondary" size="sm" asChild>
            <Link to="/ai">
              <ArrowLeft /> Asistente
            </Link>
          </Button>
        }
      />
      <KpiGrid data-enter="">
        <Kpi title="Consultas" value={nf(rows.length)} />
        <Kpi title="Tokens" value={short(tot)} />
        <Kpi
          title="Verificadas"
          value={`${pct(rows.filter((r) => r.verdict === 'verificada').length, rows.length)} %`}
        />
        <Kpi
          title="Inyecciones detectadas"
          value={nf(rows.reduce((a, r) => a + (r.injections || 0), 0))}
          hint="instrucciones en datos, marcadas"
          alert={rows.some((r) => r.injections)}
        />
      </KpiGrid>
      <section className="card">
        {rows.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Fecha</TableHead>
                <TableHead>Usuario</TableHead>
                <TableHead>Modelo</TableHead>
                <TableHead>Herramientas</TableHead>
                <TableHead className="text-right">Tokens</TableHead>
                <TableHead>Verificación</TableHead>
                <TableHead className="text-right">Tiempo</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r) => {
                const v = VERDICT[r.verdict] ?? VERDICT.sin_verificar!;
                return (
                  <TableRow key={r.id}>
                    <TableCell>{r.at}</TableCell>
                    <TableCell>{r.user}</TableCell>
                    <TableCell className="text-muted">
                      {r.provider} · {r.model}
                    </TableCell>
                    <TableCell className="text-xs">
                      {(r.tools || '')
                        .split(',')
                        .filter(Boolean)
                        .map((t) => TOOL_NAME[t] ?? t)
                        .join(', ') || '—'}
                    </TableCell>
                    <TableCell className="text-right">
                      {nf((r.tokens_in || 0) + (r.tokens_out || 0))}
                    </TableCell>
                    <TableCell>
                      <Badge variant={v[1]}>{v[0]}</Badge>
                      {!!r.injections && (
                        <Badge variant="bad" className="ml-1">
                          ⚠
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right">{((r.ms || 0) / 1000).toFixed(1)} s</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        ) : (
          <Empty>Sin consultas.</Empty>
        )}
      </section>
    </div>
  );
}
