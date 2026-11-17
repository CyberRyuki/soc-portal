import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronDown, ExternalLink, Wrench } from 'lucide-react';
import { toast } from 'sonner';
import { usePageEnter } from '@/components/layout/AppShell';
import { Empty, ErrorState, Kpi, KpiGrid, Loading, Markdown, PageHeader, Panel } from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Select, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import { useSearchParam } from '@/hooks/useSearchParam';
import { nf } from '@/lib/format';
import { useOwasp, useSaveMark } from '@/services/frameworks';
import { FrameworkNav, OW_VARIANT } from './common';
import type { OwaspItem } from '@/types/api';

export default function OwaspPage() {
  const ref = usePageEnter('owasp');
  const { canWrite } = useAuth();
  const d = useOwasp();
  const [a, setA] = useSearchParam('a', '');
  useEffect(() => {
    document.title = 'Portal SOC · OWASP Top 10';
  }, []);
  if (d.isPending) return <Loading />;
  if (d.error || !d.data) return <ErrorState error={d.error} onRetry={() => void d.refetch()} />;
  const D = d.data;
  const cnt = (k: string) => D.items.filter((i) => i.mark?.status === k).length;
  const cur = D.items.find((i) => i.id === a) ?? null;
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="OWASP Top 10 · 2025"
        subtitle="Los diez riesgos principales de las aplicaciones web, con controles, detección y la autoevaluación de los portales institucionales."
        actions={<FrameworkNav cur="owasp" />}
      />
      <KpiGrid data-enter="">
        <Kpi title="Riesgos" value="10" hint="edición 2025" />
        <Kpi title="Cumple" value={nf(cnt('cumple'))} hint="controles implantados" />
        <Kpi title="Parcial" value={nf(cnt('parcial'))} hint="con mejoras pendientes" />
        <Kpi
          title="No cumple"
          value={nf(cnt('no_cumple'))}
          hint="prioridad de remediación"
          alert={cnt('no_cumple') > 0}
        />
        <Kpi
          title="Sin evaluar"
          value={nf(D.items.filter((i) => !i.mark?.status).length)}
          hint="pulsa «Evaluar» en cada riesgo"
        />
      </KpiGrid>
      <div className="grid gap-4 md:grid-cols-2" data-enter="">
        {D.items.map((i) => {
          const m = i.mark ?? {};
          return (
            <section key={i.id} className="card p-4">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-start gap-3">
                  <span className="grid size-11 shrink-0 place-items-center rounded-xl bg-brand-soft font-mono text-[13px] font-bold text-brand">
                    {i.id.split(':')[0]}
                  </span>
                  <div>
                    <h3 className="text-[15px] font-bold leading-tight">{i.es}</h3>
                    <div className="text-xs text-muted">
                      {i.en} · {i.id}
                    </div>
                  </div>
                </div>
                {m.status ? (
                  <Badge variant={OW_VARIANT[m.status] ?? 'gray'}>{D.estados[m.status]}</Badge>
                ) : (
                  <Badge variant="gray">Sin evaluar</Badge>
                )}
              </div>
              <p className="my-2.5 text-[13.5px]">{i.resumen}</p>
              <div className="mb-2 flex flex-wrap gap-1">
                {i.alertas > 0 && (
                  <Badge variant="bad">
                    {nf(i.alertas)} alertas web · {D.days} d
                  </Badge>
                )}
                {i.mitre.map((t) => (
                  <Link key={t} to={`/mitre?t=${t}`}>
                    <Badge variant="info" className="font-mono">
                      {t}
                    </Badge>
                  </Link>
                ))}
                {i.runbooks.map((r) => (
                  <Link key={r.slug} to={`/runbooks/${r.slug}`}>
                    <Badge>📘 {r.title}</Badge>
                  </Link>
                ))}
              </div>
              <Collapsible>
                <CollapsibleTrigger className="group flex cursor-pointer items-center gap-1 text-[13px] font-semibold text-brand">
                  <ChevronDown className="size-4 transition-transform group-data-[state=open]:rotate-180" />{' '}
                  Ejemplos, controles y detección
                </CollapsibleTrigger>
                <CollapsibleContent className="text-[13px]">
                  <h4 className="mb-1 mt-2.5 font-semibold">Ejemplos</h4>
                  <ul className="list-disc pl-5">
                    {i.ejemplos.map((x) => (
                      <li key={x}>{x}</li>
                    ))}
                  </ul>
                  <h4 className="mb-1 mt-2.5 font-semibold">Controles recomendados</h4>
                  <ul className="list-disc pl-5">
                    {i.controles.map((x) => (
                      <li key={x}>{x}</li>
                    ))}
                  </ul>
                  <h4 className="mb-1 mt-2.5 font-semibold">Cómo detectarlo en el SOC</h4>
                  <ul className="list-disc pl-5">
                    {i.deteccion.map((x) => (
                      <li key={x}>
                        <Markdown src={x} className="[&>p]:my-0" />
                      </li>
                    ))}
                  </ul>
                  <h4 className="mb-1 mt-2.5 font-semibold">Herramientas</h4>
                  <div className="flex flex-wrap gap-1">
                    {i.herramientas.map((h) => (
                      <Link key={h} to={`/tools?q=${encodeURIComponent(h.split(' (')[0] ?? h)}`}>
                        <Badge variant="gray">
                          <Wrench className="size-3" /> {h}
                        </Badge>
                      </Link>
                    ))}
                  </div>
                  <a
                    className="mt-2 inline-flex items-center gap-1 text-brand"
                    href="https://top10.owasp.org/2025/"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Ficha oficial en OWASP <ExternalLink className="size-3" />
                  </a>
                </CollapsibleContent>
              </Collapsible>
              <div className="mt-2.5 flex items-center justify-between gap-2">
                <span className="truncate text-xs text-muted">
                  {m.note && `📝 ${m.note.slice(0, 90)}`}
                  {m.user && ` · ${m.user} ${(m.at ?? '').slice(0, 10)}`}
                </span>
                {canWrite && (
                  <Button variant="secondary" size="sm" onClick={() => setA(i.id)}>
                    Evaluar
                  </Button>
                )}
              </div>
            </section>
          );
        })}
      </div>
      <Panel title={`Ataques web detectados por Wazuh · ${D.days} días`} bodyClassName="px-0 pb-0">
        {D.err_wazuh ? (
          <ErrorState error={D.err_wazuh} compact />
        ) : D.web.length ? (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Regla</TableHead>
                  <TableHead>OWASP</TableHead>
                  <TableHead className="text-right">IPs</TableHead>
                  <TableHead className="text-right">Alertas</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {D.web.map((w) => (
                  <TableRow key={w.desc}>
                    <TableCell>{w.desc}</TableCell>
                    <TableCell>
                      {w.owasp ? (
                        <Badge variant="warn">{w.owasp.split(':')[0]}</Badge>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">{nf(w.ips)}</TableCell>
                    <TableCell className="text-right font-bold">{nf(w.n)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <p className="px-4 py-2 text-xs text-muted">
              La categoría OWASP se asigna por palabras clave de la descripción de la regla; es orientativa.
            </p>
          </>
        ) : (
          <Empty>Sin alertas web en el periodo.</Empty>
        )}
      </Panel>
      {cur && <EvalDialog key={cur.id} item={cur} estados={D.estados} onClose={() => setA('')} />}
    </div>
  );
}

function EvalDialog({
  item,
  estados,
  onClose,
}: {
  item: OwaspItem;
  estados: Record<string, string>;
  onClose: () => void;
}) {
  const save = useSaveMark();
  const [status, setStatus] = useState(item.mark?.status ?? '');
  const [note, setNote] = useState(item.mark?.note ?? '');
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        title={`${item.id} · ${item.es}`}
        description="Autoevaluación de los portales y aplicaciones de la institución frente a este riesgo."
      >
        {
          <>
            <Label htmlFor="ow-s">Estado</Label>
            <Select id="ow-s" value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">Sin evaluar</option>
              {Object.entries(estados).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </Select>
            <Label htmlFor="ow-n" className="mt-3">
              Notas (qué aplicaciones, qué falta, enlace a hallazgos de Vulnerabilidades)
            </Label>
            <Textarea
              id="ow-n"
              className="min-h-[110px]"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
            <h4 className="mb-1 mt-3 text-[13px] font-semibold">Controles a revisar</h4>
            <ul className="list-disc pl-5 text-[13px]">
              {item.controles.map((x) => (
                <li key={x}>{x}</li>
              ))}
            </ul>
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="secondary" onClick={onClose}>
                Cancelar
              </Button>
              <Button
                disabled={save.isPending}
                onClick={() =>
                  save.mutate(
                    { fw: 'owasp', key: item.id, status, note },
                    {
                      onSuccess: () => {
                        toast.success('Cobertura guardada');
                        onClose();
                      },
                      onError: (e) => toast.error(e.message),
                    },
                  )
                }
              >
                Guardar
              </Button>
            </div>
          </>
        }
      </DialogContent>
    </Dialog>
  );
}
