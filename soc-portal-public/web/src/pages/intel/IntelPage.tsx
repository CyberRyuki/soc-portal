import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ExternalLink, Plus, Search } from 'lucide-react';
import { usePageEnter } from '@/components/layout/AppShell';
import { Donut } from '@/components/charts';
import {
  Empty,
  ErrorState,
  HBars,
  Level,
  Loading,
  PageHeader,
  Panel,
  Risk,
  SevPill,
  StatusPill,
} from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import { useSearchParam } from '@/hooks/useSearchParam';
import { EXEC_LABEL } from '@/lib/constants';
import { dur, fdt, nf } from '@/lib/format';
import { useIntelPanel, useIocSearch } from '@/services/misc';
import { useNewIncident } from '@/pages/incidents/NewIncidentDialog';
import { useIocDetail } from '@/pages/iocs/IocDetailDialog';
import { SourcePills } from '@/pages/iocs/common';

const THREAT: Record<string, [string, 'bad' | 'warn' | 'info' | 'gray']> = {
  '1': ['Alto', 'bad'],
  '2': ['Medio', 'warn'],
  '3': ['Bajo', 'info'],
  '4': ['Indefinido', 'gray'],
};
const EXC: Record<string, string> = {
  FINISHED: 'var(--st-good)',
  ABORTED: 'var(--st-crit)',
  FAILURE: 'var(--st-crit)',
  EXECUTING: 'var(--s1)',
  WAITING: 'var(--st-warn)',
};

export default function IntelPage() {
  const ref = usePageEnter('intel');
  const [q, setQ] = useSearchParam('q', '');
  const d = useIntelPanel();
  const { meta } = useAuth();
  useEffect(() => {
    document.title = 'Portal SOC · Inteligencia';
  }, []);
  const L = meta?.links ?? {};
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Inteligencia y automatización"
        subtitle="Busca un indicador en MISP, en las alertas de Wazuh (30 días) y en los incidentes del portal."
      />
      <SearchForm key={q} initial={q} onSearch={setQ} />
      {q && <SearchResult q={q} />}
      {d.isPending ? (
        <Loading />
      ) : d.error || !d.data ? (
        <ErrorState error={d.error} onRetry={() => void d.refetch()} />
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
            <Panel title="Eventos recientes de MISP" hint="30 días" bodyClassName="px-0 pb-0">
              {d.data.eventos ? (
                d.data.eventos.length ? (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>ID</TableHead>
                        <TableHead>Fecha</TableHead>
                        <TableHead>Evento</TableHead>
                        <TableHead>Amenaza</TableHead>
                        <TableHead className="text-right">Atributos</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {d.data.eventos.map((e) => {
                        const [t, v] = THREAT[String(e.threat_level_id)] ?? ['—', 'gray'];
                        return (
                          <TableRow
                            key={e.id}
                            clickable
                            onClick={() => window.open(`${L.misp}/events/view/${e.id}`, '_blank', 'noopener')}
                          >
                            <TableCell className="mono">{e.id}</TableCell>
                            <TableCell className="whitespace-nowrap">{e.date}</TableCell>
                            <TableCell>{e.info}</TableCell>
                            <TableCell>
                              <Badge variant={v}>{t}</Badge>
                            </TableCell>
                            <TableCell className="text-right">{nf(+e.attribute_count)}</TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                ) : (
                  <Empty>Sin eventos nuevos en 30 días.</Empty>
                )
              ) : (
                <ErrorState error={d.data.err_eventos} compact />
              )}
            </Panel>
            <Panel title="IoC accionables por tipo" hint="7 días">
              {d.data.iocs ? (
                <>
                  <HBars
                    rows={d.data.iocs.tipos.map(([k, v]) => ({ key: k, label: k, value: v }))}
                    empty="Sin IoC nuevos"
                    max={10}
                  />
                  <div className="mt-2 text-xs text-muted">
                    Total: <b>{nf(d.data.iocs.total)}</b> atributos to_ids
                  </div>
                </>
              ) : (
                <ErrorState error={d.data.err_iocs} compact />
              )}
            </Panel>
          </div>
          <h2 className="flex items-baseline justify-between text-base font-bold">
            Automatización · Shuffle{' '}
            <a
              className="text-xs font-normal text-brand"
              href={L.shuffle}
              target="_blank"
              rel="noopener noreferrer"
            >
              Abrir Shuffle <ExternalLink className="inline size-3" />
            </a>
          </h2>
          {d.data.shuffle ? (
            <div className="grid gap-4 lg:grid-cols-[1fr_2fr]">
              <Panel title="Resultado de las ejecuciones" hint="últimas por workflow">
                <Donut
                  center="ejecuciones"
                  items={d.data.shuffle.estados.map(([k, v]) => ({
                    label: EXEC_LABEL[k] ?? k,
                    value: v,
                    color: EXC[k] ?? 'var(--s-neutral)',
                  }))}
                />
              </Panel>
              <Panel title="Ejecuciones recientes" bodyClassName="px-0 pb-0">
                {d.data.shuffle.recientes.length ? (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Workflow</TableHead>
                        <TableHead>Estado</TableHead>
                        <TableHead>Inicio</TableHead>
                        <TableHead className="text-right">Duración</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {d.data.shuffle.recientes.map((r) => (
                        <TableRow
                          key={r.id}
                          clickable
                          onClick={() =>
                            window.open(
                              `${L.shuffle}/workflows/${r.workflow_id}?execution_id=${r.id}`,
                              '_blank',
                              'noopener',
                            )
                          }
                        >
                          <TableCell>{r.workflow}</TableCell>
                          <TableCell>
                            <Badge
                              variant={
                                r.status === 'FINISHED'
                                  ? 'ok'
                                  : r.status === 'ABORTED' || r.status === 'FAILURE'
                                    ? 'bad'
                                    : 'warn'
                              }
                            >
                              {EXEC_LABEL[r.status] ?? r.status}
                            </Badge>
                          </TableCell>
                          <TableCell className="whitespace-nowrap">
                            {r.started ? fdt(+r.started) : '—'}
                          </TableCell>
                          <TableCell className="text-right">
                            {r.completed && r.started
                              ? dur((r.completed - r.started) / 60).replace(/^0 min$/, '< 1 min')
                              : '—'}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <Empty>Aún no hay ejecuciones.</Empty>
                )}
              </Panel>
            </div>
          ) : (
            <ErrorState error={d.data.err_shuffle} compact />
          )}
        </>
      )}
    </div>
  );
}

function SearchResult({ q }: { q: string }) {
  const r = useIocSearch(q);
  const { meta, canWrite } = useAuth();
  const newInc = useNewIncident();
  const detail = useIocDetail();
  const nav = useNavigate();
  if (r.isPending) return <Loading rows={1} h="h-28" />;
  if (r.error || !r.data) return <ErrorState error={r.error} compact />;
  const x = r.data;
  const I = x.intel ?? { score: 0, fuentes: [] };
  const found = (x.misp?.length ?? 0) + (x.wazuh?.total ?? 0) + x.incidentes.length + I.fuentes.length;
  const L = meta?.links ?? {};
  return (
    <Panel
      title={
        <>
          Resultado para <span className="mono text-sm">{x.q}</span>
        </>
      }
      className={found ? 'border-bad/40' : ''}
      actions={
        <span className="flex items-center gap-2">
          {found ? (
            <Badge variant="bad">Indicador visto</Badge>
          ) : (
            <Badge variant="ok">Sin coincidencias</Badge>
          )}
          {canWrite && (
            <Button
              size="sm"
              variant="secondary"
              onClick={() =>
                newInc.open({
                  title: `IoC: ${x.q}`,
                  iocs: x.q,
                  detected_by: 'Búsqueda de IoC · portal',
                  runbook: 'misp-ioc-match',
                })
              }
            >
              <Plus /> Incidente
            </Button>
          )}
        </span>
      }
    >
      <div className="flex flex-wrap items-center gap-2 text-[13.5px]">
        <Risk s={I.score} /> <b>Fuentes de inteligencia:</b>{' '}
        {I.fuentes.length ? (
          <SourcePills f={I.fuentes} />
        ) : (
          <span className="text-muted">en ninguna de tus fuentes</span>
        )}
        <button type="button" className="text-brand hover:underline" onClick={() => detail.open(x.q)}>
          Análisis a fondo →
        </button>
      </div>
      <div className="mt-3 grid gap-4 text-[13px] md:grid-cols-3">
        <div>
          <b>MISP</b>{' '}
          <span className="text-muted">· {x.misp ? `${nf(x.misp.length)} atributos` : 'no disponible'}</span>
          {x.misp ? (
            x.misp.length ? (
              x.misp.slice(0, 6).map((m, i) => (
                <div key={i} className="border-t border-line py-1.5">
                  <a
                    className="text-brand"
                    target="_blank"
                    rel="noopener noreferrer"
                    href={`${L.misp}/events/view/${m.event_id}`}
                  >
                    #{m.event_id}
                  </a>{' '}
                  {m.event}
                  <div className="flex flex-wrap gap-1 text-xs text-muted">
                    {m.type} · {m.category} {m.to_ids && <Badge variant="bad">to_ids</Badge>}{' '}
                    {m.tags.map((t) => (
                      <Badge key={t} variant="gray">
                        {t}
                      </Badge>
                    ))}
                  </div>
                </div>
              ))
            ) : (
              <div className="py-1.5 text-muted">No está en MISP.</div>
            )
          ) : (
            <div className="text-bad">{x.err_misp}</div>
          )}
        </div>
        <div>
          <b>Wazuh</b>{' '}
          <span className="text-muted">
            · {x.wazuh ? `${nf(x.wazuh.total)} alertas en 30 días` : 'no disponible'}
          </span>
          {x.wazuh ? (
            <>
              {x.wazuh.agentes.length > 0 && (
                <div className="my-1.5 flex flex-wrap gap-1">
                  {x.wazuh.agentes.map(([k, v]) => (
                    <Badge key={k} variant="info">
                      {k} · {nf(v)}
                    </Badge>
                  ))}
                </div>
              )}
              {x.wazuh.alertas.slice(0, 5).map((a, i) => (
                <div key={i} className="flex items-start gap-2 border-t border-line py-1.5">
                  <Level l={a.rule?.level} />
                  <div>
                    {a.rule?.description}
                    <div className="text-xs text-muted">
                      {a.agent?.name} · {fdt(a.timestamp)}
                    </div>
                  </div>
                </div>
              ))}
            </>
          ) : (
            <div className="text-bad">{x.err_wazuh}</div>
          )}
        </div>
        <div>
          <b>Incidentes del portal</b> <span className="text-muted">· {nf(x.incidentes.length)}</span>
          {x.incidentes.length ? (
            x.incidentes.map((i) => (
              <button
                key={i.code}
                type="button"
                className="block w-full border-t border-line py-1.5 text-left hover:text-brand"
                onClick={() => nav(`/incidents/${i.code}`)}
              >
                <b>{i.code}</b> {i.title}
                <div className="flex gap-1">
                  <SevPill v={i.severity} />
                  <StatusPill v={i.status} />
                </div>
              </button>
            ))
          ) : (
            <div className="py-1.5 text-muted">Ningún incidente lo menciona.</div>
          )}
        </div>
      </div>
    </Panel>
  );
}

function SearchForm({ initial, onSearch }: { initial: string; onSearch: (q: string) => void }) {
  const [draft, setDraft] = useState(initial);
  return (
    <form
      className="flex gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        onSearch(draft.trim());
      }}
    >
      <Input
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        placeholder="IP, dominio, URL o hash (MD5 / SHA1 / SHA256)…"
        autoFocus
        className="h-10"
        aria-label="Indicador a buscar"
      />
      <Button type="submit" size="lg">
        <Search /> Buscar
      </Button>
    </form>
  );
}
