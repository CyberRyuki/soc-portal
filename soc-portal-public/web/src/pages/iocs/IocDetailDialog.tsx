import { useState } from 'react';
import { create } from 'zustand';
import { Link, useNavigate } from 'react-router-dom';
import { Ban, Bot, Plus, Search } from 'lucide-react';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ErrorState, Kpi, Loading, Risk } from '@/components/shared';
import { useAuth } from '@/hooks/useAuth';
import { nf } from '@/lib/format';
import { useLookup } from '@/services/intel';
import { useNewIncident } from '@/pages/incidents/NewIncidentDialog';
import { startInvestigation } from '@/pages/ai/investigate';
import { ActionDialog, type ActionRequest } from '@/pages/sophos/ActionDialog';
import { useSophosStatus } from '@/services/sophos';

interface S {
  value: string;
  open: (v: string) => void;
  close: () => void;
}
/** Análisis a fondo de un indicador (fuentes, Wazuh, MISP y enriquecimiento externo). */
export const useIocDetail = create<S>((set) => ({
  value: '',
  open: (value) => set({ value: value.trim() }),
  close: () => set({ value: '' }),
}));
const VC: Record<string, 'bad' | 'warn' | 'ok' | 'gray'> = {
  malicioso: 'bad',
  sospechoso: 'warn',
  vulnerable: 'warn',
  limpio: 'ok',
  error: 'gray',
};

export function IocDetailDialog() {
  const { value, close } = useIocDetail();
  const { meta, canWrite } = useAuth();
  const nav = useNavigate();
  const newInc = useNewIncident();
  const q = useLookup(value);
  const x = q.data;
  const misp = meta?.links.misp ?? '';
  const [block, setBlock] = useState<ActionRequest | null>(null);
  // Sophos bloquea SHA-256 (elementos bloqueados) y dominios/URL/IP (sitios web locales)
  const sophosSt = useSophosStatus();
  const sophosKind =
    x?.sophos && !sophosSt.data?.solo_lectura
      ? /^[a-f0-9]{64}$/i.test(x.value)
        ? ('block_hash' as const)
        : /^(domain|url|ip)/.test(x.type)
          ? ('block_web' as const)
          : null
      : null;
  return (
    <Dialog open={!!value} onOpenChange={(o) => !o && close()}>
      <DialogContent
        wide
        title={`Análisis de ${value}`}
        description="Fuentes locales, Wazuh, MISP y servicios externos"
      >
        <div className="mb-3 flex justify-end">
          <Button
            size="sm"
            onClick={() => {
              close();
              void startInvestigation(nav, {
                title: `IoC ${value}`,
                question: `Investiga el indicador ${value}: en qué fuentes aparece, qué hizo en nuestra red, qué equipos tocó y si hay que abrir un incidente.`,
              });
            }}
          >
            <Bot /> Investigar con IA
          </Button>
        </div>
        {q.isPending ? (
          <Loading rows={2} />
        ) : q.error || !x ? (
          <ErrorState error={q.error} compact />
        ) : (
          <>
            <div className="grid grid-cols-2 gap-2.5 md:grid-cols-4">
              <Kpi
                title="Riesgo"
                value={<Risk s={x.score} />}
                hint={
                  x.score >= 80
                    ? 'Alto'
                    : x.score >= 50
                      ? 'Medio'
                      : x.score
                        ? 'Bajo'
                        : 'Sin datos en tus fuentes'
                }
              />
              <Kpi
                title="Fuentes"
                value={nf(x.fuentes.length)}
                hint={
                  x.fuentes
                    .map((f) => f.name)
                    .join(', ')
                    .slice(0, 70) || '—'
                }
              />
              <Kpi
                title="Wazuh · 30 días"
                value={x.wazuh == null ? '?' : nf(x.wazuh)}
                hint="alertas que lo contienen"
                alert={(x.wazuh ?? 0) > 0}
              />
              <Kpi
                title="MISP"
                value={nf(x.misp?.length ?? 0)}
                hint="eventos"
                alert={(x.misp?.length ?? 0) > 0}
              />
            </div>
            <div className="mt-4 grid gap-5 md:grid-cols-2">
              <div className="space-y-3 text-[13.5px]">
                <h3 className="font-semibold">Fuentes</h3>
                {x.fuentes.length ? (
                  <ul className="divide-y divide-line">
                    {x.fuentes.map((f) => (
                      <li key={f.id} className="flex justify-between gap-2 py-1.5">
                        <span>
                          <b>{f.name}</b>
                          {f.ref && <div className="text-xs text-muted">{f.ref}</div>}
                          {f.via !== x.value && <div className="text-xs text-muted">vía {f.via}</div>}
                        </span>
                        <span className="text-muted">confianza {f.weight}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-muted">No está en ninguna fuente.</p>
                )}
                <h3 className="font-semibold">Visto en</h3>
                {x.sightings_detalle?.length ? (
                  x.sightings_detalle.flatMap((s) =>
                    s.agents.map(([a, n]) => (
                      <div key={a} className="py-0.5">
                        🖥 <b>{a}</b> · {nf(n)} alertas{' '}
                        <span className="text-muted">· {s.last_seen.slice(0, 16)}</span>
                      </div>
                    )),
                  )
                ) : (
                  <p className="text-muted">Sin coincidencias registradas.</p>
                )}
                {!!x.sophos?.length && (
                  <>
                    <h3 className="font-semibold">Sophos Central</h3>
                    {x.sophos.map((a) => (
                      <div key={a.id} className="py-0.5">
                        🛡 <b>{a.endpoint || '—'}</b> · {a.description.slice(0, 90)}{' '}
                        <span className="text-muted">· {a.raised_at.slice(0, 16).replace('T', ' ')}</span>
                      </div>
                    ))}
                  </>
                )}
                {!!x.misp?.length && (
                  <>
                    <h3 className="font-semibold">MISP</h3>
                    <div className="flex flex-wrap gap-1">
                      {x.misp.map((e) => (
                        <a
                          key={String(e)}
                          target="_blank"
                          rel="noopener noreferrer"
                          href={`${misp}/events/view/${encodeURIComponent(String(typeof e === 'object' ? e.event_id : e))}`}
                        >
                          <Badge variant="info">
                            Evento #{String(typeof e === 'object' ? e.event_id : e)}
                          </Badge>
                        </a>
                      ))}
                    </div>
                  </>
                )}
              </div>
              <div className="text-[13.5px]">
                <h3 className="mb-2 font-semibold">Servicios externos</h3>
                {x.enriquecimiento?.length ? (
                  x.enriquecimiento.map((e) => (
                    <div key={e.provider} className="mb-2 rounded-xl border border-line p-2.5">
                      <div className="flex items-center justify-between">
                        <b>{e.provider}</b>
                        <Badge variant={VC[e.verdict] ?? 'gray'}>
                          {e.verdict}
                          {e.score != null && ` · ${e.score}`}
                        </Badge>
                      </div>
                      <div className="mono mt-1 break-words text-[11.5px] text-muted">
                        {Object.entries(e.data ?? {})
                          .filter(([, v]) => v != null && v !== '' && !(Array.isArray(v) && !v.length))
                          .map(([k, v]) => (
                            <div key={k}>
                              {k}:{' '}
                              {Array.isArray(v)
                                ? v.join(', ')
                                : typeof v === 'object'
                                  ? JSON.stringify(v)
                                  : String(v)}
                            </div>
                          ))}
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-muted">
                    No hay servicios aplicables a este tipo. Configura claves en{' '}
                    <Link className="text-brand" to="/iocs?view=integrar" onClick={close}>
                      Integrar
                    </Link>
                    .
                  </p>
                )}
              </div>
            </div>
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="secondary" size="sm" asChild>
                <Link to={`/intel?q=${encodeURIComponent(x.value)}`} onClick={close}>
                  <Search /> Buscar en el portal
                </Link>
              </Button>
              {canWrite && sophosKind && (
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() =>
                    setBlock({ kind: sophosKind, target: { values: [x.value] }, label: x.value })
                  }
                >
                  <Ban /> Bloquear en Sophos
                </Button>
              )}
              {canWrite && (
                <Button
                  size="sm"
                  onClick={() => {
                    close();
                    newInc.open({
                      title: `IoC: ${x.value}`,
                      iocs: x.value,
                      detected_by: 'Motor de inteligencia',
                      runbook: 'misp-ioc-match',
                    });
                  }}
                >
                  <Plus /> Crear incidente
                </Button>
              )}
            </div>
          </>
        )}
      </DialogContent>
      <ActionDialog req={block} onClose={() => setBlock(null)} />
    </Dialog>
  );
}
