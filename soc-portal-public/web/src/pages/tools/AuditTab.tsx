import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronDown, Download, Play } from 'lucide-react';
import { toast } from 'sonner';
import { Empty, ErrorState, Kpi, Loading } from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Select } from '@/components/ui/input';
import { useAuth } from '@/hooks/useAuth';
import { nf, short } from '@/lib/format';
import { cn } from '@/lib/utils';
import { useAudit, useAudits, useFindingToVuln, useStartAudit } from '@/services/tools';
import { FSEV, FindingSev } from './common';
import type { FindingSeverity, Tool } from '@/types/api';

const PHASES = ['Reconocimiento', 'Búsqueda', 'Validación', 'Esquema', 'Informe'];

export function AuditTab({ tool, active }: { tool: Tool; active: boolean }) {
  const { canWrite } = useAuth();
  const list = useAudits(tool.slug, active);
  const [profile, setProfile] = useState('standard');
  const [sel, setSel] = useState<number | null>(null);
  const start = useStartAudit(tool.slug);
  const toVuln = useFindingToVuln(tool.slug);
  const rows = list.data?.rows ?? [];
  const aid = sel ?? rows[0]?.id ?? null;
  const cur = rows.find((r) => r.id === aid);
  const a = useAudit(tool.slug, aid);
  if (list.isPending) return <Loading rows={1} />;
  if (list.error || !list.data) return <ErrorState error={list.error} compact />;
  const L = list.data;
  const A = a.data;
  const conf = A?.findings.filter((f) => f.status === 'confirmed') ?? [];
  const nv = A?.findings.filter((f) => f.status === 'needs_validation') ?? [];
  const base = `/portal/api/tools/${encodeURIComponent(tool.slug)}/audits`;
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-[240px] flex-1">
          <b>Auditoría de seguridad del código</b>
          <p className="mt-1 text-xs leading-relaxed text-muted">
            Análisis estático asistido por IA, con la metodología del <i>security-audit skill</i> de
            Cloudflare: reconocimiento → búsqueda por archivo → validación independiente de cada hallazgo →
            esquema → informe. Un hallazgo solo se confirma si describe la <b>frontera de confianza</b> que se
            cruza; lo que depende del despliegue queda «por validar». El código no se ejecuta.
            {!L.local && <b> El código se envía al proveedor de IA en la nube.</b>}
          </p>
        </div>
        <span className="flex items-center gap-1.5">
          <Select
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            className="w-auto"
            aria-label="Perfil"
          >
            {Object.entries(L.profiles).map(([k, p]) => (
              <option key={k} value={k}>
                {p.label} · hasta {p.files} archivos
              </option>
            ))}
          </Select>
          <Button
            size="sm"
            disabled={!L.ai || cur?.status === 'running' || !canWrite || start.isPending}
            onClick={() =>
              start.mutate(profile, {
                onSuccess: (r) => {
                  toast.success('Auditoría iniciada');
                  setSel(r.id);
                },
                onError: (e) => toast.error(`Error: ${e.message}`),
              })
            }
          >
            <Play /> Auditar
          </Button>
        </span>
      </div>
      {!L.ai && <Empty>Configura el asistente de IA (AI_PROVIDER, AI_MODEL) para auditar.</Empty>}
      {rows.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-1">
          {rows.slice(0, 8).map((r) => (
            <button
              key={r.id}
              type="button"
              onClick={() => setSel(r.id)}
              className={cn(
                'cursor-pointer rounded-lg border border-line px-2.5 py-1 text-xs font-semibold text-muted hover:text-ink',
                r.id === aid && 'border-brand bg-brand-soft text-brand',
              )}
            >
              #{r.id} · {r.started}{' '}
              {r.status === 'running'
                ? '⏳'
                : r.status === 'error'
                  ? '⚠'
                  : `· ${r.counts.confirmed}✔ ${r.counts.needs_validation}?`}
            </button>
          ))}
        </div>
      )}
      {!rows.length ? (
        <Empty>Sin auditorías todavía.</Empty>
      ) : !A ? (
        <Loading rows={1} />
      ) : A.status === 'running' ? (
        <div className="py-6">
          <div className="flex flex-wrap justify-center gap-1.5">
            {PHASES.map((p, i) => {
              const ph = parseInt(A.progress) || 1;
              return (
                <div
                  key={p}
                  className={cn(
                    'flex items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-[13px] text-muted',
                    i + 1 < ph && 'text-ink',
                    i + 1 === ph && 'border-brand text-brand',
                  )}
                >
                  <span
                    className={cn(
                      'grid size-5 place-items-center rounded-full bg-grid text-[11px] font-bold',
                      i + 1 < ph && 'bg-st-good text-white',
                      i + 1 === ph && 'bg-brand text-brand-ink',
                    )}
                  >
                    {i + 1}
                  </span>
                  {p}
                </div>
              );
            })}
          </div>
          <p className="mt-3 text-center text-[13px] text-muted">{A.progress}</p>
        </div>
      ) : A.status === 'error' ? (
        <ErrorState error={`La auditoría falló: ${A.error}`} compact />
      ) : (
        <>
          <div className="mb-3 grid grid-cols-2 gap-2.5 md:grid-cols-4">
            <Kpi
              title="Confirmados"
              value={nf(conf.length)}
              hint={
                (Object.keys(FSEV) as FindingSeverity[])
                  .map((s) => {
                    const n = conf.filter((f) => f.severity === s).length;
                    return n ? `${n} ${FSEV[s][0].toLowerCase()}` : '';
                  })
                  .filter(Boolean)
                  .join(' · ') || 'ninguno'
              }
              alert={conf.some((f) => f.severity === 'critical' || f.severity === 'high')}
            />
            <Kpi title="Por validar" value={nf(nv.length)} hint="dependen del despliegue" />
            <Kpi
              title="Señales automáticas"
              value={nf(A.signals.length)}
              hint="pistas de patrones, no hallazgos"
            />
            <Kpi
              title="Llamadas a la IA"
              value={nf(A.cost.llamadas ?? 0)}
              hint={`${short((A.cost.tokens_in ?? 0) + (A.cost.tokens_out ?? 0))} tokens · ${A.cost.archivos ?? 0} archivos`}
            />
          </div>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-xs text-muted">
            <span>
              Por {A.user} · {A.started} → {A.finished}
            </span>
            <span className="flex gap-1">
              <Button variant="secondary" size="sm" asChild>
                <a href={`${base}/${A.id}/export?fmt=md`}>
                  <Download /> Informe .md
                </a>
              </Button>
              <Button variant="secondary" size="sm" asChild>
                <a href={`${base}/${A.id}/export?fmt=json`}>
                  <Download /> findings.json
                </a>
              </Button>
            </span>
          </div>
          {A.recon?.proposito && (
            <Collapsible className="card mb-3 p-3 shadow-none">
              <CollapsibleTrigger className="group flex w-full cursor-pointer items-center gap-1 text-left text-[13.5px]">
                <ChevronDown className="size-4 transition-transform group-data-[state=open]:rotate-180" />
                <b>Reconocimiento</b> — {A.recon.proposito}
              </CollapsibleTrigger>
              <CollapsibleContent className="mt-2 text-[13px]">
                <b>Puntos de entrada:</b>
                <ul className="list-disc pl-5">
                  {(A.recon.puntos_entrada ?? []).map((x) => (
                    <li key={x}>{x}</li>
                  ))}
                </ul>
                <b>Fronteras de confianza:</b>
                <ul className="list-disc pl-5">
                  {(A.recon.fronteras ?? []).map((x) => (
                    <li key={x}>{x}</li>
                  ))}
                </ul>
              </CollapsibleContent>
            </Collapsible>
          )}
          {A.findings.length ? (
            A.findings.map((f) => (
              <div
                key={f.id}
                className={cn(
                  'mb-2.5 rounded-xl border border-line border-l-4 px-3.5 py-3',
                  f.status === 'confirmed' ? 'border-l-st-warn' : 'border-l-s-neutral',
                )}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <FindingSev s={f.severity} />
                      <b>
                        {f.id} · {f.title}
                      </b>
                    </div>
                    <div className="mt-0.5 text-xs text-muted">
                      <Link className="mono text-brand" to={`/tools/${tool.slug}/file/${f.file_id}`}>
                        {f.file}:{f.line_start}
                      </Link>{' '}
                      · {f.class}
                    </div>
                  </div>
                  {f.status === 'confirmed' && canWrite && (
                    <Button
                      variant="secondary"
                      size="sm"
                      title="Crear una vulnerabilidad en seguimiento"
                      onClick={() =>
                        toVuln.mutate(
                          { aid: A.id, fid: f.id },
                          {
                            onSuccess: (r) =>
                              toast.success(
                                r.nuevo
                                  ? 'Añadida a Vulnerabilidades'
                                  : 'Ya estaba en seguimiento (actualizada)',
                              ),
                            onError: (e) => toast.error(`Error: ${e.message}`),
                          },
                        )
                      }
                    >
                      → Vulnerabilidades
                    </Button>
                  )}
                </div>
                {f.status === 'confirmed' ? (
                  <>
                    <div className="my-2.5 grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
                      {(
                        [
                          ['Quién', f.boundary.principal],
                          ['Entrada', f.boundary.input],
                          ['Control superado', f.boundary.control],
                          ['Resultado', f.boundary.result],
                        ] as const
                      ).map(([k, v]) => (
                        <div key={k} className="rounded-lg bg-grid px-2 py-1.5">
                          <small className="block text-[10.5px] uppercase tracking-wide text-muted">
                            {k}
                          </small>
                          {v}
                        </div>
                      ))}
                    </div>
                    <div className="text-[13px]">
                      <b>Impacto:</b> {f.impact}
                    </div>
                    <div className="mt-0.5 text-[13px]">
                      <b>Corrección:</b> {f.fix}
                    </div>
                  </>
                ) : (
                  <div className="mt-1.5 text-[13px]">
                    <b>Por qué falta validar:</b> {f.reason}
                    {f.fix && (
                      <div className="mt-0.5">
                        <b>Sugerencia:</b> {f.fix}
                      </div>
                    )}
                  </div>
                )}
                {f.evidence && (
                  <pre className="mt-2 overflow-auto whitespace-pre-wrap rounded-lg bg-grid px-2.5 py-2 font-mono text-xs">
                    {f.evidence}
                  </pre>
                )}
              </div>
            ))
          ) : (
            <Empty>✔ Sin hallazgos confirmados ni por validar en los archivos revisados.</Empty>
          )}
          {A.signals.length > 0 && (
            <Collapsible className="mt-3">
              <CollapsibleTrigger className="group flex cursor-pointer items-center gap-1 text-[13px] text-muted">
                <ChevronDown className="size-4 transition-transform group-data-[state=open]:rotate-180" />{' '}
                Señales automáticas ({A.signals.length}) — patrones que el cazador revisó
              </CollapsibleTrigger>
              <CollapsibleContent>
                <ul className="mt-2 divide-y divide-line text-xs">
                  {A.signals.slice(0, 100).map((s, i) => (
                    <li key={i} className="flex gap-2 py-1.5">
                      <Badge variant="gray">{s.type}</Badge>
                      <Link className="mono shrink-0 text-brand" to={`/tools/${tool.slug}/file/${s.file_id}`}>
                        {s.file}:{s.line}
                      </Link>
                      <span className="mono break-all">{s.code}</span>
                    </li>
                  ))}
                </ul>
              </CollapsibleContent>
            </Collapsible>
          )}
        </>
      )}
    </div>
  );
}
