import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Loader2, Search } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Empty, SevPill } from '@/components/shared';
import { renderMarkdown } from '@/lib/markdown';
import { nf } from '@/lib/format';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import { useConfirm } from '@/hooks/useConfirm';
import { useNewIncident } from '@/pages/incidents/NewIncidentDialog';
import { TOOL_NAME, VERDICT, argsText, prettyJson } from './common';
import type { AiMessage, AiProposal, AiRun } from '@/types/api';

/** Convierte las citas [E1] en botones que abren la evidencia correspondiente. */
function Cited({ html, onCite }: { html: string; onCite: (ref: string) => void }) {
  const parts = useMemo(() => html.split(/(\[E\d+\])/g), [html]);
  return (
    <div className="md text-sm [&>p:first-child]:mt-0 [&>p:last-child]:mb-0">
      {parts.map((p, i) => {
        const m = /^\[(E\d+)\]$/.exec(p);
        return m ? (
          <button
            key={i}
            type="button"
            onClick={() => onCite(m[1]!)}
            className="mx-0.5 inline-block cursor-pointer rounded bg-brand-soft px-1 py-0.5 align-[1px] font-mono text-[10.5px] font-semibold text-brand"
          >
            {m[1]}
          </button>
        ) : (
          <span key={i} dangerouslySetInnerHTML={{ __html: p }} />
        );
      })}
    </div>
  );
}

export function Message({ m, can }: { m: AiMessage; can: boolean }) {
  const [showEv, setShowEv] = useState(false);
  const [openRef, setOpenRef] = useState<string | null>(null);
  const html = useMemo(() => (m.role === 'assistant' && !m.meta.error ? renderMarkdown(m.content) : ''), [m]);
  if (m.role === 'user') {
    return (
      <div className="flex max-w-[88%] flex-col items-end self-end">
        <div className="whitespace-pre-wrap rounded-[14px_14px_4px_14px] bg-brand px-3.5 py-2.5 text-sm text-brand-ink">
          {m.content}
        </div>
        <small className="mx-1.5 mt-0.5 text-[11px] text-muted">{m.at}</small>
      </div>
    );
  }
  const x = m.meta;
  const v = VERDICT[x.verdict?.veredicto ?? ''] ?? VERDICT.sin_verificar!;
  const ev = x.evidence ?? [];
  return (
    <div className="flex w-[88%] flex-col self-start">
      <div className="min-w-0 rounded-[14px_14px_14px_4px] border border-line bg-grid px-4 py-3">
        {x.error ? (
          <div className="text-[13px] text-bad">{m.content}</div>
        ) : (
          <>
            <Cited
              html={html}
              onCite={(r) => {
                setShowEv(true);
                setOpenRef(r);
              }}
            />
            {(x.proposals ?? []).map((p, i) => (
              <Proposal key={i} p={p} can={can} />
            ))}
            <div className="mt-2.5 flex flex-wrap items-center gap-2.5 border-t border-dashed border-line pt-2 text-xs">
              <Badge variant={v[1]} title={(x.verdict?.problemas ?? []).join(' · ')}>
                {v[0]}
                {x.verdict?.confianza != null && ` · ${x.verdict.confianza}%`}
              </Badge>
              {ev.length ? (
                <button
                  type="button"
                  className="cursor-pointer font-semibold text-brand"
                  onClick={() => setShowEv((s) => !s)}
                >
                  <Search className="inline size-3" /> {ev.length} evidencias
                </button>
              ) : (
                <span className="text-muted">sin herramientas</span>
              )}
              {!!x.injections && (
                <Badge
                  variant="bad"
                  title="Se detectaron posibles instrucciones incrustadas en los datos; se marcaron y no se siguieron"
                >
                  ⚠ {x.injections} posible(s) inyección(es)
                </Badge>
              )}
              <span className="text-muted">
                {x.ms ? `${(x.ms / 1000).toFixed(1)} s` : ''}
                {x.tokens && ` · ${nf(x.tokens.in + x.tokens.out)} tokens`}
              </span>
            </div>
            {!!x.verdict?.problemas?.length && (
              <div className="mt-1.5 text-xs text-muted">Verificador: {x.verdict.problemas.join(' · ')}</div>
            )}
            {showEv && (
              <div className="mt-2 space-y-1.5">
                {ev.map((e) => (
                  <details
                    key={e.ref}
                    open={openRef === e.ref}
                    className={cn(
                      'rounded-lg border border-line bg-card',
                      openRef === e.ref && 'ring-2 ring-brand',
                    )}
                  >
                    <summary className="cursor-pointer truncate px-2.5 py-1.5 text-[12.5px]">
                      <Badge variant="info">{e.ref}</Badge> {TOOL_NAME[e.tool] ?? e.tool}{' '}
                      <span className="text-muted">{argsText(e.args)}</span>
                    </summary>
                    <pre className="max-h-[260px] overflow-auto whitespace-pre-wrap break-all border-t border-line p-2.5 font-mono text-[11.5px]">
                      {prettyJson(e.data)}
                    </pre>
                  </details>
                ))}
              </div>
            )}
          </>
        )}
      </div>
      <small className="mx-1.5 mt-0.5 text-[11px] text-muted">{m.at}</small>
    </div>
  );
}

function Proposal({ p, can }: { p: AiProposal; can: boolean }) {
  const newInc = useNewIncident();
  const { meta } = useAuth();
  const [confirm, dialog] = useConfirm();
  const apply = async () => {
    if (p.tipo === 'incidente')
      return newInc.open({
        title: p.title,
        severity: p.severity,
        summary: p.summary,
        iocs: p.iocs,
        assets: p.assets,
        runbook: p.runbook,
        detected_by: p.detected_by,
      });
    if (
      !(await confirm({
        title: `¿Añadir esta nota a ${p.code}?`,
        description: p.text,
        confirmText: 'Añadir nota',
      }))
    )
      return;
    try {
      await api.post(`api/incidents/${encodeURIComponent(p.code)}/notes`, {
        text: `[Asistente IA, revisado por ${meta?.user ?? ''}] ${p.text}`,
      });
      toast.success(`Nota añadida a ${p.code}`);
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  };
  return (
    <div className="mt-2.5 flex items-center justify-between gap-3 rounded-xl border border-brand/40 bg-card px-3 py-2.5">
      <div className="min-w-0 text-[13px]">
        <b>{p.tipo === 'incidente' ? '📝 Propuesta de incidente' : `🗒 Propuesta de nota para ${p.code}`}</b>
        <div className="mt-1">
          {p.tipo === 'incidente' ? (
            <>
              <SevPill v={p.severity} /> <b>{p.title}</b>
              <div className="mt-1 text-muted">{p.summary.slice(0, 300)}</div>
            </>
          ) : (
            p.text.slice(0, 400)
          )}
        </div>
      </div>
      <Button size="sm" disabled={!can} onClick={apply}>
        {p.tipo === 'incidente' ? 'Revisar y crear…' : 'Añadir nota'}
      </Button>
      {dialog}
    </div>
  );
}

/** Pasos en vivo de la ejecución (herramientas consultadas, verificación). */
export function LiveRun({ run }: { run: AiRun | undefined }) {
  const events = run?.events ?? [];
  return (
    <div className="flex w-[88%] flex-col self-start">
      <div className="rounded-[14px_14px_14px_4px] border border-line bg-grid px-4 py-3 text-[13px]">
        {!events.length && (
          <div className="flex items-center gap-2">
            <Loader2 className="size-3.5 animate-spin text-brand" /> Preparando…
          </div>
        )}
        {events.map((ev, i) => {
          const last = i === events.length - 1 && run?.status === 'running';
          return (
            <div
              key={i}
              className={cn(
                'flex items-center gap-2 py-0.5',
                ev.kind === 'warn' ? 'text-bad' : last ? 'text-ink' : 'text-muted',
              )}
            >
              {last ? (
                <Loader2 className="size-3.5 animate-spin text-brand" />
              ) : (
                <span className="w-3.5 font-bold text-ok">✓</span>
              )}
              {ev.kind === 'tool' ? (
                <>
                  <Badge variant="info">{ev.ref}</Badge> {TOOL_NAME[ev.name ?? ''] ?? ev.name}{' '}
                  <span className="text-muted">{argsText(ev.args)}</span>
                </>
              ) : ev.kind === 'warn' ? (
                `⚠ ${ev.text}`
              ) : ev.kind === 'verify' ? (
                `🛡 ${ev.text}`
              ) : (
                ev.text
              )}
              <span className="ml-auto text-xs text-muted">{ev.t}s</span>
            </div>
          );
        })}
        {run?.status === 'error' && <Empty className="py-2 text-bad">{run.error}</Empty>}
      </div>
    </div>
  );
}
