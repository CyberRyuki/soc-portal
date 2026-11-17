import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Bot, ClipboardList, Download, Plus, Send, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { usePageEnter } from '@/components/layout/AppShell';
import { Empty, ErrorState, Loading, PageHeader } from '@/components/shared';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Textarea } from '@/components/ui/input';
import { useAuth } from '@/hooks/useAuth';
import { useConfirm } from '@/hooks/useConfirm';
import { textDownload } from '@/lib/format';
import { cn } from '@/lib/utils';
import {
  useAiChat,
  useAiChats,
  useAiRun,
  useAiStatus,
  useDeleteChat,
  useNewChat,
  useSendMessage,
} from '@/services/ai';
import { takePending } from './investigate';
import { STARTERS, TOOL_NAME, VERDICT, argsText } from './common';
import { Message, LiveRun } from './Message';

export default function AiPage() {
  const { cid = '' } = useParams();
  const ref = usePageEnter('ai' + cid);
  const nav = useNavigate();
  const { isAdmin, canWrite } = useAuth();
  const status = useAiStatus();
  const chats = useAiChats();
  const newChat = useNewChat();
  useEffect(() => {
    document.title = 'Portal SOC · Asistente IA';
  }, []);
  const on = !!status.data?.on;
  const can = canWrite && on;
  const create = async (text?: string) => {
    try {
      const r = await newChat.mutateAsync({ title: text ? text.slice(0, 70) : 'Nueva investigación' });
      if (text) sessionStorage.setItem('ai_pending_' + r.id, text);
      nav(`/ai/${r.id}`);
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  };
  if (status.isPending || chats.isPending) return <Loading />;
  if (status.error || chats.error) return <ErrorState error={status.error ?? chats.error} />;
  const S = status.data!;
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Asistente de investigación"
        subtitle="Pregunta en lenguaje natural: el asistente consulta Wazuh, MISP, IoC, incidentes, runbooks y MITRE, cita cada dato y un verificador independiente revisa la respuesta."
        actions={
          <>
            {isAdmin && (
              <Button variant="secondary" size="sm" asChild>
                <Link to="/ai/audit">
                  <ClipboardList /> Registro de uso
                </Link>
              </Button>
            )}
            <Button size="sm" disabled={!can} onClick={() => create()}>
              <Plus /> Nueva investigación
            </Button>
          </>
        }
      />
      {on ? (
        <div className="flex flex-wrap items-center gap-2 text-[13px]">
          <i className={cn('size-2 rounded-full', S.local ? 'bg-st-good' : 'bg-st-warn')} />
          <b>{S.provider}</b> · {S.model}
          <span className="text-muted">
            {S.local
              ? '· modelo local: los datos no salen de la red'
              : `· proveedor en la nube${S.redact ? ' · correos enmascarados antes de enviar' : ''}`}{' '}
            · {S.tools.length} herramientas de solo lectura · las acciones solo se proponen
          </span>
        </div>
      ) : (
        <section className="card border-warn/50 p-4 text-[13.5px]">
          <b>El asistente no está configurado.</b>
          <p className="mt-1">
            Un administrador debe definir en el <span className="mono">.env</span> del portal:{' '}
            <span className="mono">AI_PROVIDER</span> (<i>ollama</i> u <i>openai</i> para un modelo local o
            compatible, o <i>anthropic</i>), <span className="mono">AI_MODEL</span> y{' '}
            <span className="mono">AI_BASE_URL</span> o <span className="mono">AI_API_KEY</span>. Para datos
            del gobierno se recomienda un modelo local (Ollama/vLLM).
          </p>
        </section>
      )}
      {!canWrite && (
        <p className="text-[13px] text-muted">Tu rol (solo lectura) no puede iniciar investigaciones.</p>
      )}
      <div className="grid gap-3.5 lg:grid-cols-[260px_1fr]">
        <aside className="card max-h-[calc(100vh-230px)] overflow-auto p-1.5 scroll-thin lg:sticky lg:top-4">
          <div className="flex justify-between px-2.5 pb-2 pt-2.5 text-[11px] font-bold uppercase tracking-wide text-muted">
            Investigaciones <span>{chats.data.length}</span>
          </div>
          {chats.data.length ? (
            chats.data.map((c) => (
              <Link
                key={c.id}
                to={`/ai/${c.id}`}
                className={cn('block rounded-lg px-2.5 py-2 hover:bg-grid', c.id === cid && 'bg-brand-soft')}
              >
                <b className={cn('block truncate text-[13px]', c.id === cid && 'text-brand')}>{c.title}</b>
                <small className="text-[11.5px] text-muted">{c.updated}</small>
              </Link>
            ))
          ) : (
            <Empty className="py-4">Aún no hay investigaciones.</Empty>
          )}
        </aside>
        <section className="card flex min-h-[calc(100vh-230px)] min-w-0 flex-col">
          {cid ? (
            <Chat cid={cid} can={can} />
          ) : (
            <div className="m-auto max-w-[760px] p-8 text-center">
              <Bot className="mx-auto size-11 text-brand" />
              <h2 className="mt-2 text-lg font-bold">¿Qué quieres investigar?</h2>
              <p className="text-[13.5px] text-muted">
                Elige un ejemplo o escribe tu pregunta. Puedes pegar IPs, dominios, hashes o códigos de
                incidente.
              </p>
              <div className="mt-5 grid gap-2.5 text-left sm:grid-cols-2 lg:grid-cols-3">
                {STARTERS.map(([i, t]) => (
                  <button
                    key={t}
                    type="button"
                    disabled={!can}
                    onClick={() => create(t)}
                    className="flex cursor-pointer items-start gap-2.5 rounded-xl border border-line bg-card p-3 text-[13px] leading-snug transition-colors hover:border-brand hover:bg-brand-soft disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <span className="text-lg">{i}</span>
                    {t}
                  </button>
                ))}
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function Chat({ cid, can }: { cid: string; can: boolean }) {
  const nav = useNavigate();
  const chat = useAiChat(cid);
  const del = useDeleteChat();
  const send = useSendMessage(cid);
  const [confirm, dialog] = useConfirm();
  const [text, setText] = useState('');
  const [verify, setVerify] = useState(true);
  const [rid, setRid] = useState<string | null>(null);
  const [pendingQ, setPendingQ] = useState<string | null>(null);
  const run = useAiRun(rid);
  const box = useRef<HTMLDivElement>(null);
  const active = !!rid && (!run.data || run.data.status === 'running');
  const submit = async (q: string) => {
    const v = q.trim();
    if (!v || send.isPending || active) return;
    setText('');
    setPendingQ(v);
    try {
      const r = await send.mutateAsync({ text: v, verify });
      setRid(r.run);
    } catch (e) {
      setPendingQ(null);
      toast.error(`Error: ${(e as Error).message}`);
    }
  };
  // pregunta pendiente (viene de «Investigar con IA» o de un ejemplo)
  useEffect(() => {
    const p = takePending(cid);
    if (p && can) Promise.resolve().then(() => submit(p));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cid, can]);
  // al terminar la ejecución, se recarga la conversación
  useEffect(() => {
    if (rid && run.data && run.data.status !== 'running') void chat.refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rid, run.data?.status]);
  useEffect(() => {
    box.current?.scrollTo({ top: box.current.scrollHeight });
  }, [chat.data, run.data, pendingQ]);
  const exportMd = () => {
    const c = chat.data;
    if (!c) return;
    const txt =
      `# ${c.title}\n\n${c.context ? `> Contexto: ${c.context}\n\n` : ''}` +
      c.messages
        .map((m) =>
          m.role === 'user'
            ? `## 👤 ${m.at}\n\n${m.content}\n`
            : `## 🤖 ${m.at} · ${(VERDICT[m.meta.verdict?.veredicto ?? ''] ?? VERDICT.sin_verificar)![0]}\n\n${m.content}\n\n${(m.meta.evidence ?? []).map((e) => `- **${e.ref}** ${TOOL_NAME[e.tool] ?? e.tool} (${argsText(e.args)})`).join('\n')}\n`,
        )
        .join('\n');
    textDownload(`investigacion-${cid}.md`, txt);
  };
  const msgs = useMemo(() => chat.data?.messages ?? [], [chat.data]);
  if (chat.isPending) return <Loading />;
  if (chat.error || !chat.data) return <ErrorState error={chat.error} />;
  const c = chat.data;
  return (
    <>
      <div className="flex items-center gap-2 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <b className="block truncate">{c.title}</b>
          {c.context && (
            <div className="truncate text-xs text-muted">Contexto: {c.context.slice(0, 140)}</div>
          )}
        </div>
        <span className="flex-1" />
        <Button variant="secondary" size="icon-sm" title="Descargar como Markdown" onClick={exportMd}>
          <Download />
        </Button>
        <Button
          variant="secondary"
          size="icon-sm"
          title="Eliminar"
          onClick={async () => {
            if (
              await confirm({
                title: '¿Eliminar esta investigación?',
                confirmText: 'Eliminar',
                destructive: true,
              })
            ) {
              await del.mutateAsync(cid);
              nav('/ai');
            }
          }}
        >
          <Trash2 />
        </Button>
      </div>
      <div
        ref={box}
        className="flex max-h-[calc(100vh-360px)] min-h-[300px] flex-1 flex-col gap-3.5 overflow-auto p-4 scroll-thin"
      >
        {msgs.length || pendingQ ? (
          msgs.map((m) => <Message key={m.id} m={m} can={can} />)
        ) : (
          <Empty>Escribe tu primera pregunta.</Empty>
        )}
        {pendingQ && (active || chat.isFetching) && (
          <Message
            m={{ id: -1, chat_id: cid, role: 'user', content: pendingQ, meta: {}, at: 'ahora' }}
            can={can}
          />
        )}
        {active && <LiveRun run={run.data} />}
      </div>
      <form
        className="flex flex-col gap-2 border-t border-line px-4 py-3"
        onSubmit={(e) => {
          e.preventDefault();
          void submit(text);
        }}
      >
        <Textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          disabled={!can || active}
          rows={2}
          className="min-h-[52px] text-sm"
          placeholder="Pregunta, o pega indicadores… (Enter para enviar, Mayús+Enter para salto de línea)"
          aria-label="Pregunta"
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              void submit(text);
            }
          }}
        />
        <div className="flex items-center justify-between gap-2">
          <label
            className="flex items-center gap-2 text-[13px]"
            title="Un segundo modelo contrasta cada dato con las evidencias (más lento, más fiable)"
          >
            <Checkbox checked={verify} onCheckedChange={(v) => setVerify(v === true)} /> Verificar respuesta
          </label>
          <Button type="submit" disabled={!can || active || send.isPending}>
            <Send /> Enviar
          </Button>
        </div>
      </form>
      {dialog}
    </>
  );
}
