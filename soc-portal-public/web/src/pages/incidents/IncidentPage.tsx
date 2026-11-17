import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { ArrowLeft, Bot, CheckCircle2, ExternalLink, RotateCcw, Search, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { usePageEnter } from '@/components/layout/AppShell';
import { ErrorState, FieldError, Loading, Panel, SevPill, StatusPill } from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input, Select, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/hooks/useAuth';
import { SEVERITIES, SEV_LABEL, STATUSES, STATUS_LABEL } from '@/lib/constants';
import { cn } from '@/lib/utils';
import { useAddNote, useIncident, useUpdateIncident } from '@/services/incidents';
import { startInvestigation } from '@/pages/ai/investigate';
import { CloseIncidentDialog, DeleteIncidentDialog } from './IncidentActions';

const schema = z.object({
  title: z.string().trim().min(3).max(200),
  status: z.enum(STATUSES),
  severity: z.enum(SEVERITIES),
  owner: z.string().max(80),
  detected_at: z.string().max(40),
  detected_by: z.string().max(200),
  assets: z.string().max(500),
  runbook: z.string().max(80),
  summary: z.string().max(10000),
  iocs: z.string().max(10000),
  root_cause: z.string().max(10000),
  lessons: z.string().max(10000),
});
type Form = z.infer<typeof schema>;
const KIND_COLOR: Record<string, string> = { note: 'bg-st-good', status: 'bg-st-warn', created: 'bg-brand' };
const tr = (t: string) =>
  t.replace(
    /\b(Status|Severity|Owner)\b/g,
    (m) => ({ Status: 'Estado', Severity: 'Severidad', Owner: 'Responsable' })[m] ?? m,
  );

export default function IncidentPage() {
  const { code = '' } = useParams();
  const ref = usePageEnter(code);
  const nav = useNavigate();
  const { meta, canWrite, isAdmin } = useAuth();
  const [dlg, setDlg] = useState<'' | 'close' | 'delete'>('');
  const q = useIncident(code);
  const update = useUpdateIncident(code);
  const addNote = useAddNote(code);
  const form = useForm<Form>({ resolver: zodResolver(schema) });
  const noteForm = useForm<{ text: string }>({ defaultValues: { text: '' } });
  const x = q.data;
  useEffect(() => {
    if (x) {
      document.title = `Portal SOC · ${x.code}`;
      form.reset({
        title: x.title,
        status: x.status,
        severity: x.severity,
        owner: x.owner,
        detected_at: x.detected_at,
        detected_by: x.detected_by,
        assets: x.assets,
        runbook: x.runbook,
        summary: x.summary,
        iocs: x.iocs,
        root_cause: x.root_cause,
        lessons: x.lessons,
      });
    }
  }, [x, form]);
  if (q.isPending) return <Loading rows={2} />;
  if (q.error || !x) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const rb = meta?.runbooks.find((r) => r.slug === x.runbook)?.title ?? x.runbook;
  const save = form.handleSubmit(async (v) => {
    try {
      await update.mutateAsync(v);
      toast.success('Guardado');
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  });
  const note = noteForm.handleSubmit(async (v) => {
    if (!v.text.trim()) return;
    try {
      await addNote.mutateAsync(v.text.trim());
      noteForm.reset({ text: '' });
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  });
  const E = form.formState.errors;
  const ro = !canWrite;
  const iocs = (x.iocs || '').split(/\s+/).filter(Boolean);
  return (
    <div ref={ref} className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="secondary" size="sm" asChild>
          <Link to="/incidents">
            <ArrowLeft /> Incidentes
          </Link>
        </Button>
        <span className="flex-1" />
        <span className="text-xs text-muted">
          Creado por {x.created_by} · {x.created_at}
        </span>
        <Button
          size="sm"
          onClick={() =>
            startInvestigation(nav, {
              title: `${x.code} · ${x.title}`,
              context: `Incidente ${x.code}: ${x.title}. Severidad ${x.severity}, estado ${x.status}. Activos: ${x.assets || '—'}. IoC: ${(x.iocs || '').replace(/\s+/g, ' ').slice(0, 400)}`,
              question: `Investiga el incidente ${x.code}: revisa su cronología, comprueba los IoC y las alertas relacionadas, indica la técnica MITRE y el runbook, y propón los siguientes pasos.`,
            })
          }
        >
          <Bot /> Investigar con IA
        </Button>
        {canWrite &&
          (x.status === 'Closed' ? (
            <Button
              size="sm"
              variant="secondary"
              disabled={update.isPending}
              onClick={async () => {
                try {
                  await update.mutateAsync({ status: 'Investigating' });
                  toast.success(`${x.code} reabierto`);
                } catch (e) {
                  toast.error(`Error: ${(e as Error).message}`);
                }
              }}
            >
              <RotateCcw /> Reabrir
            </Button>
          ) : (
            <Button size="sm" variant="secondary" onClick={() => setDlg('close')}>
              <CheckCircle2 /> Cerrar incidente
            </Button>
          ))}
        {isAdmin && (
          <Button
            size="sm"
            variant="destructive"
            onClick={() => setDlg('delete')}
            aria-label="Eliminar incidente"
          >
            <Trash2 /> Eliminar
          </Button>
        )}
      </div>
      <CloseIncidentDialog targets={dlg === 'close' ? [x] : []} onOpenChange={(o) => !o && setDlg('')} />
      <DeleteIncidentDialog
        targets={dlg === 'delete' ? [x] : []}
        onOpenChange={(o) => !o && setDlg('')}
        onDone={() => void nav('/incidents')}
      />
      <div>
        <h1 className="text-[22px] font-bold tracking-tight">
          {x.code} · {x.title}
        </h1>
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          <SevPill v={x.severity} />
          <StatusPill v={x.status} />
          {x.runbook && (
            <Link to={`/runbooks/${x.runbook}`}>
              <Badge variant="info">📘 {rb}</Badge>
            </Link>
          )}
        </div>
      </div>
      <div className="grid gap-4 lg:grid-cols-[1.3fr_1fr]">
        <Panel title="Ficha">
          <form onSubmit={save} className="grid gap-3 sm:grid-cols-2" noValidate>
            <fieldset disabled={ro} className="contents">
              <div className="sm:col-span-2">
                <Label htmlFor="i-title">Título</Label>
                <Input id="i-title" {...form.register('title')} />
                <FieldError msg={E.title?.message} />
              </div>
              <div>
                <Label htmlFor="i-st">Estado</Label>
                <Select id="i-st" {...form.register('status')}>
                  {STATUSES.map((s) => (
                    <option key={s} value={s}>
                      {STATUS_LABEL[s]}
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <Label htmlFor="i-sev">Severidad</Label>
                <Select id="i-sev" {...form.register('severity')}>
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {SEV_LABEL[s]}
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <Label htmlFor="i-own">Responsable</Label>
                <Select id="i-own" {...form.register('owner')}>
                  {[...new Set(['', x.owner, ...(meta?.users ?? [])])].map((u) => (
                    <option key={u} value={u}>
                      {u || '—'}
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <Label htmlFor="i-dat">Detectado</Label>
                <Input id="i-dat" {...form.register('detected_at')} />
              </div>
              <div>
                <Label htmlFor="i-dby">Detectado por</Label>
                <Input id="i-dby" {...form.register('detected_by')} />
              </div>
              <div>
                <Label htmlFor="i-ass">Activos afectados</Label>
                <Input id="i-ass" {...form.register('assets')} />
              </div>
              <div className="sm:col-span-2">
                <Label htmlFor="i-rb">Runbook</Label>
                <div className="flex gap-2">
                  <Select id="i-rb" {...form.register('runbook')}>
                    <option value="">— Ninguno —</option>
                    {(meta?.runbooks ?? []).map((r) => (
                      <option key={r.slug} value={r.slug}>
                        {r.title}
                      </option>
                    ))}
                  </Select>
                  {x.runbook && (
                    <Button variant="secondary" size="sm" asChild>
                      <Link to={`/runbooks/${x.runbook}`}>
                        Abrir <ExternalLink />
                      </Link>
                    </Button>
                  )}
                </div>
              </div>
              <div className="sm:col-span-2">
                <Label htmlFor="i-sum">Resumen</Label>
                <Textarea id="i-sum" {...form.register('summary')} />
              </div>
              <div className="sm:col-span-2">
                <Label htmlFor="i-ioc">Indicadores de compromiso (IoC)</Label>
                <Textarea id="i-ioc" className="font-mono text-[12.5px]" {...form.register('iocs')} />
                {iocs.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {iocs.slice(0, 8).map((i) => (
                      <Link key={i} to={`/intel?q=${encodeURIComponent(i)}`}>
                        <Badge variant="info">
                          <Search className="size-3" /> {i}
                        </Badge>
                      </Link>
                    ))}
                  </div>
                )}
              </div>
              <div className="sm:col-span-2">
                <Label htmlFor="i-rc">Causa raíz</Label>
                <Textarea id="i-rc" {...form.register('root_cause')} />
              </div>
              <div className="sm:col-span-2">
                <Label htmlFor="i-le">Lecciones aprendidas</Label>
                <Textarea id="i-le" {...form.register('lessons')} />
              </div>
            </fieldset>
            {canWrite && (
              <div className="flex justify-end sm:col-span-2">
                <Button type="submit" disabled={update.isPending}>
                  Guardar cambios
                </Button>
              </div>
            )}
          </form>
        </Panel>
        <Panel title="Cronología">
          {canWrite && (
            <form onSubmit={note} className="mb-4">
              <Textarea
                placeholder="Añade una acción, hallazgo o decisión…"
                className="min-h-[70px]"
                aria-label="Nueva nota"
                {...noteForm.register('text')}
              />
              <div className="mt-2 text-right">
                <Button size="sm" type="submit" disabled={addNote.isPending}>
                  Añadir a la cronología
                </Button>
              </div>
            </form>
          )}
          <ol className="ml-1.5 border-l-2 border-line">
            {x.events.map((e) => (
              <li key={e.id} className="relative pb-4 pl-5">
                <span
                  className={cn(
                    'absolute -left-[7px] top-1 size-3 rounded-full',
                    KIND_COLOR[e.kind] ?? 'bg-s-neutral',
                  )}
                />
                <div className="text-xs text-muted">
                  {e.at} · {e.author}
                </div>
                <div className="whitespace-pre-wrap text-[13.5px]">{tr(e.text)}</div>
              </li>
            ))}
          </ol>
        </Panel>
      </div>
    </div>
  );
}
