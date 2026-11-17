import { useEffect, useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  FileSpreadsheet,
  Pencil,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
} from 'lucide-react';
import { toast } from 'sonner';
import { usePageEnter } from '@/components/layout/AppShell';
import {
  Dot,
  Empty,
  ErrorState,
  FieldError,
  Kpi,
  KpiGrid,
  Loading,
  PageHeader,
  Panel,
} from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Input, Select } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import { useConfirm } from '@/hooks/useConfirm';
import { useSearchParam } from '@/hooks/useSearchParam';
import { nf } from '@/lib/format';
import { cn } from '@/lib/utils';
import {
  useAcceptBaseline,
  useBulkCheck,
  useCheckAll,
  useCaptureSite,
  useCheckSite,
  useDeface,
  useVisualStatus,
  useDeleteSite,
  useImportSites,
  useParseSites,
  useSaveSite,
  useSites,
} from '@/services/sites';
import type { DefaceLevel, Site, SiteImportRow } from '@/types/api';

const STATE: Record<string, [string, 'ok' | 'bad' | 'warn' | 'gray']> = {
  up: ['En línea', 'ok'],
  down: ['Caído', 'bad'],
  degraded: ['Inestable', 'warn'],
  pending: ['Pendiente', 'gray'],
};
const EV: Record<string, [string, 'ok' | 'bad' | 'warn' | 'info' | 'gray']> = {
  down: ['Caído', 'bad'],
  up: ['Recuperado', 'ok'],
  degraded: ['Fallo', 'warn'],
  content: ['Contenido', 'warn'],
  deface: ['Desfiguración', 'bad'],
  baseline: ['Versión aceptada', 'info'],
  incident: ['Incidente', 'info'],
};
const WAF: Record<string, [string, 'ok' | 'bad' | 'warn' | 'gray']> = {
  waf: ['WAF', 'ok'],
  bypass: ['Bypass WAF', 'bad'],
  directo: ['Sin WAF', 'bad'],
  externo: ['Externo', 'gray'],
};
const DEF: Record<DefaceLevel, [string, 'ok' | 'bad' | 'warn' | 'gray' | 'info']> = {
  ok: ['Sin cambios', 'ok'],
  cambio: ['Cambio', 'info'],
  sospecha: ['Sospecha', 'warn'],
  defacement: ['DESFIGURADO', 'bad'],
};
const PAGE = 50;
const sslDays = (d: string | null, today: string) =>
  d ? Math.round((new Date(d).getTime() - new Date(today).getTime()) / 864e5) : null;

function Strip({ h }: { h: Site['hist'] }) {
  if (!h.length) return <div className="h-[30px] text-xs text-muted">Sin historial aún</div>;
  const mx = Math.max(300, ...h.map((x) => x[2] || 0));
  return (
    <svg
      viewBox={`0 0 ${Math.max(h.length, 48) * 4} 30`}
      preserveAspectRatio="xMaxYMid meet"
      className="block h-[30px] w-full"
      role="img"
      aria-label="Historial de comprobaciones"
    >
      {h.map((x, i) => {
        const hh = x[1] ? Math.max(4, ((x[2] || 0) / mx) * 30) : 30;
        return (
          <rect
            key={i}
            x={i * 4}
            y={30 - hh}
            width={3}
            height={hh}
            rx={1}
            fill={x[1] ? 'var(--st-good)' : 'var(--st-crit)'}
          >
            <title>{`${new Date(x[0] * 1000).toLocaleString('es-DO', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit' })} · ${x[1] ? `${x[2]} ms` : 'fallo'}`}</title>
          </rect>
        );
      })}
    </svg>
  );
}

// ---------------------------------------------------------------- alta / edición
const schema = z.object({
  name: z.string().trim().min(2, 'Escribe un nombre').max(100),
  url: z.string().trim().url('URL no válida').max(500),
  interval_min: z.number().int(),
  expect_code: z.string().regex(/^\d{0,3}$/, 'Código HTTP de 3 cifras'),
  keyword: z.string().max(200),
  owner: z.string().max(80),
  waf: z.string().max(20),
  server: z.string().max(200),
  change_threshold: z.number().int().min(5).max(95),
  critical: z.boolean(),
  watch_content: z.boolean(),
  auto_incident: z.boolean(),
  enabled: z.boolean(),
});
type Form = z.infer<typeof schema>;

function SiteDialog({ site, open, onClose }: { site: Site | null; open: boolean; onClose: () => void }) {
  const { meta } = useAuth();
  const save = useSaveSite();
  const del = useDeleteSite();
  const [confirm, dialog] = useConfirm();
  const form = useForm<Form>({ resolver: zodResolver(schema) });
  useEffect(() => {
    if (open)
      form.reset({
        name: site?.name ?? '',
        url: site?.url ?? '',
        interval_min: site?.interval_min ?? 15,
        expect_code: site?.expect_code != null ? String(site.expect_code) : '',
        keyword: site?.keyword ?? '',
        owner: site?.owner ?? '',
        waf: site?.waf ?? '',
        server: site?.server ?? '',
        change_threshold: site?.change_threshold ?? 40,
        critical: !!site?.critical,
        watch_content: site ? !!site.watch_content : true,
        auto_incident: site ? !!site.auto_incident : true,
        enabled: site ? !!site.enabled : true,
      });
  }, [open, site, form]);
  const submit = form.handleSubmit(async (v) => {
    try {
      await save.mutateAsync({
        id: site?.id ?? null,
        data: { ...v, expect_code: v.expect_code ? Number(v.expect_code) : null },
      });
      toast.success('Guardado');
      onClose();
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  });
  const E = form.formState.errors;
  const ck = (k: 'watch_content' | 'auto_incident' | 'enabled' | 'critical', t: string) => (
    <label className="flex items-center gap-2 text-[13.5px]">
      <Checkbox checked={form.watch(k)} onCheckedChange={(v) => form.setValue(k, v === true)} /> {t}
    </label>
  );
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={site ? 'Editar portal' : 'Añadir portal'}>
        <form onSubmit={submit} className="grid gap-3 sm:grid-cols-2" noValidate>
          <div>
            <Label htmlFor="st-n">Nombre *</Label>
            <Input id="st-n" placeholder="Portal ACME" {...form.register('name')} />
            <FieldError msg={E.name?.message} />
          </div>
          <div>
            <Label htmlFor="st-u">URL *</Label>
            <Input id="st-u" placeholder="https://acme.example" {...form.register('url')} />
            <FieldError msg={E.url?.message} />
          </div>
          <div>
            <Label htmlFor="st-i">Comprobar cada</Label>
            <Select id="st-i" {...form.register('interval_min', { valueAsNumber: true })}>
              {[1, 5, 15, 30, 60].map((n) => (
                <option key={n} value={n}>
                  {n} min
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="st-c">Código HTTP esperado</Label>
            <Input
              id="st-c"
              placeholder="vacío = cualquiera menor de 400"
              {...form.register('expect_code')}
            />
            <FieldError msg={E.expect_code?.message} />
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="st-k">Texto que debe aparecer en la página</Label>
            <Input
              id="st-k"
              placeholder="si falta, se marca como caído (posible desfiguración)"
              {...form.register('keyword')}
            />
          </div>
          <div>
            <Label htmlFor="st-w">Protección WAF</Label>
            <Select id="st-w" {...form.register('waf')}>
              <option value="">Sin dato</option>
              <option value="waf">Pasa por WAF</option>
              <option value="bypass">Bypass (no pasa por WAF)</option>
              <option value="directo">Backend directo (sin WAF)</option>
              <option value="externo">Externo / sin VIP</option>
            </Select>
          </div>
          <div>
            <Label htmlFor="st-t">Umbral de cambio de contenido</Label>
            <Select id="st-t" {...form.register('change_threshold', { valueAsNumber: true })}>
              {[20, 30, 40, 50, 60, 70].map((n) => (
                <option key={n} value={n}>
                  {n} % del texto visible
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="st-s">Servidor</Label>
            <Input id="st-s" {...form.register('server')} />
          </div>
          <div>
            <Label htmlFor="st-o">Responsable</Label>
            <Select id="st-o" {...form.register('owner')}>
              {[...new Set(['', site?.owner ?? '', ...(meta?.users ?? [])])].map((u) => (
                <option key={u} value={u}>
                  {u || '—'}
                </option>
              ))}
            </Select>
          </div>
          <div className="flex flex-wrap gap-4 sm:col-span-2">
            {ck('watch_content', 'Detectar desfiguración')}
            {ck('auto_incident', 'Proponer incidente si cae o se desfigura')}
            {ck('critical', 'Portal crítico (captura primero)')}
            {ck('enabled', 'Activo')}
          </div>
          <p className="text-xs text-muted sm:col-span-2">
            Se declara caído tras 2 fallos seguidos. La detección compara el texto visible, el título y los
            scripts externos con la versión aprobada; los cambios menores al umbral (noticias, contadores) no
            alertan.
          </p>
          <div className="flex items-center justify-between gap-2 sm:col-span-2">
            <span>
              {site && (
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={async () => {
                    if (
                      await confirm({
                        title: '¿Eliminar este portal y su historial?',
                        confirmText: 'Eliminar',
                        destructive: true,
                      })
                    ) {
                      await del.mutateAsync(site.id);
                      onClose();
                    }
                  }}
                >
                  Eliminar
                </Button>
              )}
            </span>
            <span className="flex gap-2">
              <Button variant="secondary" onClick={onClose}>
                Cancelar
              </Button>
              <Button type="submit" disabled={save.isPending}>
                {site ? 'Guardar' : 'Añadir y comprobar'}
              </Button>
            </span>
          </div>
        </form>
        {dialog}
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------- detalle (desfiguración)
function DetailDialog({
  site,
  today,
  onClose,
  onEdit,
}: {
  site: Site | null;
  today: string;
  onClose: () => void;
  onEdit: (s: Site) => void;
}) {
  const { canWrite } = useAuth();
  const D = useDeface(site?.id ?? null);
  const accept = useAcceptBaseline();
  const check = useCheckSite();
  if (!site) return null;
  const d = D.data;
  const [st, stv] = STATE[site.state] ?? [site.state, 'gray'];
  const sd = sslDays(site.ssl_expiry, today);
  return (
    <Dialog open={!!site} onOpenChange={(o) => !o && onClose()}>
      <DialogContent wide title={site.name} description={site.url}>
        <div className="space-y-4 text-[13.5px]">
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge variant={stv}>{st}</Badge>
            {site.waf && (
              <Badge variant={WAF[site.waf]?.[1] ?? 'gray'}>{WAF[site.waf]?.[0] ?? site.waf}</Badge>
            )}
            {site.deface && <Badge variant={DEF[site.deface][1]}>{DEF[site.deface][0]}</Badge>}
            {site.plan && <Badge variant="gray">Cloudflare {site.plan}</Badge>}
            <span className="flex-1" />
            <a className="text-xs text-brand" href={site.url} target="_blank" rel="noopener noreferrer">
              Abrir sitio <ExternalLink className="inline size-3" />
            </a>
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
            <div>
              <div className="text-muted">Código / respuesta</div>
              <b>
                {site.last_code ?? '—'} · {site.last_ms != null ? `${site.last_ms} ms` : '—'}
              </b>
            </div>
            <div>
              <div className="text-muted">Uptime 24 h</div>
              <b>{site.uptime24 != null ? `${site.uptime24} %` : '—'}</b>
            </div>
            <div>
              <div className="text-muted">SSL</div>
              <b className={cn(sd != null && sd <= 30 && 'text-bad')}>
                {sd != null ? `${sd} días` : site.ssl_error ? '⚠ error' : '—'}
              </b>
            </div>
            <div>
              <div className="text-muted">Servidor</div>
              <b>{site.server || '—'}</b>
            </div>
            <div className="col-span-2">
              <div className="text-muted">IP pública → backend</div>
              <span className="font-mono">
                {site.public_ip || '—'} → {site.backend_ip || '—'}
              </span>
            </div>
            <div className="col-span-2">
              <div className="text-muted">VS FortiWeb</div>
              <span className="font-mono">{site.vs || '—'}</span>
            </div>
          </div>
          <Strip h={site.hist} />
          {site.last_error && <div className="text-xs text-bad">{site.last_error}</div>}

          <section className="rounded-xl border border-line p-3">
            <h3 className="mb-2 flex items-center gap-2 font-semibold">
              {site.deface === 'defacement' || site.deface === 'sospecha' ? (
                <ShieldAlert className="size-4 text-bad" />
              ) : (
                <ShieldCheck className="size-4 text-ok" />
              )}
              Desfiguración e inyecciones
            </h3>
            {!site.watch_content ? (
              <p className="text-muted">
                La detección está desactivada para este portal (actívala en Editar).
              </p>
            ) : D.isPending ? (
              <Loading rows={1} />
            ) : !d ? (
              <ErrorState error={D.error} compact />
            ) : !d.titulo_ahora && !d.palabras_ahora ? (
              <p className="text-muted">
                Aún no se ha podido leer el contenido (el portal no respondió con HTML).
              </p>
            ) : (
              <div className="space-y-2.5">
                <p className="text-xs text-muted">
                  Versión aprobada: {d.base_at || '—'} · {d.base_by || '—'} · umbral {d.umbral} % · texto
                  cambiado ahora: <b className="text-ink">{d.cambio_pct ?? 0} %</b>
                </p>
                {d.motivos.length ? (
                  <ul className="space-y-1">
                    {d.motivos.map((m, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <Badge variant={DEF[m.nivel][1]} className="shrink-0 whitespace-nowrap">
                          {DEF[m.nivel][0]}
                        </Badge>
                        <span className="break-words">{m.motivo}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-ok">Coincide con la versión aprobada.</p>
                )}
                {d.titulo_base !== d.titulo_ahora && (
                  <div className="text-xs">
                    Título: <s className="text-muted">{d.titulo_base || '(vacío)'}</s> →{' '}
                    <b>{d.titulo_ahora || '(vacío)'}</b>
                  </div>
                )}
                {(!!d.quitado?.length || !!d.añadido?.length) && (
                  <div className="grid gap-2 md:grid-cols-2">
                    <div>
                      <div className="mb-1 text-xs font-semibold text-bad">
                        Quitado respecto a la versión aprobada
                      </div>
                      <div className="max-h-48 overflow-auto rounded-lg bg-bad/5 p-2 font-mono text-[11.5px]">
                        {d.quitado?.length ? d.quitado.map((l, i) => <div key={i}>− {l}</div>) : '—'}
                      </div>
                    </div>
                    <div>
                      <div className="mb-1 text-xs font-semibold text-ok">Añadido</div>
                      <div className="max-h-48 overflow-auto rounded-lg bg-st-good/10 p-2 font-mono text-[11.5px]">
                        {d.añadido?.length ? d.añadido.map((l, i) => <div key={i}>+ {l}</div>) : '—'}
                      </div>
                    </div>
                  </div>
                )}
                {!!d.dominios_ahora?.length && (
                  <div className="text-xs text-muted">
                    Dominios externos que carga: {d.dominios_ahora.join(', ')}
                  </div>
                )}
                {canWrite && site.deface && site.deface !== 'ok' && (
                  <div className="flex items-center justify-between gap-2 rounded-lg bg-grid p-2.5">
                    <span className="text-xs">
                      Si el cambio es legítimo (rediseño, nueva publicación), apruébalo para que no vuelva a
                      alertar.
                    </span>
                    <Button
                      size="sm"
                      disabled={accept.isPending}
                      onClick={() =>
                        accept.mutate(site.id, {
                          onSuccess: () => {
                            toast.success('Versión aceptada como buena');
                            void D.refetch();
                          },
                          onError: (e) => toast.error(e.message),
                        })
                      }
                    >
                      <CheckCircle2 /> Aceptar como versión buena
                    </Button>
                  </div>
                )}
              </div>
            )}
          </section>
          <VisualSection site={site} />
          {canWrite && (
            <div className="flex justify-end gap-2">
              <Button variant="secondary" size="sm" onClick={() => onEdit(site)}>
                <Pencil /> Editar
              </Button>
              <Button
                size="sm"
                disabled={check.isPending}
                onClick={() =>
                  check.mutate(site.id, {
                    onSuccess: () => void D.refetch(),
                    onError: (e) => toast.error(e.message),
                  })
                }
              >
                <RefreshCw className={cn(check.isPending && 'animate-spin')} /> Comprobar ahora
              </Button>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------- comparación visual (capturas)
function VisualSection({ site }: { site: Site }) {
  const { canWrite } = useAuth();
  const vs = useVisualStatus();
  const cap = useCaptureSite();
  const [view, setView] = useState<'current' | 'baseline' | 'diff'>('diff');
  const [bust, setBust] = useState(0);
  if (!vs.data?.activo)
    return (
      <section className="rounded-xl border border-line p-3 text-[13px] text-muted">
        Comparación visual desactivada: define <code>SCREENS_TOKEN</code> en el <code>.env</code> para
        activarla.
      </section>
    );
  const has = !!site.visual_at && !site.visual_error;
  const lv = site.visual_level || 'ok';
  const src = (w: string) =>
    `/portal/api/sites/${site.id}/screen/${w}?v=${encodeURIComponent(site.visual_at)}-${bust}`;
  return (
    <section className="rounded-xl border border-line p-3 text-[13.5px]">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <h3 className="font-semibold">Comparación visual</h3>
        {has && (
          <Badge variant={DEF[lv as DefaceLevel]?.[1] ?? 'gray'}>
            {site.visual_pct ?? 0} % distinta · {DEF[lv as DefaceLevel]?.[0]}
          </Badge>
        )}
        <span className="text-xs text-muted">
          {site.visual_at ? `captura ${site.visual_at}` : 'sin captura todavía'} · aprobada{' '}
          {site.visual_base_at || '—'} · cada {vs.data.intervalo_h} h
        </span>
        <span className="flex-1" />
        {canWrite && (
          <Button
            size="sm"
            variant="secondary"
            disabled={cap.isPending}
            onClick={() =>
              cap.mutate(site.id, {
                onSuccess: () => {
                  setBust((b) => b + 1);
                  toast.success('Captura actualizada');
                },
                onError: (e) => toast.error(e.message),
              })
            }
          >
            <RefreshCw className={cn(cap.isPending && 'animate-spin')} />{' '}
            {cap.isPending ? 'Capturando…' : 'Capturar ahora'}
          </Button>
        )}
      </div>
      {site.visual_error && (
        <p className="mb-2 text-xs text-bad">Última captura fallida: {site.visual_error}</p>
      )}
      {has ? (
        <>
          <div className="mb-2 flex gap-1" role="tablist" aria-label="Vista de la captura">
            {(
              [
                ['diff', 'Diferencias'],
                ['current', 'Ahora'],
                ['baseline', 'Aprobada'],
              ] as const
            ).map(([k, l]) => (
              <Button
                key={k}
                size="sm"
                variant={view === k ? 'default' : 'ghost'}
                role="tab"
                aria-selected={view === k}
                onClick={() => setView(k)}
              >
                {l}
              </Button>
            ))}
          </div>
          <a href={src(view)} target="_blank" rel="noopener noreferrer">
            <img
              src={src(view)}
              alt={`Captura ${view === 'diff' ? 'con las diferencias en rojo' : view === 'current' ? 'actual' : 'aprobada'} de ${site.name}`}
              className="w-full rounded-lg border border-line"
              loading="lazy"
              onError={(e) => ((e.target as HTMLImageElement).style.display = 'none')}
            />
          </a>
          <p className="mt-1 text-xs text-muted">
            En «Diferencias» se marcan en rojo las zonas que cambiaron respecto a la captura aprobada. Avisa
            desde el {vs.data.umbral_cambio} % y lo trata como sospecha desde el {vs.data.umbral_alerta} %.
          </p>
        </>
      ) : (
        !site.visual_error && (
          <p className="text-xs text-muted">Se capturará en la próxima ronda, o pulsa «Capturar ahora».</p>
        )
      )}
    </section>
  );
}

// ---------------------------------------------------------------- importación (Excel de cobertura WAF / CSV)
function ImportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const parse = useParseSites();
  const imp = useImportSites();
  const [rows, setRows] = useState<SiteImportRow[] | null>(null);
  const [interval, setInterval] = useState(15);
  const [watch, setWatch] = useState(true);
  const [auto, setAuto] = useState('sin_waf');
  const close = () => {
    setRows(null);
    parse.reset();
    onClose();
  };
  const by = (k: string) => (rows ?? []).filter((r) => r.waf === k).length;
  return (
    <Dialog open={open} onOpenChange={(o) => !o && close()}>
      <DialogContent
        wide
        title="Importar portales"
        description="Excel (p. ej. «Dashboard Cobertura WAF») o CSV con una columna Portal, Dominio o URL"
      >
        <div className="space-y-3 text-[13.5px]">
          <Input
            type="file"
            accept=".xlsx,.xlsm,.csv,.txt"
            className="pt-1.5"
            aria-label="Archivo de portales"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f)
                parse.mutate(f, {
                  onSuccess: (r) => setRows(r.rows),
                  onError: (err) => toast.error(err.message),
                });
            }}
          />
          {parse.isPending && <Loading rows={1} />}
          {rows && (
            <>
              <div className="flex flex-wrap gap-2">
                <Badge variant="default">{nf(rows.length)} portales</Badge>
                <Badge variant="ok">{nf(rows.filter((r) => !r.existe).length)} nuevos</Badge>
                <Badge variant="gray">
                  {nf(rows.filter((r) => r.existe).length)} ya existen (se actualiza su ficha)
                </Badge>
                <Badge variant="ok">WAF {nf(by('waf'))}</Badge>
                <Badge variant="bad">Bypass {nf(by('bypass'))}</Badge>
                <Badge variant="bad">Sin WAF {nf(by('directo'))}</Badge>
              </div>
              <div className="max-h-56 overflow-auto rounded-lg border border-line">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Portal</TableHead>
                      <TableHead>WAF</TableHead>
                      <TableHead>IP pública</TableHead>
                      <TableHead>Servidor</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.slice(0, 200).map((r) => (
                      <TableRow key={r.url}>
                        <TableCell className="font-semibold">
                          {r.name}{' '}
                          {r.existe && <span className="text-xs font-normal text-muted">(existe)</span>}
                        </TableCell>
                        <TableCell>
                          {r.waf ? (
                            <Badge variant={WAF[r.waf]?.[1] ?? 'gray'}>{WAF[r.waf]?.[0] ?? r.waf}</Badge>
                          ) : (
                            '—'
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{r.public_ip}</TableCell>
                        <TableCell className="text-xs">{r.server}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="grid gap-3 sm:grid-cols-3">
                <div>
                  <Label htmlFor="im-i">Comprobar cada</Label>
                  <Select id="im-i" value={interval} onChange={(e) => setInterval(Number(e.target.value))}>
                    {[5, 15, 30, 60].map((n) => (
                      <option key={n} value={n}>
                        {n} min
                      </option>
                    ))}
                  </Select>
                </div>
                <div>
                  <Label htmlFor="im-a">Proponer incidente</Label>
                  <Select id="im-a" value={auto} onChange={(e) => setAuto(e.target.value)}>
                    <option value="sin_waf">Solo portales sin WAF / bypass</option>
                    <option value="todos">Todos</option>
                    <option value="ninguno">Ninguno (solo avisos)</option>
                  </Select>
                </div>
                <label className="flex items-end gap-2 pb-2">
                  <Checkbox checked={watch} onCheckedChange={(v) => setWatch(v === true)} /> Detectar
                  desfiguración
                </label>
              </div>
              <p className="text-xs text-muted">
                Las primeras comprobaciones se reparten a lo largo del intervalo para no saturar la red. La
                primera lectura de cada portal se toma como su versión aprobada.
              </p>
              <div className="flex justify-end gap-2">
                <Button variant="secondary" onClick={close}>
                  Cancelar
                </Button>
                <Button
                  disabled={imp.isPending}
                  onClick={() =>
                    imp.mutate(
                      { rows, interval_min: interval, watch_content: watch, auto_incident: auto },
                      {
                        onSuccess: (r) => {
                          toast.success(`${r.nuevos} portales añadidos y ${r.actualizados} actualizados`);
                          close();
                        },
                        onError: (e) => toast.error(e.message),
                      },
                    )
                  }
                >
                  <FileSpreadsheet /> Importar {nf(rows.length)}
                </Button>
              </div>
            </>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------- comprobación masiva
function CheckAllButton({ ids }: { ids?: number[] }) {
  const bulk = useBulkCheck();
  const run = useCheckAll();
  const busy = !!bulk.data?.running || run.isPending;
  return (
    <Button
      disabled={busy || (ids !== undefined && !ids.length)}
      onClick={() =>
        run.mutate(ids, {
          onSuccess: (d) => toast.success(`Comprobando ${nf(d.total)} portales en segundo plano`),
          onError: (e) => toast.error(e.message),
        })
      }
    >
      <RefreshCw className={cn(busy && 'animate-spin')} />
      {busy ? 'Comprobando…' : ids ? `Comprobar filtrados (${nf(ids.length)})` : 'Comprobar todos'}
    </Button>
  );
}

function BulkProgress() {
  const bulk = useBulkCheck();
  const qc = useQueryClient();
  const b = bulk.data;
  const running = !!b?.running;
  const was = useRef(false);
  useEffect(() => {
    // al terminar la comprobación masiva, recarga la tabla una vez
    if (was.current && !running) void qc.invalidateQueries({ queryKey: ['sites'] });
    was.current = running;
  }, [running, qc]);
  if (!b || (!running && !b.finished)) return null;
  const pct = b.total ? Math.round((b.done / b.total) * 100) : 0;
  return (
    <div className="card flex flex-wrap items-center gap-3 px-4 py-2.5 text-[13px]" role="status">
      <RefreshCw className={cn('size-4', running ? 'animate-spin text-brand' : 'text-ok')} />
      {running ? (
        <span>
          Comprobando <b>{nf(b.done)}</b> de {nf(b.total)} portales · iniciado por {b.by} a las{' '}
          {b.started.slice(11)}
        </span>
      ) : (
        <span>
          Última comprobación masiva: {nf(b.total)} portales · terminó {b.finished.slice(5)} · {b.by}
          {b.errors ? <b className="text-bad"> · {b.errors} con error</b> : null}
        </span>
      )}
      {running && (
        <div className="h-2 min-w-[180px] flex-1 overflow-hidden rounded-full bg-grid">
          <div
            className="h-full rounded-full bg-brand transition-[width] duration-500"
            style={{ width: `${pct}%` }}
          />
        </div>
      )}
      {running && <b className="tabular-nums">{pct} %</b>}
    </div>
  );
}

// ---------------------------------------------------------------- página
export default function SitesPage() {
  const ref = usePageEnter('sites');
  const { canWrite } = useAuth();
  const q = useSites();
  const check = useCheckSite();
  const [edit, setEdit] = useState<{ open: boolean; site: Site | null }>({ open: false, site: null });
  const [detailId, setDetailId] = useState<number | null>(null);
  const [importing, setImporting] = useState(false);
  const [state, setState] = useSearchParam('state', '');
  const [waf, setWaf] = useSearchParam('waf', '');
  const [def, setDef] = useSearchParam('deface', '');
  const [server, setServer] = useSearchParam('server', '');
  const [text, setText] = useSearchParam('q', '');
  // la página vuelve a 0 al cambiar los filtros (sin efecto: se guarda junto a la «firma» de los filtros)
  const sig = [state, waf, def, server, text].join('|');
  const [pg, setPg] = useState({ sig, n: 0 });
  const page = pg.sig === sig ? pg.n : 0;
  const setPage = (f: (n: number) => number) => setPg({ sig, n: f(page) });
  useEffect(() => {
    document.title = 'Portal SOC · Portales';
  }, []);
  const rows = useMemo(() => q.data?.rows ?? [], [q.data]);
  const servers = useMemo(() => [...new Set(rows.map((s) => s.server).filter(Boolean))].sort(), [rows]);
  const filtered = useMemo(() => {
    const t = text.trim().toLowerCase();
    const rank: Record<string, number> = { defacement: 0, sospecha: 1, down: 2, degraded: 3 };
    return rows
      .filter(
        (s) =>
          (!state || s.state === state) &&
          (!waf || (waf === 'sin' ? ['bypass', 'directo'].includes(s.waf) : s.waf === waf)) &&
          (!def || (def === 'alerta' ? ['sospecha', 'defacement'].includes(s.deface) : s.deface === def)) &&
          (!server || s.server === server) &&
          (!t || `${s.name} ${s.url} ${s.public_ip} ${s.server}`.toLowerCase().includes(t)),
      )
      .sort(
        (a, b) =>
          (rank[a.deface] ?? rank[a.state] ?? 9) - (rank[b.deface] ?? rank[b.state] ?? 9) ||
          a.name.localeCompare(b.name),
      );
  }, [rows, state, waf, def, server, text]);
  if (q.isPending) return <Loading />;
  if (q.error || !q.data) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const d = q.data;
  const on = rows.filter((s) => s.enabled);
  const up = on.filter((s) => s.state === 'up').length;
  const down = on.filter((s) => s.state === 'down');
  const alert = on.filter((s) => s.deface === 'defacement' || s.deface === 'sospecha');
  const noWaf = on.filter((s) => s.waf === 'bypass' || s.waf === 'directo');
  const sslSoon = on.filter((s) => {
    const n = sslDays(s.ssl_expiry, d.today);
    return n != null && n <= 30;
  });
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE));
  const view = filtered.slice(page * PAGE, page * PAGE + PAGE);
  const detail = rows.find((s) => s.id === detailId) ?? null;
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Portales monitoreados"
        subtitle="Disponibilidad, SSL, cobertura WAF y detección de desfiguración (defacement) e inyecciones de los sitios institucionales."
        actions={
          canWrite && (
            <div className="flex gap-2">
              <CheckAllButton ids={filtered.length !== rows.length ? filtered.map((s) => s.id) : undefined} />
              <Button variant="secondary" onClick={() => setImporting(true)}>
                <FileSpreadsheet /> Importar Excel
              </Button>
              <Button onClick={() => setEdit({ open: true, site: null })}>
                <Plus /> Añadir portal
              </Button>
            </div>
          )
        }
      />
      <BulkProgress />
      <KpiGrid data-enter="">
        <Kpi
          title="En línea"
          value={
            <>
              {nf(up)}
              <span className="text-[15px] font-medium text-muted"> / {nf(on.length)}</span>
            </>
          }
          hint="portales activos"
          onClick={() => setState('up')}
        />
        <Kpi
          title="Caídos"
          value={nf(down.length)}
          hint={
            down
              .map((s) => s.name)
              .join(', ')
              .slice(0, 60) || 'Ninguno'
          }
          alert={down.length > 0}
          onClick={() => setState('down')}
        />
        <Kpi
          title="Posible desfiguración"
          value={nf(alert.length)}
          hint={
            alert
              .map((s) => s.name)
              .join(', ')
              .slice(0, 60) || 'Ninguno'
          }
          alert={alert.length > 0}
          onClick={() => setDef('alerta')}
        />
        <Kpi
          title="Sin WAF"
          value={nf(noWaf.length)}
          hint="bypass o backend directo"
          alert={noWaf.length > 0}
          onClick={() => setWaf('sin')}
        />
        <Kpi
          title="SSL caduca ≤ 30 días"
          value={nf(sslSoon.length)}
          hint={
            sslSoon
              .map((s) => s.name)
              .join(', ')
              .slice(0, 60) || 'Ninguno'
          }
          alert={sslSoon.length > 0}
        />
      </KpiGrid>

      <Panel
        title={`Portales · ${nf(filtered.length)}${filtered.length !== rows.length ? ` de ${nf(rows.length)}` : ''}`}
        bodyClassName="px-0 pb-0"
        actions={
          <div className="flex flex-wrap gap-2">
            <Select
              value={state}
              onChange={(e) => setState(e.target.value)}
              aria-label="Estado"
              className="w-auto"
            >
              <option value="">Todo estado</option>
              {Object.entries(STATE).map(([k, [l]]) => (
                <option key={k} value={k}>
                  {l}
                </option>
              ))}
            </Select>
            <Select value={waf} onChange={(e) => setWaf(e.target.value)} aria-label="WAF" className="w-auto">
              <option value="">Toda cobertura</option>
              <option value="waf">Pasa por WAF</option>
              <option value="sin">Sin WAF (bypass + directo)</option>
              <option value="bypass">Bypass</option>
              <option value="directo">Backend directo</option>
              <option value="externo">Externo</option>
            </Select>
            <Select
              value={def}
              onChange={(e) => setDef(e.target.value)}
              aria-label="Desfiguración"
              className="w-auto"
            >
              <option value="">Todo contenido</option>
              <option value="alerta">Sospecha o desfigurado</option>
              <option value="defacement">Desfigurado</option>
              <option value="cambio">Cambio</option>
              <option value="ok">Sin cambios</option>
            </Select>
            {servers.length > 1 && (
              <Select
                value={server}
                onChange={(e) => setServer(e.target.value)}
                aria-label="Servidor"
                className="w-44"
              >
                <option value="">Todos los servidores</option>
                {servers.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            )}
            <Input
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Buscar portal, IP o servidor…"
              className="w-56"
              aria-label="Buscar portales"
            />
          </div>
        }
      >
        {view.length ? (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Portal</TableHead>
                  <TableHead>Estado</TableHead>
                  <TableHead>Contenido</TableHead>
                  <TableHead>WAF</TableHead>
                  <TableHead className="text-right">Código · ms</TableHead>
                  <TableHead className="text-right">Uptime 24 h</TableHead>
                  <TableHead className="text-right">SSL</TableHead>
                  <TableHead>Comprobado</TableHead>
                  {canWrite && <TableHead className="w-10" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {view.map((s) => {
                  const [lbl, variant] = STATE[s.state] ?? [s.state, 'gray'];
                  const sd = sslDays(s.ssl_expiry, d.today);
                  const https = s.url.startsWith('https');
                  return (
                    <TableRow
                      key={s.id}
                      clickable
                      onClick={() => setDetailId(s.id)}
                      className={cn(!s.enabled && 'opacity-55', s.deface === 'defacement' && 'bg-bad/5')}
                    >
                      <TableCell className="max-w-[280px]">
                        <div className="flex items-center gap-1.5 font-semibold">
                          <Dot ok={s.state === 'up' ? true : s.state === 'down' ? false : 'warn'} />
                          <span className="truncate">{s.name}</span>
                        </div>
                        <div className="truncate text-xs text-muted">{s.server || s.url}</div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={s.enabled ? variant : 'gray'}>{s.enabled ? lbl : 'Pausado'}</Badge>
                      </TableCell>
                      <TableCell>
                        {!s.watch_content ? (
                          <span className="text-xs text-muted">no vigilado</span>
                        ) : s.deface ? (
                          <Badge
                            variant={DEF[s.deface][1]}
                            title={s.deface_reasons.map((r) => r.motivo).join('\n')}
                          >
                            {DEF[s.deface][0]}
                            {s.deface !== 'ok' && s.deface_pct ? ` · ${s.deface_pct}%` : ''}
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {s.waf ? (
                          <Badge variant={WAF[s.waf]?.[1] ?? 'gray'}>
                            {s.waf === 'waf' ? (
                              <ShieldCheck className="size-3" />
                            ) : (
                              <ShieldOff className="size-3" />
                            )}{' '}
                            {WAF[s.waf]?.[0] ?? s.waf}
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted">—</span>
                        )}
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-right text-[13px]">
                        {s.last_code ?? '—'} · {s.last_ms != null ? s.last_ms : '—'}
                      </TableCell>
                      <TableCell
                        className={cn(
                          'text-right text-[13px]',
                          s.uptime24 != null && s.uptime24 < 99 && 'text-bad',
                        )}
                      >
                        {s.uptime24 != null ? `${s.uptime24} %` : '—'}
                      </TableCell>
                      <TableCell
                        className={cn(
                          'whitespace-nowrap text-right text-[13px]',
                          sd != null && sd <= 30 && 'text-bad',
                        )}
                        title={s.ssl_expiry || s.ssl_error || ''}
                      >
                        {https ? (sd != null ? `${sd} d` : s.ssl_error ? '⚠' : '—') : 'sin HTTPS'}
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-muted">
                        {s.last_check ? s.last_check.slice(5, 16) : 'pendiente'}
                      </TableCell>
                      {canWrite && (
                        <TableCell onClick={(e) => e.stopPropagation()}>
                          <Button
                            size="icon"
                            variant="ghost"
                            aria-label={`Comprobar ${s.name}`}
                            disabled={check.isPending && check.variables === s.id}
                            onClick={() => check.mutate(s.id, { onError: (e) => toast.error(e.message) })}
                          >
                            <RefreshCw
                              className={cn(check.isPending && check.variables === s.id && 'animate-spin')}
                            />
                          </Button>
                        </TableCell>
                      )}
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            {pages > 1 && (
              <div className="flex items-center justify-end gap-2 px-4 py-2.5 text-[13px]">
                <span className="text-muted">
                  {page * PAGE + 1}–{Math.min(filtered.length, page * PAGE + PAGE)} de {nf(filtered.length)}
                </span>
                <Button
                  size="icon"
                  variant="secondary"
                  aria-label="Página anterior"
                  disabled={page === 0}
                  onClick={() => setPage((p) => p - 1)}
                >
                  <ChevronLeft />
                </Button>
                <Button
                  size="icon"
                  variant="secondary"
                  aria-label="Página siguiente"
                  disabled={page >= pages - 1}
                  onClick={() => setPage((p) => p + 1)}
                >
                  <ChevronRight />
                </Button>
              </div>
            )}
          </>
        ) : (
          <Empty>
            {rows.length
              ? 'Ningún portal coincide con los filtros.'
              : 'Aún no hay portales: impórtalos desde Excel.'}
          </Empty>
        )}
      </Panel>

      <Panel title="Últimos eventos">
        {d.events.length ? (
          <ul className="space-y-2">
            {d.events.map((e) => {
              const [t, v] = EV[e.kind] ?? [e.kind, 'gray'];
              return (
                <li key={e.id} className="flex items-start gap-2 text-[13px]">
                  <Badge variant={v}>{t}</Badge>
                  <div className="flex-1 break-words">
                    <button
                      type="button"
                      className="font-semibold hover:text-brand"
                      onClick={() => setDetailId(e.site_id)}
                    >
                      {e.name}
                    </button>{' '}
                    · {e.text}
                  </div>
                  <span className="whitespace-nowrap text-xs text-muted">{e.at}</span>
                </li>
              );
            })}
          </ul>
        ) : (
          <Empty>Sin eventos todavía.</Empty>
        )}
      </Panel>
      <DetailDialog
        site={detail}
        today={d.today}
        onClose={() => setDetailId(null)}
        onEdit={(s) => {
          setDetailId(null);
          setEdit({ open: true, site: s });
        }}
      />
      <ImportDialog open={importing} onClose={() => setImporting(false)} />
      <SiteDialog site={edit.site} open={edit.open} onClose={() => setEdit({ open: false, site: null })} />
    </div>
  );
}
