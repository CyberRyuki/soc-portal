import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  BarChart3,
  BookOpen,
  Clock,
  Copy,
  Download,
  ExternalLink,
  FolderOpen,
  Lock,
  Pencil,
  RefreshCw,
  Settings,
  Trash2,
} from 'lucide-react';
import { toast } from 'sonner';
import { usePageEnter } from '@/components/layout/AppShell';
import { Empty, ErrorState, Loading, Markdown } from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useAuth } from '@/hooks/useAuth';
import { useConfirm } from '@/hooks/useConfirm';
import { useSearchParam } from '@/hooks/useSearchParam';
import { fsize, nf } from '@/lib/format';
import { useDeleteToolFile, useSyncTool, useTool, useToolFile, uploadToolFiles } from '@/services/tools';
import { useQueryClient } from '@tanstack/react-query';
import { AuditTab } from './AuditTab';
import { MetricsTab } from './MetricsTab';
import { CodeView } from './CodeView';
import { LangDot, PLAT_ICON, STATUS_VARIANT, tagList } from './common';
import type { Tool } from '@/types/api';

const TABS = [
  ['readme', 'README', BookOpen],
  ['files', 'Archivos', FolderOpen],
  ['usage', 'Uso', Settings],
  ['audit', 'Auditoría', Lock],
  ['metrics', 'Métricas', BarChart3],
  ['log', 'Historial', Clock],
] as const;

export default function ToolPage() {
  const { slug = '', fid } = useParams();
  const ref = usePageEnter(slug + (fid ?? ''));
  const nav = useNavigate();
  const qc = useQueryClient();
  const { canWrite } = useAuth();
  const q = useTool(slug);
  const sync = useSyncTool(slug);
  const [tabParam, setTab] = useSearchParam('tab', '');
  const [upMsg, setUpMsg] = useState('');
  const t = q.data;
  useEffect(() => {
    if (t) document.title = `Portal SOC · ${t.name}`;
  }, [t]);
  if (q.isPending) return <Loading />;
  if (q.error || !t) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const tab = fid ? 'files' : tabParam || (t.readme ? 'readme' : t.files.length ? 'files' : 'usage');
  const gh = t.repo_url && /github\.com/.test(t.repo_url) ? t.repo_url : '';
  const onUpload = async (files: FileList | null) => {
    if (!files?.length) return;
    const r = await uploadToolFiles(slug, Array.from(files), setUpMsg);
    setUpMsg('');
    toast(`${r.done} archivos subidos${r.fail ? `, ${r.fail} con error` : ''}`);
    void qc.invalidateQueries({ queryKey: ['tools'] });
  };
  const doSync = (cache: boolean) =>
    sync.mutate(cache, {
      onSuccess: (r) =>
        toast.success(
          cache
            ? `Copia local de ${r.copiados} archivos`
            : `Sincronizado: ${r.archivos} archivos (rama ${r.rama})`,
        ),
      onError: (e) => toast.error(`Error: ${e.message}`),
    });
  return (
    <div ref={ref} className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="secondary" size="sm" asChild>
          <Link to="/tools">
            <ArrowLeft /> Herramientas
          </Link>
        </Button>
        <span className="flex-1" />
        {(t.homepage || (!gh && t.repo_url)) && (
          <Button variant="secondary" size="sm" asChild>
            <a href={t.homepage || t.repo_url} target="_blank" rel="noopener noreferrer">
              Sitio oficial <ExternalLink />
            </a>
          </Button>
        )}
        {gh && (
          <>
            <Button variant="secondary" size="sm" asChild>
              <a href={gh} target="_blank" rel="noopener noreferrer">
                Ver en GitHub <ExternalLink />
              </a>
            </Button>
            {canWrite && (
              <Button
                variant="secondary"
                size="sm"
                disabled={sync.isPending}
                onClick={() => doSync(false)}
                title="Actualiza README y lista de archivos"
              >
                <RefreshCw className={sync.isPending ? 'animate-spin' : ''} /> Sincronizar
              </Button>
            )}
          </>
        )}
        {canWrite && (
          <Button size="sm" asChild>
            <Link to={`/tools/${slug}/edit`}>
              <Pencil /> Editar
            </Link>
          </Button>
        )}
      </div>
      <div className="flex items-start gap-3.5">
        <span className="grid size-[52px] shrink-0 place-items-center rounded-xl bg-brand-soft text-brand">
          <Settings className="size-6" />
        </span>
        <div className="min-w-0">
          <h1 className="text-[22px] font-bold tracking-tight">
            {t.name} {t.version && <span className="text-[15px] font-medium text-muted">v{t.version}</span>}
          </h1>
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[13px]">
            <Badge variant={STATUS_VARIANT[t.status] ?? 'gray'}>{t.status}</Badge>
            <Badge variant="info">{t.category || 'Sin categoría'}</Badge>
            {t.platform && (
              <span>
                {PLAT_ICON[t.platform] ?? ''} {t.platform}
              </span>
            )}
            <LangDot l={t.language} />
            {t.license && <span className="text-muted">⚖ {t.license}</span>}
            {t.stars != null && gh && <span className="text-muted">★ {t.stars}</span>}
            {t.gh_synced && <span className="text-muted">sincronizado {t.gh_synced}</span>}
          </div>
        </div>
      </div>
      {!!t.requires_auth && (
        <section className="card border-bad/50 bg-bad/5 p-4">
          <b className="text-bad">
            <Lock className="inline size-4" /> Requiere autorización antes de usarla
          </b>
          <div className="mt-1 text-[13.5px]">
            {t.auth_note || 'Solicita aprobación del responsable de seguridad.'}
          </div>
        </section>
      )}
      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        <section className="card min-w-0 p-4">
          <Tabs
            value={tab}
            onValueChange={(v) => {
              if (fid) nav(`/tools/${slug}?tab=${v}`);
              else setTab(v);
            }}
          >
            <TabsList className="mb-3.5">
              {TABS.map(([k, l, I]) => (
                <TabsTrigger key={k} value={k}>
                  <I />
                  {l}
                  {k === 'files' && (
                    <Badge variant="gray" className="ml-1">
                      {t.files.length}
                    </Badge>
                  )}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
          {fid ? (
            <FileView tool={t} fid={fid} />
          ) : tab === 'readme' ? (
            t.readme ? (
              <Markdown src={t.readme} />
            ) : (
              <Empty>
                Sin README. {gh ? 'Pulsa «Sincronizar» para traerlo de GitHub o ' : ''}
                <Link className="text-brand" to={`/tools/${slug}/edit`}>
                  escríbelo aquí
                </Link>
                .
              </Empty>
            )
          ) : tab === 'usage' ? (
            t.usage ? (
              <Markdown src={t.usage} />
            ) : (
              <Empty>
                Sin instrucciones de uso.{' '}
                <Link className="text-brand" to={`/tools/${slug}/edit`}>
                  Añádelas
                </Link>
                .
              </Empty>
            )
          ) : tab === 'log' ? (
            t.log.length ? (
              <ol className="ml-1.5 border-l-2 border-line">
                {t.log.map((e) => (
                  <li key={e.id} className="relative pb-3.5 pl-5">
                    <span className="absolute -left-[7px] top-1 size-3 rounded-full bg-brand" />
                    <div className="text-xs text-muted">
                      {e.at} · {e.user}
                    </div>
                    <div className="text-[13.5px]">{e.text}</div>
                  </li>
                ))}
              </ol>
            ) : (
              <Empty>Sin cambios registrados.</Empty>
            )
          ) : tab === 'audit' ? (
            <AuditTab tool={t} active />
          ) : tab === 'metrics' ? (
            <MetricsTab tool={t} active />
          ) : (
            <FilesTab tool={t} canWrite={canWrite} />
          )}
        </section>
        <aside className="space-y-4">
          <section className="card p-4">
            <h3 className="mb-2 text-[14.5px] font-semibold">Acerca de</h3>
            <p className="mb-2.5 text-[13.5px]">
              {t.description || <span className="text-muted">Sin descripción.</span>}
            </p>
            <div className="mb-2.5 flex flex-wrap gap-1">
              {tagList(t.tags).map((x) => (
                <Badge key={x} variant="info">
                  {x}
                </Badge>
              ))}
            </div>
            <div className="space-y-1 text-[13px]">
              {gh && (
                <div>
                  🔗{' '}
                  <a className="text-brand" href={gh} target="_blank" rel="noopener noreferrer">
                    {gh.replace('https://github.com/', '')}
                  </a>
                </div>
              )}
              <div>
                👤 Responsable: <b>{t.owner || '—'}</b>
              </div>
              <div>
                📄 {t.files.length} archivos · {fsize(t.files.reduce((a, f) => a + (f.size ?? 0), 0))}
              </div>
              <div className="text-muted">
                Actualizado por {t.updated_by || '—'} · {t.updated_at}
              </div>
            </div>
          </section>
          {canWrite && (
            <section className="card p-4">
              <h3 className="mb-2 text-[14.5px] font-semibold">Subir archivos</h3>
              <Label htmlFor="tf">Archivos</Label>
              <Input
                id="tf"
                type="file"
                multiple
                className="pt-1.5"
                onChange={(e) => void onUpload(e.target.files)}
              />
              <Label htmlFor="td" className="mt-2">
                o una carpeta completa
              </Label>
              <Input
                id="td"
                type="file"
                multiple
                className="pt-1.5"
                {...({ webkitdirectory: '' } as object)}
                onChange={(e) => void onUpload(e.target.files)}
              />
              <p className="mt-1.5 text-xs text-muted">
                {upMsg || 'Se calcula el SHA256 de cada archivo para verificar su integridad.'}
              </p>
              {gh && (
                <Button
                  variant="secondary"
                  size="sm"
                  className="mt-2.5"
                  disabled={sync.isPending}
                  onClick={() => doSync(true)}
                >
                  <Download /> Guardar copia local de GitHub
                </Button>
              )}
            </section>
          )}
        </aside>
      </div>
    </div>
  );
}

function FilesTab({ tool, canWrite }: { tool: Tool; canWrite: boolean }) {
  const nav = useNavigate();
  const del = useDeleteToolFile(tool.slug);
  const [confirm, dialog] = useConfirm();
  const files = [...tool.files].sort(
    (a, b) => Number(a.path.includes('/')) - Number(b.path.includes('/')) || a.path.localeCompare(b.path),
  );
  if (!files.length)
    return (
      <Empty>
        Sin archivos. Súbelos desde el panel de la derecha{tool.repo_url ? ' o sincroniza con GitHub' : ''}.
      </Empty>
    );
  return (
    <>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Archivo</TableHead>
            <TableHead className="text-right">Tamaño</TableHead>
            <TableHead>Origen</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {files.map((f) => {
            const dir = f.path.includes('/') ? f.path.slice(0, f.path.lastIndexOf('/') + 1) : '';
            return (
              <TableRow key={f.id} clickable onClick={() => nav(`/tools/${tool.slug}/file/${f.id}`)}>
                <TableCell>
                  📄 <span className="text-muted">{dir}</span>
                  <b>{f.path.slice(dir.length)}</b>
                </TableCell>
                <TableCell className="text-right">{fsize(f.size)}</TableCell>
                <TableCell>
                  <Badge variant={f.source === 'github' ? 'info' : 'gray'}>
                    {f.source === 'github' ? 'GitHub' : 'Subido'}
                  </Badge>
                  {f.source === 'github' && !!f.cached && (
                    <span className="ml-1 text-muted" title="Hay copia local en el portal">
                      💾
                    </span>
                  )}
                </TableCell>
                <TableCell className="whitespace-nowrap text-right" onClick={(e) => e.stopPropagation()}>
                  <Button variant="secondary" size="icon-sm" asChild>
                    <a
                      href={`/portal/api/tools/${encodeURIComponent(tool.slug)}/files/${f.id}/download`}
                      title="Descargar"
                    >
                      <Download />
                    </a>
                  </Button>
                  {canWrite && (
                    <Button
                      variant="secondary"
                      size="icon-sm"
                      className="ml-1"
                      title="Quitar"
                      onClick={async () => {
                        if (
                          await confirm({
                            title: '¿Quitar este archivo del repositorio interno?',
                            confirmText: 'Quitar',
                            destructive: true,
                          })
                        )
                          del.mutate(f.id);
                      }}
                    >
                      <Trash2 />
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      {dialog}
    </>
  );
}

function FileView({ tool, fid }: { tool: Tool; fid: string }) {
  const q = useToolFile(tool.slug, fid);
  if (q.isPending) return <Loading rows={1} h="h-64" />;
  if (q.error || !q.data) return <ErrorState error={q.error} compact />;
  const f = q.data;
  return (
    <div>
      <div className="mb-2.5 flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <Link className="text-brand" to={`/tools/${tool.slug}?tab=files`}>
            {tool.name}
          </Link>{' '}
          / <b className="mono break-all">{f.path}</b>
          <div className="mt-0.5 text-xs text-muted">
            {f.lines != null && `${nf(f.lines)} líneas · `}
            {fsize(f.size)} · {f.lang}
            {f.sha256 && (
              <>
                {' '}
                · SHA256{' '}
                <span className="mono" title={f.sha256}>
                  {f.sha256.slice(0, 16)}…
                </span>
              </>
            )}
          </div>
        </div>
        <span className="flex gap-1">
          {f.text != null && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => navigator.clipboard.writeText(f.text ?? '').then(() => toast('Copiado'))}
            >
              <Copy /> Copiar
            </Button>
          )}
          <Button variant="secondary" size="sm" asChild>
            <a href={`/portal/api/tools/${encodeURIComponent(tool.slug)}/files/${f.id}/download`}>
              <Download /> Descargar
            </a>
          </Button>
        </span>
      </div>
      {f.text == null ? (
        <Empty>
          Archivo binario o demasiado grande para mostrarlo (más de 3 MB). Descárgalo para revisarlo.
        </Empty>
      ) : f.lang === 'markdown' ? (
        <div className="card p-4 shadow-none">
          <Markdown src={f.text} />
        </div>
      ) : (
        <CodeView src={f.text} lang={f.lang} lines={f.lines} />
      )}
    </div>
  );
}
