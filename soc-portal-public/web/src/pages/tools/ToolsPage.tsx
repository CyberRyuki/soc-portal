import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { BookMarked, Download, Lock, Plus, Wrench } from 'lucide-react';
import { toast } from 'sonner';
import { usePageEnter } from '@/components/layout/AppShell';
import { Chips, Empty, ErrorState, Kpi, KpiGrid, Loading, PageHeader } from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/hooks/useAuth';
import { useSearchParam } from '@/hooks/useSearchParam';
import { nf } from '@/lib/format';
import { cn } from '@/lib/utils';
import { useSaveTool, useSecuritySummary, useTools } from '@/services/tools';
import { CatalogDialog } from './CatalogDialog';
import { FindingSev, LangDot, PLAT_ICON, STATUS_VARIANT, tagList } from './common';
import type { FindingSeverity } from '@/types/api';

export default function ToolsPage() {
  const ref = usePageEnter('tools');
  const { meta, canWrite } = useAuth();
  const [cat, setCat] = useSearchParam('cat', '');
  const [q, setQ] = useSearchParam('q', '');
  const [plat, setPlat] = useSearchParam('p', '');
  const [draft, setDraft] = useState(q);
  const [catalog, setCatalog] = useState(false);
  const nav = useNavigate();
  const [gh, setGh] = useState<string | null>(null);
  const d = useTools({ cat, q, platform: plat });
  const sec = useSecuritySummary();
  const save = useSaveTool();
  useEffect(() => {
    document.title = 'Portal SOC · Herramientas';
  }, []);
  if (d.isPending) return <Loading />;
  if (d.error || !d.data) return <ErrorState error={d.error} onRetry={() => void d.refetch()} />;
  const D = d.data,
    S = sec.data;
  const tot = S ? S.critical + S.high + S.medium + S.low + S.informational : 0;
  const importGh = async () => {
    const m = (gh ?? '').match(/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:\/|$)/);
    if (!m) return toast.error('No parece una URL de GitHub');
    try {
      const t = await save.mutateAsync({
        slug: null,
        data: {
          name: m[2],
          repo_url: `https://github.com/${m[1]}/${m[2]}`,
          owner: meta?.user ?? '',
          status: 'En evaluación',
          requires_auth: false,
        },
      });
      setGh(null);
      nav(`/tools/${t.slug}`);
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  };
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Herramientas del SOC"
        subtitle="Repositorio interno de scripts y utilidades: documentación, código, versiones y quién autoriza su uso."
        actions={
          canWrite && (
            <>
              <Button variant="secondary" onClick={() => setCatalog(true)}>
                <BookMarked /> Catálogo
              </Button>
              <Button variant="secondary" onClick={() => setGh('')}>
                <Download /> Importar de GitHub
              </Button>
              <Button asChild>
                <Link to="/tools/new/edit">
                  <Plus /> Nueva herramienta
                </Link>
              </Button>
            </>
          )
        }
      />
      <KpiGrid data-enter="">
        <Kpi
          title="Herramientas"
          value={nf(D.total)}
          hint={`${nf(D.rows.length)} con estos filtros`}
          onClick={() => {
            setCat('');
            setPlat('');
            setQ('');
            setDraft('');
          }}
        />
        {D.plataformas.map((p) => (
          <Kpi
            key={p}
            title={`${PLAT_ICON[p] ?? ''} ${p}`}
            value={nf(D.por_plataforma[p] ?? 0)}
            onClick={() => setPlat(p === plat ? '' : p)}
          />
        ))}
      </KpiGrid>
      {S && (
        <section className="card flex flex-wrap items-center gap-3 px-4 py-3 text-[13px]">
          <b>🔒 Seguridad del código</b>
          <span className="text-xs text-muted">
            {S.auditadas
              ? `${S.auditadas} herramienta(s) auditada(s) · última auditoría de cada una`
              : 'Aún no se ha auditado ninguna herramienta: ábrela y usa la pestaña «Auditoría».'}
          </span>
          <span className="flex-1" />
          {S.auditadas > 0 && (
            <>
              {(['critical', 'high', 'medium', 'low'] as FindingSeverity[]).map((k) => (
                <span key={k} className="flex items-center gap-1">
                  <FindingSev s={k} />
                  <b>{S[k]}</b>
                </span>
              ))}
              <span className="flex items-center gap-1">
                <Badge variant="gray">Por validar</Badge>
                <b>{S.needs_validation}</b>
              </span>
              {!tot && <Badge variant="ok">✔ Sin hallazgos</Badge>}
            </>
          )}
        </section>
      )}
      <div className="flex flex-wrap gap-2">
        <Chips
          options={[
            ['', 'Todas'],
            ...D.categorias.map(
              (c) =>
                [
                  c,
                  <>
                    {c} <span className="font-normal text-muted">{D.por_categoria[c] ?? 0}</span>
                  </>,
                ] as [string, React.ReactNode],
            ),
          ]}
          value={cat}
          onChange={setCat}
        />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Chips
          options={[
            ['', 'Todas las plataformas'],
            ...D.plataformas.map((p) => [p, `${PLAT_ICON[p] ?? ''} ${p}`] as [string, string]),
          ]}
          value={plat}
          onChange={setPlat}
        />
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && setQ(draft)}
          placeholder="Buscar por nombre, etiqueta o lenguaje… (Enter)"
          className="min-w-[220px] flex-1"
          aria-label="Buscar herramienta"
        />
      </div>
      {D.rows.length ? (
        <div className="grid gap-3.5 sm:grid-cols-2 xl:grid-cols-3" data-enter="">
          {D.rows.map((t) => (
            <Link
              key={t.slug}
              to={`/tools/${t.slug}`}
              className={cn(
                'card flex flex-col p-4 transition-all hover:-translate-y-0.5 hover:border-brand/50 hover:shadow-lg',
                t.status === 'Obsoleta' && 'opacity-60',
              )}
            >
              <div className="mb-2.5 flex items-start justify-between gap-2">
                <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-brand-soft text-brand">
                  <Wrench className="size-5" />
                </span>
                <span className="flex gap-1">
                  {t.requires_auth ? (
                    <Badge variant="bad" title="Requiere autorización antes de usarla">
                      <Lock className="size-3" /> Autorización
                    </Badge>
                  ) : null}
                  <Badge variant={STATUS_VARIANT[t.status] ?? 'gray'}>{t.status}</Badge>
                </span>
              </div>
              <h4 className="text-[15px] font-bold leading-snug">{t.name}</h4>
              <div className="mb-1.5 text-xs text-muted">{t.category}</div>
              <p className="mb-2.5 line-clamp-3 text-[13px] text-muted">{t.description}</p>
              <div className="mb-2.5 flex flex-wrap gap-1">
                {tagList(t.tags)
                  .slice(0, 4)
                  .map((x) => (
                    <Badge key={x} variant="gray">
                      {x}
                    </Badge>
                  ))}
              </div>
              <div className="mt-auto flex items-center justify-between gap-2 text-xs text-muted">
                <span className="flex items-center gap-3">
                  {t.platform && (
                    <span>
                      {PLAT_ICON[t.platform] ?? ''} {t.platform}
                    </span>
                  )}
                  <LangDot l={t.language} />
                  {t.files > 0 && <span>📄 {t.files}</span>}
                  {t.stars != null && t.repo_url && <span>★ {t.stars}</span>}
                </span>
                <span>{(t.updated_at || '').slice(0, 10)}</span>
              </div>
            </Link>
          ))}
        </div>
      ) : (
        <div className="card">
          <Empty>No hay herramientas{cat || q ? ' con estos filtros' : ''}.</Empty>
        </div>
      )}
      <CatalogDialog open={catalog} onClose={() => setCatalog(false)} />
      <Dialog open={gh !== null} onOpenChange={(o) => !o && setGh(null)}>
        <DialogContent
          title="Importar de GitHub"
          description="Se traen el README y el árbol de archivos; cada archivo se descarga al abrirlo."
        >
          <Label htmlFor="gh">URL del repositorio</Label>
          <Input
            id="gh"
            value={gh ?? ''}
            onChange={(e) => setGh(e.target.value)}
            placeholder="https://github.com/usuario/repositorio"
            onKeyDown={(e) => e.key === 'Enter' && importGh()}
            autoFocus
          />
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setGh(null)}>
              Cancelar
            </Button>
            <Button onClick={importGh} disabled={save.isPending}>
              Importar
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
