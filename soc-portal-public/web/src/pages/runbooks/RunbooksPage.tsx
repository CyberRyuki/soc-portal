import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { BookOpen, Compass, Plus } from 'lucide-react';
import { usePageEnter } from '@/components/layout/AppShell';
import { Chips, Empty, ErrorState, Kpi, KpiGrid, Loading, PageHeader, SevPill } from '@/components/shared';
import { Button } from '@/components/ui/button';
import { Input, Select } from '@/components/ui/input';
import { useAuth } from '@/hooks/useAuth';
import { useSearchParam } from '@/hooks/useSearchParam';
import { useRunbooks } from '@/services/runbooks';
import { nf } from '@/lib/format';
import { LevelPill, MitreChips, OwaspChips } from './common';

const HINT: Record<string, string> = {
  Básico: 'nivel 1 · incidentes frecuentes',
  Intermedio: 'nivel 2 · requiere análisis',
  Avanzado: 'equipo completo · crisis',
};

export default function RunbooksPage() {
  const ref = usePageEnter('runbooks');
  const { canWrite } = useAuth();
  const nav = useNavigate();
  const q = useRunbooks();
  const [level, setLevel] = useSearchParam('level', '');
  const [cat, setCat] = useSearchParam('cat', '');
  const [text, setText] = useSearchParam('q', '');
  const [draft, setDraft] = useState(text);
  useEffect(() => {
    document.title = 'Portal SOC · Runbooks';
  }, []);
  const rows = useMemo(() => q.data ?? [], [q.data]);
  const cats = useMemo(() => [...new Set(rows.map((r) => r.category).filter(Boolean))].sort(), [rows]);
  const list = useMemo(() => {
    const t = text.toLowerCase();
    return rows.filter(
      (r) =>
        (!level || r.level === level) &&
        (!cat || r.category === cat) &&
        (!t || [r.title, r.description, r.mitre, r.owasp, r.category].join(' ').toLowerCase().includes(t)),
    );
  }, [rows, level, cat, text]);
  if (q.isPending) return <Loading />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const by = (l: string) => rows.filter((r) => r.level === l).length;
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Runbooks"
        subtitle={`${rows.length} procedimientos de respuesta, mapeados a MITRE ATT&CK y OWASP Top 10`}
        actions={
          <>
            <Button variant="secondary" asChild>
              <Link to="/mitre">
                <Compass /> Matriz ATT&CK
              </Link>
            </Button>
            {canWrite && (
              <Button asChild>
                <Link to="/runbooks/new">
                  <Plus /> Nuevo runbook
                </Link>
              </Button>
            )}
          </>
        }
      />
      <KpiGrid data-enter="">
        <Kpi title="Todos" value={nf(rows.length)} hint="procedimientos" onClick={() => setLevel('')} />
        {(['Básico', 'Intermedio', 'Avanzado'] as const).map((l) => (
          <Kpi
            key={l}
            title={<LevelPill v={l} />}
            value={nf(by(l))}
            hint={HINT[l]}
            onClick={() => setLevel(l)}
          />
        ))}
      </KpiGrid>
      <div className="flex flex-wrap items-center gap-2">
        <Chips
          options={[
            ['', 'Todos los niveles'],
            ['Básico', 'Básico'],
            ['Intermedio', 'Intermedio'],
            ['Avanzado', 'Avanzado'],
          ]}
          value={level}
          onChange={setLevel}
        />
        <Select
          value={cat}
          onChange={(e) => setCat(e.target.value)}
          className="w-auto"
          aria-label="Categoría"
        >
          <option value="">Todas las categorías</option>
          {cats.map((c) => (
            <option key={c}>{c}</option>
          ))}
        </Select>
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && setText(draft)}
          placeholder="Buscar por nombre, técnica (T1486) u OWASP (A05)… (Enter)"
          className="min-w-[220px] flex-1"
          aria-label="Buscar"
        />
      </div>
      {list.length ? (
        <div className="grid gap-3.5 sm:grid-cols-2 xl:grid-cols-3" data-enter="">
          {list.map((r) => (
            <div
              key={r.slug}
              role="link"
              tabIndex={0}
              onClick={() => nav(`/runbooks/${r.slug}`)}
              onKeyDown={(e) => e.key === 'Enter' && nav(`/runbooks/${r.slug}`)}
              className="card flex cursor-pointer flex-col p-4 transition-all hover:-translate-y-0.5 hover:border-brand/50 hover:shadow-lg"
            >
              <div className="mb-2.5 flex items-start justify-between gap-2">
                <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-brand-soft text-brand">
                  <BookOpen className="size-5" />
                </span>
                <span className="flex gap-1">
                  <LevelPill v={r.level} />
                  {r.severity && <SevPill v={r.severity} />}
                </span>
              </div>
              <h4 className="text-[15px] font-bold leading-snug">{r.title}</h4>
              <div className="mb-1.5 text-xs text-muted">{r.category}</div>
              <p className="mb-2.5 line-clamp-3 text-[13px] text-muted">{r.description}</p>
              <div className="mb-2.5 flex flex-wrap gap-1">
                <MitreChips s={r.mitre} />
                <OwaspChips s={r.owasp} />
              </div>
              <div className="mt-auto flex items-center justify-between text-xs text-muted">
                <span>
                  {r.updated_by} · {(r.updated_at || '').slice(0, 10)}
                </span>
                <span className="text-brand">Leer →</span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="card">
          <Empty>Ningún runbook con estos filtros.</Empty>
        </div>
      )}
    </div>
  );
}
