import { useEffect } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, Pencil, Plus } from 'lucide-react';
import { usePageEnter } from '@/components/layout/AppShell';
import { ErrorState, Loading, Markdown } from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/hooks/useAuth';
import { useRunbook } from '@/services/runbooks';
import { useNewIncident } from '@/pages/incidents/NewIncidentDialog';
import { LevelPill, MitreChips, OwaspChips } from './common';
import type { Severity } from '@/lib/constants';

export default function RunbookPage() {
  const { slug = '' } = useParams();
  const ref = usePageEnter(slug);
  const { canWrite } = useAuth();
  const q = useRunbook(slug);
  const newInc = useNewIncident();
  useEffect(() => {
    if (q.data) document.title = `Portal SOC · ${q.data.title}`;
  }, [q.data]);
  // las casillas [ ] del runbook se pueden marcar durante la respuesta (solo en esta vista)
  useEffect(() => {
    ref.current
      ?.querySelectorAll<HTMLInputElement>('.md input[type=checkbox]')
      .forEach((c) => (c.disabled = false));
  });
  if (q.isPending) return <Loading />;
  if (q.error || !q.data) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const r = q.data;
  return (
    <div ref={ref} className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="secondary" size="sm" asChild>
          <Link to="/runbooks">
            <ArrowLeft /> Runbooks
          </Link>
        </Button>
        <span className="flex-1" />
        <span className="text-xs text-muted">
          Actualizado por {r.updated_by} · {r.updated_at}
        </span>
        {canWrite && (
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => newInc.open({ runbook: r.slug, severity: (r.severity || 'High') as Severity })}
            >
              <Plus /> Incidente con este runbook
            </Button>
            <Button size="sm" asChild>
              <Link to={`/runbooks/${r.slug}/edit`}>
                <Pencil /> Editar
              </Link>
            </Button>
          </>
        )}
      </div>
      <div className="flex flex-wrap gap-1.5">
        <LevelPill v={r.level} />
        {r.category && <Badge variant="gray">{r.category}</Badge>}
        <MitreChips s={r.mitre} max={12} />
        <OwaspChips s={r.owasp} />
      </div>
      <article className="card px-7 py-6">
        <Markdown src={r.body} />
      </article>
    </div>
  );
}
