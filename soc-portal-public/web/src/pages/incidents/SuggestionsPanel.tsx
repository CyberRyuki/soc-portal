import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Lightbulb, Plus, X } from 'lucide-react';
import { toast } from 'sonner';
import { Panel, SevPill } from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/hooks/useAuth';
import { useDismissSuggestion, useSuggestions } from '@/services/incidents';
import { useNewIncident } from './NewIncidentDialog';

const SOURCE: Record<string, string> = {
  monitor: 'Portales',
  sophos: 'Sophos',
  m365: 'Microsoft 365',
  inteligencia: 'IoC / Wazuh',
  shuffle: 'Shuffle',
};

/**
 * Las detecciones (portales, Sophos, 365, IoC, Shuffle) no crean incidentes: proponen. El analista revisa y decide.
 */
export function SuggestionsPanel() {
  const { canWrite } = useAuth();
  const S = useSuggestions('pending');
  const dismiss = useDismissSuggestion();
  const newInc = useNewIncident();
  const [showAll, setShowAll] = useState(false);
  const items = S.data?.items ?? [];
  if (!items.length) return null;
  const view = showAll ? items : items.slice(0, 6);
  return (
    <Panel
      title={`Sugerencias de incidente · ${items.length}`}
      hint="Detecciones automáticas pendientes de revisión: tú decides si se convierten en incidente."
      className="border-st-warn/40"
      actions={
        items.length > 6 && (
          <Button size="sm" variant="ghost" onClick={() => setShowAll((v) => !v)}>
            {showAll ? 'Ver menos' : `Ver las ${items.length}`}
          </Button>
        )
      }
    >
      <ul className="divide-y divide-line">
        {view.map((s) => (
          <li key={s.id} className="flex flex-wrap items-start gap-3 py-2.5 first:pt-0 last:pb-0">
            <Lightbulb className="mt-0.5 size-4 shrink-0 text-warn" />
            <div className="min-w-[240px] flex-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <SevPill v={s.severity} />
                <b className="text-[13.5px]">{s.title}</b>
                {s.n > 1 && <Badge variant="gray">×{s.n}</Badge>}
              </div>
              <div className="mt-0.5 line-clamp-2 text-xs text-muted">{s.data.summary}</div>
              <div className="mt-0.5 text-xs text-muted">
                {SOURCE[s.source] ?? s.source} · {s.at.slice(5, 16)}
                {s.n > 1 && ` · última ${s.last_at.slice(5, 16)}`}
                {s.data.assets && ` · ${s.data.assets.slice(0, 80)}`}
              </div>
            </div>
            {canWrite && (
              <div className="flex gap-1.5">
                <Button size="sm" onClick={() => newInc.open({ ...s.data, suggestion_id: s.id })}>
                  <Plus /> Crear incidente
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={dismiss.isPending}
                  onClick={() =>
                    dismiss.mutate(
                      { id: s.id, note: 'Descartada (falso positivo o sin impacto)' },
                      {
                        onSuccess: () => toast.success('Sugerencia descartada'),
                        onError: (e) => toast.error(e.message),
                      },
                    )
                  }
                  aria-label={`Descartar ${s.title}`}
                >
                  <X /> Descartar
                </Button>
              </div>
            )}
          </li>
        ))}
      </ul>
      <p className="mt-2 text-xs text-muted">
        Las repeticiones de la misma detección se agrupan (×N). Lo descartado queda registrado en la{' '}
        <Link to="/audit" className="text-brand">
          auditoría
        </Link>
        .
      </p>
    </Panel>
  );
}
