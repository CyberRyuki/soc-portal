import { useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Input, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useSophosAction, type SophosActionInput } from '@/services/sophos';
import type { SophosActionKind } from '@/types/api';

export interface ActionRequest {
  kind: SophosActionKind;
  target: Record<string, unknown>;
  /** Texto que describe sobre qué se actúa (equipos, hashes…). */
  label: string;
  incident?: string;
}

const TITLE: Record<SophosActionKind, string> = {
  isolate: 'Aislar equipo',
  unisolate: 'Quitar aislamiento',
  scan: 'Escanear equipo',
  alert_action: 'Acción sobre la alerta',
  block_hash: 'Bloquear SHA-256 en Sophos',
  block_web: 'Bloquear dominio / URL / IP en Sophos',
  unblock_hash: 'Quitar bloqueo de SHA-256',
  unblock_web: 'Quitar bloqueo web',
};
export const CONTAINMENT: SophosActionKind[] = ['isolate', 'unisolate', 'block_hash', 'block_web'];

/**
 * Confirmación humana de una acción en Sophos Central. El motivo es obligatorio y queda en la auditoría
 * y, si se indica, en la cronología del incidente.
 */
export function ActionDialog({
  req,
  fourEyes,
  onClose,
}: {
  req: ActionRequest | null;
  fourEyes?: boolean;
  onClose: () => void;
}) {
  return (
    <Dialog open={!!req} onOpenChange={(o) => !o && onClose()}>
      {req && <Body key={JSON.stringify(req)} req={req} fourEyes={!!fourEyes} onClose={onClose} />}
    </Dialog>
  );
}

function Body({ req, fourEyes, onClose }: { req: ActionRequest; fourEyes: boolean; onClose: () => void }) {
  const run = useSophosAction();
  const [reason, setReason] = useState('');
  const [incident, setIncident] = useState(req.incident ?? '');
  const contain = CONTAINMENT.includes(req.kind);
  const pendingOnly = contain && fourEyes;
  const submit = async () => {
    const body: SophosActionInput = {
      kind: req.kind,
      target: req.target,
      reason: reason.trim(),
      incident: incident.trim(),
    };
    try {
      const a = await run.mutateAsync(body);
      if (a.status === 'done') toast.success(`${a.nombre}: ${a.result}`);
      else if (a.status === 'pending')
        toast.info('Acción registrada: necesita la aprobación de otra persona');
      else toast.error(`${a.nombre}: ${a.result}`);
      onClose();
    } catch (e) {
      toast.error((e as Error).message);
    }
  };
  return (
    <DialogContent title={TITLE[req.kind]} description={req.label}>
      <div className="space-y-3">
        {contain && (
          <div className="flex gap-2 rounded-lg border border-st-warn/40 bg-st-warn/10 p-2.5 text-[13px]">
            <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" />
            <span>
              Es una acción de <b>contención</b> que se aplica en los equipos de inmediato.
              {pendingOnly
                ? ' Está activa la regla de cuatro ojos: quedará pendiente hasta que otra persona la apruebe.'
                : ' Al confirmar, tú eres quien la aprueba.'}
            </span>
          </div>
        )}
        <div>
          <Label htmlFor="sa-reason">Motivo *</Label>
          <Textarea
            id="sa-reason"
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Por qué se hace (queda en la auditoría)…"
          />
        </div>
        <div>
          <Label htmlFor="sa-inc">Incidente relacionado (opcional)</Label>
          <Input
            id="sa-inc"
            value={incident}
            onChange={(e) => setIncident(e.target.value)}
            placeholder="INC-2026-001"
          />
        </div>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>
            Cancelar
          </Button>
          <Button
            variant={contain ? 'destructive' : 'default'}
            disabled={reason.trim().length < 5 || run.isPending}
            onClick={() => void submit()}
          >
            {pendingOnly ? 'Solicitar aprobación' : 'Confirmar'}
          </Button>
        </div>
      </div>
    </DialogContent>
  );
}
