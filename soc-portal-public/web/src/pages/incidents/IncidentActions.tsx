import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { CheckCircle2, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { FieldError } from '@/components/shared';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Input, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useCloseIncident, useDeleteIncident } from '@/services/incidents';

const closeSchema = z.object({
  resolution: z.string().trim().min(5, 'Describe brevemente cómo se resolvió').max(5000),
  root_cause: z.string().max(10000),
  lessons: z.string().max(10000),
});
type CloseForm = z.infer<typeof closeSchema>;

export interface Target {
  code: string;
  title: string;
  root_cause?: string;
  lessons?: string;
}

/** Cierra uno o varios incidentes dejando la resolución en su cronología. */
export function CloseIncidentDialog({
  targets,
  onOpenChange,
  onDone,
}: {
  targets: Target[];
  onOpenChange: (open: boolean) => void;
  onDone?: () => void;
}) {
  const one = targets.length === 1 ? targets[0] : undefined;
  const close = useCloseIncident();
  const form = useForm<CloseForm>({
    resolver: zodResolver(closeSchema),
    values: { resolution: '', root_cause: one?.root_cause ?? '', lessons: one?.lessons ?? '' },
  });
  const E = form.formState.errors;
  const submit = form.handleSubmit(async (v) => {
    let ok = 0;
    for (const t of targets) {
      try {
        await close.mutateAsync({
          code: t.code,
          resolution: v.resolution,
          // en cierre múltiple solo se escribe causa/lecciones si se rellenaron, para no borrar las de cada uno
          ...(one || v.root_cause.trim() ? { root_cause: v.root_cause } : {}),
          ...(one || v.lessons.trim() ? { lessons: v.lessons } : {}),
        });
        ok++;
      } catch (e) {
        toast.error(`${t.code}: ${(e as Error).message}`);
      }
    }
    if (ok) toast.success(ok === 1 ? `${targets[0]?.code} cerrado` : `${ok} incidentes cerrados`);
    onOpenChange(false);
    onDone?.();
  });
  return (
    <Dialog open={targets.length > 0} onOpenChange={onOpenChange}>
      <DialogContent
        title={one ? `Cerrar ${one.code}` : `Cerrar ${targets.length} incidentes`}
        description={one ? one.title : targets.map((t) => t.code).join(', ')}
      >
        <form onSubmit={submit} className="space-y-3" noValidate>
          <div>
            <Label htmlFor="c-res">Resolución *</Label>
            <Textarea
              id="c-res"
              rows={3}
              placeholder="Qué se hizo para resolverlo (contención, erradicación, recuperación)…"
              {...form.register('resolution')}
            />
            <FieldError msg={E.resolution?.message} />
          </div>
          <div>
            <Label htmlFor="c-rc">Causa raíz</Label>
            <Textarea id="c-rc" rows={2} {...form.register('root_cause')} />
          </div>
          <div>
            <Label htmlFor="c-ll">Lecciones aprendidas</Label>
            <Textarea id="c-ll" rows={2} {...form.register('lessons')} />
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
              Cancelar
            </Button>
            <Button type="submit" disabled={close.isPending}>
              <CheckCircle2 /> Cerrar {one ? 'incidente' : `${targets.length} incidentes`}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Borrado definitivo (solo administradores): hay que escribir ELIMINAR para confirmar. */
export function DeleteIncidentDialog({
  targets,
  onOpenChange,
  onDone,
}: {
  targets: Target[];
  onOpenChange: (open: boolean) => void;
  onDone?: () => void;
}) {
  const del = useDeleteIncident();
  const [word, setWord] = useState('');
  const set = (o: boolean) => {
    if (!o) setWord('');
    onOpenChange(o);
  };
  const run = async () => {
    let ok = 0;
    for (const t of targets) {
      try {
        await del.mutateAsync(t.code);
        ok++;
      } catch (e) {
        toast.error(`${t.code}: ${(e as Error).message}`);
      }
    }
    if (ok) toast.success(ok === 1 ? `${targets[0]?.code} eliminado` : `${ok} incidentes eliminados`);
    set(false);
    onDone?.();
  };
  return (
    <Dialog open={targets.length > 0} onOpenChange={set}>
      <DialogContent
        title={
          targets.length === 1 ? `Eliminar ${targets[0]?.code}` : `Eliminar ${targets.length} incidentes`
        }
        description="Se borran el incidente y toda su cronología. No se puede deshacer."
      >
        <div className="space-y-3">
          <ul className="max-h-40 overflow-auto rounded-lg border border-line p-2 text-[13px]">
            {targets.map((t) => (
              <li key={t.code}>
                <b>{t.code}</b> · {t.title}
              </li>
            ))}
          </ul>
          <p className="text-[13px] text-muted">
            Para incidentes reales es mejor <b>cerrarlos</b>: así queda el historial para auditorías y
            métricas. Elimina solo duplicados o pruebas. El borrado queda registrado en la auditoría de
            accesos.
          </p>
          <div>
            <Label htmlFor="d-word">
              Escribe <b>ELIMINAR</b> para confirmar
            </Label>
            <Input id="d-word" autoComplete="off" value={word} onChange={(e) => setWord(e.target.value)} />
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => set(false)}>
              Cancelar
            </Button>
            <Button
              variant="destructive"
              disabled={word !== 'ELIMINAR' || del.isPending}
              onClick={() => void run()}
            >
              <Trash2 /> Eliminar definitivamente
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
