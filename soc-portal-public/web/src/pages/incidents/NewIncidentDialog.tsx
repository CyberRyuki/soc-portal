import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { create } from 'zustand';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input, Select, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { FieldError } from '@/components/shared';
import { useAuth } from '@/hooks/useAuth';
import { SEVERITIES, SEV_LABEL } from '@/lib/constants';
import { useCreateIncident, type IncidentInput } from '@/services/incidents';

interface NewIncidentState {
  isOpen: boolean;
  prefill: IncidentInput;
  open: (prefill?: IncidentInput) => void;
  close: () => void;
}
/** Estado global: cualquier página puede abrir «Nuevo incidente» con datos prellenados. */
export const useNewIncident = create<NewIncidentState>((set) => ({
  isOpen: false,
  prefill: {},
  open: (prefill = {}) => set({ isOpen: true, prefill }),
  close: () => set({ isOpen: false }),
}));

const schema = z.object({
  title: z.string().trim().min(3, 'Escribe un título (mínimo 3 caracteres)').max(200),
  severity: z.enum(SEVERITIES),
  owner: z.string().max(80),
  detected_by: z.string().max(200),
  assets: z.string().max(500),
  runbook: z.string().max(80),
  summary: z.string().max(5000),
  iocs: z.string().max(5000),
});
type Form = z.infer<typeof schema>;

export function NewIncidentDialog() {
  const { isOpen, prefill, close } = useNewIncident();
  const { meta } = useAuth();
  const nav = useNavigate();
  const create = useCreateIncident();
  const form = useForm<Form>({ resolver: zodResolver(schema) });
  useEffect(() => {
    if (isOpen)
      form.reset({
        title: prefill.title ?? '',
        severity: prefill.severity ?? 'High',
        owner: prefill.owner ?? meta?.user ?? '',
        detected_by: prefill.detected_by ?? '',
        assets: prefill.assets ?? '',
        runbook: prefill.runbook ?? '',
        summary: prefill.summary ?? '',
        iocs: prefill.iocs ?? '',
      });
  }, [isOpen, prefill, meta?.user, form]);

  const submit = form.handleSubmit(async (v) => {
    try {
      const r = await create.mutateAsync({ ...v, suggestion_id: prefill.suggestion_id });
      close();
      toast.success(`${r.code} creado`);
      nav(`/incidents/${r.code}`);
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  });
  const E = form.formState.errors;
  return (
    <Dialog open={isOpen} onOpenChange={(o) => !o && close()}>
      <DialogContent title="Nuevo incidente" description="El número se asigna solo (INC-AAAA-NNN).">
        <form onSubmit={submit} className="grid gap-3 sm:grid-cols-2" noValidate>
          <div className="sm:col-span-2">
            <Label htmlFor="ni-title">Título *</Label>
            <Input
              id="ni-title"
              autoFocus
              placeholder="p. ej. Fuerza bruta contra srv-dc01"
              {...form.register('title')}
            />
            <FieldError msg={E.title?.message} />
          </div>
          <div>
            <Label htmlFor="ni-sev">Severidad</Label>
            <Select id="ni-sev" {...form.register('severity')}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {SEV_LABEL[s]}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="ni-owner">Responsable</Label>
            <Select id="ni-owner" {...form.register('owner')}>
              <option value="">—</option>
              {(meta?.users ?? []).map((u) => (
                <option key={u} value={u}>
                  {u}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="ni-det">Detectado por</Label>
            <Input
              id="ni-det"
              placeholder="Regla Wazuh 5712 / usuario / CSIRT"
              {...form.register('detected_by')}
            />
          </div>
          <div>
            <Label htmlFor="ni-assets">Activos afectados</Label>
            <Input id="ni-assets" placeholder="srv-dc01, 10.0.0.5" {...form.register('assets')} />
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="ni-rb">Runbook</Label>
            <Select id="ni-rb" {...form.register('runbook')}>
              <option value="">— Ninguno —</option>
              {(meta?.runbooks ?? []).map((r) => (
                <option key={r.slug} value={r.slug}>
                  {r.title}
                </option>
              ))}
            </Select>
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="ni-sum">Resumen</Label>
            <Textarea
              id="ni-sum"
              placeholder="Qué pasó, impacto, primeras acciones…"
              {...form.register('summary')}
            />
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="ni-ioc">Indicadores de compromiso (IoC)</Label>
            <Textarea
              id="ni-ioc"
              className="font-mono text-[12.5px]"
              placeholder="Uno por línea: IPs, dominios, hashes, URLs"
              {...form.register('iocs')}
            />
          </div>
          <div className="flex justify-end gap-2 sm:col-span-2">
            <Button variant="secondary" onClick={close}>
              Cancelar
            </Button>
            <Button type="submit" disabled={create.isPending}>
              Crear incidente
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
