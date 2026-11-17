import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { toast } from 'sonner';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input, Select, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { FieldError } from '@/components/shared';
import { useAuth } from '@/hooks/useAuth';
import { useConfirm } from '@/hooks/useConfirm';
import { SEVERITIES, SEV_LABEL, VULN_STATUS_LABEL } from '@/lib/constants';
import { useDeleteVuln, useSaveVuln } from '@/services/vulns';
import { useNewIncident } from '@/pages/incidents/NewIncidentDialog';
import type { Vuln } from '@/types/api';

const schema = z.object({
  cve: z
    .string()
    .trim()
    .max(40)
    .regex(/^(CVE-\d{4}-\d{4,})?$/i, 'Formato CVE-AAAA-NNNN'),
  cvss: z
    .string()
    .trim()
    .max(5)
    .regex(/^(10(\.0)?|\d(\.\d)?)?$/, 'Entre 0 y 10'),
  title: z.string().trim().min(3, 'Escribe un título').max(200),
  severity: z.enum(SEVERITIES),
  status: z.string().max(20),
  asset: z.string().max(2000),
  package: z.string().max(300),
  port: z.string().max(40),
  owner: z.string().max(80),
  due_date: z.string().max(10),
  solution: z.string().max(5000),
  notes: z.string().max(5000),
});
type Form = z.infer<typeof schema>;

export function VulnDialog({
  vuln,
  open,
  onClose,
}: {
  vuln: Vuln | null;
  open: boolean;
  onClose: (saved?: boolean) => void;
}) {
  const { meta } = useAuth();
  const save = useSaveVuln();
  const del = useDeleteVuln();
  const [confirm, dialog] = useConfirm();
  const newInc = useNewIncident();
  const form = useForm<Form>({ resolver: zodResolver(schema) });
  useEffect(() => {
    if (open)
      form.reset({
        cve: vuln?.cve ?? '',
        cvss: vuln?.cvss != null ? String(vuln.cvss) : '',
        title: vuln?.title ?? '',
        severity: vuln?.severity ?? 'High',
        status: vuln?.status ?? 'Open',
        asset: vuln?.asset ?? '',
        package: vuln?.package ?? '',
        port: vuln?.port ?? '',
        owner: vuln?.owner ?? '',
        due_date: vuln?.due_date ?? '',
        solution: vuln?.solution ?? '',
        notes: vuln?.notes ?? '',
      });
  }, [open, vuln, form]);
  const submit = form.handleSubmit(async (v) => {
    try {
      await save.mutateAsync({ id: vuln?.id ?? null, data: { ...v, cvss: v.cvss ? Number(v.cvss) : null } });
      toast.success('Guardado');
      onClose(true);
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  });
  const remove = async () => {
    if (
      !vuln ||
      !(await confirm({
        title: '¿Eliminar esta vulnerabilidad?',
        confirmText: 'Eliminar',
        destructive: true,
      }))
    )
      return;
    await del.mutateAsync(vuln.id);
    onClose(true);
  };
  const E = form.formState.errors;
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={vuln ? 'Editar vulnerabilidad' : 'Registrar vulnerabilidad'}>
        <form onSubmit={submit} className="grid gap-3 sm:grid-cols-2" noValidate>
          <div>
            <Label htmlFor="v-cve">CVE</Label>
            <Input id="v-cve" placeholder="CVE-2024-3400" {...form.register('cve')} />
            <FieldError msg={E.cve?.message} />
          </div>
          <div>
            <Label htmlFor="v-cvss">CVSS</Label>
            <Input id="v-cvss" placeholder="9.8" {...form.register('cvss')} />
            <FieldError msg={E.cvss?.message} />
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="v-title">Título *</Label>
            <Input
              id="v-title"
              placeholder="p. ej. Ejecución remota en PAN-OS GlobalProtect"
              {...form.register('title')}
            />
            <FieldError msg={E.title?.message} />
          </div>
          <div>
            <Label htmlFor="v-sev">Severidad</Label>
            <Select id="v-sev" {...form.register('severity')}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {SEV_LABEL[s]}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="v-st">Estado</Label>
            <Select id="v-st" {...form.register('status')}>
              {Object.entries(VULN_STATUS_LABEL).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </Select>
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="v-asset">Activos afectados</Label>
            <Input id="v-asset" placeholder="fw-perimetral, 10.0.0.9" {...form.register('asset')} />
          </div>
          <div>
            <Label htmlFor="v-pkg">Paquete / producto</Label>
            <Input id="v-pkg" {...form.register('package')} />
          </div>
          <div>
            <Label htmlFor="v-port">Puerto</Label>
            <Input id="v-port" {...form.register('port')} />
          </div>
          <div>
            <Label htmlFor="v-own">Responsable</Label>
            <Select id="v-own" {...form.register('owner')}>
              {[...new Set(['', vuln?.owner ?? '', ...(meta?.users ?? [])])].map((u) => (
                <option key={u} value={u}>
                  {u || '—'}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="v-due">Fecha límite</Label>
            <Input id="v-due" type="date" {...form.register('due_date')} />
            {!vuln && <p className="mt-1 text-xs text-muted">Vacía = según la severidad</p>}
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="v-sol">Solución</Label>
            <Textarea id="v-sol" className="min-h-[60px]" {...form.register('solution')} />
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="v-notes">Notas (avance, excepción, aceptación de riesgo…)</Label>
            <Textarea id="v-notes" className="min-h-[60px]" {...form.register('notes')} />
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 sm:col-span-2">
            <span className="flex gap-2">
              {vuln && (
                <>
                  <Button variant="secondary" size="sm" onClick={remove}>
                    Eliminar
                  </Button>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      onClose();
                      newInc.open({
                        title: `Vulnerabilidad: ${vuln.cve || vuln.title}`,
                        assets: vuln.asset,
                        runbook: 'vulnerabilidad-critica',
                        severity: vuln.severity,
                      });
                    }}
                  >
                    ＋ Incidente
                  </Button>
                </>
              )}
            </span>
            <span className="flex gap-2">
              <Button variant="secondary" onClick={() => onClose()}>
                Cancelar
              </Button>
              <Button type="submit" disabled={save.isPending}>
                Guardar
              </Button>
            </span>
          </div>
        </form>
        {dialog}
      </DialogContent>
    </Dialog>
  );
}
