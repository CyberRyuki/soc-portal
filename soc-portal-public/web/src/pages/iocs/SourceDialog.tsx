import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { toast } from 'sonner';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input, Select } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { FieldError } from '@/components/shared';
import { IOC_TYPE_LABEL } from '@/lib/constants';
import { useSaveSource, type SourceInput } from '@/services/intel';
import type { IntelSource } from '@/types/api';

const schema = z.object({
  name: z.string().trim().min(2, 'Escribe un nombre').max(120),
  url: z
    .string()
    .trim()
    .max(500)
    .refine((u) => !u || /^https?:\/\//i.test(u), 'Debe empezar por http:// o https://'),
  fmt: z.enum(['lines', 'csv']),
  ioc_type: z.string().max(10),
  csv_col: z.number().int().min(0).max(100),
  ref_col: z.string().max(5),
  auth_header: z.string().max(300),
  weight: z.number().int().min(1, 'Entre 1 y 100').max(100, 'Entre 1 y 100'),
  interval_h: z.number().min(0.5).max(720),
  retention_days: z.number().int().min(0).max(3650),
  tlp: z.enum(['clear', 'green', 'amber', 'red']),
  enabled: z.boolean(),
});
type Form = z.infer<typeof schema>;

interface Props {
  open: boolean;
  source: IntelSource | null;
  kind: 'feed' | 'misp';
  onClose: () => void;
}
export function SourceDialog({ open, source, kind, onClose }: Props) {
  const k = source?.kind ?? kind;
  const isMisp = k === 'misp';
  const save = useSaveSource();
  const form = useForm<Form>({ resolver: zodResolver(schema) });
  useEffect(() => {
    if (open)
      form.reset({
        name: source?.name ?? (isMisp ? 'MISP ACME' : ''),
        url: source?.url ?? '',
        fmt: (source?.fmt as 'lines' | 'csv') ?? 'lines',
        ioc_type: source?.ioc_type ?? 'auto',
        csv_col: source?.csv_col ?? 0,
        ref_col: source?.ref_col != null ? String(source.ref_col) : '',
        auth_header: source?.auth_header ?? '',
        weight: source?.weight ?? (isMisp ? 90 : 70),
        interval_h: source?.interval_h ?? (isMisp ? 6 : 12),
        retention_days: source?.retention_days ?? (isMisp ? 90 : 30),
        tlp: (source?.tlp as Form['tlp']) ?? 'amber',
        enabled: source ? !!source.enabled : true,
      });
  }, [open, source, isMisp, form]);
  const submit = form.handleSubmit(async (v) => {
    if (k === 'feed' && !v.url) return form.setError('url', { message: 'La URL es obligatoria' });
    try {
      const data: SourceInput = { ...v, kind: k, ref_col: v.ref_col ? Number(v.ref_col) : null };
      await save.mutateAsync({ id: source?.id ?? null, data });
      toast.success('Guardado');
      onClose();
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  });
  const E = form.formState.errors;
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={source ? 'Editar fuente' : isMisp ? 'Conectar mi MISP' : 'Nuevo feed por URL'}>
        <form onSubmit={submit} className="grid gap-3 sm:grid-cols-2" noValidate>
          <div className="sm:col-span-2">
            <Label htmlFor="s-name">Nombre *</Label>
            <Input id="s-name" {...form.register('name')} />
            <FieldError msg={E.name?.message} />
          </div>
          {k === 'feed' && (
            <>
              <div className="sm:col-span-2">
                <Label htmlFor="s-url">URL del feed *</Label>
                <Input id="s-url" placeholder="https://…/lista.txt (también .gz)" {...form.register('url')} />
                <FieldError msg={E.url?.message} />
              </div>
              <div>
                <Label htmlFor="s-fmt">Formato</Label>
                <Select id="s-fmt" {...form.register('fmt')}>
                  <option value="lines">Un IoC por línea</option>
                  <option value="csv">CSV (elige columna)</option>
                </Select>
              </div>
              <div>
                <Label htmlFor="s-type">Tipo de IoC</Label>
                <Select id="s-type" {...form.register('ioc_type')}>
                  <option value="auto">Detectar solo</option>
                  {Object.entries(IOC_TYPE_LABEL).map(([v, t]) => (
                    <option key={v} value={v}>
                      {t}
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <Label htmlFor="s-col">Columna del IoC (CSV, empieza en 0)</Label>
                <Input id="s-col" type="number" {...form.register('csv_col', { valueAsNumber: true })} />
              </div>
              <div>
                <Label htmlFor="s-ref">Columna de referencia (opcional)</Label>
                <Input id="s-ref" placeholder="p. ej. familia de malware" {...form.register('ref_col')} />
              </div>
              <div className="sm:col-span-2">
                <Label htmlFor="s-auth">Cabecera de autenticación (opcional)</Label>
                <Input
                  id="s-auth"
                  placeholder="Auth-Key: tu_clave · Authorization: Bearer …"
                  {...form.register('auth_header')}
                />
              </div>
            </>
          )}
          {isMisp && (
            <p className="text-[13px] text-muted sm:col-span-2">
              Descarga los atributos marcados para detección (to_ids) de tu MISP de los últimos días indicados
              en «Caducidad». Usa la conexión ya configurada en el portal.
            </p>
          )}
          <div>
            <Label htmlFor="s-w">Confianza (1-100)</Label>
            <Input
              id="s-w"
              type="number"
              min={1}
              max={100}
              {...form.register('weight', { valueAsNumber: true })}
            />
            <FieldError msg={E.weight?.message} />
          </div>
          {k !== 'manual' && (
            <div>
              <Label htmlFor="s-int">Actualizar cada (horas)</Label>
              <Input
                id="s-int"
                type="number"
                step="0.5"
                min={0.5}
                {...form.register('interval_h', { valueAsNumber: true })}
              />
            </div>
          )}
          <div>
            <Label htmlFor="s-ret">Caducidad (días sin aparecer{isMisp && ' · ventana de MISP'})</Label>
            <Input
              id="s-ret"
              type="number"
              min={0}
              {...form.register('retention_days', { valueAsNumber: true })}
            />
            <p className="mt-1 text-xs text-muted">0 = no caduca</p>
          </div>
          <div>
            <Label htmlFor="s-tlp">TLP</Label>
            <Select id="s-tlp" {...form.register('tlp')}>
              {['clear', 'green', 'amber', 'red'].map((t) => (
                <option key={t} value={t}>
                  TLP:{t.toUpperCase()}
                </option>
              ))}
            </Select>
          </div>
          <label className="flex items-center gap-2 text-[13.5px] sm:col-span-2">
            <Checkbox
              checked={form.watch('enabled')}
              onCheckedChange={(c) => form.setValue('enabled', c === true)}
            />{' '}
            Activa (se usa para correlacionar)
          </label>
          <div className="flex justify-end gap-2 sm:col-span-2">
            <Button variant="secondary" onClick={onClose}>
              Cancelar
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {source ? 'Guardar' : 'Añadir y descargar'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
