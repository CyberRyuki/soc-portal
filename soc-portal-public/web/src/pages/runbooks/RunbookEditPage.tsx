import { useEffect, useMemo } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { ArrowLeft, Save, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { ErrorState, FieldError, Loading, Markdown, PageHeader } from '@/components/shared';
import { Button } from '@/components/ui/button';
import { Input, Select, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useConfirm } from '@/hooks/useConfirm';
import { SEVERITIES, SEV_LABEL } from '@/lib/constants';
import { useDeleteRunbook, useRunbook, useSaveRunbook } from '@/services/runbooks';
import { LEVELS } from './common';

const schema = z.object({
  title: z.string().trim().min(3, 'Mínimo 3 caracteres').max(200),
  description: z.string().max(300),
  level: z.string().max(20),
  category: z.string().max(60),
  severity: z.string().max(10),
  mitre: z
    .string()
    .max(200)
    .regex(/^(\s*T\d{4}(\.\d{3})?\s*(,|$))*$/i, 'Formato: T1566, T1204.002'),
  owasp: z.string().max(200),
  body: z.string().min(10, 'Escribe el contenido del runbook').max(200_000),
});
type Form = z.infer<typeof schema>;
const TEMPLATE = '# Runbook — Título\n\n1. Primer paso\n2. Segundo paso\n';

export default function RunbookEditPage() {
  const { slug } = useParams();
  const isNew = !slug;
  const nav = useNavigate();
  const q = useRunbook(slug ?? '');
  const save = useSaveRunbook();
  const del = useDeleteRunbook();
  const [confirm, dialog] = useConfirm();
  const form = useForm<Form>({
    resolver: zodResolver(schema),
    defaultValues: {
      title: '',
      description: '',
      level: '',
      category: '',
      severity: '',
      mitre: '',
      owasp: '',
      body: TEMPLATE,
    },
  });
  useEffect(() => {
    if (q.data)
      form.reset({
        title: q.data.title,
        description: q.data.description,
        level: q.data.level ?? '',
        category: q.data.category ?? '',
        severity: q.data.severity ?? '',
        mitre: q.data.mitre ?? '',
        owasp: q.data.owasp ?? '',
        body: q.data.body,
      });
  }, [q.data, form]);
  const body = form.watch('body');
  const preview = useMemo(() => body, [body]);
  if (!isNew && q.isPending) return <Loading />;
  if (!isNew && (q.error || !q.data)) return <ErrorState error={q.error} />;
  const submit = form.handleSubmit(async (v) => {
    try {
      const r = await save.mutateAsync({ slug: slug ?? null, data: v });
      toast.success('Guardado');
      nav(`/runbooks/${r.slug}`);
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  });
  const remove = async () => {
    if (
      !slug ||
      !(await confirm({
        title: '¿Eliminar este runbook?',
        description: 'Esta acción no se puede deshacer.',
        confirmText: 'Eliminar',
        destructive: true,
      }))
    )
      return;
    await del.mutateAsync(slug);
    nav('/runbooks');
  };
  const E = form.formState.errors;
  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      <PageHeader
        title={isNew ? 'Nuevo runbook' : `Editar · ${q.data?.title}`}
        actions={
          <>
            <Button variant="secondary" size="sm" asChild>
              <Link to={isNew ? '/runbooks' : `/runbooks/${slug}`}>
                <ArrowLeft /> Volver
              </Link>
            </Button>
            {!isNew && (
              <Button variant="secondary" size="sm" onClick={remove}>
                <Trash2 /> Eliminar
              </Button>
            )}
            <Button size="sm" type="submit" disabled={save.isPending}>
              <Save /> Guardar
            </Button>
          </>
        }
      />
      <div className="card grid gap-3 p-5 md:grid-cols-2">
        <div>
          <Label htmlFor="rb-t">Título</Label>
          <Input id="rb-t" {...form.register('title')} />
          <FieldError msg={E.title?.message} />
        </div>
        <div>
          <Label htmlFor="rb-d">Descripción corta</Label>
          <Input id="rb-d" {...form.register('description')} />
        </div>
        <div>
          <Label htmlFor="rb-l">Nivel</Label>
          <Select id="rb-l" {...form.register('level')}>
            <option value="">—</option>
            {LEVELS.map((l) => (
              <option key={l}>{l}</option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="rb-c">Categoría</Label>
          <Input id="rb-c" placeholder="Identidad, Malware, Correo…" {...form.register('category')} />
        </div>
        <div>
          <Label htmlFor="rb-s">Severidad típica</Label>
          <Select id="rb-s" {...form.register('severity')}>
            <option value="">—</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {SEV_LABEL[s]}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="rb-m">Técnicas MITRE ATT&CK (separadas por comas)</Label>
          <Input id="rb-m" placeholder="T1566, T1204.002" {...form.register('mitre')} />
          <FieldError msg={E.mitre?.message} />
        </div>
        <div className="md:col-span-2">
          <Label htmlFor="rb-o">OWASP Top 10 (opcional)</Label>
          <Input id="rb-o" placeholder="A05:2025, A01:2025" {...form.register('owasp')} />
        </div>
        <div className="grid gap-3 md:col-span-2 lg:grid-cols-2">
          <div>
            <Label htmlFor="rb-b">Contenido (Markdown)</Label>
            <Textarea
              id="rb-b"
              className="min-h-[460px] font-mono text-[12.5px]"
              {...form.register('body')}
            />
            <FieldError msg={E.body?.message} />
          </div>
          <div>
            <Label>Vista previa</Label>
            <div className="card min-h-[460px] overflow-auto p-4 shadow-none">
              <Markdown src={preview} />
            </div>
          </div>
        </div>
      </div>
      {dialog}
    </form>
  );
}
