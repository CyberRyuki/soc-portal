import { useEffect } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { ArrowLeft, Save, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { ErrorState, FieldError, Loading, Markdown, PageHeader } from '@/components/shared';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input, Select, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/hooks/useAuth';
import { useConfirm } from '@/hooks/useConfirm';
import { useDeleteTool, useSaveTool, useTool, useTools } from '@/services/tools';

const url = z
  .string()
  .trim()
  .max(500)
  .refine((u) => !u || /^https?:\/\//i.test(u), 'Debe empezar por http:// o https://');
const schema = z.object({
  name: z.string().trim().min(2, 'Escribe un nombre').max(120),
  repo_url: url,
  homepage: url,
  category: z.string().max(80),
  status: z.string().max(30),
  platform: z.string().max(30),
  language: z.string().max(40),
  version: z.string().max(30),
  license: z.string().max(60),
  owner: z.string().max(80),
  description: z.string().max(500),
  tags: z.string().max(300),
  requires_auth: z.boolean(),
  auth_note: z.string().max(2000),
  usage: z.string().max(200_000),
  readme: z.string().max(500_000),
});
type Form = z.infer<typeof schema>;

export default function ToolEditPage() {
  const { slug } = useParams();
  const isNew = !slug;
  const nav = useNavigate();
  const { meta } = useAuth();
  const meta2 = useTools({});
  const q = useTool(slug ?? '');
  const save = useSaveTool();
  const del = useDeleteTool();
  const [confirm, dialog] = useConfirm();
  const form = useForm<Form>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: '',
      repo_url: '',
      homepage: '',
      category: '',
      status: 'En evaluación',
      platform: '',
      language: '',
      version: '',
      license: '',
      owner: meta?.user ?? '',
      description: '',
      tags: '',
      requires_auth: false,
      auth_note: '',
      usage: '',
      readme: '',
    },
  });
  useEffect(() => {
    const t = q.data;
    if (t)
      form.reset({
        name: t.name,
        repo_url: t.repo_url ?? '',
        homepage: t.homepage ?? '',
        category: t.category ?? '',
        status: t.status,
        platform: t.platform ?? '',
        language: t.language ?? '',
        version: t.version ?? '',
        license: t.license ?? '',
        owner: t.owner ?? '',
        description: t.description ?? '',
        tags: t.tags ?? '',
        requires_auth: !!t.requires_auth,
        auth_note: t.auth_note ?? '',
        usage: t.usage ?? '',
        readme: t.readme ?? '',
      });
    else if (isNew && meta2.data) form.setValue('category', meta2.data.categorias[0] ?? '');
  }, [q.data, isNew, meta2.data, form]);
  if ((!isNew && q.isPending) || meta2.isPending) return <Loading />;
  if ((!isNew && (q.error || !q.data)) || !meta2.data) return <ErrorState error={q.error ?? meta2.error} />;
  const M = meta2.data;
  const submit = form.handleSubmit(async (v) => {
    try {
      const t = await save.mutateAsync({ slug: slug ?? null, data: v });
      toast.success('Guardado');
      nav(`/tools/${t.slug}`);
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  });
  const E = form.formState.errors;
  const usage = form.watch('usage');
  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      <PageHeader
        title={isNew ? 'Nueva herramienta' : `Editar · ${q.data?.name}`}
        actions={
          <>
            <Button variant="secondary" size="sm" asChild>
              <Link to={isNew ? '/tools' : `/tools/${slug}`}>
                <ArrowLeft /> Volver
              </Link>
            </Button>
            {!isNew && (
              <Button
                variant="secondary"
                size="sm"
                onClick={async () => {
                  if (
                    slug &&
                    (await confirm({
                      title: '¿Eliminar la herramienta y todos sus archivos del portal?',
                      confirmText: 'Eliminar',
                      destructive: true,
                    }))
                  ) {
                    await del.mutateAsync(slug);
                    nav('/tools');
                  }
                }}
              >
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
          <Label htmlFor="t-n">Nombre *</Label>
          <Input id="t-n" placeholder="p. ej. Crawler-Scanner" {...form.register('name')} />
          <FieldError msg={E.name?.message} />
        </div>
        <div>
          <Label htmlFor="t-r">Repositorio (GitHub u otro)</Label>
          <Input
            id="t-r"
            placeholder="https://github.com/usuario/repositorio"
            {...form.register('repo_url')}
          />
          <FieldError msg={E.repo_url?.message} />
        </div>
        <div>
          <Label htmlFor="t-c">Categoría</Label>
          <Select id="t-c" {...form.register('category')}>
            {M.categorias.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="t-s">Estado</Label>
          <Select id="t-s" {...form.register('status')}>
            {M.estados.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="t-p">Plataforma</Label>
          <Select id="t-p" {...form.register('platform')}>
            <option value="">—</option>
            {M.plataformas.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="t-h">Sitio oficial</Label>
          <Input id="t-h" placeholder="https://…" {...form.register('homepage')} />
          <FieldError msg={E.homepage?.message} />
        </div>
        <div>
          <Label htmlFor="t-l">Lenguaje</Label>
          <Input id="t-l" placeholder="Python, PowerShell, Bash…" {...form.register('language')} />
        </div>
        <div>
          <Label htmlFor="t-v">Versión</Label>
          <Input id="t-v" placeholder="1.0" {...form.register('version')} />
        </div>
        <div>
          <Label htmlFor="t-lic">Licencia</Label>
          <Input id="t-lic" placeholder="MIT, GPL-3.0, interna…" {...form.register('license')} />
        </div>
        <div>
          <Label htmlFor="t-o">Responsable</Label>
          <Select id="t-o" {...form.register('owner')}>
            {[...new Set(['', q.data?.owner ?? '', ...(meta?.users ?? [])])].map((u) => (
              <option key={u} value={u}>
                {u || '—'}
              </option>
            ))}
          </Select>
        </div>
        <div className="md:col-span-2">
          <Label htmlFor="t-d">Descripción corta</Label>
          <Input id="t-d" {...form.register('description')} />
        </div>
        <div className="md:col-span-2">
          <Label htmlFor="t-t">Etiquetas (separadas por comas)</Label>
          <Input id="t-t" placeholder="osint, tor, phishing" {...form.register('tags')} />
        </div>
        <div className="md:col-span-2">
          <label className="mb-1.5 flex items-center gap-2 text-[13.5px]">
            <Checkbox
              checked={form.watch('requires_auth')}
              onCheckedChange={(v) => form.setValue('requires_auth', v === true)}
            />{' '}
            Requiere autorización antes de usarla
          </label>
          <Textarea
            className="min-h-[60px]"
            placeholder="Quién autoriza, en qué casos se permite, restricciones (máquina aislada, alcance…)"
            aria-label="Nota de autorización"
            {...form.register('auth_note')}
          />
        </div>
        <div className="grid gap-3 md:col-span-2 lg:grid-cols-2">
          <div>
            <Label htmlFor="t-u">Uso / instalación (Markdown)</Label>
            <Textarea
              id="t-u"
              className="min-h-[420px] font-mono text-[12.5px]"
              {...form.register('usage')}
            />
          </div>
          <div>
            <Label>Vista previa</Label>
            <div className="card min-h-[420px] overflow-auto p-4 shadow-none">
              <Markdown src={usage} />
            </div>
          </div>
        </div>
        <div className="md:col-span-2">
          <Label htmlFor="t-rm">README (Markdown · si está vacío y hay GitHub, se trae al sincronizar)</Label>
          <Textarea
            id="t-rm"
            className="min-h-[200px] font-mono text-[12.5px]"
            {...form.register('readme')}
          />
        </div>
      </div>
      {dialog}
    </form>
  );
}
