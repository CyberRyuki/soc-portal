import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Copy, Download, Plus } from 'lucide-react';
import { toast } from 'sonner';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { usePageEnter } from '@/components/layout/AppShell';
import {
  Avatar,
  Chips,
  Empty,
  ErrorState,
  FieldError,
  Kpi,
  KpiGrid,
  Loading,
  PageHeader,
} from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Input, Select } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import { useConfirm } from '@/hooks/useConfirm';
import { useSearchParam } from '@/hooks/useSearchParam';
import { csvDownload, nf } from '@/lib/format';
import {
  useAdminUsers,
  useAuthLog,
  useCreateUser,
  useDeleteUser,
  useUpdateUser,
  type UserInput,
} from '@/services/account';
import type { AdminUser, Role } from '@/types/api';

const ROLE_VARIANT: Record<string, 'bad' | 'info' | 'gray'> = {
  admin: 'bad',
  analyst: 'info',
  viewer: 'gray',
};
const EVC: Record<string, 'ok' | 'gray' | 'warn' | 'bad' | 'info'> = {
  login: 'ok',
  logout: 'gray',
  expired: 'gray',
  login_fail: 'warn',
  mfa_fail: 'warn',
  unknown: 'warn',
  locked: 'bad',
  blocked: 'bad',
  ip_block: 'bad',
  disabled: 'bad',
  ldap_down: 'bad',
  ldap_nogroup: 'warn',
  pw_change: 'info',
  mfa_on: 'info',
  mfa_off: 'warn',
  recovery: 'warn',
  admin: 'info',
};
type Row = AdminUser & { sessions?: number; mfa_required?: boolean; role_name?: string };

export default function AdminPage() {
  const ref = usePageEnter('admin');
  const [view, setView] = useSearchParam('view', 'users');
  const [newOpen, setNewOpen] = useState(false);
  const [edit, setEdit] = useState<Row | null>(null);
  const [secret, setSecret] = useState<{ title: string; user: string; pw: string } | null>(null);
  const d = useAdminUsers();
  useEffect(() => {
    document.title = 'Portal SOC · Usuarios y accesos';
  }, []);
  if (d.isPending) return <Loading />;
  if (d.error || !d.data) return <ErrorState error={d.error} onRetry={() => void d.refetch()} />;
  const D = d.data,
    S = D.stats,
    P = S.politica;
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Usuarios y accesos"
        subtitle="Cuentas del portal, roles, MFA y registro de auditoría de accesos."
        actions={
          <>
            <Chips
              options={[
                ['users', 'Usuarios'],
                ['log', 'Registro de accesos'],
              ]}
              value={view}
              onChange={setView}
            />
            <Button size="sm" onClick={() => setNewOpen(true)}>
              <Plus /> Nuevo usuario
            </Button>
          </>
        }
      />
      <KpiGrid data-enter="">
        <Kpi title="Usuarios" value={nf(S.usuarios)} hint={`${nf(S.sesiones)} sesiones abiertas`} />
        <Kpi
          title="Accesos · 24 h"
          value={nf(S.logins_24h)}
          hint="inicios de sesión correctos"
          onClick={() => setView('log')}
        />
        <Kpi
          title="Intentos fallidos · 24 h"
          value={nf(S.fallos_24h)}
          hint="contraseña, MFA o usuario inexistente"
          alert={S.fallos_24h > 20}
        />
        <Kpi
          title="Cuentas bloqueadas"
          value={nf(S.bloqueados)}
          hint={`${P.max_fails} fallos → ${P.lock_min} min`}
          alert={S.bloqueados > 0}
        />
        <Kpi
          title="Sin MFA"
          value={nf(S.sin_mfa)}
          hint={`obligatorio para: ${P.mfa_roles.map((r) => D.roles[r]).join(', ') || 'nadie'}`}
          alert={S.sin_mfa > 0}
        />
      </KpiGrid>
      <p className="text-xs text-muted">
        Cierre por inactividad: {P.idle_min} min · sesión máxima {P.max_hours} h · Active Directory:{' '}
        {S.ldap ? <b className="text-ok">conectado</b> : 'no configurado (LDAP_ENABLED)'}
      </p>
      {view === 'log' ? (
        <AuthLog events={D.events} />
      ) : (
        <section className="card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Usuario</TableHead>
                <TableHead>Origen</TableHead>
                <TableHead>Rol</TableHead>
                <TableHead>MFA</TableHead>
                <TableHead>Estado</TableHead>
                <TableHead>Último acceso</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(D.rows as Row[]).map((u) => (
                <TableRow key={u.id}>
                  <TableCell>
                    <span className="flex items-center gap-2.5">
                      <Avatar name={u.display || u.username} />
                      <span>
                        <b>{u.username}</b>
                        <div className="text-xs text-muted">
                          {u.display}
                          {u.email && ` · ${u.email}`}
                        </div>
                      </span>
                    </span>
                  </TableCell>
                  <TableCell>
                    <Badge variant="gray">{u.source === 'ldap' ? 'AD' : 'Local'}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={ROLE_VARIANT[u.role]}>{u.role_name ?? D.roles[u.role]}</Badge>
                  </TableCell>
                  <TableCell>
                    {u.mfa_enabled ? (
                      <Badge variant="ok">✓ Activado</Badge>
                    ) : u.mfa_required ? (
                      <Badge variant="bad">Pendiente</Badge>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {!u.enabled ? (
                      <Badge variant="gray">Desactivada</Badge>
                    ) : u.locked ? (
                      <Badge variant="bad">🔒 Bloqueada</Badge>
                    ) : u.must_change ? (
                      <Badge variant="warn">Clave temporal</Badge>
                    ) : (
                      <Badge variant="ok">Activa</Badge>
                    )}
                    {!!u.sessions && <span className="ml-1 text-xs text-muted">{u.sessions} ses.</span>}
                  </TableCell>
                  <TableCell className="text-[12.5px]">
                    {u.last_login ?? 'nunca'}
                    <div className="mono text-[11.5px] text-muted">{u.last_ip ?? ''}</div>
                  </TableCell>
                  <TableCell>
                    <Button variant="secondary" size="sm" onClick={() => setEdit(u)}>
                      Gestionar
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </section>
      )}
      <NewUserDialog open={newOpen} roles={D.roles} onClose={() => setNewOpen(false)} onSecret={setSecret} />
      <EditUserDialog user={edit} roles={D.roles} onClose={() => setEdit(null)} onSecret={setSecret} />
      <Dialog open={!!secret} onOpenChange={(o) => !o && setSecret(null)}>
        <DialogContent title={secret?.title ?? ''}>
          <p className="text-[13.5px]">
            Entrega esta contraseña temporal a <b>{secret?.user}</b> por un canal seguro. Se le pedirá
            cambiarla al entrar. <b>No se volverá a mostrar.</b>
          </p>
          <div className="mono my-3 rounded-xl bg-grid p-3.5 text-center text-xl tracking-wide">
            {secret?.pw}
          </div>
          <div className="flex justify-between">
            <Button
              variant="secondary"
              onClick={() => navigator.clipboard.writeText(secret?.pw ?? '').then(() => toast('Copiada'))}
            >
              <Copy /> Copiar
            </Button>
            <Button onClick={() => setSecret(null)}>Hecho</Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

const newSchema = z.object({
  username: z
    .string()
    .trim()
    .min(2, 'Mínimo 2 caracteres')
    .max(64)
    .regex(/^[\w.@-]+$/, 'Solo letras, números, punto, guion y @'),
  source: z.enum(['local', 'ldap']),
  display: z.string().max(120),
  email: z
    .string()
    .max(200)
    .refine((e) => !e || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e), 'Correo no válido'),
  role: z.enum(['admin', 'analyst', 'viewer']),
  password: z.string().max(200),
});
function NewUserDialog({
  open,
  roles,
  onClose,
  onSecret,
}: {
  open: boolean;
  roles: Record<Role, string>;
  onClose: () => void;
  onSecret: (s: { title: string; user: string; pw: string }) => void;
}) {
  const create = useCreateUser();
  const form = useForm<z.infer<typeof newSchema>>({
    resolver: zodResolver(newSchema),
    defaultValues: { username: '', source: 'local', display: '', email: '', role: 'analyst', password: '' },
  });
  useEffect(() => {
    if (open) form.reset();
  }, [open, form]);
  const src = form.watch('source');
  const submit = form.handleSubmit(async (v) => {
    try {
      const r = await create.mutateAsync(v);
      onClose();
      if (r.password) onSecret({ title: 'Usuario creado', user: r.username, pw: r.password });
      else toast.success('Usuario creado');
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  });
  const E = form.formState.errors;
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent title="Nuevo usuario">
        <form onSubmit={submit} className="grid gap-3 sm:grid-cols-2" noValidate>
          <div>
            <Label htmlFor="u-n">Usuario *</Label>
            <Input
              id="u-n"
              placeholder="nombre.apellido"
              autoCapitalize="off"
              {...form.register('username')}
            />
            <FieldError msg={E.username?.message} />
          </div>
          <div>
            <Label htmlFor="u-s">Origen</Label>
            <Select id="u-s" {...form.register('source')}>
              <option value="local">Cuenta local</option>
              <option value="ldap">Cuenta del dominio (AD)</option>
            </Select>
          </div>
          <div>
            <Label htmlFor="u-d">Nombre completo</Label>
            <Input id="u-d" {...form.register('display')} />
          </div>
          <div>
            <Label htmlFor="u-e">Correo</Label>
            <Input id="u-e" type="email" {...form.register('email')} />
            <FieldError msg={E.email?.message} />
          </div>
          <div>
            <Label htmlFor="u-r">Rol</Label>
            <Select id="u-r" {...form.register('role')}>
              {(Object.entries(roles) as [Role, string][]).map(([k, t]) => (
                <option key={k} value={k}>
                  {t}
                </option>
              ))}
            </Select>
          </div>
          {src === 'local' && (
            <div>
              <Label htmlFor="u-p">Contraseña inicial</Label>
              <Input
                id="u-p"
                type="password"
                autoComplete="new-password"
                placeholder="vacía = se genera una temporal"
                {...form.register('password')}
              />
            </div>
          )}
          <p className="text-xs text-muted sm:col-span-2">
            <b>Administrador:</b> todo, incluidos usuarios. <b>Analista:</b> incidentes, IoC,
            vulnerabilidades, herramientas… <b>Solo lectura:</b> consulta y pantalla NOC. Las cuentas del
            dominio también pueden entrar directamente si pertenecen a un grupo del SOC en AD.
          </p>
          <div className="flex justify-end gap-2 sm:col-span-2">
            <Button variant="secondary" onClick={onClose}>
              Cancelar
            </Button>
            <Button type="submit" disabled={create.isPending}>
              Crear
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function EditUserDialog({
  user: u,
  roles,
  onClose,
  onSecret,
}: {
  user: Row | null;
  roles: Record<Role, string>;
  onClose: () => void;
  onSecret: (s: { title: string; user: string; pw: string }) => void;
}) {
  const { me } = useAuth();
  const upd = useUpdateUser();
  const del = useDeleteUser();
  const [confirm, dialog] = useConfirm();
  const form = useForm<{ display: string; email: string; role: Role; enabled: '1' | '0' }>();
  useEffect(() => {
    if (u) form.reset({ display: u.display, email: u.email, role: u.role, enabled: u.enabled ? '1' : '0' });
  }, [u, form]);
  if (!u) return null;
  const self = me?.id === u.id;
  const act = async (body: UserInput, ask?: string) => {
    if (ask && !(await confirm({ title: ask, confirmText: 'Continuar' }))) return;
    try {
      const r = await upd.mutateAsync({ id: u.id, data: body });
      if (r.password) {
        onClose();
        onSecret({ title: 'Contraseña restablecida', user: u.username, pw: r.password });
      } else {
        toast.success('Hecho');
        onClose();
      }
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  };
  const submit = form.handleSubmit((v) =>
    act({
      display: v.display,
      email: v.email,
      ...(self ? {} : { role: v.role, enabled: v.enabled === '1' }),
    }),
  );
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        title={u.username}
        description={u.source === 'ldap' ? 'Active Directory' : 'Cuenta local'}
      >
        <form onSubmit={submit} className="grid gap-3 sm:grid-cols-2" noValidate>
          <div>
            <Label htmlFor="e-d">Nombre</Label>
            <Input id="e-d" {...form.register('display')} />
          </div>
          <div>
            <Label htmlFor="e-e">Correo</Label>
            <Input id="e-e" type="email" {...form.register('email')} />
          </div>
          <div>
            <Label htmlFor="e-r">Rol</Label>
            <Select id="e-r" disabled={self} {...form.register('role')}>
              {(Object.entries(roles) as [Role, string][]).map(([k, t]) => (
                <option key={k} value={k}>
                  {t}
                </option>
              ))}
            </Select>
            {u.source === 'ldap' && (
              <p className="mt-1 text-[11.5px] text-muted">
                En cuentas de AD el rol se recalcula con sus grupos en cada inicio.
              </p>
            )}
          </div>
          <div>
            <Label htmlFor="e-s">Estado</Label>
            <Select id="e-s" disabled={self} {...form.register('enabled')}>
              <option value="1">Activa</option>
              <option value="0">Desactivada</option>
            </Select>
          </div>
          <div className="text-right sm:col-span-2">
            <Button type="submit" disabled={upd.isPending}>
              Guardar
            </Button>
          </div>
        </form>
        <h3 className="mb-2 mt-4 text-[14px] font-semibold">Acciones</h3>
        <div className="flex flex-wrap gap-2">
          {u.locked && (
            <Button variant="secondary" size="sm" onClick={() => act({ unlock: 1 })}>
              🔓 Desbloquear
            </Button>
          )}
          {u.source === 'local' && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() =>
                act({ reset_password: 1 }, '¿Generar una contraseña temporal nueva y cerrar sus sesiones?')
              }
            >
              🔑 Restablecer contraseña
            </Button>
          )}
          {!!u.mfa_enabled && (
            <Button
              variant="secondary"
              size="sm"
              onClick={() => act({ reset_mfa: 1 }, '¿Restablecer el MFA? Tendrá que configurarlo de nuevo.')}
            >
              📱 Restablecer MFA
            </Button>
          )}
          {!!u.sessions && (
            <Button variant="secondary" size="sm" onClick={() => act({ logout: 1 })}>
              ⏏ Cerrar sus sesiones ({u.sessions})
            </Button>
          )}
          {!self && (
            <Button
              variant="secondary"
              size="sm"
              className="text-bad"
              onClick={async () => {
                if (
                  await confirm({
                    title: '¿Eliminar este usuario?',
                    description: 'Su historial de accesos se conserva.',
                    confirmText: 'Eliminar',
                    destructive: true,
                  })
                ) {
                  await del.mutateAsync(u.id);
                  onClose();
                }
              }}
            >
              ✕ Eliminar
            </Button>
          )}
          <Button variant="secondary" size="sm" asChild>
            <Link to={`/admin?view=log&q=${encodeURIComponent(u.username)}`} onClick={onClose}>
              📜 Ver sus accesos
            </Link>
          </Button>
        </div>
        <p className="mt-3 text-xs text-muted">
          Creada {u.created_at ?? '—'} · último acceso {u.last_login ?? 'nunca'}{' '}
          {u.last_ip && `desde ${u.last_ip}`}
        </p>
        {dialog}
      </DialogContent>
    </Dialog>
  );
}

function AuthLog({ events }: { events: Record<string, string> }) {
  const [daysS, setDays] = useSearchParam('days', '7');
  const [ev, setEv] = useSearchParam('event', '');
  const [q, setQ] = useSearchParam('q', '');
  const [draft, setDraft] = useState(q);
  const days = Number(daysS) || 7;
  const log = useAuthLog(days, ev, q);
  const rows = log.data ?? [];
  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <Chips
          options={[
            [1, '24 h'],
            [7, '7 días'],
            [30, '30 días'],
            [90, '90 días'],
          ]}
          value={days}
          onChange={(v) => setDays(String(v))}
        />
        <Select value={ev} onChange={(e) => setEv(e.target.value)} className="w-auto" aria-label="Evento">
          <option value="">Todos los eventos</option>
          {Object.entries(events).map(([k, t]) => (
            <option key={k} value={k}>
              {t}
            </option>
          ))}
        </Select>
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && setQ(draft)}
          placeholder="Usuario o IP… (Enter)"
          className="min-w-[200px] flex-1"
          aria-label="Buscar"
        />
        <Button
          variant="secondary"
          onClick={() =>
            csvDownload('registro-accesos.csv', rows as unknown as Record<string, unknown>[], [
              'at',
              'username',
              'ip',
              'event_name',
              'detail',
            ])
          }
        >
          <Download /> CSV
        </Button>
      </div>
      <section className="card">
        {log.isPending ? (
          <Loading rows={1} />
        ) : log.error ? (
          <ErrorState error={log.error} compact />
        ) : rows.length ? (
          <div className="max-h-[640px] overflow-auto scroll-thin">
            <Table>
              <TableHeader className="sticky top-0 bg-card">
                <TableRow>
                  <TableHead>Fecha</TableHead>
                  <TableHead>Usuario</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Evento</TableHead>
                  <TableHead>Detalle</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="whitespace-nowrap">{r.at}</TableCell>
                    <TableCell className="font-bold">{r.username}</TableCell>
                    <TableCell className="mono">{r.ip}</TableCell>
                    <TableCell>
                      <Badge variant={EVC[r.event] ?? 'gray'}>{r.event_name}</Badge>
                    </TableCell>
                    <TableCell className="text-[12.5px] text-muted">{r.detail}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <Empty>Sin eventos con estos filtros.</Empty>
        )}
      </section>
    </>
  );
}
