import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { Copy, Download, KeyRound, ShieldCheck, Smartphone } from 'lucide-react';
import { toast } from 'sonner';
import DOMPurify from 'dompurify';
import { usePageEnter } from '@/components/layout/AppShell';
import { Avatar, Loading, PageHeader, Panel } from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import { textDownload } from '@/lib/format';
import { cn } from '@/lib/utils';
import {
  useChangePassword,
  useMfaDisable,
  useMfaEnable,
  useMfaSetup,
  useRevokeSessions,
} from '@/services/account';
import type { MfaSetup } from '@/types/api';

const ROLE_VARIANT: Record<string, 'bad' | 'info' | 'gray'> = {
  admin: 'bad',
  analyst: 'info',
  viewer: 'gray',
};
const uaShort = (ua: string) => {
  const b = /Edg\//.test(ua)
    ? 'Edge'
    : /Firefox\//.test(ua)
      ? 'Firefox'
      : /Chrome\//.test(ua)
        ? 'Chrome'
        : /Safari\//.test(ua)
          ? 'Safari'
          : 'Navegador';
  const o = /Windows/.test(ua)
    ? 'Windows'
    : /Android/.test(ua)
      ? 'Android'
      : /iPhone|iPad/.test(ua)
        ? 'iOS'
        : /Mac OS/.test(ua)
          ? 'macOS'
          : /Linux/.test(ua)
            ? 'Linux'
            : '';
  return `${b}${o ? ` · ${o}` : ''}`;
};
export const passwordRules = (v: string, username: string): [boolean, string][] => [
  [v.length >= 12, 'Al menos 12 caracteres'],
  [/[a-z]/.test(v) && /[A-Z]/.test(v), 'Mayúsculas y minúsculas'],
  [/\d/.test(v), 'Algún número'],
  [/[^\w\s]|_/.test(v), 'Algún símbolo (!#$%…)'],
  [!v.toLowerCase().includes(username.toLowerCase()), 'Sin tu nombre de usuario'],
];

export default function AccountPage() {
  const ref = usePageEnter('account');
  const { me, loading, refresh } = useAuth();
  useEffect(() => {
    document.title = 'Portal SOC · Mi cuenta';
  }, []);
  if (loading || !me) return <Loading />;
  const forced = me.state !== 'ok';
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Mi cuenta"
        subtitle="Datos de acceso, contraseña, verificación en dos pasos y sesiones abiertas."
      />
      {forced && (
        <section className="card border-warn/50 bg-st-warn/10 p-4 text-[13.5px]">
          <b>Antes de continuar:</b>{' '}
          {me.state === 'change_password'
            ? 'cambia la contraseña temporal por una propia.'
            : 'tu rol exige la verificación en dos pasos (MFA). Actívala abajo con tu teléfono.'}
        </section>
      )}
      <section className="card flex flex-wrap items-center gap-4 p-4">
        <Avatar name={me.display || me.username} className="size-14 rounded-xl text-xl" />
        <div className="flex-1">
          <h3 className="flex flex-wrap items-center gap-2 text-[15px] font-semibold">
            {me.display || me.username} <Badge variant={ROLE_VARIANT[me.role]}>{me.role_name}</Badge>
            <Badge variant="gray">{me.source === 'ldap' ? 'Active Directory' : 'Cuenta local'}</Badge>
          </h3>
          <div className="text-[13px] text-muted">
            {me.username}
            {me.email && ` · ${me.email}`} · último acceso {me.last_login ?? '—'} desde {me.last_ip ?? '—'}
          </div>
        </div>
      </section>
      <div className="grid gap-4 md:grid-cols-2">
        <Panel title="Contraseña">
          {me.source === 'ldap' ? (
            <p className="text-[13.5px] text-muted">
              Tu cuenta es del dominio: la contraseña se cambia en Windows (Ctrl+Alt+Supr → Cambiar
              contraseña).
            </p>
          ) : (
            <PasswordForm
              username={me.username}
              changed={me.pw_changed}
              onDone={async () => {
                await refresh();
              }}
            />
          )}
        </Panel>
        <Panel
          title={
            <span className="flex items-center gap-2">
              Verificación en dos pasos (MFA){' '}
              {me.mfa_enabled ? (
                <Badge variant="ok">Activada</Badge>
              ) : me.mfa_required ? (
                <Badge variant="bad">Obligatoria</Badge>
              ) : (
                <Badge variant="gray">Desactivada</Badge>
              )}
            </span>
          }
        >
          <MfaBox
            enabled={!!me.mfa_enabled}
            required={me.mfa_required}
            left={me.recovery_left}
            onChange={refresh}
          />
        </Panel>
      </div>
      <Sessions />
    </div>
  );
}

function PasswordForm({
  username,
  changed,
  onDone,
}: {
  username: string;
  changed: string | null;
  onDone: () => Promise<void>;
}) {
  const nav = useNavigate();
  const { me } = useAuth();
  const ch = useChangePassword();
  const form = useForm<{ current: string; new: string; new2: string }>({
    defaultValues: { current: '', new: '', new2: '' },
  });
  const v = form.watch('new');
  const rules = useMemo(() => passwordRules(v, username), [v, username]);
  const submit = form.handleSubmit(async (d) => {
    if (d.new !== d.new2) return toast.error('Las contraseñas nuevas no coinciden');
    if (!rules.every(([ok]) => ok)) return toast.error('La contraseña nueva no cumple las reglas');
    try {
      await ch.mutateAsync({ current: d.current, new: d.new });
      toast.success('Contraseña cambiada');
      form.reset();
      await onDone();
      if (me?.state === 'change_password') nav('/');
    } catch (e) {
      toast.error(`Error: ${(e as Error).message}`);
    }
  });
  return (
    <form onSubmit={submit} className="space-y-3">
      <div>
        <Label htmlFor="pw-c">Contraseña actual</Label>
        <Input
          id="pw-c"
          type="password"
          autoComplete="current-password"
          required
          {...form.register('current')}
        />
      </div>
      <div>
        <Label htmlFor="pw-n">Nueva contraseña</Label>
        <Input id="pw-n" type="password" autoComplete="new-password" required {...form.register('new')} />
      </div>
      <div>
        <Label htmlFor="pw-2">Repite la nueva contraseña</Label>
        <Input id="pw-2" type="password" autoComplete="new-password" required {...form.register('new2')} />
      </div>
      <ul className="space-y-0.5 text-xs">
        {rules.map(([ok, t]) => (
          <li key={t} className={cn(ok && v ? 'text-ok' : 'text-muted')}>
            {ok && v ? '✓' : '○'} {t}
          </li>
        ))}
      </ul>
      <div className="text-right">
        <Button type="submit" disabled={ch.isPending}>
          <KeyRound /> Cambiar contraseña
        </Button>
      </div>
      <p className="text-xs text-muted">
        Al cambiarla se cierran tus otras sesiones abiertas. Último cambio: {changed ?? '—'}
      </p>
    </form>
  );
}

function MfaBox({
  enabled,
  required,
  left,
  onChange,
}: {
  enabled: boolean;
  required: boolean;
  left: number;
  onChange: () => Promise<void>;
}) {
  const setup = useMfaSetup();
  const enable = useMfaEnable();
  const disable = useMfaDisable();
  const [s, setS] = useState<MfaSetup | null>(null);
  const [code, setCode] = useState('');
  const [recovery, setRecovery] = useState<string[] | null>(null);
  if (recovery) {
    const txt = recovery.join('\n');
    return (
      <div>
        <p className="font-semibold text-ok">
          <ShieldCheck className="inline size-4" /> MFA activado.
        </p>
        <p className="my-2 text-[13.5px]">
          Guarda estos <b>códigos de recuperación</b> en un lugar seguro (gestor de contraseñas). Cada uno
          sirve una vez si pierdes el teléfono. <b>No se volverán a mostrar.</b>
        </p>
        <div className="grid grid-cols-2 gap-1.5 rounded-xl bg-grid p-3 font-mono text-sm">
          {recovery.map((c) => (
            <span key={c}>{c}</span>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => navigator.clipboard.writeText(txt).then(() => toast('Copiados'))}
          >
            <Copy /> Copiar
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() =>
              textDownload(
                'codigos-recuperacion-soc.txt',
                `Códigos de recuperación · Portal SOC ACME\n\n${txt}`,
                'text/plain',
              )
            }
          >
            <Download /> Descargar .txt
          </Button>
          <Button size="sm" onClick={() => window.location.assign('/portal/')}>
            Continuar
          </Button>
        </div>
      </div>
    );
  }
  if (s) {
    return (
      <div>
        <ol className="mb-3 list-decimal pl-5 text-[13.5px]">
          <li>Abre tu app Authenticator y escanea este código.</li>
          <li>Escribe el código de 6 dígitos que aparece.</li>
        </ol>
        <div className="flex flex-wrap items-center gap-4">
          <div
            className="size-[180px] rounded-xl bg-white p-2 [&>svg]:size-full"
            dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(s.qr, { USE_PROFILES: { svg: true } }) }}
          />
          <div className="min-w-[200px] flex-1">
            <Label>¿No puedes escanear? Clave manual</Label>
            <div className="mono break-all rounded-lg bg-grid px-2.5 py-2 text-sm">{s.secret}</div>
            <form
              className="mt-3 flex gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                enable.mutate(code, {
                  onSuccess: (r) => {
                    setRecovery(r.recovery);
                    void onChange();
                  },
                  onError: (err) => toast.error(`Error: ${err.message}`),
                });
              }}
            >
              <Input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="123456"
                inputMode="numeric"
                maxLength={6}
                autoFocus
                aria-label="Código"
              />
              <Button type="submit" disabled={enable.isPending}>
                Verificar
              </Button>
            </form>
          </div>
        </div>
      </div>
    );
  }
  if (enabled) {
    return (
      <div>
        <p className="text-[13.5px]">
          Al entrar se te pide un código de tu app Authenticator. Te quedan <b>{left}</b> códigos de
          recuperación.
        </p>
        {required ? (
          <p className="mt-2 text-xs text-muted">
            Tu rol exige MFA. Si cambias de teléfono, pide a un administrador que lo restablezca.
          </p>
        ) : (
          <form
            className="mt-3 flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              disable.mutate(code, {
                onSuccess: () => {
                  toast.success('MFA desactivado');
                  setCode('');
                  void onChange();
                },
                onError: (err) => toast.error(`Error: ${err.message}`),
              });
            }}
          >
            <Input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="Código para desactivar"
              inputMode="numeric"
              aria-label="Código"
            />
            <Button variant="secondary" type="submit" disabled={disable.isPending}>
              Desactivar
            </Button>
          </form>
        )}
      </div>
    );
  }
  return (
    <div>
      <p className="text-[13.5px]">
        Añade una capa extra: además de la contraseña, un código de 6 dígitos de <b>Google Authenticator</b>,{' '}
        <b>Microsoft Authenticator</b> u otra app TOTP.
      </p>
      <Button
        className="mt-3"
        onClick={() =>
          setup.mutate(undefined, { onSuccess: setS, onError: (e) => toast.error(`Error: ${e.message}`) })
        }
        disabled={setup.isPending}
      >
        <Smartphone /> Activar MFA
      </Button>
    </div>
  );
}

function Sessions() {
  const { me, refresh } = useAuth();
  const revoke = useRevokeSessions();
  if (!me) return null;
  return (
    <Panel
      title={
        <>
          Sesiones abiertas <span className="text-xs font-normal text-muted">{me.sessions.length}</span>
        </>
      }
      actions={
        me.sessions.length > 1 && (
          <Button
            variant="secondary"
            size="sm"
            onClick={() =>
              revoke.mutate(undefined, {
                onSuccess: () => {
                  toast.success('Otras sesiones cerradas');
                  void refresh();
                },
              })
            }
          >
            Cerrar las demás sesiones
          </Button>
        )
      }
      bodyClassName="px-0 pb-0"
    >
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Dispositivo</TableHead>
            <TableHead>IP</TableHead>
            <TableHead>Inicio</TableHead>
            <TableHead>Última actividad</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {me.sessions.map((s) => (
            <TableRow key={s.id}>
              <TableCell className="text-[12.5px]">
                {uaShort(s.ua)} {s.current && <Badge variant="ok">Esta sesión</Badge>}
              </TableCell>
              <TableCell className="mono">{s.ip}</TableCell>
              <TableCell>{s.created}</TableCell>
              <TableCell>{s.last_seen}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Panel>
  );
}
