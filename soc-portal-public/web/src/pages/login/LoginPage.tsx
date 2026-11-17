import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useQuery } from '@tanstack/react-query';
import { KeyRound, LoaderCircle, Shield, Smartphone } from 'lucide-react';
import { api, ApiError } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { FieldError } from '@/components/shared';
import type { LoginResult } from '@/types/api';

const credsSchema = z.object({
  username: z.string().trim().min(1, 'Escribe tu usuario').max(80),
  password: z.string().min(1, 'Escribe tu contraseña').max(200),
});
type Creds = z.infer<typeof credsSchema>;

/** Destino seguro tras entrar: solo rutas internas del portal. */
/** Solo rutas internas del portal: evita redirecciones abiertas (`//evil.com`, `https://…`, `/\\evil`). */
export function safeNext(search: string = location.search): string {
  const n = new URLSearchParams(search).get('next') ?? '';
  if (!n.startsWith('/') || n.startsWith('//') || n.includes('\\')) return '/portal/';
  return n.startsWith('/portal/') || n === '/portal' ? n : `/portal${n}`;
}

export default function LoginPage() {
  const cfg = useQuery({
    queryKey: ['auth-config'],
    queryFn: () => api.get<{ ldap: boolean }>('auth/config'),
    staleTime: Infinity,
  });
  const [ticket, setTicket] = useState<string | null>(null);
  const [recovery, setRecovery] = useState(false);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const form = useForm<Creds>({
    resolver: zodResolver(credsSchema),
    defaultValues: { username: '', password: '' },
  });

  useEffect(() => {
    document.title = 'Portal SOC · Iniciar sesión';
  }, []);

  const finish = () => window.location.assign(safeNext());

  const onLogin = form.handleSubmit(async (v) => {
    setError('');
    setBusy(true);
    try {
      const r = await api.post<LoginResult>('auth/login', v);
      if (r.mfa) {
        setTicket(r.mfa as unknown as string);
        return;
      }
      finish();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'No se pudo iniciar sesión');
    } finally {
      setBusy(false);
    }
  });

  const onMfa = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!ticket || !code.trim()) return;
    setError('');
    setBusy(true);
    try {
      await api.post('auth/mfa', { ticket, code: code.trim() });
      finish();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Código no válido');
      setCode('');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-screen lg:grid-cols-[1.1fr_1fr]">
      <section className="relative hidden overflow-hidden bg-[#0b1220] p-10 text-[#e3f2ff] lg:flex lg:flex-col lg:justify-between">
        <div className="absolute -right-24 -top-24 size-[420px] rounded-full bg-[radial-gradient(circle,#f59e0b,transparent_70%)] opacity-30 blur-3xl" />
        <div className="absolute -bottom-32 -left-16 size-[520px] rounded-full bg-[radial-gradient(circle,#22d3ee,transparent_70%)] opacity-25 blur-3xl" />
        <div className="relative flex items-center gap-3">
          <span className="grid size-10 place-items-center rounded-xl bg-gradient-to-br from-[#2f5bea] to-[#7a5af8]">
            <Shield className="size-5" />
          </span>
          <div>
            <b className="block text-[15px]">Portal SOC</b>
            <small className="text-[12px] text-[#8aa4bf]">ACME · Centro de Operaciones de Seguridad</small>
          </div>
        </div>
        <div className="relative max-w-md">
          <h2 className="text-3xl font-bold leading-tight">
            Monitoreo, inteligencia de amenazas y respuesta en un solo lugar.
          </h2>
          <p className="mt-3 text-[14px] text-[#8aa4bf]">
            Wazuh, MISP y Shuffle integrados: alertas, indicadores, incidentes con SLA, runbooks, ATT&CK y un
            asistente de investigación.
          </p>
        </div>
        <p className="relative text-[12px] text-[#8aa4bf]">
          Acceso restringido al personal autorizado. Toda actividad queda registrada.
        </p>
      </section>
      <section className="grid place-items-center p-6">
        <div className="w-full max-w-sm">
          <h1 className="text-2xl font-bold">Iniciar sesión</h1>
          <p className="mt-1 text-[13.5px] text-muted">
            {cfg.data?.ldap
              ? 'Usa tu cuenta del dominio ACME o una cuenta local de emergencia.'
              : 'Usa tu cuenta del portal.'}
          </p>
          {!ticket ? (
            <form onSubmit={onLogin} className="mt-6 space-y-4" noValidate>
              <div>
                <Label htmlFor="username">Usuario</Label>
                <Input id="username" autoComplete="username" autoFocus {...form.register('username')} />
                <FieldError msg={form.formState.errors.username?.message} />
              </div>
              <div>
                <Label htmlFor="password">Contraseña</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  {...form.register('password')}
                />
                <FieldError msg={form.formState.errors.password?.message} />
              </div>
              {error && (
                <p role="alert" className="rounded-lg bg-bad/10 px-3 py-2 text-[13px] text-bad">
                  {error}
                </p>
              )}
              <Button type="submit" size="lg" className="w-full" disabled={busy}>
                {busy ? <LoaderCircle className="animate-spin" /> : <KeyRound />} Entrar
              </Button>
            </form>
          ) : (
            <form onSubmit={onMfa} className="mt-6 space-y-4">
              <div className="flex items-center gap-2 rounded-xl bg-brand-soft px-3 py-2 text-[13px] text-brand">
                <Smartphone className="size-4" /> Verificación en dos pasos
              </div>
              <p className="text-[13px] text-muted">
                {recovery
                  ? 'Escribe uno de tus códigos de recuperación (cada uno sirve una sola vez).'
                  : 'Escribe el código de 6 dígitos de tu app Authenticator.'}
              </p>
              <Input
                autoFocus
                value={code}
                inputMode={recovery ? 'text' : 'numeric'}
                maxLength={recovery ? 11 : 6}
                placeholder={recovery ? 'XXXXX-XXXXX' : '••••••'}
                className="h-12 text-center font-mono text-xl tracking-[6px]"
                aria-label="Código de verificación"
                onChange={(e) => {
                  setCode(e.target.value);
                  if (!recovery && e.target.value.replace(/\D/g, '').length === 6) void onMfa();
                }}
              />
              {error && (
                <p role="alert" className="rounded-lg bg-bad/10 px-3 py-2 text-[13px] text-bad">
                  {error}
                </p>
              )}
              <Button type="submit" size="lg" className="w-full" disabled={busy}>
                {busy && <LoaderCircle className="animate-spin" />} Verificar
              </Button>
              <button
                type="button"
                className="block w-full text-center text-[12.5px] text-brand hover:underline"
                onClick={() => {
                  setRecovery((r) => !r);
                  setCode('');
                }}
              >
                {recovery ? 'Usar la app Authenticator' : '¿Sin teléfono? Usar un código de recuperación'}
              </button>
            </form>
          )}
        </div>
      </section>
    </div>
  );
}
