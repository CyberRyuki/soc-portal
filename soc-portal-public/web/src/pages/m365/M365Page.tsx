import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Ban,
  ExternalLink,
  KeyRound,
  LogOut,
  MailX,
  MoreHorizontal,
  Plus,
  RefreshCw,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Unlock,
  UserX,
} from 'lucide-react';
import { toast } from 'sonner';
import { usePageEnter } from '@/components/layout/AppShell';
import {
  Chips,
  Empty,
  ErrorState,
  HBars,
  Kpi,
  KpiGrid,
  Loading,
  PageHeader,
  Panel,
} from '@/components/shared';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input, Select, Textarea } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAuth } from '@/hooks/useAuth';
import { useSearchParam } from '@/hooks/useSearchParam';
import { nf } from '@/lib/format';
import { cn } from '@/lib/utils';
import { useNewIncident } from '@/pages/incidents/NewIncidentDialog';
import {
  useM365Action,
  useM365Actions,
  useM365Alerts,
  useM365Audits,
  useM365Decide,
  useM365Posture,
  useM365Risky,
  useM365Rules,
  useM365ScanRules,
  useM365SignIns,
  useM365Status,
  useM365Sync,
} from '@/services/m365';
import type { M365ActionKind, M365Alert, M365Status } from '@/types/api';

const VIEWS: [string, string][] = [
  ['alertas', 'Alertas'],
  ['inicios', 'Inicios de sesión'],
  ['riesgo', 'Usuarios en riesgo'],
  ['correo', 'Correo'],
  ['auditoria', 'Auditoría'],
  ['postura', 'Secure Score'],
  ['acciones', 'Acciones'],
];
const SEV: Record<string, [string, 'bad' | 'warn' | 'gray' | 'info']> = {
  high: ['Alta', 'bad'],
  medium: ['Media', 'warn'],
  low: ['Baja', 'gray'],
  informational: ['Info', 'info'],
};
const ST: Record<string, [string, 'bad' | 'warn' | 'ok' | 'gray' | 'info']> = {
  new: ['Nueva', 'bad'],
  inProgress: ['En curso', 'warn'],
  resolved: ['Resuelta', 'ok'],
  pending: ['Pendiente', 'warn'],
  running: ['En curso', 'info'],
  done: ['Hecha', 'ok'],
  failed: ['Falló', 'bad'],
  rejected: ['Rechazada', 'gray'],
};
const SVC: Record<string, string> = {
  serviceOperational: 'Operativo',
  serviceDegradation: 'Degradado',
  serviceInterruption: 'Interrupción',
  restoringService: 'Restaurando',
  extendedRecovery: 'Recuperación prolongada',
  investigating: 'Investigando',
  verifyingService: 'Verificando',
  serviceRestored: 'Restaurado',
  postIncidentReviewPublished: 'Informe publicado',
  falsePositive: 'Falso positivo',
};
const RISK: Record<string, 'bad' | 'warn' | 'gray'> = { high: 'bad', medium: 'warn', low: 'gray' };
const KIND: Record<M365ActionKind, [string, boolean]> = {
  revoke_sessions: ['Revocar sesiones', true],
  disable_user: ['Bloquear inicio de sesión', true],
  enable_user: ['Desbloquear inicio de sesión', false],
  force_password: ['Forzar cambio de contraseña', true],
  confirm_compromised: ['Confirmar cuenta comprometida', true],
  dismiss_risk: ['Descartar riesgo', false],
  resolve_alert: ['Resolver alerta en Defender', false],
  disable_rule: ['Desactivar regla de bandeja de entrada', true],
};

interface Req {
  kind: M365ActionKind;
  target: Record<string, unknown>;
  label: string;
}

/** Puede actuar: rol con escritura en el portal y 365 sin modo solo lectura. */
function useCanAct() {
  const { canWrite } = useAuth();
  const st = useM365Status();
  return canWrite && !!st.data?.configurado && !st.data?.solo_lectura;
}

export default function M365Page() {
  const ref = usePageEnter('m365');
  const [view, setView] = useSearchParam('view', 'alertas');
  const st = useM365Status();
  const [req, setReq] = useState<Req | null>(null);
  useEffect(() => {
    document.title = 'Portal SOC · Microsoft 365';
  }, []);
  if (st.isPending) return <Loading rows={2} />;
  if (st.error || !st.data) return <ErrorState error={st.error} onRetry={() => void st.refetch()} />;
  const s = st.data;
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Microsoft 365"
        subtitle="Defender, identidad (Entra ID), correo, auditoría y Secure Score. Las acciones sobre cuentas siempre las confirma una persona."
        actions={
          s.configurado && (
            <Chips
              options={VIEWS.map(([k, l]) => [
                k,
                k === 'acciones' && s.pendientes ? `${l} (${s.pendientes})` : l,
              ])}
              value={view}
              onChange={setView}
            />
          )
        }
      />
      {!s.configurado ? (
        <Setup />
      ) : (
        <>
          <StatusBar s={s} />
          {view === 'inicios' ? (
            <SignInsView onAction={setReq} />
          ) : view === 'riesgo' ? (
            <RiskView onAction={setReq} />
          ) : view === 'correo' ? (
            <MailView onAction={setReq} />
          ) : view === 'auditoria' ? (
            <AuditView />
          ) : view === 'postura' ? (
            <PostureView />
          ) : view === 'acciones' ? (
            <ActionsView fourEyes={!!s.four_eyes} />
          ) : (
            <AlertsView onAction={setReq} />
          )}
        </>
      )}
      <ActionDialog req={req} fourEyes={!!s.four_eyes} onClose={() => setReq(null)} />
    </div>
  );
}

function Setup() {
  return (
    <Panel title="Conectar Microsoft 365">
      <ol className="list-decimal space-y-2 pl-5 text-[13.5px]">
        <li>
          En <b>Entra ID → Registros de aplicaciones → Nuevo registro</b> crea «Portal SOC ACME» (una sola
          organización).
        </li>
        <li>
          En <b>Permisos de API → Microsoft Graph → Permisos de aplicación</b> añade los de lectura y, si
          quieres actuar, los de escritura (ver <code>docs/m365.md</code>). Pulsa{' '}
          <b>Conceder consentimiento de administrador</b>.
        </li>
        <li>
          En <b>Certificados y secretos</b> crea un secreto y cópialo (solo se muestra una vez).
        </li>
        <li>
          Añade al <code>.env</code> y recrea el bridge:
          <pre className="mt-1.5 overflow-x-auto rounded-lg bg-grid p-2.5 font-mono text-[12px]">
            {`M365_TENANT_ID=<id del directorio>
M365_CLIENT_ID=<id de la aplicación>
M365_CLIENT_SECRET=<secreto>
M365_READ_ONLY=false   # true = solo ver`}
          </pre>
        </li>
      </ol>
    </Panel>
  );
}

function StatusBar({ s }: { s: M365Status }) {
  const sync = useM365Sync();
  const bad = !s.conectado || s.sync_msg?.startsWith('Error');
  return (
    <div
      className={cn('card flex flex-wrap items-center gap-3 px-4 py-2.5 text-[13px]', bad && 'border-bad/50')}
    >
      <ShieldCheck className={cn('size-4', bad ? 'text-bad' : 'text-ok')} />
      {s.conectado ? (
        <span>
          Conectado a <b>{s.organizacion}</b>
        </span>
      ) : (
        <span className="text-bad">Sin conexión: {s.error}</span>
      )}
      <span className="text-muted">
        Alertas: {s.ultima_sync || '—'} · {s.sync_msg || '—'} · cada {s.poll_min} min
      </span>
      <span className="flex-1" />
      {s.solo_lectura && <Badge variant="gray">Solo lectura</Badge>}
      {s.four_eyes && <Badge variant="info">Cuatro ojos</Badge>}
      <Button
        size="sm"
        variant="secondary"
        disabled={sync.isPending}
        onClick={() =>
          sync.mutate(undefined, {
            onSuccess: () => toast.success('Sincronizando con Microsoft 365…'),
            onError: (e) => toast.error(e.message),
          })
        }
      >
        <RefreshCw className={cn(sync.isPending && 'animate-spin')} /> Sincronizar
      </Button>
    </div>
  );
}

/** Menú de acciones sobre un usuario (se reutiliza en alertas, inicios de sesión y riesgo). */
function UserMenu({ upn, onAction, risky }: { upn: string; onAction: (r: Req) => void; risky?: boolean }) {
  const act = useCanAct();
  if (!act || !upn) return null;
  const a = (kind: M365ActionKind) => () => onAction({ kind, target: { user: upn }, label: upn });
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          size="icon"
          variant="ghost"
          aria-label={`Acciones sobre ${upn}`}
          onClick={(e) => e.stopPropagation()}
        >
          <MoreHorizontal />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>{upn}</DropdownMenuLabel>
        <DropdownMenuItem onSelect={a('revoke_sessions')}>
          <LogOut /> Revocar sesiones
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={a('force_password')}>
          <KeyRound /> Forzar cambio de contraseña
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={a('disable_user')}>
          <UserX /> Bloquear inicio de sesión
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={a('enable_user')}>
          <Unlock /> Desbloquear inicio de sesión
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={a('confirm_compromised')}>
          <ShieldAlert /> Confirmar comprometida
        </DropdownMenuItem>
        {risky && (
          <DropdownMenuItem onSelect={a('dismiss_risk')}>
            <ShieldCheck /> Descartar riesgo
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// ---------------------------------------------------------------- alertas de Defender
function AlertsView({ onAction }: { onAction: (r: Req) => void }) {
  const { canWrite } = useAuth();
  const act = useCanAct();
  const newInc = useNewIncident();
  const [days, setDays] = useState(7);
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [draft, setDraft] = useState('');
  const [q, setQ] = useState('');
  const [open, setOpen] = useState<M365Alert | null>(null);
  const A = useM365Alerts({ days, severity, status, q });
  if (A.isPending) return <Loading rows={3} />;
  if (A.error || !A.data) return <ErrorState error={A.error} onRetry={() => void A.refetch()} />;
  const { items, stats } = A.data;
  const n = (k: string) => stats.severidad.find((x) => x[0] === k)?.[1] ?? 0;
  const toIncident = (a: M365Alert) =>
    newInc.open({
      title: `Microsoft 365: ${a.title}`.slice(0, 200),
      severity: a.severity === 'high' ? 'High' : a.severity === 'medium' ? 'Medium' : 'Low',
      detected_by: `Microsoft Defender (${a.service})`,
      assets: a.users.join(', '),
      iocs: [...a.ips, ...a.urls].join('\n'),
      summary: `${a.description}\n\nCategoría: ${a.category}. MITRE: ${a.mitre.join(', ') || '—'}.${a.url ? `\nDefender: ${a.url}` : ''}`,
    });
  return (
    <>
      <KpiGrid>
        <Kpi title="Alertas" value={nf(items.length)} hint={`últimos ${days} días`} />
        <Kpi
          title="Abiertas"
          value={nf(stats.abiertas)}
          alert={stats.abiertas > 0}
          onClick={() => setStatus('new')}
        />
        <Kpi
          title="Severidad alta"
          value={nf(n('high'))}
          alert={n('high') > 0}
          onClick={() => setSeverity('high')}
        />
        <Kpi
          title="Con IoC conocido"
          value={nf(items.filter((a) => Object.keys(a.matches).length).length)}
          hint="cruzado con el motor de IoC"
        />
      </KpiGrid>
      <Panel title="Por servicio">
        <HBars
          rows={stats.servicio.map(([k, v]) => ({
            label: k.replace('microsoftDefenderFor', 'Defender for '),
            value: v,
          }))}
        />
      </Panel>
      <Panel
        title="Alertas de Microsoft Defender"
        bodyClassName="px-0 pb-0"
        actions={
          <div className="flex flex-wrap gap-2">
            <Chips
              options={[
                [1, '24 h'],
                [7, '7 días'],
                [30, '30 días'],
              ]}
              value={days}
              onChange={setDays}
            />
            <Select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              aria-label="Severidad"
              className="w-auto"
            >
              <option value="">Toda severidad</option>
              <option value="high">Alta</option>
              <option value="medium">Media</option>
              <option value="low">Baja</option>
            </Select>
            <Select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              aria-label="Estado"
              className="w-auto"
            >
              <option value="">Todo estado</option>
              <option value="new">Nuevas</option>
              <option value="inProgress">En curso</option>
              <option value="resolved">Resueltas</option>
            </Select>
            <Input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && setQ(draft)}
              placeholder="Usuario, IP, texto… (Enter)"
              className="w-52"
              aria-label="Buscar alertas"
            />
          </div>
        }
      >
        {items.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Fecha</TableHead>
                <TableHead>Severidad</TableHead>
                <TableHead>Alerta</TableHead>
                <TableHead>Usuarios</TableHead>
                <TableHead>Estado</TableHead>
                {canWrite && <TableHead className="w-10" />}
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((a) => (
                <TableRow key={a.id} clickable onClick={() => setOpen(a)}>
                  <TableCell className="whitespace-nowrap text-muted">
                    {a.created.slice(0, 16).replace('T', ' ')}
                  </TableCell>
                  <TableCell>
                    <Badge variant={SEV[a.severity]?.[1] ?? 'gray'}>
                      {SEV[a.severity]?.[0] ?? a.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-[460px]">
                    <div className="font-semibold">{a.title}</div>
                    <div className="text-xs text-muted">
                      {a.category} · {a.service.replace('microsoftDefenderFor', 'Defender for ')}
                      {!!Object.keys(a.matches).length && (
                        <b className="text-bad"> · IoC conocido: {Object.keys(a.matches).join(', ')}</b>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="max-w-[220px] truncate text-[13px]">
                    {a.users.join(', ') || '—'}
                  </TableCell>
                  <TableCell>
                    <Badge variant={ST[a.status]?.[1] ?? 'gray'}>{ST[a.status]?.[0] ?? a.status}</Badge>
                  </TableCell>
                  {canWrite && (
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button size="icon" variant="ghost" aria-label={`Acciones de la alerta ${a.title}`}>
                            <MoreHorizontal />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onSelect={() => toIncident(a)}>
                            <Plus /> Crear incidente
                          </DropdownMenuItem>
                          {act && a.status !== 'resolved' && (
                            <>
                              <DropdownMenuItem
                                onSelect={() =>
                                  onAction({
                                    kind: 'resolve_alert',
                                    target: { alert_id: a.id, classification: 'truePositive' },
                                    label: `${a.title} · verdadero positivo`,
                                  })
                                }
                              >
                                <ShieldCheck /> Resolver (verdadero positivo)
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onSelect={() =>
                                  onAction({
                                    kind: 'resolve_alert',
                                    target: { alert_id: a.id, classification: 'falsePositive' },
                                    label: `${a.title} · falso positivo`,
                                  })
                                }
                              >
                                <Ban /> Resolver (falso positivo)
                              </DropdownMenuItem>
                            </>
                          )}
                          {act &&
                            a.users
                              .filter((u) => u.includes('@'))
                              .slice(0, 3)
                              .map((u) => (
                                <DropdownMenuItem
                                  key={u}
                                  onSelect={() =>
                                    onAction({ kind: 'revoke_sessions', target: { user: u }, label: u })
                                  }
                                >
                                  <LogOut /> Revocar sesiones de {u}
                                </DropdownMenuItem>
                              ))}
                          {a.url && (
                            <DropdownMenuItem asChild>
                              <a href={a.url} target="_blank" rel="noopener noreferrer">
                                <ExternalLink /> Abrir en Defender
                              </a>
                            </DropdownMenuItem>
                          )}
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty>Sin alertas de Defender en este periodo.</Empty>
        )}
      </Panel>
      <Dialog open={!!open} onOpenChange={(o) => !o && setOpen(null)}>
        {open && (
          <DialogContent
            wide
            title={open.title}
            description={`${open.category} · ${open.service} · ${open.created.replace('T', ' ')}`}
          >
            <div className="space-y-3 text-[13.5px]">
              <div className="flex flex-wrap gap-1.5">
                <Badge variant={SEV[open.severity]?.[1] ?? 'gray'}>{SEV[open.severity]?.[0]}</Badge>
                <Badge variant={ST[open.status]?.[1] ?? 'gray'}>{ST[open.status]?.[0] ?? open.status}</Badge>
                {open.mitre.map((t) => (
                  <Badge key={t} variant="info">
                    {t}
                  </Badge>
                ))}
              </div>
              <p>{open.description}</p>
              {open.recommended && (
                <div className="rounded-lg bg-grid p-2.5 text-[13px]">
                  <b>Acciones recomendadas por Microsoft:</b> {open.recommended}
                </div>
              )}
              <dl className="grid grid-cols-[120px_1fr] gap-x-3 gap-y-1 text-[13px]">
                <dt className="text-muted">Usuarios</dt>
                <dd>{open.users.join(', ') || '—'}</dd>
                <dt className="text-muted">IP</dt>
                <dd className="font-mono">{open.ips.join(', ') || '—'}</dd>
                <dt className="text-muted">URL</dt>
                <dd className="break-all font-mono text-xs">{open.urls.join(', ') || '—'}</dd>
                <dt className="text-muted">Incidente Defender</dt>
                <dd>{open.incident_id || '—'}</dd>
              </dl>
              {open.url && (
                <a className="text-brand" href={open.url} target="_blank" rel="noopener noreferrer">
                  Abrir en Microsoft Defender <ExternalLink className="inline size-3" />
                </a>
              )}
            </div>
          </DialogContent>
        )}
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------- inicios de sesión
function SignInsView({ onAction }: { onAction: (r: Req) => void }) {
  const [hours, setHours] = useState(24);
  const [only, setOnly] = useState('');
  const S = useM365SignIns(hours);
  if (S.isPending) return <Loading rows={3} />;
  if (S.error || !S.data) return <ErrorState error={S.error} onRetry={() => void S.refetch()} />;
  const d = S.data;
  const rows = d.items.filter(
    (x) =>
      !only ||
      (only === 'fail' && !x.ok) ||
      (only === 'risk' && x.risk !== 'none' && x.risk !== 'hidden') ||
      (only === 'foreign' && x.foreign && x.ok),
  );
  return (
    <>
      <KpiGrid>
        <Kpi
          title="Inicios de sesión"
          value={nf(d.total)}
          hint={`últimas ${hours} h${d.truncado ? ' (muestra)' : ''}`}
        />
        <Kpi
          title="Fallidos"
          value={nf(d.fallidos)}
          alert={d.fallidos > 50}
          onClick={() => setOnly('fail')}
        />
        <Kpi title="Con riesgo" value={nf(d.riesgo)} alert={d.riesgo > 0} onClick={() => setOnly('risk')} />
        <Kpi
          title="Correctos desde el extranjero"
          value={nf(d.extranjero_ok)}
          hint="revisa si se esperaban"
          alert={d.extranjero_ok > 0}
          onClick={() => setOnly('foreign')}
        />
      </KpiGrid>
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Usuarios con más fallos">
          <HBars rows={d.por_usuario.map(([k, v]) => ({ label: k, value: v }))} />
        </Panel>
        <Panel title="IP con más fallos">
          <HBars rows={d.por_ip.map(([k, v]) => ({ label: k, value: v }))} />
        </Panel>
        <Panel title="Países">
          <HBars rows={d.por_pais.map(([k, v]) => ({ label: k, value: v }))} />
        </Panel>
      </div>
      <Panel
        title="Inicios de sesión a revisar"
        hint="Fallidos, con riesgo o desde fuera del país"
        bodyClassName="px-0 pb-0"
        actions={
          <div className="flex flex-wrap gap-2">
            <Chips
              options={[
                [1, '1 h'],
                [24, '24 h'],
                [72, '3 días'],
                [168, '7 días'],
              ]}
              value={hours}
              onChange={setHours}
            />
            <Select
              value={only}
              onChange={(e) => setOnly(e.target.value)}
              aria-label="Tipo"
              className="w-auto"
            >
              <option value="">Todo</option>
              <option value="fail">Fallidos</option>
              <option value="risk">Con riesgo</option>
              <option value="foreign">Correctos desde el extranjero</option>
            </Select>
          </div>
        }
      >
        {rows.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Fecha</TableHead>
                <TableHead>Usuario</TableHead>
                <TableHead>Resultado</TableHead>
                <TableHead>Origen</TableHead>
                <TableHead>Aplicación</TableHead>
                <TableHead>Riesgo</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.slice(0, 300).map((x, i) => (
                <TableRow key={`${x.at}-${x.user}-${i}`}>
                  <TableCell className="whitespace-nowrap text-muted">{x.at.slice(5, 16)}</TableCell>
                  <TableCell className="font-semibold">{x.user}</TableCell>
                  <TableCell>
                    {x.ok ? (
                      <Badge variant="ok">Correcto</Badge>
                    ) : (
                      <span title={x.error}>
                        <Badge variant="bad">Fallido {x.code}</Badge>
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-[13px]">
                    <span className="font-mono text-xs">{x.ip}</span>{' '}
                    <b className={cn(x.foreign && 'text-bad')}>{x.country}</b> {x.city}
                  </TableCell>
                  <TableCell className="text-[13px]">
                    {x.app}
                    <div className="text-xs text-muted">{x.client}</div>
                  </TableCell>
                  <TableCell>
                    {x.risk !== 'none' && x.risk !== 'hidden' ? (
                      <Badge variant={RISK[x.risk] ?? 'gray'}>{x.risk}</Badge>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <UserMenu upn={x.user} onAction={onAction} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty>Nada que revisar en este periodo.</Empty>
        )}
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- usuarios en riesgo
function RiskView({ onAction }: { onAction: (r: Req) => void }) {
  const R = useM365Risky();
  if (R.isPending) return <Loading rows={2} />;
  if (R.error || !R.data) return <ErrorState error={R.error} onRetry={() => void R.refetch()} />;
  const d = R.data;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel
        title={`Usuarios en riesgo · ${d.usuarios.length}`}
        hint="Entra ID Protection"
        bodyClassName="px-0 pb-0"
      >
        {d.usuarios.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Usuario</TableHead>
                <TableHead>Riesgo</TableHead>
                <TableHead>Estado</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {d.usuarios.map((u) => (
                <TableRow key={u.id}>
                  <TableCell>
                    <b>{u.name}</b>
                    <div className="text-xs text-muted">{u.upn}</div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={RISK[u.level] ?? 'gray'}>{u.level}</Badge>
                  </TableCell>
                  <TableCell className="text-[13px]">
                    {u.state === 'confirmedCompromised' ? (
                      <b className="text-bad">Comprometida</b>
                    ) : (
                      'En riesgo'
                    )}
                    <div className="text-xs text-muted">{u.updated.replace('T', ' ')}</div>
                  </TableCell>
                  <TableCell>
                    <UserMenu upn={u.upn} onAction={onAction} risky />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty>Ningún usuario en riesgo.</Empty>
        )}
      </Panel>
      <Panel title="Detecciones de riesgo · 7 días" bodyClassName="px-0 pb-0">
        {d.detecciones.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Fecha</TableHead>
                <TableHead>Usuario</TableHead>
                <TableHead>Tipo</TableHead>
                <TableHead>Origen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {d.detecciones.map((x, i) => (
                <TableRow key={i}>
                  <TableCell className="whitespace-nowrap text-muted">{x.at.slice(5)}</TableCell>
                  <TableCell className="text-[13px]">{x.upn}</TableCell>
                  <TableCell>
                    <Badge variant={RISK[x.level] ?? 'gray'}>{x.type}</Badge>
                  </TableCell>
                  <TableCell className="whitespace-nowrap font-mono text-xs">
                    {x.ip} {x.country}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty>Sin detecciones.</Empty>
        )}
      </Panel>
    </div>
  );
}

// ---------------------------------------------------------------- correo (reglas de bandeja de entrada)
function MailView({ onAction }: { onAction: (r: Req) => void }) {
  const { canWrite } = useAuth();
  const act = useCanAct();
  const R = useM365Rules();
  const scan = useM365ScanRules();
  const d = R.data?.scan;
  const running = !!R.data?.running;
  return (
    <Panel
      title="Reglas de bandeja de entrada sospechosas"
      hint="Reenvíos a dominios externos o reglas que borran/ocultan correo: señal típica de cuenta comprometida o fraude BEC."
      bodyClassName="px-0 pb-0"
      actions={
        canWrite && (
          <Button
            size="sm"
            disabled={running || scan.isPending}
            onClick={() =>
              scan.mutate(undefined, {
                onSuccess: () => toast.success('Revisando buzones en segundo plano…'),
                onError: (e) => toast.error(e.message),
              })
            }
          >
            <ScanSearch className={cn(running && 'animate-pulse')} />{' '}
            {running ? 'Revisando…' : 'Revisar buzones'}
          </Button>
        )
      }
    >
      {R.isPending ? (
        <Loading rows={1} />
      ) : R.error ? (
        <ErrorState error={R.error} compact />
      ) : !d ? (
        <Empty>
          Aún no se han revisado los buzones. Pulsa «Revisar buzones» (primero los usuarios en riesgo o con
          alertas).
        </Empty>
      ) : (
        <>
          <p className="px-4 pb-2 text-xs text-muted">
            Última revisión {d.at}: {nf(d.revisados)} buzones de {nf(d.usuarios)} usuarios ({nf(d.sin_buzon)}{' '}
            sin buzón).
          </p>
          {d.reglas.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Usuario</TableHead>
                  <TableHead>Regla</TableHead>
                  <TableHead>Qué hace</TableHead>
                  <TableHead>Estado</TableHead>
                  {act && <TableHead className="w-10" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {d.reglas.map((r) => (
                  <TableRow key={r.rule_id}>
                    <TableCell className="font-semibold">{r.upn}</TableCell>
                    <TableCell className="text-[13px]">
                      «{r.name || 'sin nombre'}»
                      <div className="line-clamp-1 font-mono text-[11px] text-muted" title={r.condiciones}>
                        {r.condiciones}
                      </div>
                    </TableCell>
                    <TableCell className="text-[13px]">
                      {r.externos.length ? (
                        <span className="text-bad">
                          Reenvía a <b>{r.externos.join(', ')}</b>
                        </span>
                      ) : null}
                      {r.oculta && <div className="text-warn">Borra u oculta mensajes</div>}
                    </TableCell>
                    <TableCell>
                      {r.enabled ? (
                        <Badge variant={r.nivel === 'alto' ? 'bad' : 'warn'}>Activa</Badge>
                      ) : (
                        <Badge variant="gray">Desactivada</Badge>
                      )}
                    </TableCell>
                    {act && (
                      <TableCell>
                        {r.enabled && (
                          <Button
                            size="icon"
                            variant="ghost"
                            aria-label={`Desactivar regla de ${r.upn}`}
                            onClick={() =>
                              onAction({
                                kind: 'disable_rule',
                                target: { user: r.upn, rule_id: r.rule_id, rule_name: r.name },
                                label: `${r.upn} · «${r.name}»`,
                              })
                            }
                          >
                            <MailX />
                          </Button>
                        )}
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <Empty>No se encontraron reglas sospechosas.</Empty>
          )}
        </>
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------- auditoría del directorio
function AuditView() {
  const [days, setDays] = useState(7);
  const [onlySens, setOnlySens] = useState(true);
  const A = useM365Audits(days);
  if (A.isPending) return <Loading rows={2} />;
  if (A.error || !A.data) return <ErrorState error={A.error} onRetry={() => void A.refetch()} />;
  const rows = A.data.filter((x) => !onlySens || x.sensible);
  return (
    <Panel
      title="Auditoría de Entra ID / 365"
      hint="Cambios de roles, acceso condicional, aplicaciones y consentimientos, contraseñas y métodos de autenticación."
      bodyClassName="px-0 pb-0"
      actions={
        <div className="flex gap-2">
          <Chips
            options={[
              [1, '24 h'],
              [7, '7 días'],
              [30, '30 días'],
            ]}
            value={days}
            onChange={setDays}
          />
          <Chips
            options={[
              ['s', 'Solo sensibles'],
              ['t', 'Todo'],
            ]}
            value={onlySens ? 's' : 't'}
            onChange={(v) => setOnlySens(v === 's')}
          />
        </div>
      }
    >
      {rows.length ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Fecha</TableHead>
              <TableHead>Actividad</TableHead>
              <TableHead>Quién</TableHead>
              <TableHead>Sobre</TableHead>
              <TableHead>Resultado</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((x, i) => (
              <TableRow key={i}>
                <TableCell className="whitespace-nowrap text-muted">{x.at.slice(5, 16)}</TableCell>
                <TableCell>
                  <b className={cn(x.sensible && 'text-warn')}>{x.activity}</b>
                  <div className="text-xs text-muted">{x.category}</div>
                </TableCell>
                <TableCell className="text-[13px]">{x.by}</TableCell>
                <TableCell className="max-w-[280px] truncate text-[13px]" title={x.target}>
                  {x.target}
                </TableCell>
                <TableCell>
                  <Badge variant={x.result === 'success' ? 'ok' : 'warn'}>{x.result}</Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : (
        <Empty>Sin cambios en este periodo.</Empty>
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------- Secure Score y estado del servicio
function PostureView() {
  const P = useM365Posture();
  if (P.isPending) return <Loading rows={3} />;
  if (P.error || !P.data) return <ErrorState error={P.error} onRetry={() => void P.refetch()} />;
  const d = P.data;
  const pct = d.score != null && d.max ? Math.round((d.score / d.max) * 100) : null;
  const down = d.servicios.filter((s) => s.status !== 'serviceOperational');
  return (
    <>
      <KpiGrid>
        <Kpi
          title="Microsoft Secure Score"
          value={pct != null ? `${pct} %` : '—'}
          hint={d.score != null ? `${nf(d.score)} de ${nf(d.max ?? 0)} puntos · ${d.fecha}` : ''}
        />
        {d.comparativa.slice(0, 1).map((c) => (
          <Kpi
            key={c.tipo}
            title="Media de organizaciones"
            value={d.max ? `${Math.round((c.media / d.max) * 100)} %` : nf(c.media)}
            hint={c.tipo}
          />
        ))}
        <Kpi
          title="Servicios con incidencias"
          value={nf(down.length)}
          alert={down.length > 0}
          hint={down.map((s) => s.service).join(', ') || 'Todo operativo'}
        />
        <Kpi title="Mejoras disponibles" value={nf(d.recomendaciones.length)} hint="ordenadas por puntos" />
      </KpiGrid>
      <div className="grid gap-4 lg:grid-cols-[1.4fr_1fr]">
        <Panel title="Recomendaciones con más impacto" bodyClassName="px-0 pb-0">
          {d.recomendaciones.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Recomendación</TableHead>
                  <TableHead className="text-right">Puntos</TableHead>
                  <TableHead>Impacto / coste</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {d.recomendaciones.map((r) => (
                  <TableRow key={r.control}>
                    <TableCell>
                      {r.url ? (
                        <a
                          href={r.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-semibold hover:text-brand"
                        >
                          {r.title} <ExternalLink className="inline size-3" />
                        </a>
                      ) : (
                        <b>{r.title}</b>
                      )}
                      <div className="text-xs text-muted">{r.category}</div>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-right font-mono text-[13px]">
                      +{r.gain}{' '}
                      <span className="text-muted">
                        ({r.score}/{r.max})
                      </span>
                    </TableCell>
                    <TableCell className="text-xs text-muted">
                      {r.impact || '—'} / {r.cost || '—'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <Empty>Sin recomendaciones pendientes.</Empty>
          )}
        </Panel>
        <Panel title="Estado de los servicios">
          <ul className="space-y-1.5 text-[13px]">
            {d.servicios.map((s) => (
              <li key={s.service} className="flex items-center justify-between gap-2">
                <span>{s.service}</span>
                <Badge variant={s.status === 'serviceOperational' ? 'ok' : 'warn'}>
                  {SVC[s.status] ?? s.status}
                </Badge>
              </li>
            ))}
          </ul>
          {!!d.incidencias.length && (
            <>
              <h3 className="mb-1.5 mt-3 font-semibold">Incidencias abiertas de Microsoft</h3>
              <ul className="space-y-1.5 text-[13px]">
                {d.incidencias.map((i) => (
                  <li key={i.id || i.title}>
                    <b>{i.id}</b> {i.title}{' '}
                    <span className="text-xs text-muted">
                      · {i.service} · {i.start}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Panel>
      </div>
    </>
  );
}

// ---------------------------------------------------------------- acciones
function ActionsView({ fourEyes }: { fourEyes: boolean }) {
  const { me } = useAuth();
  const act = useCanAct();
  const [status, setStatus] = useState('');
  const A = useM365Actions(status);
  const decide = useM365Decide();
  const run = (id: number, approve: boolean) =>
    decide.mutate(
      { id, approve },
      {
        onSuccess: (a) =>
          a.status === 'done'
            ? toast.success(`${a.nombre}: ${a.result}`)
            : a.status === 'rejected'
              ? toast.info('Acción rechazada')
              : toast.error(`${a.nombre}: ${a.result}`),
        onError: (e) => toast.error(e.message),
      },
    );
  return (
    <Panel
      title="Acciones en Microsoft 365"
      hint={
        fourEyes
          ? 'Cuatro ojos activo: la contención la aprueba alguien distinto de quien la pide.'
          : 'Las pedidas por Shuffle quedan pendientes hasta que una persona las aprueba.'
      }
      bodyClassName="px-0 pb-0"
      actions={
        <Chips
          options={[
            ['', 'Todas'],
            ['pending', 'Pendientes'],
            ['done', 'Hechas'],
            ['failed', 'Fallidas'],
            ['rejected', 'Rechazadas'],
          ]}
          value={status}
          onChange={setStatus}
        />
      }
    >
      {A.isPending ? (
        <Loading rows={1} />
      ) : A.error || !A.data ? (
        <ErrorState error={A.error} onRetry={() => void A.refetch()} />
      ) : A.data.length ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>#</TableHead>
              <TableHead>Acción</TableHead>
              <TableHead>Sobre</TableHead>
              <TableHead>Motivo</TableHead>
              <TableHead>Pedida por</TableHead>
              <TableHead>Estado</TableHead>
              <TableHead>Resultado</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {A.data.map((a) => {
              const self = fourEyes && a.contencion && a.requested_by === me?.username;
              return (
                <TableRow key={a.id}>
                  <TableCell className="text-muted">{a.id}</TableCell>
                  <TableCell className="whitespace-nowrap font-semibold">
                    {a.nombre}
                    {a.contencion && <div className="text-xs font-normal text-warn">contención</div>}
                  </TableCell>
                  <TableCell className="max-w-[220px] truncate text-[13px]" title={a.label}>
                    {a.label}
                  </TableCell>
                  <TableCell className="max-w-[240px] text-[13px]">
                    {a.reason}
                    {a.incident && (
                      <div>
                        <Link to={`/incidents/${a.incident}`} className="text-xs text-brand">
                          {a.incident}
                        </Link>
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-[13px]">
                    {a.requested_by}
                    <div className="text-xs text-muted">
                      {a.origin === 'shuffle' ? 'Shuffle' : 'portal'} · {a.at.slice(5, 16)}
                    </div>
                  </TableCell>
                  <TableCell>
                    {a.status === 'pending' && act ? (
                      <div className="flex gap-1.5">
                        <Button
                          size="sm"
                          disabled={decide.isPending || self}
                          title={self ? 'La tiene que aprobar otra persona' : undefined}
                          onClick={() => run(a.id, true)}
                        >
                          Aprobar
                        </Button>
                        <Button
                          size="sm"
                          variant="secondary"
                          disabled={decide.isPending}
                          onClick={() => run(a.id, false)}
                        >
                          Rechazar
                        </Button>
                      </div>
                    ) : (
                      <Badge variant={ST[a.status]?.[1] ?? 'gray'}>{ST[a.status]?.[0] ?? a.status}</Badge>
                    )}
                  </TableCell>
                  <TableCell className="max-w-[260px] text-xs text-muted">
                    {a.result}
                    {a.decided_by && (
                      <div>
                        {a.status === 'rejected' ? 'rechazó' : 'aprobó'} {a.decided_by} ·{' '}
                        {a.decided_at.slice(5, 16)}
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      ) : (
        <Empty>Sin acciones {status ? 'con ese estado' : 'todavía'}.</Empty>
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------- confirmación humana de una acción
function ActionDialog({
  req,
  fourEyes,
  onClose,
}: {
  req: Req | null;
  fourEyes: boolean;
  onClose: () => void;
}) {
  return (
    <Dialog open={!!req} onOpenChange={(o) => !o && onClose()}>
      {req && <ActionBody key={JSON.stringify(req)} req={req} fourEyes={fourEyes} onClose={onClose} />}
    </Dialog>
  );
}

function ActionBody({ req, fourEyes, onClose }: { req: Req; fourEyes: boolean; onClose: () => void }) {
  const run = useM365Action();
  const [reason, setReason] = useState('');
  const [incident, setIncident] = useState('');
  const [name, contain] = KIND[req.kind];
  const pendingOnly = contain && fourEyes;
  const submit = () =>
    run.mutate(
      { kind: req.kind, target: req.target, reason: reason.trim(), incident: incident.trim() },
      {
        onSuccess: (a) => {
          if (a.status === 'done') toast.success(`${a.nombre}: ${a.result}`);
          else if (a.status === 'pending')
            toast.info('Acción registrada: necesita la aprobación de otra persona');
          else toast.error(`${a.nombre}: ${a.result}`);
          onClose();
        },
        onError: (e) => toast.error(e.message),
      },
    );
  return (
    <DialogContent title={name} description={req.label}>
      <div className="space-y-3">
        {contain && (
          <div className="flex gap-2 rounded-lg border border-st-warn/40 bg-st-warn/10 p-2.5 text-[13px]">
            <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" />
            <span>
              Acción de <b>contención</b> sobre una cuenta real de 365: afecta al usuario de inmediato.
              {pendingOnly
                ? ' Con cuatro ojos activo quedará pendiente hasta que otra persona la apruebe.'
                : ' Al confirmar, tú eres quien la aprueba.'}
            </span>
          </div>
        )}
        <div>
          <Label htmlFor="ma-reason">Motivo *</Label>
          <Textarea
            id="ma-reason"
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Por qué se hace (queda en la auditoría)…"
          />
        </div>
        <div>
          <Label htmlFor="ma-inc">Incidente relacionado (opcional)</Label>
          <Input
            id="ma-inc"
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
            onClick={submit}
          >
            {pendingOnly ? 'Solicitar aprobación' : 'Confirmar'}
          </Button>
        </div>
      </div>
    </DialogContent>
  );
}
