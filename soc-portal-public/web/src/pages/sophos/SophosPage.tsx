import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Ban,
  CheckCircle2,
  Lock,
  MoreHorizontal,
  Plus,
  RefreshCw,
  ScanSearch,
  ShieldCheck,
  Unlock,
  XCircle,
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
import { since } from '@/lib/format';
import { cn } from '@/lib/utils';
import { useNewIncident } from '@/pages/incidents/NewIncidentDialog';
import { useIocDetail } from '@/pages/iocs/IocDetailDialog';
import {
  useSophosActions,
  useSophosAlerts,
  useSophosBlocked,
  useSophosDecide,
  useSophosEndpoints,
  useSophosStatus,
  useSophosSync,
} from '@/services/sophos';
import type { SophosAlert, SophosEndpoint, SophosStatus } from '@/types/api';
import { ActionDialog, type ActionRequest } from './ActionDialog';

const VIEWS: [string, string][] = [
  ['alertas', 'Alertas'],
  ['equipos', 'Equipos'],
  ['bloqueos', 'Bloqueos'],
  ['acciones', 'Acciones'],
];
const SEV: Record<string, { label: string; v: 'bad' | 'warn' | 'gray' }> = {
  high: { label: 'Alta', v: 'bad' },
  medium: { label: 'Media', v: 'warn' },
  low: { label: 'Baja', v: 'gray' },
};
const HEALTH: Record<string, { label: string; v: 'ok' | 'warn' | 'bad' | 'gray' }> = {
  good: { label: 'Buena', v: 'ok' },
  suspicious: { label: 'Sospechosa', v: 'warn' },
  bad: { label: 'Mala', v: 'bad' },
  unknown: { label: 'Desconocida', v: 'gray' },
};
const ALERT_ACTION: Record<string, string> = {
  acknowledge: 'Marcar como revisada',
  cleanPua: 'Limpiar PUA',
  cleanVirus: 'Limpiar malware',
  authPua: 'Autorizar aplicación (PUA)',
  clearThreat: 'Borrar amenaza',
  clearHmpa: 'Borrar alerta de exploit',
  sendMsgPua: 'Avisar al usuario (PUA)',
  sendMsgThreat: 'Avisar al usuario (amenaza)',
};
const STATUS: Record<string, { label: string; v: 'ok' | 'warn' | 'bad' | 'gray' | 'info' }> = {
  pending: { label: 'Pendiente', v: 'warn' },
  running: { label: 'En curso', v: 'info' },
  done: { label: 'Hecha', v: 'ok' },
  failed: { label: 'Falló', v: 'bad' },
  rejected: { label: 'Rechazada', v: 'gray' },
};

/** Puede pedir acciones en Sophos: rol del portal con escritura y credencial que no sea de solo lectura. */
function useCanAct() {
  const { canWrite } = useAuth();
  const st = useSophosStatus();
  return canWrite && !st.data?.solo_lectura;
}

export default function SophosPage() {
  const ref = usePageEnter('sophos');
  const [view, setView] = useSearchParam('view', 'alertas');
  const st = useSophosStatus();
  const [req, setReq] = useState<ActionRequest | null>(null);
  useEffect(() => {
    document.title = 'Portal SOC · Sophos Central';
  }, []);
  if (st.isPending) return <Loading rows={2} />;
  if (st.error || !st.data) return <ErrorState error={st.error} onRetry={() => void st.refetch()} />;
  const s = st.data;
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Sophos Central"
        subtitle="Alertas y equipos protegidos por Sophos, con respuesta (aislar, escanear, bloquear) siempre confirmada por una persona."
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
          {view === 'equipos' ? (
            <EndpointsView onAction={setReq} />
          ) : view === 'bloqueos' ? (
            <BlockedView onAction={setReq} tag={s.web_tag ?? ''} />
          ) : view === 'acciones' ? (
            <ActionsView fourEyes={!!s.four_eyes} />
          ) : (
            <AlertsView onAction={setReq} />
          )}
        </>
      )}
      <ActionDialog req={req} fourEyes={s.four_eyes} onClose={() => setReq(null)} />
    </div>
  );
}

function Setup() {
  return (
    <Panel title="Conectar Sophos Central">
      <ol className="list-decimal space-y-2 pl-5 text-[13.5px]">
        <li>
          En Sophos Central ve a <b>Configuración global → Credenciales de API</b> y crea una credencial con
          el rol <b>Service Principal Super Admin</b> (necesario para aislar y bloquear; con solo lectura usa{' '}
          <b>Service Principal Read-Only</b>).
        </li>
        <li>
          Copia el <b>Client ID</b> y el <b>Client Secret</b> (el secreto solo se muestra una vez).
        </li>
        <li>
          Añádelos al <code>.env</code> del servidor y recrea el bridge:
          <pre className="mt-1.5 overflow-x-auto rounded-lg bg-grid p-2.5 font-mono text-[12px]">
            {`SOPHOS_CLIENT_ID=...
SOPHOS_CLIENT_SECRET=...
# opcionales
SOPHOS_AUTO_INCIDENT=high        # abrir incidente con alertas high (medium, low o vacío = no)
SOPHOS_FOUR_EYES=false           # true: la contención la aprueba otra persona
SOPHOS_WEB_TAG=SOC-ACME-BLOQUEO # etiqueta para sitios bloqueados`}
          </pre>
        </li>
        <li>
          El servidor necesita salida HTTPS a <code>id.sophos.com</code> y <code>*.central.sophos.com</code>.
        </li>
      </ol>
    </Panel>
  );
}

function StatusBar({ s }: { s: SophosStatus }) {
  const sync = useSophosSync();
  const bad = !s.conectado || s.sync_msg?.startsWith('Error');
  return (
    <div
      className={cn('card flex flex-wrap items-center gap-3 px-4 py-2.5 text-[13px]', bad && 'border-bad/50')}
    >
      <ShieldCheck className={cn('size-4', bad ? 'text-bad' : 'text-ok')} />
      {s.conectado ? (
        <span>
          Conectado · región <b>{s.region?.replace(/^https?:\/\//, '')}</b>
        </span>
      ) : (
        <span className="text-bad">Sin conexión: {s.error}</span>
      )}
      <span className="text-muted">
        Última sincronización: {s.ultima_sync || '—'} · {s.sync_msg || '—'} · cada {s.poll_min} min
      </span>
      <span className="flex-1" />
      {s.solo_lectura && (
        <Badge variant="gray" title="Credencial Service Principal ReadOnly: sin aislar, escanear ni bloquear">
          Solo lectura
        </Badge>
      )}
      {s.four_eyes && <Badge variant="info">Cuatro ojos</Badge>}
      {s.auto_incidente && (
        <Badge variant="gray">Incidente automático ≥ {SEV[s.auto_incidente]?.label}</Badge>
      )}
      <Button
        size="sm"
        variant="secondary"
        disabled={sync.isPending}
        onClick={() =>
          sync.mutate(undefined, {
            onSuccess: () => toast.success('Sincronizando con Sophos…'),
            onError: (e) => toast.error(e.message),
          })
        }
      >
        <RefreshCw className={cn(sync.isPending && 'animate-spin')} /> Sincronizar
      </Button>
    </div>
  );
}

// ---------------------------------------------------------------- alertas
function AlertsView({ onAction }: { onAction: (r: ActionRequest) => void }) {
  const { canWrite } = useAuth();
  const act = useCanAct();
  const newInc = useNewIncident();
  const iocDetail = useIocDetail();
  const [days, setDays] = useState(7);
  const [severity, setSeverity] = useState('');
  const [text, setText] = useState('');
  const [q, setQ] = useState('');
  const A = useSophosAlerts({ days, severity, q });
  if (A.isPending) return <Loading rows={3} />;
  if (A.error || !A.data) return <ErrorState error={A.error} onRetry={() => void A.refetch()} />;
  const { items, stats } = A.data;
  const n = (k: string) => stats.severidad.find((x) => x[0] === k)?.[1] ?? 0;
  const toIncident = (a: SophosAlert) =>
    newInc.open({
      title: `Sophos: ${a.description.slice(0, 150)}`,
      severity: a.severity === 'high' ? 'High' : a.severity === 'medium' ? 'Medium' : 'Low',
      detected_by: 'Sophos Central',
      assets: a.endpoint,
      iocs: a.iocs.join('\n'),
      summary: `Alerta de Sophos Central (${a.category} · ${a.type}) en ${a.endpoint || 'equipo desconocido'}${a.person ? ` · usuario ${a.person}` : ''}.\n\n${a.description}`,
    });
  return (
    <>
      <KpiGrid>
        <Kpi title="Alertas" value={items.length} hint={`últimos ${days} días`} />
        <Kpi
          title="Severidad alta"
          value={n('high')}
          alert={n('high') > 0}
          onClick={() => setSeverity('high')}
        />
        <Kpi title="Media" value={n('medium')} onClick={() => setSeverity('medium')} />
        <Kpi
          title="Con IoC conocido"
          value={stats.con_ioc}
          alert={stats.con_ioc > 0}
          hint="cruzado con el motor de IoC"
        />
      </KpiGrid>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Por categoría">
          <HBars rows={stats.categorias.map(([k, v]) => ({ label: k || '—', value: v }))} />
        </Panel>
        <Panel title="Equipos con más alertas">
          <HBars rows={stats.equipos.map(([k, v]) => ({ label: k, value: v }))} />
        </Panel>
      </div>
      <Panel
        title="Alertas"
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
              <option value="">Todas</option>
              <option value="high">Alta</option>
              <option value="medium">Media</option>
              <option value="low">Baja</option>
            </Select>
            <Input
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && setQ(text)}
              placeholder="Buscar equipo, usuario, texto… (Enter)"
              className="w-60"
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
                <TableHead>Equipo</TableHead>
                <TableHead>Descripción</TableHead>
                <TableHead>IoC</TableHead>
                <TableHead>Incidente</TableHead>
                {canWrite && <TableHead className="w-10" />}
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((a) => (
                <TableRow key={a.id}>
                  <TableCell className="whitespace-nowrap text-muted">
                    {a.raised_at.slice(0, 16).replace('T', ' ')}
                  </TableCell>
                  <TableCell>
                    <Badge variant={SEV[a.severity]?.v ?? 'gray'}>
                      {SEV[a.severity]?.label ?? a.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="whitespace-nowrap font-semibold">
                    {a.endpoint || '—'}
                    {a.person && <div className="text-xs font-normal text-muted">{a.person}</div>}
                  </TableCell>
                  <TableCell className="max-w-[520px]">
                    <div className="line-clamp-2 text-[13px]">{a.description}</div>
                    <div className="text-xs text-muted">
                      {a.category} · {a.product}
                      {a.state !== 'open' && ` · ${ALERT_ACTION[a.state] ?? a.state}`}
                    </div>
                  </TableCell>
                  <TableCell>
                    {Object.keys(a.matches).length ? (
                      <button type="button" onClick={() => iocDetail.open(Object.keys(a.matches)[0] ?? '')}>
                        <Badge variant="bad" title={Object.keys(a.matches).join(', ')}>
                          {Object.keys(a.matches).length} conocido(s)
                        </Badge>
                      </button>
                    ) : a.iocs.length ? (
                      <span className="text-xs text-muted">{a.iocs.length}</span>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    {a.incident ? (
                      <Link to={`/incidents/${a.incident}`} className="font-semibold text-brand">
                        {a.incident}
                      </Link>
                    ) : null}
                  </TableCell>
                  {canWrite && (
                    <TableCell>
                      {(act || !a.incident) && (
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button size="icon" variant="ghost" aria-label={`Acciones de la alerta ${a.id}`}>
                              <MoreHorizontal />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            {!a.incident && (
                              <DropdownMenuItem onSelect={() => toIncident(a)}>
                                <Plus /> Crear incidente
                              </DropdownMenuItem>
                            )}
                            {act && a.endpoint_id && (
                              <>
                                <DropdownMenuItem
                                  onSelect={() =>
                                    onAction({
                                      kind: 'isolate',
                                      target: { ids: [a.endpoint_id] },
                                      label: a.endpoint,
                                      incident: a.incident,
                                    })
                                  }
                                >
                                  <Lock /> Aislar {a.endpoint || 'equipo'}
                                </DropdownMenuItem>
                                <DropdownMenuItem
                                  onSelect={() =>
                                    onAction({
                                      kind: 'scan',
                                      target: { ids: [a.endpoint_id] },
                                      label: a.endpoint,
                                      incident: a.incident,
                                    })
                                  }
                                >
                                  <ScanSearch /> Escanear
                                </DropdownMenuItem>
                              </>
                            )}
                            {act && a.allowed.length > 0 && (
                              <>
                                <DropdownMenuSeparator />
                                <DropdownMenuLabel>En Sophos</DropdownMenuLabel>
                                {a.allowed.map((act) => (
                                  <DropdownMenuItem
                                    key={act}
                                    onSelect={() =>
                                      onAction({
                                        kind: 'alert_action',
                                        target: { alert_id: a.id, action: act },
                                        label: `${ALERT_ACTION[act] ?? act} · ${a.description.slice(0, 120)}`,
                                        incident: a.incident,
                                      })
                                    }
                                  >
                                    {ALERT_ACTION[act] ?? act}
                                  </DropdownMenuItem>
                                ))}
                              </>
                            )}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      )}
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty>Sin alertas de Sophos en este periodo.</Empty>
        )}
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- equipos
function EndpointsView({ onAction }: { onAction: (r: ActionRequest) => void }) {
  const canWrite = useCanAct();
  const [text, setText] = useState('');
  const [q, setQ] = useState('');
  const [health, setHealth] = useState('');
  const [isolated, setIsolated] = useState('');
  const E = useSophosEndpoints({ q, health, isolated });
  if (E.isPending) return <Loading rows={3} />;
  if (E.error || !E.data) return <ErrorState error={E.error} onRetry={() => void E.refetch()} />;
  const rows = E.data.items;
  const count = (h: string) => rows.filter((r) => r.health === h).length;
  const act = (kind: 'isolate' | 'unisolate' | 'scan', e: SophosEndpoint) =>
    onAction({ kind, target: { ids: [e.id] }, label: `${e.hostname} · ${e.ip}` });
  return (
    <>
      <KpiGrid>
        <Kpi title="Equipos" value={rows.length} hint={`inventario: ${E.data.sincronizado || '—'}`} />
        <Kpi
          title="Salud mala"
          value={count('bad')}
          alert={count('bad') > 0}
          onClick={() => setHealth('bad')}
        />
        <Kpi title="Sospechosa" value={count('suspicious')} onClick={() => setHealth('suspicious')} />
        <Kpi
          title="Aislados"
          value={rows.filter((r) => r.isolation === 'isolated').length}
          onClick={() => setIsolated('1')}
        />
      </KpiGrid>
      <Panel
        title="Equipos protegidos"
        bodyClassName="px-0 pb-0"
        actions={
          <div className="flex flex-wrap gap-2">
            <Select
              value={health}
              onChange={(e) => setHealth(e.target.value)}
              aria-label="Salud"
              className="w-auto"
            >
              <option value="">Toda salud</option>
              {Object.entries(HEALTH).map(([k, v]) => (
                <option key={k} value={k}>
                  {v.label}
                </option>
              ))}
            </Select>
            <Select
              value={isolated}
              onChange={(e) => setIsolated(e.target.value)}
              aria-label="Aislamiento"
              className="w-auto"
            >
              <option value="">Aislados y no</option>
              <option value="1">Solo aislados</option>
              <option value="0">No aislados</option>
            </Select>
            <Input
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && setQ(text)}
              placeholder="Nombre, IP o usuario… (Enter)"
              className="w-56"
              aria-label="Buscar equipos"
            />
          </div>
        }
      >
        {rows.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Equipo</TableHead>
                <TableHead>Salud</TableHead>
                <TableHead>Aislamiento</TableHead>
                <TableHead>Sistema</TableHead>
                <TableHead>Usuario</TableHead>
                <TableHead>Antimanipulación</TableHead>
                <TableHead>Visto</TableHead>
                {canWrite && <TableHead className="w-10" />}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((e) => (
                <TableRow key={e.id}>
                  <TableCell className="whitespace-nowrap">
                    <b>{e.hostname}</b>
                    <div className="font-mono text-xs text-muted">
                      {e.ip} · {e.type === 'server' ? 'servidor' : 'equipo'}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={HEALTH[e.health]?.v ?? 'gray'}>
                      {HEALTH[e.health]?.label ?? e.health}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {e.isolation === 'isolated' ? (
                      <Badge variant="bad">Aislado</Badge>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </TableCell>
                  <TableCell className="text-[13px]">{e.os}</TableCell>
                  <TableCell className="text-[13px]">{e.person || '—'}</TableCell>
                  <TableCell>
                    {e.tamper ? (
                      <CheckCircle2 className="size-4 text-ok" />
                    ) : (
                      <XCircle className="size-4 text-bad" />
                    )}
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-muted">hace {since(e.last_seen)}</TableCell>
                  {canWrite && (
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button size="icon" variant="ghost" aria-label={`Acciones de ${e.hostname}`}>
                            <MoreHorizontal />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          {e.isolation === 'isolated' ? (
                            <DropdownMenuItem onSelect={() => act('unisolate', e)}>
                              <Unlock /> Quitar aislamiento
                            </DropdownMenuItem>
                          ) : (
                            <DropdownMenuItem onSelect={() => act('isolate', e)}>
                              <Lock /> Aislar de la red
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuItem onSelect={() => act('scan', e)}>
                            <ScanSearch /> Escanear ahora
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty>Ningún equipo coincide (o aún no se ha sincronizado el inventario).</Empty>
        )}
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- bloqueos
function BlockedView({ onAction, tag }: { onAction: (r: ActionRequest) => void; tag: string }) {
  const canWrite = useCanAct();
  const B = useSophosBlocked();
  const [text, setText] = useState('');
  const vals = text
    .split(/[\s,;]+/)
    .map((x) => x.trim())
    .filter(Boolean);
  const hashes = vals.filter((v) => /^[a-f0-9]{64}$/i.test(v));
  const web = vals.filter((v) => !/^[a-f0-9]{32,128}$/i.test(v));
  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_1.2fr]">
      {canWrite && (
        <Panel title="Enviar IoC a Sophos" hint="Se bloquean en todos los equipos gestionados">
          <div className="space-y-3">
            <div>
              <Label htmlFor="sb-vals">Indicadores (uno por línea, máx. 100)</Label>
              <Textarea
                id="sb-vals"
                rows={7}
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder={
                  '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\nmalo-phish.xyz\nhttps://evil.example.org/login'
                }
                className="font-mono text-[12.5px]"
              />
            </div>
            <p className="text-xs text-muted">
              <b>SHA-256</b> → «Elementos bloqueados» (no se ejecutan). <b>Dominios, URL e IP públicas</b> →
              «Sitios web locales» con la etiqueta <code>{tag}</code>: para que se bloqueen, la política de{' '}
              <b>Control web</b> de Sophos debe tener esa etiqueta en «Bloquear». Se rechazan IP privadas y
              dominios de la lista segura.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="destructive"
                disabled={!hashes.length}
                onClick={() =>
                  onAction({
                    kind: 'block_hash',
                    target: { values: hashes },
                    label: `${hashes.length} SHA-256`,
                  })
                }
              >
                <Ban /> Bloquear {hashes.length} hash(es)
              </Button>
              <Button
                variant="destructive"
                disabled={!web.length}
                onClick={() =>
                  onAction({ kind: 'block_web', target: { values: web }, label: web.slice(0, 5).join(', ') })
                }
              >
                <Ban /> Bloquear {web.length} sitio(s)
              </Button>
            </div>
          </div>
        </Panel>
      )}
      <Panel title="Bloqueado ahora en Sophos" bodyClassName="px-0 pb-0">
        {B.isPending ? (
          <Loading rows={1} />
        ) : B.error || !B.data ? (
          <ErrorState error={B.error} onRetry={() => void B.refetch()} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Tipo</TableHead>
                <TableHead>Valor</TableHead>
                <TableHead>Comentario</TableHead>
                {canWrite && <TableHead className="w-10" />}
              </TableRow>
            </TableHeader>
            <TableBody>
              {B.data.hashes.map((h) => (
                <TableRow key={h.id}>
                  <TableCell>
                    <Badge variant="gray">SHA-256</Badge>
                  </TableCell>
                  <TableCell className="max-w-[260px] truncate font-mono text-xs" title={h.sha256}>
                    {h.sha256}
                  </TableCell>
                  <TableCell className="text-xs text-muted">{h.comment}</TableCell>
                  {canWrite && (
                    <TableCell>
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label={`Quitar bloqueo ${h.sha256.slice(0, 12)}`}
                        onClick={() =>
                          onAction({
                            kind: 'unblock_hash',
                            target: { id: h.id, label: h.sha256 },
                            label: h.sha256,
                          })
                        }
                      >
                        <Unlock />
                      </Button>
                    </TableCell>
                  )}
                </TableRow>
              ))}
              {B.data.web.map((w) => (
                <TableRow key={w.id}>
                  <TableCell>
                    <Badge variant={w.tags.includes(B.data.web_tag) ? 'bad' : 'gray'}>Web</Badge>
                  </TableCell>
                  <TableCell className="max-w-[260px] truncate font-mono text-xs" title={w.url}>
                    {w.url}
                  </TableCell>
                  <TableCell className="text-xs text-muted">
                    {w.tags.join(', ')} {w.comment && `· ${w.comment}`}
                  </TableCell>
                  {canWrite && (
                    <TableCell>
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label={`Quitar bloqueo ${w.url}`}
                        onClick={() =>
                          onAction({ kind: 'unblock_web', target: { id: w.id, label: w.url }, label: w.url })
                        }
                      >
                        <Unlock />
                      </Button>
                    </TableCell>
                  )}
                </TableRow>
              ))}
              {!B.data.hashes.length && !B.data.web.length && (
                <TableRow>
                  <TableCell colSpan={4} className="py-6 text-center text-muted">
                    Nada bloqueado desde la API todavía.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        )}
      </Panel>
    </div>
  );
}

// ---------------------------------------------------------------- acciones (cola de aprobación + historial)
function ActionsView({ fourEyes }: { fourEyes: boolean }) {
  const { me } = useAuth();
  const canWrite = useCanAct();
  const [status, setStatus] = useState('');
  const A = useSophosActions(status);
  const decide = useSophosDecide();
  const run = async (id: number, approve: boolean) => {
    try {
      const a = await decide.mutateAsync({ id, approve, note: approve ? '' : 'Rechazada desde el portal' });
      if (a.status === 'done') toast.success(`${a.nombre}: ${a.result}`);
      else if (a.status === 'rejected') toast.info('Acción rechazada');
      else toast.error(`${a.nombre}: ${a.result}`);
    } catch (e) {
      toast.error((e as Error).message);
    }
  };
  return (
    <Panel
      title="Acciones en Sophos"
      hint={
        fourEyes
          ? 'Regla de cuatro ojos activa: la contención la aprueba alguien distinto de quien la pide.'
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
            {A.data.map((a) => (
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
                  {a.status === 'pending' && canWrite ? (
                    <div className="flex gap-1.5">
                      <Button
                        size="sm"
                        disabled={
                          decide.isPending || (fourEyes && a.contencion && a.requested_by === me?.username)
                        }
                        title={
                          fourEyes && a.contencion && a.requested_by === me?.username
                            ? 'La tiene que aprobar otra persona'
                            : undefined
                        }
                        onClick={() => void run(a.id, true)}
                      >
                        Aprobar
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={decide.isPending}
                        onClick={() => void run(a.id, false)}
                      >
                        Rechazar
                      </Button>
                    </div>
                  ) : (
                    <Badge variant={STATUS[a.status]?.v ?? 'gray'}>
                      {STATUS[a.status]?.label ?? a.status}
                    </Badge>
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
            ))}
          </TableBody>
        </Table>
      ) : (
        <Empty>Sin acciones {status ? 'con ese estado' : 'todavía'}.</Empty>
      )}
    </Panel>
  );
}
