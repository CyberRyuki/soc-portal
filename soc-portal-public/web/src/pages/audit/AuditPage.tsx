import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Download, KeyRound, ShieldCheck, ShieldX } from 'lucide-react';
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
import { Input, Select } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useSearchParam } from '@/hooks/useSearchParam';
import { api, qs } from '@/lib/api';
import { nf } from '@/lib/format';
import { cn } from '@/lib/utils';

interface Change {
  id: number;
  at: string;
  user: string;
  role: string;
  ip: string;
  method: string;
  path: string;
  module: string;
  action: string;
  target: string;
  status: number;
  ms: number;
  detail: string;
}
interface AuditData {
  items: Change[];
  stats: {
    total: number;
    rechazados: number;
    usuarios: [string, number][];
    modulos: [string, number][];
    usuarios_lista: string[];
  };
  conservacion_dias: number;
}
interface Verify {
  ok: boolean;
  registros: number;
  mensaje: string;
  alterado?: number;
}
interface SysLine {
  id: number;
  at: string;
  level: 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL' | string;
  logger: string;
  msg: string;
}
const MODULES = [
  'Incidentes',
  'Vulnerabilidades',
  'IoC / inteligencia',
  'Sophos',
  'Runbooks',
  'Herramientas',
  'Portales',
  'Contactos',
  'MITRE / OWASP',
  'Asistente IA',
  'Usuarios y accesos',
  'Administración',
  'Mi cuenta',
  'Integración (Shuffle/Wazuh)',
  'Auditoría',
];

export default function AuditPage() {
  const ref = usePageEnter('audit');
  const [view, setView] = useSearchParam('view', 'cambios');
  useEffect(() => {
    document.title = 'Portal SOC · Auditoría';
  }, []);
  return (
    <div ref={ref} className="space-y-4">
      <PageHeader
        title="Auditoría"
        subtitle="Todo cambio en el portal (quién, cuándo, desde dónde y qué) y el registro del sistema. Solo administradores."
        actions={
          <div className="flex flex-wrap gap-2">
            <Chips
              options={[
                ['cambios', 'Cambios'],
                ['sistema', 'Registro del sistema'],
              ]}
              value={view}
              onChange={setView}
            />
            <Button size="sm" variant="secondary" asChild>
              <Link to="/admin?view=log">
                <KeyRound /> Accesos e inicios de sesión
              </Link>
            </Button>
          </div>
        }
      />
      {view === 'sistema' ? <SystemLog /> : <Changes />}
    </div>
  );
}

function Integrity() {
  const [run, setRun] = useState(0);
  const v = useQuery({
    queryKey: ['audit', 'verify', run],
    queryFn: () => api.get<Verify>('api/admin/audit/verify'),
    enabled: run > 0,
  });
  return (
    <div className="flex flex-wrap items-center gap-2 text-[13px]">
      <Button size="sm" variant="secondary" disabled={v.isFetching} onClick={() => setRun((n) => n + 1)}>
        <ShieldCheck /> Verificar integridad
      </Button>
      {v.data &&
        (v.data.ok ? (
          <span className="flex items-center gap-1 text-ok">
            <ShieldCheck className="size-4" /> {v.data.mensaje}
          </span>
        ) : (
          <span className="flex items-center gap-1 font-semibold text-bad">
            <ShieldX className="size-4" /> {v.data.mensaje}
          </span>
        ))}
      {v.error && <span className="text-bad">{v.error.message}</span>}
    </div>
  );
}

function Changes() {
  const [userF, setUserF] = useSearchParam('user', '');
  const [module, setModule] = useSearchParam('module', '');
  const [result, setResult] = useSearchParam('result', '');
  const [since, setSince] = useSearchParam('since', '');
  const [until, setUntil] = useSearchParam('until', '');
  const [q, setQ] = useSearchParam('q', '');
  const [draft, setDraft] = useState(q);
  const [open, setOpen] = useState<Change | null>(null);
  const f = { user_f: userF, module, result, since, until, q };
  const A = useQuery({
    queryKey: ['audit', f],
    queryFn: () => api.get<AuditData>(`api/admin/audit${qs(f)}`),
    refetchInterval: 30_000,
  });
  if (A.isPending) return <Loading rows={3} />;
  if (A.error || !A.data) return <ErrorState error={A.error} onRetry={() => void A.refetch()} />;
  const { items, stats } = A.data;
  return (
    <>
      <KpiGrid>
        <Kpi title="Cambios · 7 días" value={nf(stats.total)} />
        <Kpi
          title="Rechazados · 7 días"
          value={nf(stats.rechazados)}
          hint="sin permiso, sin sesión o con error"
          alert={stats.rechazados > 0}
          onClick={() => setResult('error')}
        />
        <Kpi title="Personas e integraciones" value={stats.usuarios.length} hint="con cambios en 7 días" />
        <Kpi
          title="Conservación"
          value={A.data.conservacion_dias ? `${A.data.conservacion_dias} d` : 'siempre'}
          hint="AUDIT_DAYS"
        />
      </KpiGrid>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Quién cambia más (7 días)">
          <HBars
            rows={stats.usuarios.map(([k, v]) => ({ label: k, value: v, onClick: () => setUserF(k) }))}
          />
        </Panel>
        <Panel title="Qué se cambia (7 días)">
          <HBars
            rows={stats.modulos.map(([k, v]) => ({ label: k, value: v, onClick: () => setModule(k) }))}
          />
        </Panel>
      </div>
      <Panel
        title="Registro de cambios"
        hint="Los secretos (contraseñas, claves, tokens) se guardan ocultos. Cada registro está encadenado al anterior."
        bodyClassName="px-0 pb-0"
        actions={<Integrity />}
      >
        <div className="flex flex-wrap items-end gap-2 px-4 pb-3">
          <Select
            value={userF}
            onChange={(e) => setUserF(e.target.value)}
            aria-label="Usuario"
            className="w-auto"
          >
            <option value="">Todos los usuarios</option>
            {stats.usuarios_lista.map((u) => (
              <option key={u} value={u}>
                {u}
              </option>
            ))}
          </Select>
          <Select
            value={module}
            onChange={(e) => setModule(e.target.value)}
            aria-label="Módulo"
            className="w-auto"
          >
            <option value="">Todos los módulos</option>
            {MODULES.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </Select>
          <Select
            value={result}
            onChange={(e) => setResult(e.target.value)}
            aria-label="Resultado"
            className="w-auto"
          >
            <option value="">Todo resultado</option>
            <option value="ok">Correctos</option>
            <option value="error">Rechazados / con error</option>
          </Select>
          <Input
            type="date"
            value={since}
            onChange={(e) => setSince(e.target.value)}
            aria-label="Desde"
            className="w-auto"
          />
          <Input
            type="date"
            value={until}
            onChange={(e) => setUntil(e.target.value)}
            aria-label="Hasta"
            className="w-auto"
          />
          <Input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && setQ(draft)}
            placeholder="Objeto, IP, texto… (Enter)"
            className="w-52"
            aria-label="Buscar en la auditoría"
          />
          <span className="flex-1" />
          <Button size="sm" variant="secondary" asChild>
            <a href={`/portal/api/admin/audit/export.csv${qs(f)}`}>
              <Download /> Exportar CSV
            </a>
          </Button>
        </div>
        {items.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Fecha</TableHead>
                <TableHead>Quién</TableHead>
                <TableHead>Desde</TableHead>
                <TableHead>Módulo</TableHead>
                <TableHead>Acción</TableHead>
                <TableHead>Objeto</TableHead>
                <TableHead>Resultado</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((c) => (
                <TableRow key={c.id} clickable onClick={() => setOpen(c)}>
                  <TableCell className="whitespace-nowrap text-muted">{c.at}</TableCell>
                  <TableCell className="whitespace-nowrap">
                    <b>{c.user}</b>
                    {c.role && <div className="text-xs text-muted">{c.role}</div>}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{c.ip}</TableCell>
                  <TableCell className="whitespace-nowrap">{c.module}</TableCell>
                  <TableCell className="whitespace-nowrap text-[13px]">{c.action}</TableCell>
                  <TableCell className="max-w-[200px] truncate font-semibold" title={c.target}>
                    {c.target || <span className="font-normal text-muted">—</span>}
                  </TableCell>
                  <TableCell>
                    <StatusBadge code={c.status} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <Empty>Sin cambios con estos filtros.</Empty>
        )}
      </Panel>
      <Dialog open={!!open} onOpenChange={(o) => !o && setOpen(null)}>
        {open && (
          <DialogContent title={`${open.action} · ${open.module}`} description={`#${open.id} · ${open.at}`}>
            <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[13px]">
              <dt className="text-muted">Quién</dt>
              <dd>
                <b>{open.user}</b> {open.role && `(${open.role})`}
              </dd>
              <dt className="text-muted">Desde</dt>
              <dd className="font-mono">{open.ip}</dd>
              <dt className="text-muted">Petición</dt>
              <dd className="break-all font-mono text-xs">
                {open.method} {open.path}
              </dd>
              <dt className="text-muted">Resultado</dt>
              <dd>
                <StatusBadge code={open.status} /> <span className="text-muted">· {open.ms} ms</span>
              </dd>
              <dt className="text-muted">Datos enviados</dt>
              <dd>
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-grid p-2.5 font-mono text-[11.5px]">
                  {pretty(open.detail)}
                </pre>
              </dd>
            </dl>
          </DialogContent>
        )}
      </Dialog>
    </>
  );
}

function pretty(s: string) {
  if (!s) return '—';
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}

function StatusBadge({ code }: { code: number }) {
  const txt =
    code < 400
      ? 'Correcto'
      : code === 401
        ? 'Sin sesión'
        : code === 403
          ? 'Sin permiso'
          : code === 428
            ? 'Requiere cambio de clave/MFA'
            : code >= 500
              ? 'Error del servidor'
              : 'Rechazado';
  return (
    <Badge variant={code < 400 ? 'ok' : code >= 500 ? 'bad' : 'warn'} title={`HTTP ${code}`}>
      {txt}
    </Badge>
  );
}

function SystemLog() {
  const [level, setLevel] = useState('INFO');
  const [draft, setDraft] = useState('');
  const [q, setQ] = useState('');
  const L = useQuery({
    queryKey: ['audit', 'syslog', level, q],
    queryFn: () => api.get<SysLine[]>(`api/admin/syslog${qs({ level, q })}`),
    refetchInterval: 10_000,
  });
  return (
    <Panel
      title="Registro del sistema"
      hint="Últimos mensajes del bridge (en memoria; se reinicia con el contenedor). Para el histórico completo: docker logs soc-bridge."
      actions={
        <div className="flex flex-wrap gap-2">
          <Chips
            options={[
              ['INFO', 'Todo'],
              ['WARNING', 'Avisos y errores'],
              ['ERROR', 'Solo errores'],
            ]}
            value={level}
            onChange={setLevel}
          />
          <Input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && setQ(draft)}
            placeholder="Buscar… (Enter)"
            className="w-52"
            aria-label="Buscar en el registro"
          />
        </div>
      }
    >
      {L.isPending ? (
        <Loading rows={2} />
      ) : L.error || !L.data ? (
        <ErrorState error={L.error} onRetry={() => void L.refetch()} />
      ) : L.data.length ? (
        <div className="max-h-[65vh] overflow-auto rounded-lg border border-line bg-grid/40 p-2 font-mono text-[12px] leading-relaxed">
          {L.data.map((l) => (
            <div key={l.id} className="flex gap-2 border-b border-line/50 py-0.5 last:border-0">
              <span className="shrink-0 text-muted">{l.at.slice(5)}</span>
              <span
                className={cn(
                  'w-[62px] shrink-0 font-bold',
                  l.level === 'ERROR' || l.level === 'CRITICAL'
                    ? 'text-bad'
                    : l.level === 'WARNING'
                      ? 'text-warn'
                      : 'text-muted',
                )}
              >
                {l.level}
              </span>
              <span className="whitespace-pre-wrap break-all">{l.msg}</span>
            </div>
          ))}
        </div>
      ) : (
        <Empty>Sin mensajes con este filtro.</Empty>
      )}
    </Panel>
  );
}
