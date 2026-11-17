import { NavLink, useNavigate } from 'react-router-dom';
import {
  Activity,
  BookOpen,
  Bot,
  Bug,
  Crosshair,
  Globe,
  Radar,
  LayoutDashboard,
  LayoutGrid,
  LogOut,
  Monitor,
  Moon,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Cloud,
  ScrollText,
  Sun,
  Sparkles,
  Users,
  UserRound,
  Wrench,
  type LucideIcon,
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import { THEME_LABEL, useUi } from '@/store/ui';
import { Avatar } from '@/components/shared';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Button } from '@/components/ui/button';
import type { Metrics, SophosStatus } from '@/types/api';

interface Item {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
  badge?: 'incidents' | 'sophos' | 'm365';
  /** solo visible para administradores */
  admin?: boolean;
}
const SECTIONS: { title: string; items: Item[] }[] = [
  {
    title: 'Operación',
    items: [
      { to: '/', label: 'Resumen', icon: LayoutDashboard, end: true },
      { to: '/threats', label: 'Amenazas', icon: ShieldAlert },
      { to: '/agents', label: 'Agentes', icon: Server },
      { to: '/noc', label: 'Vista NOC', icon: Monitor },
    ],
  },
  {
    title: 'Inteligencia',
    items: [
      { to: '/iocs', label: 'IoC', icon: Crosshair },
      { to: '/intel', label: 'Inteligencia', icon: Search },
      { to: '/ai', label: 'Asistente IA', icon: Bot },
      { to: '/vulns', label: 'Vulnerabilidades', icon: Bug },
      { to: '/sites', label: 'Portales', icon: Globe },
      { to: '/exposure', label: 'Exposición', icon: Radar },
    ],
  },
  {
    title: 'Respuesta',
    items: [
      { to: '/incidents', label: 'Incidentes', icon: Activity, badge: 'incidents' },
      { to: '/sophos', label: 'Sophos', icon: ShieldCheck, badge: 'sophos' },
      { to: '/m365', label: 'Microsoft 365', icon: Cloud, badge: 'm365' },
      { to: '/runbooks', label: 'Runbooks', icon: BookOpen },
      { to: '/mitre', label: 'ATT&CK · OWASP', icon: LayoutGrid },
      { to: '/tools', label: 'Herramientas', icon: Wrench },
      { to: '/contacts', label: 'Contactos', icon: Users },
      { to: '/audit', label: 'Auditoría', icon: ScrollText, admin: true },
    ],
  },
];
const THEME_ICON = { light: Sun, dark: Moon, xr: Sparkles } as const;

export function Sidebar() {
  const { me, logout, isAdmin } = useAuth();
  const { theme, cycleTheme, sidebarOpen, setSidebar } = useUi();
  const nav = useNavigate();
  const [q, setQ] = useState('');
  const search = useRef<HTMLInputElement>(null);
  const metrics = useQuery({
    queryKey: ['metrics', 'badge'],
    queryFn: () => api.get<Metrics>('api/metrics', { background: true }),
    refetchInterval: 60_000,
    enabled: !!me,
  });
  const sophos = useQuery({
    queryKey: ['sophos', 'status'],
    queryFn: () => api.get<SophosStatus>('api/sophos/status', { background: true }),
    refetchInterval: 60_000,
    enabled: !!me,
  });
  const open = metrics.data?.abiertos.length ?? 0;
  const pending = sophos.data?.pendientes ?? 0;
  const sugg = useQuery({
    queryKey: ['incidents', 'suggestions', 'pending'],
    queryFn: () => api.get<{ items: unknown[] }>('api/incidents/suggestions', { background: true }),
    refetchInterval: 60_000,
    enabled: !!me,
  });
  const nSugg = sugg.data?.items.length ?? 0;
  const m365q = useQuery({
    queryKey: ['m365', 'status'],
    queryFn: () => api.get<{ pendientes?: number }>('api/m365/status', { background: true }),
    refetchInterval: 60_000,
    enabled: !!me,
  });
  const pending365 = m365q.data?.pendientes ?? 0;
  const late = metrics.data?.vencidos.length ?? 0;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (
        e.key === '/' &&
        !/INPUT|TEXTAREA|SELECT/.test((document.activeElement as HTMLElement)?.tagName ?? '')
      ) {
        e.preventDefault();
        search.current?.focus();
      }
    };
    addEventListener('keydown', onKey);
    return () => removeEventListener('keydown', onKey);
  }, []);
  const ThemeIcon = THEME_ICON[theme];

  return (
    <>
      <div
        className={cn('fixed inset-0 z-30 bg-black/45 lg:hidden', sidebarOpen ? 'block' : 'hidden')}
        onClick={() => setSidebar(false)}
        aria-hidden="true"
      />
      <aside
        className={cn(
          'glass fixed bottom-2.5 left-2.5 top-2.5 z-40 flex w-[232px] flex-col rounded-[18px] border border-line p-2.5 shadow-card transition-transform duration-200',
          'max-lg:-translate-x-[calc(100%+20px)]',
          sidebarOpen && 'max-lg:translate-x-0',
        )}
        aria-label="Menú principal"
      >
        <NavLink
          to="/"
          className="flex items-center gap-2.5 px-1.5 pb-3 pt-1"
          onClick={() => setSidebar(false)}
        >
          <span className="grid size-8 place-items-center rounded-[10px] bg-gradient-to-br from-[#2f5bea] to-[#7a5af8] text-white">
            <Shield className="size-[18px]" />
          </span>
          <span className="flex flex-col leading-tight">
            <b className="text-[14px]">Portal SOC</b>
            <small className="text-[11px] text-muted">ACME · CSIRT</small>
          </span>
        </NavLink>
        <form
          className="mb-1.5 flex items-center gap-2 rounded-[10px] border border-line bg-bg/60 px-2"
          onSubmit={(e) => {
            e.preventDefault();
            const v = q.trim();
            if (!v) return;
            nav(`/intel?q=${encodeURIComponent(v)}`);
            setQ('');
            setSidebar(false);
          }}
        >
          <Search className="size-[15px] shrink-0 text-muted" />
          <input
            ref={search}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Buscar IoC, IP, incidente…"
            aria-label="Buscar"
            className="min-w-0 flex-1 bg-transparent py-2 text-[13px] outline-none placeholder:text-muted"
          />
          <kbd className="rounded-[5px] border border-line px-1.5 py-0.5 font-mono text-[10.5px] text-muted">
            /
          </kbd>
        </form>
        <nav className="scroll-thin -mx-1 flex-1 overflow-y-auto px-1">
          {SECTIONS.map((s) => (
            <div key={s.title}>
              <div className="mx-2.5 mb-1.5 mt-3.5 text-[10px] font-bold uppercase tracking-[.06em] text-muted/85">
                {s.title}
              </div>
              {s.items
                .filter((it) => !it.admin || isAdmin)
                .map((it) => (
                  <NavLink
                    key={it.to}
                    to={it.to}
                    end={it.end}
                    onClick={() => setSidebar(false)}
                    className={({ isActive }) =>
                      cn(
                        'mb-px flex items-center gap-2.5 rounded-[10px] px-2.5 py-2 text-[13.5px] font-semibold text-muted transition-colors hover:bg-brand-soft hover:text-ink',
                        isActive &&
                          'bg-brand text-brand-ink shadow-[0_6px_18px_color-mix(in_srgb,var(--brand)_40%,transparent)] hover:bg-brand hover:text-brand-ink',
                      )
                    }
                  >
                    <it.icon className="size-[17px] shrink-0" />
                    <span className="flex-1 truncate">{it.label}</span>
                    {it.badge === 'm365' && pending365 > 0 && (
                      <em
                        className="min-w-5 rounded-full bg-st-warn px-1.5 py-0.5 text-center text-[11px] font-bold not-italic text-black"
                        title={`${pending365} acciones pendientes de aprobación`}
                      >
                        {pending365}
                      </em>
                    )}
                    {it.badge === 'sophos' && pending > 0 && (
                      <em
                        className="min-w-5 rounded-full bg-st-warn px-1.5 py-0.5 text-center text-[11px] font-bold not-italic text-black"
                        title={`${pending} acciones pendientes de aprobación`}
                      >
                        {pending}
                      </em>
                    )}
                    {it.badge === 'incidents' && nSugg > 0 && (
                      <em
                        className="min-w-5 rounded-full bg-st-warn px-1.5 py-0.5 text-center text-[11px] font-bold not-italic text-black"
                        title={`${nSugg} sugerencias de incidente por revisar`}
                      >
                        {nSugg}
                      </em>
                    )}
                    {it.badge === 'incidents' && open > 0 && (
                      <em
                        className={cn(
                          'min-w-5 rounded-full px-1.5 py-0.5 text-center text-[11px] font-bold not-italic',
                          late ? 'bg-bad text-white' : 'bg-grid text-ink',
                        )}
                        title={`${open} abiertos · ${late} con SLA vencido`}
                      >
                        {open}
                      </em>
                    )}
                  </NavLink>
                ))}
            </div>
          ))}
        </nav>
        <div className="mt-1.5 flex flex-col gap-1.5 border-t border-line pt-2">
          <div className="flex items-center justify-between px-1.5 text-[13px] text-muted">
            <span className="flex items-center gap-2">
              <ThemeIcon className="size-4" /> Tema{' '}
              <b className="font-semibold text-ink">{THEME_LABEL[theme]}</b>
            </span>
            <Button
              variant="outline"
              size="icon-sm"
              onClick={cycleTheme}
              aria-label="Cambiar tema"
              title="Cambiar tema (claro → oscuro → XR)"
            >
              <ThemeIcon />
            </Button>
          </div>
          {me && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  className="flex w-full cursor-pointer items-center gap-2 rounded-xl border border-line bg-card px-1 py-1 text-left hover:bg-grid"
                  aria-label="Menú de usuario"
                >
                  <Avatar name={me.display || me.username} className="size-[30px] rounded-[9px]" />
                  <span className="min-w-0 flex-1 leading-tight">
                    <b className="block truncate text-[13px]">{me.display || me.username}</b>
                    <small className="text-[11px] text-muted">{me.role_name}</small>
                  </span>
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent side="top" align="start" className="w-[212px]">
                <DropdownMenuLabel>
                  <b className="block text-ink">{me.username}</b>
                  {me.source === 'ldap' ? 'Cuenta del dominio' : 'Cuenta local'} · {me.role_name}
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => nav('/account')}>
                  <UserRound /> Mi cuenta y seguridad
                </DropdownMenuItem>
                {isAdmin && (
                  <DropdownMenuItem onSelect={() => nav('/admin')}>
                    <Shield /> Usuarios y accesos
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem onSelect={() => void logout()}>
                  <LogOut /> Cerrar sesión
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </aside>
    </>
  );
}
