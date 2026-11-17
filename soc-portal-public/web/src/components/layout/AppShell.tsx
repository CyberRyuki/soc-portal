import { Suspense, useEffect, useRef } from 'react';
import { Link, Outlet, useLocation } from 'react-router-dom';
import { Menu, Monitor, Plus } from 'lucide-react';
import gsap from 'gsap';
import { Sidebar } from './Sidebar';
import { Button } from '@/components/ui/button';
import { Dot, Loading } from '@/components/shared';
import { useAuth } from '@/hooks/useAuth';
import { useUi } from '@/store/ui';
import { greeting, todayLong } from '@/lib/format';
import { NewIncidentDialog, useNewIncident } from '@/pages/incidents/NewIncidentDialog';
import { DrillDialog } from '@/pages/threats/DrillDialog';
import { IocDetailDialog } from '@/pages/iocs/IocDetailDialog';

const PAGE: Record<string, string> = {
  '': 'Resumen',
  threats: 'Amenazas',
  agents: 'Agentes',
  vulns: 'Vulnerabilidades',
  iocs: 'IoC',
  sites: 'Portales',
  exposure: 'Exposición',
  intel: 'Inteligencia',
  ai: 'Asistente IA',
  incidents: 'Incidentes',
  runbooks: 'Runbooks',
  mitre: 'ATT&CK · OWASP',
  tools: 'Herramientas',
  contacts: 'Contactos',
  account: 'Mi cuenta',
  admin: 'Usuarios y accesos',
};
const MOTION = !window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

/** Animación de entrada escalonada de las tarjetas al cambiar de página. */
export function usePageEnter(key: string) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!MOTION || !ref.current) return;
    const els = ref.current.querySelectorAll<HTMLElement>('[data-enter] > *, .card');
    const list = Array.from(els).slice(0, 40);
    if (!list.length) return;
    const tw = gsap.fromTo(
      list,
      { y: 10, opacity: 0 },
      {
        y: 0,
        opacity: 1,
        duration: 0.35,
        stagger: 0.016,
        ease: 'power2.out',
        clearProps: 'transform,opacity',
      },
    );
    return () => {
      tw.kill();
    };
  }, [key]);
  return ref;
}

export function AppShell() {
  const { me, canWrite } = useAuth();
  const { setSidebar } = useUi();
  const loc = useLocation();
  const first = loc.pathname.split('/')[1] ?? '';
  const newInc = useNewIncident();
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [loc.pathname]);
  return (
    <div className="lg:pl-[252px]">
      <Sidebar />
      <header className="mx-auto flex max-w-[1400px] items-center gap-3 px-4 pt-4">
        <Button
          variant="outline"
          size="icon"
          className="lg:hidden"
          onClick={() => setSidebar(true)}
          aria-label="Abrir menú"
        >
          <Menu />
        </Button>
        <div className="min-w-0 leading-tight">
          <b className="text-[15px]">
            {greeting(me ? (me.display || me.username).split(' ')[0] : undefined)}
          </b>
          <small className="flex items-center gap-1.5 truncate text-xs text-muted">
            <Dot ok />
            {todayLong()} · Portal SOC · {PAGE[first] ?? ''}
          </small>
        </div>
        <span className="flex-1" />
        <Button variant="secondary" size="sm" asChild>
          <Link to="/noc" title="Vista para pantalla de la sala SOC">
            <Monitor /> NOC
          </Link>
        </Button>
        {canWrite && (
          <Button size="sm" onClick={() => newInc.open()}>
            <Plus /> Incidente
          </Button>
        )}
      </header>
      <main className="mx-auto max-w-[1400px] px-4 pb-12 pt-5">
        <Suspense fallback={<Loading />}>
          <Outlet />
        </Suspense>
      </main>
      <NewIncidentDialog />
      <DrillDialog />
      <IocDetailDialog />
    </div>
  );
}
