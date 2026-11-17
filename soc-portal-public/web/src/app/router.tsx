import { lazy } from 'react';
import { createBrowserRouter, Navigate, Outlet, useLocation } from 'react-router-dom';
import { AppShell } from '@/components/layout/AppShell';
import { useAuth } from '@/hooks/useAuth';
import { Loading } from '@/components/shared';
import { ErrorPage } from '@/pages/ErrorPage';

/* Carga diferida por página (code splitting). */
const Login = lazy(() => import('@/pages/login/LoginPage'));
const Home = lazy(() => import('@/pages/home/HomePage'));
const Threats = lazy(() => import('@/pages/threats/ThreatsPage'));
const Agents = lazy(() => import('@/pages/agents/AgentsPage'));
const Noc = lazy(() => import('@/pages/noc/NocPage'));
const Incidents = lazy(() => import('@/pages/incidents/IncidentsPage'));
const Incident = lazy(() => import('@/pages/incidents/IncidentPage'));
const Runbooks = lazy(() => import('@/pages/runbooks/RunbooksPage'));
const Runbook = lazy(() => import('@/pages/runbooks/RunbookPage'));
const RunbookEdit = lazy(() => import('@/pages/runbooks/RunbookEditPage'));
const Vulns = lazy(() => import('@/pages/vulns/VulnsPage'));
const Iocs = lazy(() => import('@/pages/iocs/IocsPage'));
const Sophos = lazy(() => import('@/pages/sophos/SophosPage'));
const M365 = lazy(() => import('@/pages/m365/M365Page'));
const Sites = lazy(() => import('@/pages/sites/SitesPage'));
const Exposure = lazy(() => import('@/pages/exposure/ExposurePage'));
const Intel = lazy(() => import('@/pages/intel/IntelPage'));
const Ai = lazy(() => import('@/pages/ai/AiPage'));
const AiAudit = lazy(() => import('@/pages/ai/AiAuditPage'));
const Mitre = lazy(() => import('@/pages/frameworks/MitrePage'));
const Owasp = lazy(() => import('@/pages/frameworks/OwaspPage'));
const Tools = lazy(() => import('@/pages/tools/ToolsPage'));
const ToolDetail = lazy(() => import('@/pages/tools/ToolPage'));
const ToolEdit = lazy(() => import('@/pages/tools/ToolEditPage'));
const Contacts = lazy(() => import('@/pages/contacts/ContactsPage'));
const Account = lazy(() => import('@/pages/account/AccountPage'));
const Admin = lazy(() => import('@/pages/admin/AdminPage'));
const Audit = lazy(() => import('@/pages/audit/AuditPage'));

/** Exige sesión; si la cuenta tiene pasos pendientes (contraseña, MFA) fuerza /account. */
function RequireAuth() {
  const { me, loading } = useAuth();
  const loc = useLocation();
  if (loading) return <Loading />;
  if (!me) return <Navigate to={`/login?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />;
  if (me.state !== 'ok' && loc.pathname !== '/account') return <Navigate to="/account" replace />;
  return <Outlet />;
}
function RequireAdmin() {
  const { isAdmin } = useAuth();
  return isAdmin ? <Outlet /> : <Navigate to="/" replace />;
}

export const router = createBrowserRouter(
  [
    { path: '/login', element: <Login />, errorElement: <ErrorPage /> },
    {
      element: <RequireAuth />,
      errorElement: <ErrorPage />,
      children: [
        { path: '/noc', element: <Noc /> },
        {
          element: <AppShell />,
          children: [
            { index: true, element: <Home /> },
            { path: 'threats', element: <Threats /> },
            { path: 'agents', element: <Agents /> },
            { path: 'incidents', element: <Incidents /> },
            { path: 'incidents/:code', element: <Incident /> },
            { path: 'runbooks', element: <Runbooks /> },
            { path: 'runbooks/new', element: <RunbookEdit /> },
            { path: 'runbooks/:slug', element: <Runbook /> },
            { path: 'runbooks/:slug/edit', element: <RunbookEdit /> },
            { path: 'vulns', element: <Vulns /> },
            { path: 'iocs', element: <Iocs /> },
            { path: 'sophos', element: <Sophos /> },
            { path: 'm365', element: <M365 /> },
            { path: 'sites', element: <Sites /> },
            { path: 'exposure', element: <Exposure /> },
            { path: 'intel', element: <Intel /> },
            { path: 'ai', element: <Ai /> },
            { path: 'ai/audit', element: <AiAudit /> },
            { path: 'ai/:cid', element: <Ai /> },
            { path: 'mitre', element: <Mitre /> },
            { path: 'owasp', element: <Owasp /> },
            { path: 'tools', element: <Tools /> },
            { path: 'tools/new/edit', element: <ToolEdit /> },
            { path: 'tools/:slug', element: <ToolDetail /> },
            { path: 'tools/:slug/edit', element: <ToolEdit /> },
            { path: 'tools/:slug/file/:fid', element: <ToolDetail /> },
            { path: 'contacts', element: <Contacts /> },
            { path: 'account', element: <Account /> },
            {
              element: <RequireAdmin />,
              children: [
                { path: 'admin', element: <Admin /> },
                { path: 'audit', element: <Audit /> },
              ],
            },
            { path: '*', element: <Navigate to="/" replace /> },
          ],
        },
      ],
    },
  ],
  { basename: '/portal' },
);
