import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from '@/lib/api';
import type { Me, Meta, Role } from '@/types/api';

interface AuthCtx {
  me: Me | null;
  meta: Meta | null;
  loading: boolean;
  /** true si el rol puede escribir (admin o analyst) */
  canWrite: boolean;
  isAdmin: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}
const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const meQ = useQuery({
    queryKey: ['me'],
    queryFn: () => api.get<Me>('auth/me'),
    retry: (n, e) => !(e instanceof ApiError && (e.status === 401 || e.status === 428)) && n < 1,
    staleTime: 5 * 60_000,
    enabled: !window.location.pathname.startsWith('/portal/login'),
  });
  const metaQ = useQuery({
    queryKey: ['meta'],
    queryFn: () => api.get<Meta>('api/meta'),
    enabled: !!meQ.data,
    staleTime: 5 * 60_000,
  });
  const refresh = useCallback(async () => {
    await qc.invalidateQueries({ queryKey: ['me'] });
  }, [qc]);
  const logout = useCallback(async () => {
    try {
      await api.post('auth/logout');
    } finally {
      qc.clear();
      window.location.assign('/portal/login');
    }
  }, [qc]);
  useEffect(() => {
    const onUnauth = () => {
      if (!location.pathname.startsWith('/portal/login'))
        window.location.assign(
          '/portal/login?next=' + encodeURIComponent(location.pathname + location.search),
        );
    };
    window.addEventListener('soc:unauthorized', onUnauth);
    return () => window.removeEventListener('soc:unauthorized', onUnauth);
  }, []);
  const me = meQ.data ?? null;
  const value = useMemo<AuthCtx>(
    () => ({
      me,
      meta: metaQ.data ?? null,
      loading: meQ.isPending && meQ.fetchStatus !== 'idle',
      canWrite: me?.role === 'admin' || me?.role === 'analyst',
      isAdmin: me?.role === 'admin',
      refresh,
      logout,
    }),
    [me, metaQ.data, meQ.isPending, meQ.fetchStatus, refresh, logout],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('useAuth debe usarse dentro de AuthProvider');
  return c;
}
export const hasRole = (me: Me | null, roles: Role[]): boolean => !!me && roles.includes(me.role);
