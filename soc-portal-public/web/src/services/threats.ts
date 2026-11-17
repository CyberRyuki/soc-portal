import { useQuery } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type { AgentsDetail, AlertDoc, HomeData, Overview, ThreatRange, Threats } from '@/types/api';

/** `interval` en ms; 0 = sin refresco automático. Se pausa solo cuando la pestaña no está visible. */
export const useHome = (background = false, interval = 60_000) =>
  useQuery({
    queryKey: ['home'],
    queryFn: () => api.get<HomeData>('data', { background }),
    refetchInterval: interval || false,
  });
export const useOverview = (interval = 30_000) =>
  useQuery({
    queryKey: ['overview'],
    queryFn: () => api.get<Overview>('api/overview', { background: true }),
    refetchInterval: interval || false,
  });
export const useThreats = (range: ThreatRange, minLevel: number, interval = 0) =>
  useQuery({
    queryKey: ['threats', range, minLevel],
    queryFn: () => api.get<Threats>(`api/threats${qs({ range, min_level: minLevel })}`),
    staleTime: 120_000,
    refetchInterval: interval ? Math.max(interval, 60_000) : false, // Wazuh: como mucho cada minuto
  });
export const useAlerts = (field: string, value: string, range: ThreatRange, minLevel: number) =>
  useQuery({
    queryKey: ['alerts', field, value, range, minLevel],
    queryFn: () => api.get<AlertDoc[]>(`api/alerts${qs({ field, value, range, min_level: minLevel })}`),
    enabled: !!field && !!value,
  });
export const useAgents = () =>
  useQuery({ queryKey: ['agents'], queryFn: () => api.get<AgentsDetail>('api/agents'), staleTime: 300_000 });
