import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type {
  SophosAction,
  SophosActionKind,
  SophosAlerts,
  SophosBlocked,
  SophosEndpoint,
  SophosStatus,
} from '@/types/api';

export const sophosKeys = { all: ['sophos'] as const };

export const useSophosStatus = () =>
  useQuery({
    queryKey: ['sophos', 'status'],
    queryFn: () => api.get<SophosStatus>('api/sophos/status', { background: true }),
    refetchInterval: 60_000,
  });
export const useSophosAlerts = (f: { days: number; severity: string; q: string }, enabled = true) =>
  useQuery({
    queryKey: ['sophos', 'alerts', f],
    queryFn: () => api.get<SophosAlerts>(`api/sophos/alerts${qs(f)}`),
    enabled,
    refetchInterval: 120_000,
  });
export const useSophosEndpoints = (f: { q: string; health: string; isolated: string }, enabled = true) =>
  useQuery({
    queryKey: ['sophos', 'endpoints', f],
    queryFn: () => api.get<{ items: SophosEndpoint[]; sincronizado: string }>(`api/sophos/endpoints${qs(f)}`),
    enabled,
  });
export const useSophosBlocked = (enabled = true) =>
  useQuery({
    queryKey: ['sophos', 'blocked'],
    queryFn: () => api.get<SophosBlocked>('api/sophos/blocked'),
    enabled,
  });
export const useSophosActions = (status = '', enabled = true) =>
  useQuery({
    queryKey: ['sophos', 'actions', status],
    queryFn: () => api.get<SophosAction[]>(`api/sophos/actions${qs({ status })}`),
    enabled,
    refetchInterval: 30_000,
  });

export interface SophosActionInput {
  kind: SophosActionKind;
  target: Record<string, unknown>;
  reason: string;
  incident?: string;
}
function inv(qc: ReturnType<typeof useQueryClient>) {
  void qc.invalidateQueries({ queryKey: sophosKeys.all });
  void qc.invalidateQueries({ queryKey: ['incidents'] });
}
export function useSophosAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: SophosActionInput) => api.post<SophosAction>('api/sophos/actions', b),
    onSuccess: () => inv(qc),
  });
}
export function useSophosDecide() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, approve, note }: { id: number; approve: boolean; note?: string }) =>
      api.post<SophosAction>(`api/sophos/actions/${id}/${approve ? 'approve' : 'reject'}`, {
        note: note ?? '',
      }),
    onSuccess: () => inv(qc),
  });
}
export function useSophosSync() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post('api/sophos/sync', {}),
    onSuccess: () => setTimeout(() => inv(qc), 4000),
  });
}
