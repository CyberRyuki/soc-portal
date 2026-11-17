import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type {
  M365Action,
  M365ActionKind,
  M365Alerts,
  M365Audit,
  M365Posture,
  M365Risky,
  M365RulesScan,
  M365SignIns,
  M365Status,
} from '@/types/api';

export const useM365Status = () =>
  useQuery({
    queryKey: ['m365', 'status'],
    queryFn: () => api.get<M365Status>('api/m365/status', { background: true }),
    refetchInterval: 60_000,
  });
export const useM365Alerts = (f: { days: number; severity: string; status: string; q: string }) =>
  useQuery({
    queryKey: ['m365', 'alerts', f],
    queryFn: () => api.get<M365Alerts>(`api/m365/alerts${qs(f)}`),
    refetchInterval: 120_000,
  });
export const useM365SignIns = (hours: number) =>
  useQuery({
    queryKey: ['m365', 'signins', hours],
    queryFn: () => api.get<M365SignIns>(`api/m365/signins${qs({ hours })}`),
  });
export const useM365Risky = () =>
  useQuery({ queryKey: ['m365', 'risky'], queryFn: () => api.get<M365Risky>('api/m365/risky') });
export const useM365Posture = () =>
  useQuery({ queryKey: ['m365', 'posture'], queryFn: () => api.get<M365Posture>('api/m365/posture') });
export const useM365Audits = (days: number) =>
  useQuery({
    queryKey: ['m365', 'audits', days],
    queryFn: () => api.get<M365Audit[]>(`api/m365/audits${qs({ days })}`),
  });
export const useM365Rules = () =>
  useQuery({
    queryKey: ['m365', 'rules'],
    queryFn: () => api.get<{ scan: M365RulesScan | null; running: boolean }>('api/m365/rules'),
    refetchInterval: (q) => (q.state.data?.running ? 3000 : false),
  });
export const useM365Actions = (status = '') =>
  useQuery({
    queryKey: ['m365', 'actions', status],
    queryFn: () => api.get<M365Action[]>(`api/m365/actions${qs({ status })}`),
    refetchInterval: 30_000,
  });

const inv = (qc: ReturnType<typeof useQueryClient>) => {
  void qc.invalidateQueries({ queryKey: ['m365'] });
  void qc.invalidateQueries({ queryKey: ['incidents'] });
};
export interface M365ActionInput {
  kind: M365ActionKind;
  target: Record<string, unknown>;
  reason: string;
  incident?: string;
}
export function useM365Action() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: M365ActionInput) => api.post<M365Action>('api/m365/actions', b),
    onSuccess: () => inv(qc),
  });
}
export function useM365Decide() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, approve }: { id: number; approve: boolean }) =>
      api.post<M365Action>(`api/m365/actions/${id}/${approve ? 'approve' : 'reject'}`, {}),
    onSuccess: () => inv(qc),
  });
}
export function useM365Sync() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post('api/m365/sync', {}),
    onSuccess: () => setTimeout(() => inv(qc), 4000),
  });
}
export function useM365ScanRules() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post('api/m365/rules/scan', {}),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['m365', 'rules'] }),
  });
}
