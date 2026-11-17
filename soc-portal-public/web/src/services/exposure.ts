import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type { ExpAsset, ExpConfig, ExpFinding, ExpJob, ExpService, ExpSummary } from '@/types/api';

export const useExpSummary = () =>
  useQuery({
    queryKey: ['exposure', 'summary'],
    queryFn: () => api.get<ExpSummary>('api/exposure/summary', { background: true }),
    refetchInterval: (q) => (q.state.data?.en_curso ? 3000 : 60_000),
  });
export const useExpJobs = () =>
  useQuery({
    queryKey: ['exposure', 'jobs'],
    queryFn: () =>
      api.get<{ items: ExpJob[]; en_curso: number | null }>('api/exposure/jobs', { background: true }),
    refetchInterval: (q) => (q.state.data?.en_curso ? 2000 : 30_000),
  });
export const useExpFindings = (f: { status: string; severity: string; category: string; q: string }) =>
  useQuery({
    queryKey: ['exposure', 'findings', f],
    queryFn: () => api.get<ExpFinding[]>(`api/exposure/findings${qs(f)}`),
  });
export const useExpAssets = (f: { only: string; q: string }) =>
  useQuery({
    queryKey: ['exposure', 'assets', f],
    queryFn: () => api.get<ExpAsset[]>(`api/exposure/assets${qs(f)}`),
  });
export const useExpServices = (q: string) =>
  useQuery({
    queryKey: ['exposure', 'services', q],
    queryFn: () => api.get<ExpService[]>(`api/exposure/services${qs({ q })}`),
  });
export const useExpConfig = () =>
  useQuery({ queryKey: ['exposure', 'config'], queryFn: () => api.get<ExpConfig>('api/exposure/config') });

const inv = (qc: ReturnType<typeof useQueryClient>) => {
  void qc.invalidateQueries({ queryKey: ['exposure'] });
  void qc.invalidateQueries({ queryKey: ['overview'] });
};
export function useExpScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (kind: 'pasivo' | 'completo') => api.post<ExpJob>('api/exposure/scan', { kind }),
    onSuccess: () => inv(qc),
  });
}
export function useExpStop() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: () => api.post('api/exposure/stop', {}), onSuccess: () => inv(qc) });
}
export function useExpSaveConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (c: Partial<ExpConfig>) => api.put<ExpConfig>('api/admin/exposure/config', c),
    onSuccess: () => inv(qc),
  });
}
export function useExpFindingSet() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ key, status, note }: { key: string; status: string; note?: string }) =>
      api.put(`api/exposure/findings/${encodeURIComponent(key)}`, { status, note: note ?? '' }),
    onSuccess: () => inv(qc),
  });
}
export function useExpAssetSet() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ key, status }: { key: string; status: string }) =>
      api.put(`api/exposure/assets/${key}`, { status }),
    onSuccess: () => inv(qc),
  });
}
export function useExpToPortal() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (key: string) => api.post(`api/exposure/assets/${key}/portal`, {}),
    onSuccess: () => {
      inv(qc);
      void qc.invalidateQueries({ queryKey: ['sites'] });
    },
  });
}
