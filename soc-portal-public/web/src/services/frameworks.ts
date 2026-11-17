import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type { MitreDetail, MitreMatrix, OwaspData } from '@/types/api';

export const useMitre = (days: number) =>
  useQuery({
    queryKey: ['mitre', days],
    queryFn: () => api.get<MitreMatrix>(`api/mitre${qs({ days })}`),
    staleTime: 600_000,
  });
export const useMitreDetail = (tid: string, days: number) =>
  useQuery({
    queryKey: ['mitre', 'detail', tid, days],
    queryFn: () => api.get<MitreDetail>(`api/mitre/${encodeURIComponent(tid)}${qs({ days })}`),
    enabled: !!tid,
  });
export const useOwasp = () =>
  useQuery({ queryKey: ['owasp'], queryFn: () => api.get<OwaspData>('api/owasp'), staleTime: 600_000 });
export function useSaveMark() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      fw,
      key,
      status,
      note,
    }: {
      fw: 'mitre' | 'owasp';
      key: string;
      status: string;
      note: string;
    }) => api.put(`api/frameworks/${fw}/${encodeURIComponent(key)}`, { status, note }),
    onSuccess: (_, v) => void qc.invalidateQueries({ queryKey: [v.fw] }),
  });
}
export const useRefreshMitre = () => useMutation({ mutationFn: () => api.post('api/mitre/refresh') });
