import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { Runbook, RunbookSummary } from '@/types/api';

export const useRunbooks = () =>
  useQuery({
    queryKey: ['runbooks'],
    queryFn: () => api.get<RunbookSummary[]>('api/runbooks'),
    staleTime: 300_000,
  });
export const useRunbook = (slug: string) =>
  useQuery({
    queryKey: ['runbooks', slug],
    queryFn: () => api.get<Runbook>(`api/runbooks/${encodeURIComponent(slug)}`),
    enabled: !!slug,
  });

export type RunbookInput = Pick<
  Runbook,
  'title' | 'description' | 'body' | 'level' | 'category' | 'severity' | 'mitre' | 'owasp'
>;
export function useSaveRunbook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ slug, data }: { slug: string | null; data: RunbookInput }) =>
      slug
        ? api.put<Runbook>(`api/runbooks/${encodeURIComponent(slug)}`, data)
        : api.post<Runbook>('api/runbooks', data),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['runbooks'] });
      void qc.invalidateQueries({ queryKey: ['meta'] });
    },
  });
}
export function useDeleteRunbook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (slug: string) => api.delete(`api/runbooks/${encodeURIComponent(slug)}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['runbooks'] }),
  });
}
