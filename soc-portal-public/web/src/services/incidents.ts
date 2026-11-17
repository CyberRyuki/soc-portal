import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type { Incident, IncidentDetail, Metrics } from '@/types/api';

export interface IncidentFilter {
  status?: string;
  severity?: string;
  q?: string;
}
export const incidentKeys = {
  all: ['incidents'] as const,
  list: (f: IncidentFilter) => ['incidents', 'list', f] as const,
  one: (code: string) => ['incidents', 'one', code] as const,
  metrics: ['metrics'] as const,
};

export const useIncidents = (f: IncidentFilter) =>
  useQuery({ queryKey: incidentKeys.list(f), queryFn: () => api.get<Incident[]>(`api/incidents${qs(f)}`) });
export const useIncident = (code: string) =>
  useQuery({
    queryKey: incidentKeys.one(code),
    queryFn: () => api.get<IncidentDetail>(`api/incidents/${encodeURIComponent(code)}`),
    enabled: !!code,
  });
export const useMetrics = () =>
  useQuery({ queryKey: incidentKeys.metrics, queryFn: () => api.get<Metrics>('api/metrics') });

export type IncidentInput = Partial<
  Pick<
    Incident,
    | 'title'
    | 'severity'
    | 'status'
    | 'owner'
    | 'detected_by'
    | 'assets'
    | 'summary'
    | 'iocs'
    | 'runbook'
    | 'root_cause'
    | 'lessons'
    | 'detected_at'
  >
> & { /** si viene de una sugerencia, se marca como aceptada al crear */ suggestion_id?: number };

function invalidate(qc: ReturnType<typeof useQueryClient>) {
  void qc.invalidateQueries({ queryKey: incidentKeys.all });
  void qc.invalidateQueries({ queryKey: incidentKeys.metrics });
  void qc.invalidateQueries({ queryKey: ['home'] });
}
export function useCreateIncident() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: IncidentInput) => api.post<{ code: string }>('api/incidents', body),
    onSuccess: () => invalidate(qc),
  });
}
export function useUpdateIncident(code: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: IncidentInput) =>
      api.put<IncidentDetail>(`api/incidents/${encodeURIComponent(code)}`, body),
    onSuccess: () => invalidate(qc),
  });
}
export function useMoveIncident() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ code, status }: { code: string; status: string }) =>
      api.put<IncidentDetail>(`api/incidents/${encodeURIComponent(code)}`, { status }),
    onSuccess: () => invalidate(qc),
  });
}
export function useAddNote(code: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (text: string) => api.post(`api/incidents/${encodeURIComponent(code)}/notes`, { text }),
    onSuccess: () => invalidate(qc),
  });
}

export interface CloseInput {
  resolution: string;
  root_cause?: string;
  lessons?: string;
}
export function useCloseIncident() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ code, ...body }: CloseInput & { code: string }) =>
      api.post<IncidentDetail>(`api/incidents/${encodeURIComponent(code)}/close`, body),
    onSuccess: () => invalidate(qc),
  });
}
/** Borrado definitivo: el backend solo lo permite a administradores. */
export function useDeleteIncident() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (code: string) =>
      api.delete<{ deleted: string }>(`api/incidents/${encodeURIComponent(code)}`),
    onSuccess: () => invalidate(qc),
  });
}

export interface Suggestion {
  id: number;
  at: string;
  last_at: string;
  n: number;
  source: string;
  key: string;
  title: string;
  severity: string;
  data: IncidentInput;
  status: 'pending' | 'accepted' | 'dismissed';
  incident: string;
  decided_by: string;
  decided_at: string;
  note: string;
}
export const useSuggestions = (status = 'pending') =>
  useQuery({
    queryKey: ['incidents', 'suggestions', status],
    queryFn: () =>
      api.get<{ items: Suggestion[]; auto: boolean }>(`api/incidents/suggestions${qs({ status })}`, {
        background: true,
      }),
    refetchInterval: 60_000,
  });
export function useDismissSuggestion() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, note }: { id: number; note?: string }) =>
      api.post(`api/incidents/suggestions/${id}/dismiss`, { note: note ?? '' }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['incidents', 'suggestions'] }),
  });
}
