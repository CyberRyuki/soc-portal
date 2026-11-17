import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type {
  BulkCheckRow,
  IntelCatalogEntry,
  IntelJob,
  IntelLookup,
  IntelOverlap,
  IntelOverviewData,
  IntelSource,
  Sighting,
} from '@/types/api';

export interface JobsData {
  jobs: IntelJob[];
  cola: number;
}
export const useIntelOverview = () =>
  useQuery({
    queryKey: ['intel', 'overview'],
    queryFn: () =>
      api.get<IntelOverviewData & { providers?: { name: string; on: boolean }[] }>('api/intel/overview'),
  });
export const useIntelOverlap = () =>
  useQuery({
    queryKey: ['intel', 'overlap'],
    queryFn: () => api.get<IntelOverlap>('api/intel/overlap'),
    staleTime: 300_000,
  });
/** Lista de trabajos; se refresca cada 3 s mientras haya alguno en curso. */
export const useIntelJobs = () =>
  useQuery({
    queryKey: ['intel', 'jobs'],
    queryFn: () => api.get<JobsData>('api/intel/jobs', { background: true }),
    refetchInterval: (q) =>
      q.state.data?.jobs.some((j) => j.status === 'running' || j.status === 'queued') || q.state.data?.cola
        ? 3000
        : false,
  });
export const useSightings = (days: number, q = '', minScore = 0) =>
  useQuery({
    queryKey: ['intel', 'sightings', days, q, minScore],
    queryFn: () => api.get<Sighting[]>(`api/intel/sightings${qs({ days, q, min_score: minScore })}`),
  });
export const useLookup = (v: string) =>
  useQuery({
    queryKey: ['intel', 'lookup', v],
    queryFn: () => api.get<IntelLookup>(`api/intel/lookup${qs({ deep: 1, v })}`),
    enabled: !!v,
    staleTime: 600_000,
  });
export const useSources = () =>
  useQuery({ queryKey: ['intel', 'sources'], queryFn: () => api.get<IntelSource[]>('api/intel/sources') });
export const useCatalog = () =>
  useQuery({
    queryKey: ['intel', 'catalog'],
    queryFn: () => api.get<IntelCatalogEntry[]>('api/intel/catalog'),
  });

const inv = (qc: ReturnType<typeof useQueryClient>) => void qc.invalidateQueries({ queryKey: ['intel'] });
export const useBulkCheck = () =>
  useMutation({
    mutationFn: (text: string) =>
      api.post<{ resultados: BulkCheckRow[]; limite: number }>('api/intel/check', { text }),
  });
export function useRetro() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (days: number) => api.post<{ encolado: boolean }>('api/intel/retro', { days }),
    onSuccess: () => inv(qc),
  });
}
export function useAddCatalog() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (keys: string[]) => api.post('api/intel/catalog', { keys }),
    onSuccess: () => inv(qc),
  });
}
export function useRunSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.post(`api/intel/sources/${id}/run`),
    onSuccess: () => inv(qc),
  });
}
export function useDeleteSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.delete(`api/intel/sources/${id}`),
    onSuccess: () => inv(qc),
  });
}
export interface SourceInput {
  kind: 'feed' | 'misp' | 'manual';
  name: string;
  url?: string;
  fmt?: string;
  ioc_type?: string;
  csv_col?: number;
  ref_col?: number | null;
  auth_header?: string;
  weight: number;
  interval_h?: number;
  retention_days?: number;
  tlp: string;
  enabled: boolean;
}
export function useSaveSource() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number | null; data: SourceInput }) =>
      id ? api.put(`api/intel/sources/${id}`, data) : api.post('api/intel/sources', data),
    onSuccess: () => inv(qc),
  });
}
export interface ParsedIocs {
  iocs: { value: string; type: string }[];
  ignorados: string[];
}
export const useParseIocs = () =>
  useMutation({ mutationFn: (text: string) => api.post<ParsedIocs>('api/iocs/parse', { text }) });
export interface AddResult {
  leidos: number;
  añadidos: number;
  ya_conocidos: number;
  misp_event?: string | number;
  misp_error?: string;
}
export function useAddIocs() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post<AddResult>('api/intel/add', body),
    onSuccess: () => inv(qc),
  });
}
