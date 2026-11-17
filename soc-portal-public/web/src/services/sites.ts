import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { DefaceDetail, Site, SiteImportRow, SitesData } from '@/types/api';

export const useSites = () =>
  useQuery({
    queryKey: ['sites'],
    queryFn: () => api.get<SitesData>('api/sites', { background: true }),
    refetchInterval: 60_000,
  });
export type SiteInput = Partial<
  Pick<
    Site,
    | 'name'
    | 'url'
    | 'interval_min'
    | 'expect_code'
    | 'keyword'
    | 'owner'
    | 'waf'
    | 'plan'
    | 'server'
    | 'public_ip'
    | 'change_threshold'
  >
> & { watch_content: boolean; auto_incident: boolean; enabled: boolean; critical?: boolean };
const inv = (qc: ReturnType<typeof useQueryClient>) => {
  void qc.invalidateQueries({ queryKey: ['sites'] });
  void qc.invalidateQueries({ queryKey: ['home'] });
};
export function useSaveSite() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number | null; data: SiteInput }) =>
      id ? api.put(`api/sites/${id}`, data) : api.post('api/sites', data),
    onSuccess: () => inv(qc),
  });
}
export function useDeleteSite() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: (id: number) => api.delete(`api/sites/${id}`), onSuccess: () => inv(qc) });
}
export function useCheckSite() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.post(`api/sites/${id}/check`),
    onSuccess: () => inv(qc),
  });
}

export const useDeface = (id: number | null) =>
  useQuery({
    queryKey: ['sites', 'deface', id],
    queryFn: () => api.get<DefaceDetail>(`api/sites/${id}/deface`),
    enabled: id != null,
  });
export function useAcceptBaseline() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.post(`api/sites/${id}/baseline`),
    onSuccess: () => inv(qc),
  });
}
export function useParseSites() {
  return useMutation({
    mutationFn: (f: File) =>
      api.post<{ rows: SiteImportRow[]; nuevos: number; existentes: number }>(
        `api/sites/import/parse?filename=${encodeURIComponent(f.name)}`,
        undefined,
        { raw: f, headers: { 'Content-Type': 'application/octet-stream' } },
      ),
  });
}
export function useImportSites() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: {
      rows: SiteImportRow[];
      interval_min: number;
      watch_content: boolean;
      auto_incident: string;
    }) => api.post<{ nuevos: number; actualizados: number }>('api/sites/import', b),
    onSuccess: () => inv(qc),
  });
}

export interface BulkCheck {
  running: boolean;
  total: number;
  done: number;
  errors: number;
  by: string;
  started: string;
  finished: string;
}
/** Estado de la comprobación masiva: consulta cada 2 s mientras está en curso. */
export const useBulkCheck = () =>
  useQuery({
    queryKey: ['sites', 'bulk'],
    queryFn: () => api.get<BulkCheck>('api/sites/check-all', { background: true }),
    refetchInterval: (q) => (q.state.data?.running ? 2000 : false),
  });
export function useCheckAll() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (ids?: number[]) => api.post<BulkCheck>('api/sites/check-all', ids ? { ids } : {}),
    onSuccess: (d) => qc.setQueryData(['sites', 'bulk'], d),
  });
}

export function useCaptureSite() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.post(`api/sites/${id}/screen`),
    onSuccess: () => inv(qc),
  });
}
export const useVisualStatus = () =>
  useQuery({
    queryKey: ['sites', 'visual'],
    queryFn: () =>
      api.get<{
        activo: boolean;
        running: boolean;
        done: number;
        total: number;
        last: string;
        intervalo_h: number;
        umbral_cambio: number;
        umbral_alerta: number;
      }>('api/sites/visual/status', { background: true }),
    refetchInterval: 60_000,
  });
