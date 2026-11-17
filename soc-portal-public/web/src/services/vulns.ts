import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type { ScanPreview, Vuln, VulnList, WazuhVulnHost, WazuhVulns } from '@/types/api';

export interface WazuhVulnFilter {
  severity?: string;
  agent?: string;
  q?: string;
}
export interface VulnFilter {
  status?: string;
  severity?: string;
  source?: string;
  q?: string;
}
export const useWazuhVulns = (f: WazuhVulnFilter) =>
  useQuery({
    queryKey: ['vulns', 'wazuh', f],
    queryFn: () => api.get<WazuhVulns>(`api/vulns/wazuh${qs(f)}`),
    staleTime: 600_000,
  });
export const useWazuhVulnHosts = (cve: string) =>
  useQuery({
    queryKey: ['vulns', 'wazuh', 'cve', cve],
    queryFn: () => api.get<WazuhVulnHost[]>(`api/vulns/wazuh/${encodeURIComponent(cve)}`),
    enabled: !!cve,
  });
export const useVulns = (f: VulnFilter) =>
  useQuery({ queryKey: ['vulns', 'track', f], queryFn: () => api.get<VulnList>(`api/vulns${qs(f)}`) });

const inv = (qc: ReturnType<typeof useQueryClient>) => {
  void qc.invalidateQueries({ queryKey: ['vulns', 'track'] });
  void qc.invalidateQueries({ queryKey: ['home'] });
};
export type VulnInput = Partial<
  Pick<
    Vuln,
    | 'cve'
    | 'cvss'
    | 'title'
    | 'severity'
    | 'status'
    | 'asset'
    | 'package'
    | 'port'
    | 'owner'
    | 'due_date'
    | 'solution'
    | 'notes'
  >
>;
export function useSaveVuln() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number | null; data: VulnInput }) =>
      id ? api.put<Vuln>(`api/vulns/${id}`, data) : api.post<Vuln>('api/vulns', data),
    onSuccess: () => inv(qc),
  });
}
export function useDeleteVuln() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: (id: number) => api.delete(`api/vulns/${id}`), onSuccess: () => inv(qc) });
}
export function useTrackCve() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: { cve: string; severity?: string }) =>
      api.post<{ id: number; nuevo: boolean }>('api/vulns/track', b),
    onSuccess: () => inv(qc),
  });
}
export interface ImportResult {
  total?: number;
  omitidos: number;
  columnas?: Record<string, string>;
  muestra?: Partial<Vuln>[];
  nuevas?: number;
  actualizadas?: number;
}
export function useImportScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: { text: string; scanner: string; preview: boolean }) =>
      api.post<ImportResult & ScanPreview>('api/vulns/import', b),
    onSuccess: (_, v) => !v.preview && inv(qc),
  });
}
