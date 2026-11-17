import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type {
  Audit,
  AuditList,
  SecuritySummary,
  Tool,
  ToolCatalogEntry,
  ToolFileContent,
  ToolList,
  ToolMetrics,
} from '@/types/api';

export interface ToolFilter {
  cat?: string;
  q?: string;
  platform?: string;
}
export const useTools = (f: ToolFilter) =>
  useQuery({ queryKey: ['tools', 'list', f], queryFn: () => api.get<ToolList>(`api/tools${qs(f)}`) });
export const useTool = (slug: string) =>
  useQuery({
    queryKey: ['tools', 'one', slug],
    queryFn: () => api.get<Tool>(`api/tools/${encodeURIComponent(slug)}`),
    enabled: !!slug,
  });
export const useToolCatalog = (enabled = true) =>
  useQuery({
    queryKey: ['tools', 'catalog'],
    queryFn: () => api.get<ToolCatalogEntry[]>('api/tools/catalog'),
    enabled,
  });
export const useSecuritySummary = () =>
  useQuery({
    queryKey: ['tools', 'security'],
    queryFn: () => api.get<SecuritySummary>('api/tools/security-summary', { background: true }),
  });
export const useToolFile = (slug: string, fid: string) =>
  useQuery({
    queryKey: ['tools', 'file', slug, fid],
    queryFn: () => api.get<ToolFileContent>(`api/tools/${encodeURIComponent(slug)}/files/${fid}`),
    enabled: !!slug && !!fid,
  });
export const useToolMetrics = (slug: string, enabled: boolean) =>
  useQuery({
    queryKey: ['tools', 'metrics', slug],
    queryFn: () => api.get<ToolMetrics>(`api/tools/${encodeURIComponent(slug)}/metrics`),
    enabled,
    staleTime: 600_000,
  });
export const useAudits = (slug: string, enabled: boolean) =>
  useQuery({
    queryKey: ['tools', 'audits', slug],
    queryFn: () => api.get<AuditList>(`api/tools/${encodeURIComponent(slug)}/audits`, { background: true }),
    enabled,
    refetchInterval: (q) => (q.state.data?.rows.some((r) => r.status === 'running') ? 2000 : false),
  });
export const useAudit = (slug: string, aid: number | null) =>
  useQuery({
    queryKey: ['tools', 'audit', slug, aid],
    queryFn: () =>
      api.get<Audit>(`api/tools/${encodeURIComponent(slug)}/audits/${aid}`, { background: true }),
    enabled: !!aid,
    refetchInterval: (q) => (q.state.data?.status === 'running' ? 2000 : false),
  });

const inv = (qc: ReturnType<typeof useQueryClient>) => void qc.invalidateQueries({ queryKey: ['tools'] });
export type ToolInput = Partial<
  Pick<
    Tool,
    | 'name'
    | 'repo_url'
    | 'category'
    | 'status'
    | 'platform'
    | 'homepage'
    | 'language'
    | 'version'
    | 'license'
    | 'owner'
    | 'description'
    | 'tags'
    | 'auth_note'
    | 'usage'
    | 'readme'
  >
> & { requires_auth: boolean };
export function useSaveTool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ slug, data }: { slug: string | null; data: ToolInput | Partial<Tool> }) =>
      slug ? api.put<Tool>(`api/tools/${encodeURIComponent(slug)}`, data) : api.post<Tool>('api/tools', data),
    onSuccess: () => inv(qc),
  });
}
export function useDeleteTool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (slug: string) => api.delete(`api/tools/${encodeURIComponent(slug)}`),
    onSuccess: () => inv(qc),
  });
}
export function useAddToolCatalog() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (names: string[]) => api.post<{ añadidas: number }>('api/tools/catalog', { names }),
    onSuccess: () => inv(qc),
  });
}
export function useSyncTool(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (cache: boolean) =>
      api.post<{ archivos?: number; rama?: string; copiados?: number }>(
        `api/tools/${encodeURIComponent(slug)}/github${qs({ cache: cache ? 1 : 0 })}`,
      ),
    onSuccess: () => inv(qc),
  });
}
export function useDeleteToolFile(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (fid: number) => api.delete(`api/tools/${encodeURIComponent(slug)}/files/${fid}`),
    onSuccess: () => inv(qc),
  });
}
export function useStartAudit(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (profile: string) =>
      api.post<{ id: number }>(`api/tools/${encodeURIComponent(slug)}/audits`, { profile }),
    onSuccess: () => inv(qc),
  });
}
export function useFindingToVuln(slug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ aid, fid }: { aid: number; fid: string }) =>
      api.post<{ id: number; nuevo: boolean }>(
        `api/tools/${encodeURIComponent(slug)}/audits/${aid}/findings/${fid}/vuln`,
      ),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['vulns'] }),
  });
}
/** Sube archivos uno a uno (cuerpo binario) e informa del progreso. */
export async function uploadToolFiles(
  slug: string,
  files: File[],
  onProgress: (msg: string) => void,
): Promise<{ done: number; fail: number }> {
  let done = 0,
    fail = 0;
  for (const f of files) {
    const path = (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name;
    onProgress(`Subiendo ${path}… (${done + fail + 1} de ${files.length})`);
    try {
      await api.post(`api/tools/${encodeURIComponent(slug)}/files${qs({ path })}`, undefined, {
        raw: f,
        headers: { 'Content-Type': 'application/octet-stream' },
      });
      done++;
    } catch {
      fail++;
    }
  }
  return { done, fail };
}
