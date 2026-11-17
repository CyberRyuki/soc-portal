import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { AiAuditRow, AiChat, AiChatDetail, AiRun, AiStatus } from '@/types/api';

export const useAiStatus = () =>
  useQuery({
    queryKey: ['ai', 'status'],
    queryFn: () => api.get<AiStatus>('api/ai/status'),
    staleTime: 300_000,
  });
export const useAiChats = () =>
  useQuery({ queryKey: ['ai', 'chats'], queryFn: () => api.get<AiChat[]>('api/ai/chats') });
export const useAiChat = (cid: string) =>
  useQuery({
    queryKey: ['ai', 'chat', cid],
    queryFn: () => api.get<AiChatDetail>(`api/ai/chats/${encodeURIComponent(cid)}`),
    enabled: !!cid,
  });
/** Estado de una ejecución; se consulta cada 800 ms mientras siga en curso. */
export const useAiRun = (rid: string | null) =>
  useQuery({
    queryKey: ['ai', 'run', rid],
    queryFn: () => api.get<AiRun>(`api/ai/runs/${rid}`, { background: true }),
    enabled: !!rid,
    refetchInterval: (q) => (q.state.data?.status === 'running' || !q.state.data ? 800 : false),
    retry: 3,
  });
export const useAiAudit = () =>
  useQuery({ queryKey: ['ai', 'audit'], queryFn: () => api.get<AiAuditRow[]>('api/admin/ai-audit') });
export function useNewChat() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: { title: string; context?: string }) => api.post<{ id: string }>('api/ai/chats', b),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['ai', 'chats'] }),
  });
}
export function useDeleteChat() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (cid: string) => api.delete(`api/ai/chats/${encodeURIComponent(cid)}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['ai', 'chats'] }),
  });
}
export const useSendMessage = (cid: string) =>
  useMutation({
    mutationFn: (b: { text: string; verify: boolean }) =>
      api.post<{ run: string }>(`api/ai/chats/${encodeURIComponent(cid)}/messages`, b),
  });
