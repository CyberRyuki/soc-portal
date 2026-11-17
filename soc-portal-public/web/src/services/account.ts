import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, qs } from '@/lib/api';
import type { AdminUser, AdminUsers, AuthLogRow, Contact, MfaSetup, Role } from '@/types/api';

export const useContacts = () =>
  useQuery({ queryKey: ['contacts'], queryFn: () => api.get<Contact[]>('api/contacts') });
export function useSaveContacts() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (rows: Contact[]) => api.put('api/contacts', rows),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['contacts'] }),
  });
}
export const useChangePassword = () =>
  useMutation({ mutationFn: (b: { current: string; new: string }) => api.post('auth/password', b) });
export const useMfaSetup = () => useMutation({ mutationFn: () => api.post<MfaSetup>('auth/mfa/setup') });
export const useMfaEnable = () =>
  useMutation({
    mutationFn: (code: string) => api.post<{ recovery: string[] }>('auth/mfa/enable', { code }),
  });
export const useMfaDisable = () =>
  useMutation({ mutationFn: (code: string) => api.post('auth/mfa/disable', { code }) });
export const useRevokeSessions = () =>
  useMutation({ mutationFn: (id?: string) => api.post('auth/sessions/revoke', { id }) });

export const useAdminUsers = () =>
  useQuery({
    queryKey: ['admin', 'users'],
    queryFn: () => api.get<AdminUsers & { events: Record<string, string> }>('api/admin/users'),
  });
export const useAuthLog = (days: number, event: string, q: string) =>
  useQuery({
    queryKey: ['admin', 'log', days, event, q],
    queryFn: () =>
      api.get<(AuthLogRow & { username: string; event_name: string })[]>(
        `api/admin/authlog${qs({ days, event, q })}`,
      ),
  });
export interface UserInput {
  username?: string;
  source?: 'local' | 'ldap';
  display?: string;
  email?: string;
  role?: Role;
  password?: string;
  enabled?: boolean;
  unlock?: 1;
  reset_password?: 1;
  reset_mfa?: 1;
  logout?: 1;
}
export interface UserResult extends Partial<AdminUser> {
  password?: string;
  username: string;
}
export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (b: UserInput) => api.post<UserResult>('api/admin/users', b),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['admin'] }),
  });
}
export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: UserInput }) =>
      api.put<UserResult>(`api/admin/users/${id}`, data),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['admin'] }),
  });
}
export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.delete(`api/admin/users/${id}`),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['admin'] }),
  });
}
