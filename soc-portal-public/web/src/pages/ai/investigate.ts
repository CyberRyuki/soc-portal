import type { NavigateFunction } from 'react-router-dom';
import { api } from '@/lib/api';
import { toast } from 'sonner';

export interface InvestigateInput {
  title: string;
  context?: string;
  question: string;
}
const PENDING = 'ai_pending_';

/** Crea una conversación con contexto y abre el asistente con la pregunta lista para enviarse. */
export async function startInvestigation(nav: NavigateFunction, inp: InvestigateInput): Promise<void> {
  try {
    const r = await api.post<{ id: string }>('api/ai/chats', {
      title: inp.title.slice(0, 120),
      context: inp.context ?? '',
    });
    sessionStorage.setItem(PENDING + r.id, inp.question);
    nav(`/ai/${r.id}`);
  } catch (e) {
    toast.error(`No se pudo abrir el asistente: ${(e as Error).message}`);
  }
}
export function takePending(cid: string): string | null {
  const v = sessionStorage.getItem(PENDING + cid);
  if (v) sessionStorage.removeItem(PENDING + cid);
  return v;
}
