/**
 * Cliente HTTP del portal.
 * - Cookie de sesión HttpOnly (same-origin) + cabecera anti-CSRF `X-SOC: 1` que exige el backend.
 * - Las peticiones de refresco automático llevan `X-Background: 1` para no contar como actividad.
 * - 401 → evento `soc:unauthorized` (el router redirige al login). 428 → `soc:must-change` (cuenta).
 */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;
  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

export const API_BASE = '/portal/';

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  body?: unknown;
  /** cuerpo binario sin serializar (subida de archivos) */
  raw?: BodyInit;
  background?: boolean;
  signal?: AbortSignal;
  headers?: Record<string, string>;
}

function messageFrom(status: number, data: unknown): string {
  if (data && typeof data === 'object' && 'detail' in data) {
    const d = (data as { detail: unknown }).detail;
    if (typeof d === 'string') return d;
    if (Array.isArray(d))
      return d.map((x) => (x && typeof x === 'object' && 'msg' in x ? String(x.msg) : String(x))).join('; ');
  }
  if (data && typeof data === 'object' && 'error' in data) return String((data as { error: unknown }).error);
  return `Error ${status}`;
}

function parseBody(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const url = path.startsWith('/') ? path : API_BASE + path;
  const headers: Record<string, string> = { 'X-SOC': '1', Accept: 'application/json', ...opts.headers };
  let body: BodyInit | undefined = opts.raw;
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.body);
  }
  if (opts.background) headers['X-Background'] = '1';
  const res = await fetch(url, {
    method: opts.method ?? 'GET',
    headers,
    body,
    credentials: 'same-origin',
    signal: opts.signal,
  });
  const data = parseBody(await res.text());
  if (res.status === 401) {
    // En el propio login (contraseña, MFA, bloqueo) el 401 trae el motivo real: se muestra tal cual.
    if (/^auth\/(login|mfa)$/.test(path)) throw new ApiError(401, messageFrom(401, data), data);
    window.dispatchEvent(new CustomEvent('soc:unauthorized'));
    throw new ApiError(401, 'Sesión caducada');
  }
  if (res.status === 428) {
    window.dispatchEvent(new CustomEvent('soc:must-change'));
    throw new ApiError(428, messageFrom(428, data), data);
  }
  if (!res.ok) throw new ApiError(res.status, messageFrom(res.status, data), data);
  return data as T;
}

export const api = {
  get: <T>(path: string, opts?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...opts, method: 'GET' }),
  post: <T>(path: string, body?: unknown, opts?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...opts, method: 'POST', body }),
  put: <T>(path: string, body?: unknown, opts?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...opts, method: 'PUT', body }),
  delete: <T>(path: string, opts?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...opts, method: 'DELETE' }),
};

/** Construye una query string omitiendo valores vacíos. */
export function qs(params: object): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params as Record<string, unknown>))
    if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : '';
}
