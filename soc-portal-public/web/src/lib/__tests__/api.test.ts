import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError, qs } from '../api';

const respond = (status: number, body: unknown) =>
  vi
    .fn()
    .mockImplementation(
      async () => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status }),
    );

describe('api', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('envía la cabecera anti-CSRF y serializa el cuerpo', async () => {
    const f = respond(200, { ok: true });
    vi.stubGlobal('fetch', f);
    await api.post('api/incidents', { title: 'x' });
    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/portal/api/incidents');
    expect((init.headers as Record<string, string>)['X-SOC']).toBe('1');
    expect(init.body).toBe('{"title":"x"}');
    expect(init.credentials).toBe('same-origin');
  });

  it('marca las peticiones de fondo', async () => {
    const f = respond(200, {});
    vi.stubGlobal('fetch', f);
    await api.get('api/metrics', { background: true });
    expect(
      ((f.mock.calls[0] as [string, RequestInit])[1].headers as Record<string, string>)['X-Background'],
    ).toBe('1');
  });

  it('convierte el detalle de FastAPI en un ApiError legible', async () => {
    vi.stubGlobal('fetch', respond(400, { detail: 'Escribe un título' }));
    await expect(api.post('api/incidents', {})).rejects.toMatchObject({
      status: 400,
      message: 'Escribe un título',
    });
  });

  it('une los errores de validación 422', async () => {
    vi.stubGlobal('fetch', respond(422, { detail: [{ msg: 'campo a' }, { msg: 'campo b' }] }));
    await expect(api.get('api/x')).rejects.toThrow('campo a; campo b');
  });

  it('emite soc:unauthorized en 401', async () => {
    vi.stubGlobal('fetch', respond(401, { detail: 'no' }));
    const spy = vi.fn();
    window.addEventListener('soc:unauthorized', spy);
    await expect(api.get('auth/me')).rejects.toBeInstanceOf(ApiError);
    expect(spy).toHaveBeenCalledOnce();
    window.removeEventListener('soc:unauthorized', spy);
  });

  it('en el login muestra el motivo real del 401 y no lo trata como sesión caducada', async () => {
    vi.stubGlobal('fetch', respond(401, { error: 'Cuenta bloqueada 15 min' }));
    const spy = vi.fn();
    window.addEventListener('soc:unauthorized', spy);
    await expect(api.post('auth/login', { username: 'a', password: 'b' })).rejects.toThrow(
      'Cuenta bloqueada 15 min',
    );
    await expect(api.post('auth/mfa', { ticket: 't', code: '1' })).rejects.toThrow('Cuenta bloqueada 15 min');
    expect(spy).not.toHaveBeenCalled();
    window.removeEventListener('soc:unauthorized', spy);
  });

  it('qs omite valores vacíos y codifica', () => {
    expect(qs({ a: '', b: undefined, c: 'x y', d: 0 })).toBe('?c=x+y&d=0');
    expect(qs({})).toBe('');
  });
});
