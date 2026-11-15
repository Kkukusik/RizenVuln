import { it, expect, vi, afterEach } from 'vitest';
import { api, ApiError } from './client';
afterEach(() => vi.unstubAllGlobals());
it('propagates server errors', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok: false,
    status: 403,
    json: async () => ({
      error: {
        message: 'Нет прав'
      }
    })
  }));
  await expect(api('projects')).rejects.toThrow('Нет прав');
});
it('sends session credentials', async () => {
  const fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({
      items: []
    })
  });
  vi.stubGlobal('fetch', fetch);
  await api('projects');
  expect(fetch.mock.calls[0][1].credentials).toBe('same-origin');
});
it('retains status for authentication', () => {
  expect(new ApiError(401, 'Войдите').status).toBe(401);
});
it('stores CSRF on login, sends it on mutations, and clears it on logout', async () => {
  const { clearSession } = await import('./client');
  clearSession();
  const fetch = vi.fn().mockResolvedValueOnce({ok:true,json:async()=>({csrf_token:'test-csrf'})}).mockResolvedValue({ok:true,json:async()=>({ok:true})});
  vi.stubGlobal('fetch',fetch);
  await api('auth/login','POST',{email:'admin@example.test',password:'fixture'});
  expect(sessionStorage.getItem('csrf')).toBe('test-csrf');
  await api('projects','POST',{name:'Test'});
  expect(fetch.mock.calls[1][1].headers['X-CSRF-Token']).toBe('test-csrf');
  expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({name:'Test'});
  clearSession();
  await api('auth/logout','POST');
  expect(fetch.mock.calls[2][1].headers['X-CSRF-Token']).toBe('');
  expect(sessionStorage.getItem('csrf')).toBeNull();
});
it('reports malformed server errors and network failures', async () => {
  vi.stubGlobal('fetch',vi.fn().mockResolvedValueOnce({ok:false,status:502,json:async()=>{throw new SyntaxError();}}).mockRejectedValueOnce(new TypeError('Network unavailable')));
  await expect(api('projects')).rejects.toMatchObject({status:502,message:'Некорректный ответ сервера'});
  await expect(api('projects')).rejects.toThrow('Network unavailable');
});
it('rejects malformed successful responses before rendering them as data', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => { throw new SyntaxError('Invalid JSON'); }
  }));
  await expect(api('projects')).rejects.toMatchObject({
    status: 502,
    message: 'Некорректный ответ сервера'
  });
});
