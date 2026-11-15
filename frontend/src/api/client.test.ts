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
