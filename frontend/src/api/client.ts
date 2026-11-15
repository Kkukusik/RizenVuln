let csrf = sessionStorage.getItem('csrf') ?? '';
export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}
export async function api<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const response = await fetch(`/api/v1/${path}`, {
    method,
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(method === 'GET' ? {} : {
        'X-CSRF-Token': csrf
      })
    },
    ...(body === undefined ? {} : {
      body: JSON.stringify(body)
    })
  });
  const data = await response.json().catch(() => ({
    error: {
      message: 'Некорректный ответ сервера'
    }
  }));
  if (!response.ok) throw new ApiError(response.status, data.error?.message ?? `Ошибка HTTP ${response.status}`);
  if (data.csrf_token) {
    csrf = data.csrf_token;
    sessionStorage.setItem('csrf', csrf);
  }
  return (data as T);
}
export function clearSession() {
  csrf = '';
  sessionStorage.removeItem('csrf');
}
