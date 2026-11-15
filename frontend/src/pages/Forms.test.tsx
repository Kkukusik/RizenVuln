import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, it, expect, vi } from 'vitest';
import { Login, AddForm, Resource } from './App';
function wrapper(children: React.ReactNode) {
  return <QueryClientProvider client={new QueryClient({
    defaultOptions: {
      queries: {
        retry: false
      },
      mutations: {
        retry: false
      }
    }
  })}>{children}</QueryClientProvider>;
}
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
it('validates login fields', () => {
  render(wrapper(<Login />));
  expect(screen.getByLabelText('Email')).toBeRequired();
  expect(screen.getByLabelText('Пароль')).toHaveAttribute('type', 'password');
});
it('submits project form to API', async () => {
  const fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({
      items: [],
      id: 'created'
    })
  });
  vi.stubGlobal('fetch', fetch);
  const done = vi.fn();
  render(wrapper(<AddForm section="projects" onClose={() => {}} onSuccess={done} />));
  fireEvent.change(screen.getByLabelText('Название'), {
    target: {
      value: 'Production'
    }
  });
  fireEvent.click(screen.getByRole('button', {
    name: 'Добавить'
  }));
  await waitFor(() => expect(done).toHaveBeenCalled());
  expect(fetch.mock.calls.some(([path, options]) => path === '/api/v1/projects' && options.method === 'POST' && JSON.parse(options.body).name === 'Production')).toBe(true);
});
it('sends severity filter and displays API errors', async () => {
  const fetch = vi.fn().mockImplementation(async (path: string) => path.includes('severity=CRITICAL') ? {
    ok: false,
    status: 503,
    json: async () => ({
      error: {
        message: 'Источник недоступен'
      }
    })
  } : {
    ok: true,
    json: async () => ({
      items: [],
      total: 0,
      page: 1,
      per_page: 25
    })
  });
  vi.stubGlobal('fetch', fetch);
  render(wrapper(<Resource section="vulnerabilities" admin={false} />));
  fireEvent.change(screen.getByLabelText('Критичность'), {
    target: {
      value: 'CRITICAL'
    }
  });
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Источник недоступен'));
});
