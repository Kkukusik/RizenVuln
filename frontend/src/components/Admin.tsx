import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { DataRow } from '../types';
import { ErrorNotice } from './Common';
export function UserManagement() {
  const client = useQueryClient();
  const q = useQuery({
    queryKey: ['users'],
    queryFn: () => api<{
      items: DataRow[];
    }>('settings/users')
  });
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('viewer');
  const [target, setTarget] = useState('');
  const [reset, setReset] = useState('');
  const create = useMutation({
    mutationFn: () => api('settings/users', 'POST', {
      email,
      password,
      role
    }),
    onSuccess: () => {
      setEmail('');
      setPassword('');
      client.invalidateQueries({
        queryKey: ['users']
      });
    }
  });
  const update = useMutation({
    mutationFn: () => api(`settings/users/${target}/password`, 'POST', {
      password: reset
    }),
    onSuccess: () => setReset('')
  });
  return <section className="panel admin"><h2>Пользователи</h2>{q.error && <ErrorNotice error={q.error} />}<div className="table-wrap"><table><thead><tr><th>Email</th><th>Роль</th></tr></thead><tbody>{q.data?.items.map(u => <tr key={u.id}><td>{String(u.email)}</td><td>{String(u.role)}</td></tr>)}</tbody></table></div><h2>Новый пользователь</h2><form className="admin-form" onSubmit={e => {
      e.preventDefault();
      create.mutate();
    }}><label>Email<input required type="email" value={email} onChange={e => setEmail(e.target.value)} /></label><label>Пароль<input required type="password" minLength={16} maxLength={256} autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} /></label><label>Роль<select value={role} onChange={e => setRole(e.target.value)}><option value="viewer">Наблюдатель</option><option value="admin">Администратор</option></select></label><button className="primary" disabled={create.isPending}>Создать</button></form>{create.error && <ErrorNotice error={create.error} />}<h2>Смена пароля и отзыв сессий</h2><form className="admin-form" onSubmit={e => {
      e.preventDefault();
      update.mutate();
    }}><label>Пользователь<select required value={target} onChange={e => setTarget(e.target.value)}><option value="">Выберите пользователя</option>{q.data?.items.map(u => <option key={u.id} value={u.id}>{String(u.email)}</option>)}</select></label><label>Новый пароль<input required type="password" minLength={16} maxLength={256} autoComplete="new-password" value={reset} onChange={e => setReset(e.target.value)} /></label><button disabled={update.isPending}>Сменить пароль</button></form>{update.error && <ErrorNotice error={update.error} />}<p>Все сессии выбранного пользователя будут отозваны. При смене собственного пароля войдите заново.</p></section>;
}
const events: Record<string, string> = {
  vulnerability: 'Critical / High CVE',
  fix_available: 'Доступное исправление',
  kev: 'CISA KEV',
  stable_release: 'Стабильный релиз',
  image_outdated: 'Доступное обновление образа',
  scan_or_integration_failed: 'Ошибка сканирования / интеграции',
  test: 'Тестовые сообщения'
};
export function NotificationRules() {
  const client = useQueryClient();
  const q = useQuery({
    queryKey: ['notification-rules'],
    queryFn: () => api<{
      items: DataRow[];
    }>('notifications/rules')
  });
  const m = useMutation({
    mutationFn: ({
      event,
      enabled
    }: {
      event: string;
      enabled: boolean;
    }) => api('notifications/rules', 'POST', {
      event,
      enabled
    }),
    onSuccess: () => client.invalidateQueries({
      queryKey: ['notification-rules']
    })
  });
  return <section className="panel admin"><h2>Правила уведомлений</h2>{q.error && <ErrorNotice error={q.error} />} {m.error && <ErrorNotice error={m.error} />}<div className="integration-grid">{Object.entries(events).map(([event, title]) => <label key={event} className="check"><input type="checkbox" checked={q.data?.items.find(r => r.event === event)?.enabled !== false} disabled={m.isPending || q.isPending} onChange={e => m.mutate({
          event,
          enabled: e.target.checked
        })} />{title}</label>)}</div><p>Выключенное событие не ставится в очередь. Уже созданные задания сохраняются.</p></section>;
}
