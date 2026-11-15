import { useState, type FormEvent } from 'react';
import { NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ShieldCheck, LayoutDashboard, Folder, Container, Github, Bug, Boxes, Server, ArrowUpCircle, Wrench, FileText, Bell, Plug, Settings, LogOut, RefreshCw, Plus, Download } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, AreaChart, Area, CartesianGrid } from 'recharts';
import { api, ApiError, clearSession } from '../api/client';
import type { DataRow, Page, User, DashboardData } from '../types';
import { MetricChart } from '../components/Charts';
import { UserManagement, NotificationRules } from '../components/Admin';
import { PackageExplorer, SbomCompare } from '../components/Sbom';
import { Badge, DataTable, Detail, ErrorNotice, Theme } from '../components/Common';
const sections = ([['dashboard', 'Обзор', LayoutDashboard], ['projects', 'Проекты', Folder], ['images', 'Образы', Container], ['repositories', 'GitHub', Github], ['vulnerabilities', 'Уязвимости', Bug], ['sbom', 'SBOM Explorer', Boxes], ['deployments', 'Развёртывания', Server], ['updates', 'Обновления', ArrowUpCircle], ['remediation', 'Исправления', Wrench], ['reports', 'Отчёты', FileText], ['notifications', 'Уведомления', Bell], ['integrations', 'Интеграции', Plug], ['settings', 'Настройки', Settings]] as const);
const columns: Record<string, string[]> = {
  projects: ['name', 'description', 'created_at'],
  images: ['reference', 'digest', 'status', 'last_checked'],
  repositories: ['full_name', 'branch', 'status', 'last_checked'],
  vulnerabilities: ['vulnerability_id', 'severity', 'package', 'installed_version', 'fixed_version', 'kev', 'epss', 'status'],
  sbom: ['format', 'storage_status', 'sha256', 'created_at'],
  deployments: ['server', 'namespace', 'container', 'image', 'environment', 'running', 'last_seen'],
  updates: ['candidate', 'status', 'major_warning', 'reason'],
  remediation: ['vulnerability_id', 'severity', 'package', 'fixed_version', 'status'],
  reports: ['source', 'status', 'digest', 'started_at', 'completed_at'],
  notifications: ['event', 'message', 'status', 'attempts', 'created_at'],
  integrations: ['kind', 'enabled', 'status', 'error', 'last_checked']
};
export default function App() {
  const user = useQuery({
    queryKey: ['me'],
    queryFn: () => api<User>('auth/me'),
    retry: false
  });
  const client = useQueryClient();
  const location = useLocation();
  const logout = useMutation({
    mutationFn: () => api('auth/logout', 'POST'),
    onSuccess: () => {
      clearSession();
      client.clear();
      window.location.assign('/');
    }
  });
  if (user.isPending) return <div className="loading">RizenVuln · Загрузка…</div>;
  if (user.error) {
    if (user.error instanceof ApiError && user.error.status === 401) return <Login />;
    return <div className="login"><ErrorNotice error={user.error} /><button onClick={() => user.refetch()}>Повторить</button></div>;
  }
  const title = sections.find(s => location.pathname.startsWith('/' + s[0]))?.[1] ?? 'Обзор';
  return <div className="layout"><aside><div className="brand"><ShieldCheck /><div>Rizen<span>Vuln</span><small>INFRASTRUCTURE SECURITY</small></div></div><div className="nav-label">РАБОЧЕЕ ПРОСТРАНСТВО</div><nav>{sections.map(([path, label, Icon]) => <NavLink key={path} to={'/' + path}><Icon size={18} />{label}</NavLink>)}</nav><div className="sidebar-foot"><span className="dot" /> Мониторинг без вмешательства</div></aside><main><header><div><div className="breadcrumb">RizenVuln / Инфраструктура</div><h1>{title}</h1></div><div className="header-actions"><Theme /><span className="user">{user.data?.email}</span><button aria-label="Выйти" onClick={() => logout.mutate()}><LogOut size={17} /></button></div></header>{logout.error && <ErrorNotice error={logout.error} />}<div className="content"><Routes><Route path="/" element={<Navigate to="/dashboard" replace />} /><Route path="/dashboard" element={<Dashboard />} />{Object.keys(columns).map(section => <Route key={section} path={'/' + section} element={<Resource key={section} section={section} admin={user.data?.role === 'admin'} />} />)}<Route path="/settings" element={<SettingsPage />} /><Route path="*" element={<Navigate to="/dashboard" replace />} /></Routes></div></main></div>;
}
export function Login() {
  const client = useQueryClient();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const mutation = useMutation({
    mutationFn: () => api('auth/login', 'POST', {
      email,
      password
    }),
    onSuccess: () => client.invalidateQueries({
      queryKey: ['me']
    })
  });
  function submit(e: FormEvent) {
    e.preventDefault();
    mutation.mutate();
  }
  return <div className="login"><form onSubmit={submit} className="panel"><ShieldCheck size={38} className="accent" /><h1>RizenVuln</h1><p>Центр безопасности вашей инфраструктуры</p><label>Email<input type="email" required autoComplete="username" value={email} onChange={e => setEmail(e.target.value)} /></label><label>Пароль<input type="password" required autoComplete="current-password" maxLength={256} value={password} onChange={e => setPassword(e.target.value)} /></label>{mutation.error && <ErrorNotice error={mutation.error} />}<button className="primary" disabled={mutation.isPending}>{mutation.isPending ? 'Вход…' : 'Войти в систему'}</button></form></div>;
}
function Dashboard() {
  const q = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api<DashboardData>('dashboard'),
    refetchInterval: 30000
  });
  if (q.isPending) return <p>Загрузка показателей…</p>;
  if (q.error) return <ErrorNotice error={q.error} />;
  const d = q.data;
  const count = (s: string) => d.severity.find(v => v.severity === s)?.count ?? 0;
  return <><div className="page-intro"><div><h2>Безопасность под контролем</h2><p>Актуальное состояние отслеживаемых источников</p></div><span className="pill"><span className="dot" /> Последнее сканирование: {d.counts.last_scan ? new Date(d.counts.last_scan).toLocaleString('ru-RU') : 'ещё не выполнялось'}</span></div>{d.counts.stale_images > 0 && <div className="warning">У {d.counts.stale_images} образов нет актуального успешного сканирования. Их безопасность не подтверждена.</div>}<div className="stats">{[['Проекты', d.counts.projects, 'blue'], ['Образы', d.counts.images, 'blue'], ['Critical CVE', count('CRITICAL'), 'red'], ['High CVE', count('HIGH'), 'amber'], ['Medium CVE', count('MEDIUM'), 'amber'], ['Low CVE', count('LOW'), 'green'], ['Есть исправление', d.counts.fixes, 'green'], ['Есть обновление', d.counts.updates, 'amber']].map(([label, value, color]) => <div className="stat panel" key={String(label)}><span>{label}</span><strong className={String(color)}>{value}</strong><small>По данным мониторинга</small></div>)}</div><div className="charts"><section className="panel"><h2>Уязвимости по критичности</h2>{d.severity.length ? <ResponsiveContainer width="100%" height={250}><BarChart data={d.severity}><CartesianGrid strokeDasharray="3 3" stroke="#293246" /><XAxis dataKey="severity" /><YAxis allowDecimals={false} /><Tooltip /><Bar dataKey="count" name="Уязвимости" fill="#8b7cf8" radius={[6, 6, 0, 0]} /></BarChart></ResponsiveContainer> : <div className="empty">Результатов сканирования пока нет</div>}</section><section className="panel"><h2>Динамика обнаружений</h2>{d.trend.length ? <ResponsiveContainer width="100%" height={250}><AreaChart data={d.trend.map(v => ({
            ...v,
            date: new Date(v.date).toLocaleDateString('ru-RU')
          }))}><CartesianGrid strokeDasharray="3 3" stroke="#293246" /><XAxis dataKey="date" /><YAxis allowDecimals={false} /><Tooltip /><Area type="monotone" dataKey="count" name="Обнаружения CVE" stroke="#8b7cf8" fill="#8b7cf830" /></AreaChart></ResponsiveContainer> : <div className="empty">График появится после первой проверки</div>}</section></div><div className="charts"><MetricChart title="Уязвимости по проектам" data={d.by_project ?? []} x="name" value="count" /><MetricChart title="Отмечено как исправленное" data={(d.fixes ?? []).map(v => ({
        ...v,
        date: new Date(v.date).toLocaleDateString('ru-RU')
      }))} x="date" value="count" /><MetricChart title="Активность сканирования" data={d.trend.map(v => ({
        ...v,
        date: new Date(v.date).toLocaleDateString('ru-RU')
      }))} x="date" value="scans" /></div><section className="panel"><h2>Подключённые интеграции</h2><div className="integration-grid">{d.integrations.map(i => <div className="integration" key={i.id}><Plug size={20} /><strong>{String(i.kind).toUpperCase()}</strong><Badge value={i.status} />{i.error != null && <small>{String(i.error)}</small>}</div>)}</div></section><p className="muted">EPSS оценивает вероятность эксплуатации. Наличие в CISA KEV указывает на известную эксплуатацию. Одобрение версии не гарантирует отсутствие CVE.</p></>;
}
export function Resource({
  section,
  admin
}: {
  section: string;
  admin: boolean;
}) {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [project, setProject] = useState('');
  const [fix, setFix] = useState(false);
  const [kev, setKev] = useState(false);
  const [image,setImage]=useState('');
  const [environment,setEnvironment]=useState('');
  const [epss,setEpss]=useState('');
  const [sort, setSort] = useState('id');
  const [order, setOrder] = useState('desc');
  const [selected, setSelected] = useState<DataRow | null>(null);
  const [adding, setAdding] = useState(false);
  const client = useQueryClient();
  const params = new URLSearchParams({
    page: String(page),
    q: search,
    sort,
    order
  });
  if (severity) params.set('severity', severity);
  if (status) params.set('status', status);
  if (project) params.set('project_id', project);
  if (fix) params.set('fix_available', 'true');
  if (kev) params.set('kev', 'true');
  if(image)params.set('image_id',image);
  if(environment)params.set('environment',environment);
  if(epss)params.set('min_epss',epss);
  const imageOptions=useQuery({queryKey:['image-options',project],queryFn:()=>api<Page>(`images?per_page=100${project?'&project_id='+project:''}`),enabled:['vulnerabilities','remediation'].includes(section)});
  const q = useQuery({
    queryKey: [section, params.toString()],
    queryFn: () => api<Page>(`${section}?${params}`)
  });
  const projects = useQuery({
    queryKey: ['project-options'],
    queryFn: () => api<Page>('projects?per_page=100')
  });
  const action = useMutation({
    mutationFn: ({
      path,
      body,
      method = 'POST'
    }: {
      path: string;
      body?: unknown;
      method?: string;
    }) => api(path, method, body),
    onSuccess: () => {
      client.invalidateQueries({
        queryKey: [section]
      });
      setSelected(null);
    }
  });
  function filter(fn: () => void) {
    fn();
    setPage(1);
  }
  function download(value: unknown, name: string) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], {
      type: 'application/json'
    }));
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }
  const vulnerable = ['vulnerabilities', 'remediation'].includes(section);
  return <><div className="page-intro"><div><h2>{sections.find(s => s[0] === section)?.[1]}</h2><p>{q.data ? `${q.data.total} записей` : 'Загрузка данных…'}</p></div><div className="actions"><button onClick={() => q.refetch()} aria-label="Обновить"><RefreshCw size={16} /></button>{['reports', 'sbom', 'vulnerabilities'].includes(section) && <button onClick={() => download(q.data, `${section}.json`)}><Download size={16} />Экспорт страницы</button>}{admin && ['projects', 'images', 'repositories'].includes(section) && <button className="primary" onClick={() => setAdding(true)}><Plus size={16} />Добавить</button>}{admin && section === 'notifications' && <button className="primary" disabled={action.isPending} onClick={() => action.mutate({
          path: 'notifications/test'
        })}>Тест Telegram</button>}{admin && section === 'integrations' && <button onClick={() => setAdding(true)}>Мониторинг Harbor</button>}</div></div>
 {q.error && <ErrorNotice error={q.error} />} {action.error && <ErrorNotice error={action.error} />}
 <section className="panel table-panel"><div className="filters"><input aria-label="Поиск" placeholder="Поиск…" value={search} onChange={e => filter(() => setSearch(e.target.value))} />{vulnerable && <><select aria-label="Критичность" value={severity} onChange={e => filter(() => setSeverity(e.target.value))}><option value="">Все уровни</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map(v => <option key={v}>{v}</option>)}</select><select aria-label="Статус исправления" value={status} onChange={e => filter(() => setStatus(e.target.value))}><option value="">Все статусы</option>{['NEW', 'IN_PROGRESS', 'PENDING_VERIFICATION', 'FIXED', 'RISK_ACCEPTED', 'FALSE_POSITIVE'].map(v => <option key={v}>{v}</option>)}</select><label className="check"><input type="checkbox" checked={fix} onChange={e => filter(() => setFix(e.target.checked))} />Есть исправление</label><label className="check"><input type="checkbox" checked={kev} onChange={e => filter(() => setKev(e.target.checked))} />KEV</label><select aria-label="Образ" value={image} onChange={e=>filter(()=>setImage(e.target.value))}><option value="">Все образы</option>{imageOptions.data?.items.map(i=><option key={i.id} value={i.id}>{String(i.reference)}</option>)}</select><select aria-label="Окружение" value={environment} onChange={e=>filter(()=>setEnvironment(e.target.value))}><option value="">Все окружения</option>{['production','staging','test','unknown'].map(v=><option key={v}>{v}</option>)}</select><input type="number" aria-label="Минимальный EPSS" min="0" max="1" step="0.01" placeholder="EPSS от 0 до 1" value={epss} onChange={e=>filter(()=>setEpss(e.target.value))}/></>}{['images', 'repositories', 'vulnerabilities', 'remediation'].includes(section) && <select aria-label="Проект" value={project} onChange={e => filter(() => setProject(e.target.value))}><option value="">Все проекты</option>{projects.data?.items.map(p => <option key={p.id} value={p.id}>{String(p.name)}</option>)}</select>}</div>
 {q.isPending ? <div className="empty">Загрузка…</div> : <DataTable rows={q.data?.items ?? []} columns={columns[section]} sort={sort} onSort={s => {
        setSort(s);
        setOrder(order === 'asc' ? 'desc' : 'asc');
      }} onSelect={setSelected} />}
 <div className="pagination"><span>Страница {page} · Всего {q.data?.total ?? 0}</span><div><button disabled={page === 1} onClick={() => setPage(p => p - 1)}>Назад</button><button disabled={page * 25 >= (q.data?.total ?? 0)} onClick={() => setPage(p => p + 1)}>Далее</button></div></div></section>
 {section === 'notifications' && admin && <NotificationRules />}
 {section === 'sbom' && <SbomCompare items={q.data?.items ?? []} />}
 {selected && <><Detail row={selected} onClose={() => setSelected(null)}>{section === 'sbom' && <PackageExplorer id={selected.id} />}</Detail><div className="detail-actions">{section === 'images' && admin && <button className="primary" disabled={action.isPending} onClick={() => action.mutate({
          path: `images/${selected.id}/scan`
        })}>Запустить проверку</button>}{section === 'sbom' && <button className="primary" onClick={() => api(`sbom/${selected.id}`).then(v => download(v, `sbom-${selected.id}.json`)).catch(() => alert('Не удалось скачать SBOM'))}>Скачать документ</button>}{section === 'remediation' && admin && <select aria-label="Изменить статус" defaultValue="" onChange={e => {
          if (e.target.value) action.mutate({
            path: `remediation/${selected.id}`,
            method: 'PATCH',
            body: {
              status: e.target.value,
              note: 'Изменено через Dashboard'
            }
          });
        }}><option value="">Изменить статус…</option>{['NEW', 'IN_PROGRESS', 'PENDING_VERIFICATION', 'FIXED', 'RISK_ACCEPTED', 'FALSE_POSITIVE'].map(s => <option key={s}>{s}</option>)}</select>}{section === 'updates' && admin && <button className="primary" onClick={() => action.mutate({
          path: `updates/${selected.id}/approve`,
          body: {
            environment: 'production'
          }
        })}>Одобрить для production</button>}</div></>}
 {adding && <AddForm section={section} onClose={() => setAdding(false)} onSuccess={() => {
      setAdding(false);
      client.invalidateQueries({
        queryKey: [section]
      });
      client.invalidateQueries({
        queryKey: ['project-options']
      });
    }} />}</>;
}
export function AddForm({
  section,
  onClose,
  onSuccess
}: {
  section: string;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [project, setProject] = useState('');
  const [branch, setBranch] = useState('main');
  const [commits, setCommits] = useState(false);
  const [harborName, setHarborName] = useState('');
  const projects = useQuery({
    queryKey: ['project-options'],
    queryFn: () => api<Page>('projects?per_page=100')
  });
  const harbor = useQuery({
    queryKey: ['harbor-projects'],
    queryFn: () => api<{
      items: DataRow[];
    }>('integrations/harbor/projects'),
    enabled: section === 'integrations'
  });
  const m = useMutation({
    mutationFn: () => api(section === 'integrations' ? 'integrations/harbor/monitor' : section, 'POST', section === 'projects' ? {
      name,
      description
    } : section === 'integrations' ? {
      project_id: project,
      harbor_project: harborName
    } : {
      project_id: project,
      reference: name,
      branch,
      track_commits: commits
    }),
    onSuccess
  });
  return <div className="overlay"><form className="modal" onSubmit={e => {
      e.preventDefault();
      m.mutate();
    }}><h2>Добавить {section === 'projects' ? 'проект' : section === 'images' ? 'образ' : section === 'integrations' ? 'проект Harbor' : 'репозиторий'}</h2>{section !== 'projects' && <label>Проект<select required value={project} onChange={e => setProject(e.target.value)}><option value="">Выберите проект</option>{projects.data?.items.map(p => <option key={p.id} value={p.id}>{String(p.name)}</option>)}</select></label>}{section === 'integrations' ? <><label>Проект Harbor<select required value={harborName} onChange={e => setHarborName(e.target.value)}><option value="">Выберите проект Harbor</option>{harbor.data?.items.map(p => <option key={String(p.project_id)} value={String(p.name)}>{String(p.name)}</option>)}</select></label>{harbor.error && <ErrorNotice error={harbor.error} />}</> : <label>{section === 'projects' ? 'Название' : section === 'images' ? 'OCI image' : 'GitHub repository'}<input required maxLength={section === 'projects' ? 120 : 512} placeholder={section === 'images' ? 'nginx:stable-alpine' : section === 'repositories' ? 'https://github.com/goharbor/harbor' : ''} value={name} onChange={e => setName(e.target.value)} /></label>}{section === 'projects' && <label>Описание<textarea maxLength={4000} value={description} onChange={e => setDescription(e.target.value)} /></label>}{section === 'repositories' && <><label>Ветка<input required value={branch} onChange={e => setBranch(e.target.value)} /></label><label className="check"><input type="checkbox" checked={commits} onChange={e => setCommits(e.target.checked)} />Отслеживать коммиты</label></>}{m.error && <ErrorNotice error={m.error} />}<div className="actions"><button type="button" onClick={onClose}>Отмена</button><button className="primary" disabled={m.isPending}>{m.isPending ? 'Сохранение…' : 'Добавить'}</button></div></form></div>;
}
function SettingsPage() {
  const q = useQuery({
    queryKey: ['settings'],
    queryFn: () => api<Record<string, unknown>>('settings')
  });
  return <><section className="panel"><h2>Политика мониторинга</h2>{q.error && <ErrorNotice error={q.error} />}<p>Настройки подключений и секреты задаются администратором сервера через окружение. Изменения требуют перезапуска RizenVuln.</p><dl>{Object.entries(q.data ?? {}).map(([key, v]) => <div className="detail-row" key={key}><dt>{({
              app: 'Приложение',
              role: 'Ваша роль',
              scan_enabled: 'Сканирование включено',
              scan_interval_seconds: 'Интервал сканирования, секунд',
              max_concurrent_scans: 'Параллельных проверок',
              read_only_infrastructure: 'Наблюдение без изменения инфраструктуры'
            } as Record<string, string>)[key] ?? key}</dt><dd>{String(v)}</dd></div>)}</dl></section>{q.data?.role === 'admin' && <UserManagement />}</>;
}
