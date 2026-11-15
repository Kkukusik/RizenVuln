import { useState, type ReactNode } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import type { DataRow } from '../types';
export function ErrorNotice({
  error
}: {
  error: unknown;
}) {
  return <div role="alert" className="error"><AlertTriangle size={18} />{error instanceof Error ? error.message : 'Не удалось загрузить данные'}</div>;
}
export function Badge({
  value
}: {
  value: unknown;
}) {
  const text = String(value ?? 'UNKNOWN');
  return <span className={`badge ${['CRITICAL', 'FAILED', 'ERROR', 'SCAN_FAILED'].includes(text) ? 'red' : ['HIGH', 'PENDING', 'NEW', 'UNKNOWN', 'UNAVAILABLE', 'LOCAL_ONLY'].includes(text) ? 'amber' : ['COMPLETED', 'CONNECTED', 'SCANNED', 'FIXED', 'STORED', 'SYNCED'].includes(text) ? 'green' : 'blue'}`}>{text}</span>;
}
export function display(value: unknown): string {
  if (value == null) return '—';
  if (typeof value === 'boolean') return value ? 'Да' : 'Нет';
  if (typeof value === 'object') return Array.isArray(value) ? `${value.length} записей` : 'Подробнее';
  if (typeof value === 'string' && /^\d{4}-\d\d-\d\dT/.test(value)) return new Date(value).toLocaleString('ru-RU');
  return String(value);
}
export function Detail({
  row,
  onClose,
  children
}: {
  row: DataRow;
  onClose: () => void;
  children?: ReactNode;
}) {
  return <div className="overlay"><section className="modal detail" role="dialog" aria-modal="true" aria-label="Подробности записи"><button className="close" onClick={onClose} aria-label="Закрыть"><X /></button><h2>Подробности</h2>{children}{Object.entries(row).map(([key, value]) => <div className="detail-row" key={key}><strong>{labels[key] ?? key}</strong>{typeof value === 'object' && value !== null ? <pre>{JSON.stringify(value, null, 2)}</pre> : <span>{display(value)}</span>}</div>)}</section></div>;
}
export const labels: Record<string, string> = {
  id: 'Идентификатор',
  name: 'Название',
  description: 'Описание',
  reference: 'Образ',
  registry: 'Реестр',
  digest: 'Digest',
  status: 'Статус',
  created_at: 'Создано',
  last_checked: 'Последняя проверка',
  full_name: 'Репозиторий',
  branch: 'Ветка',
  vulnerability_id: 'CVE',
  package: 'Пакет',
  installed_version: 'Установлено',
  fixed_version: 'Исправлено в',
  severity: 'Критичность',
  epss: 'EPSS',
  kev: 'CISA KEV',
  format: 'Формат',
  storage_status: 'Хранилище',
  source: 'Источник',
  server: 'Сервер',
  namespace: 'Namespace',
  container: 'Контейнер',
  environment: 'Окружение',
  image: 'Образ',
  running: 'Запущен',
  last_seen: 'Последнее обнаружение',
  candidate: 'Доступная версия',
  major_warning: 'Смена major',
  reason: 'Причина',
  event: 'Событие',
  message: 'Сообщение',
  attempts: 'Попытки',
  kind: 'Тип',
  enabled: 'Включено',
  error: 'Ошибка',
  last_error: 'Последняя ошибка',
  started_at: 'Начало',
  completed_at: 'Завершено',
  scanner_version: 'Версия сканера',
  scan_run_id: 'Сканирование',
  object_key: 'Объект S3',
  project_id: 'Проект',
  target: 'Цель',
  data: 'Данные GitHub',
  metadata: 'Метаданные'
};
export function DataTable({
  rows,
  columns,
  onSelect,
  sort,
  onSort
}: {
  rows: DataRow[];
  columns: string[];
  onSelect: (row: DataRow) => void;
  sort: string;
  onSort: (s: string) => void;
}) {
  return <div className="table-wrap"><table><thead><tr>{columns.map(c => <th key={c}><button onClick={() => onSort(c)}>{labels[c] ?? c} {sort === c ? '↓' : ''}</button></th>)}</tr></thead><tbody>{rows.map(row => <tr key={row.id} onClick={() => onSelect(row)} tabIndex={0} onKeyDown={e => {
          if (e.key === 'Enter') onSelect(row);
        }}>{columns.map(c => <td key={c}>{['status', 'severity', 'storage_status'].includes(c) ? <Badge value={row[c]} /> : <span title={display(row[c])}>{display(row[c])}</span>}</td>)}</tr>)}</tbody></table>{!rows.length && <div className="empty">Записей пока нет. Добавьте источник мониторинга или измените фильтры.</div>}</div>;
}
export function Theme() {
  const [light, setLight] = useState(localStorage.getItem('theme') === 'light');
  document.documentElement.dataset.theme = light ? 'light' : 'dark';
  return <button aria-label="Переключить тему" onClick={() => {
    setLight(!light);
    localStorage.setItem('theme', !light ? 'light' : 'dark');
  }}>{light ? 'Тёмная тема' : 'Светлая тема'}</button>;
}
