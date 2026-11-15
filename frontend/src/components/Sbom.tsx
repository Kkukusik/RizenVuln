import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import type { Page, DataRow } from '../types';
import { ErrorNotice } from './Common';
interface Package {
  name: string;
  version: string;
  license: string;
  purl: string;
}
export function PackageExplorer({
  id
}: {
  id: string;
}) {
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const q = useQuery({
    queryKey: ['packages', id, search, page],
    queryFn: () => api<Page<Package>>(`sbom/${id}/packages?q=${encodeURIComponent(search)}&page=${page}`)
  });
  return <section><h2>Состав образа</h2><input aria-label="Поиск пакета" placeholder="Название пакета или лицензия" value={search} onChange={e => {
      setSearch(e.target.value);
      setPage(1);
    }} />{q.error && <ErrorNotice error={q.error} />}<div className="table-wrap"><table><thead><tr><th>Пакет</th><th>Версия</th><th>Лицензия</th></tr></thead><tbody>{q.data?.items.map((p, i) => <tr key={p.purl || `${p.name}-${i}`}><td>{p.name}</td><td>{p.version}</td><td>{p.license}</td></tr>)}</tbody></table></div><div className="pagination"><span>{q.data?.total ?? 0} пакетов</span><div><button disabled={page === 1} onClick={() => setPage(p => p - 1)}>Назад</button><button disabled={page * 25 >= (q.data?.total ?? 0)} onClick={() => setPage(p => p + 1)}>Далее</button></div></div><p>Состав SBOM может быть неполным и сам по себе не подтверждает отсутствие CVE.</p></section>;
}
export function SbomCompare({
  items
}: {
  items: DataRow[];
}) {
  const [left, setLeft] = useState('');
  const [right, setRight] = useState('');
  const q = useQuery({
    queryKey: ['sbom-compare', left, right],
    queryFn: () => api<{
      added: string[][];
      removed: string[][];
      warning: string;
    }>(`sbom/compare?left=${left}&right=${right}`),
    enabled: !!left && !!right
  });
  const options = items.filter(i => ['cyclonedx-json', 'spdx-json'].includes(String(i.format)));
  return <section className="panel compare"><h2>Сравнение состава</h2><div className="filters"><select aria-label="Первый SBOM" value={left} onChange={e => setLeft(e.target.value)}><option value="">Первый результат</option>{options.map(i => <option key={i.id} value={i.id}>{String(i.format)} · {String(i.created_at)}</option>)}</select><select aria-label="Второй SBOM" value={right} onChange={e => setRight(e.target.value)}><option value="">Второй результат</option>{options.map(i => <option key={i.id} value={i.id}>{String(i.format)} · {String(i.created_at)}</option>)}</select></div>{q.error && <ErrorNotice error={q.error} />} {q.data && <><p>Добавлено: {q.data.added.length} · Удалено: {q.data.removed.length}</p><pre>{JSON.stringify({
          добавлено: q.data.added,
          удалено: q.data.removed
        }, null, 2)}</pre><p>{q.data.warning}</p></>}</section>;
}
