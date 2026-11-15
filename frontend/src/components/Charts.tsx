import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
export function MetricChart({
  title,
  data,
  x,
  value
}: {
  title: string;
  data: Record<string, string | number>[];
  x: string;
  value: string;
}) {
  return <section className="panel"><h2>{title}</h2>{data.length ? <ResponsiveContainer width="100%" height={220}><BarChart data={data}><CartesianGrid strokeDasharray="3 3" stroke="#293246" /><XAxis dataKey={x} /><YAxis allowDecimals={false} /><Tooltip /><Bar name={title} dataKey={value} fill="#5ac7b0" radius={[5, 5, 0, 0]} /></BarChart></ResponsiveContainer> : <div className="empty">Данные пока отсутствуют</div>}</section>;
}
