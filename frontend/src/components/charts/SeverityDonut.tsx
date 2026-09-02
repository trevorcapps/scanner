import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import { SEVERITY_COLOR } from '@/lib/format';

export function SeverityDonut({ data }: { data: Record<string, number> }) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const rows = order
    .map((s) => ({ name: s, value: data[s] ?? 0 }))
    .filter((r) => r.value > 0);
  const total = rows.reduce((a, r) => a + r.value, 0);

  if (total === 0) {
    return <div className="flex h-full items-center justify-center text-2xs text-faint">No findings</div>;
  }

  return (
    <div className="flex h-full items-center gap-4">
      <div className="relative h-40 w-40 shrink-0">
        <ResponsiveContainer>
          <PieChart>
            <Pie
              data={rows}
              dataKey="value"
              innerRadius={48}
              outerRadius={70}
              paddingAngle={2}
              stroke="rgb(var(--surface))"
            >
              {rows.map((r) => (
                <Cell key={r.name} fill={SEVERITY_COLOR[r.name]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: 'rgb(var(--surface-raised))',
                border: '1px solid rgb(var(--line))',
                borderRadius: 4,
                fontFamily: 'monospace',
                fontSize: 11,
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="data text-2xl font-semibold text-text">{total}</span>
          <span className="eyebrow">findings</span>
        </div>
      </div>
      <ul className="flex-1 space-y-1.5">
        {rows.map((r) => (
          <li key={r.name} className="flex items-center gap-2 text-xs">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEVERITY_COLOR[r.name] }} />
            <span className="capitalize text-text-soft">{r.name}</span>
            <span className="data ml-auto text-text">{r.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
