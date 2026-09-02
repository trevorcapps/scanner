import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { CvssDistribution } from '@/types';

function barColor(min: number): string {
  if (min >= 9) return 'rgb(var(--danger))';
  if (min >= 7) return 'rgb(var(--amber))';
  if (min >= 4) return 'rgb(var(--blue))';
  return 'rgb(var(--cyan))';
}

export function CvssHistogram({ data }: { data: CvssDistribution }) {
  const rows = data.buckets.map((b) => ({ ...b, label: b.range }));

  return (
    <div className="h-44">
      <ResponsiveContainer>
        <BarChart data={rows} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
          <XAxis
            dataKey="label"
            tick={{ fill: 'rgb(var(--muted))', fontSize: 10, fontFamily: 'monospace' }}
            axisLine={{ stroke: 'rgb(var(--line))' }}
            tickLine={false}
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: 'rgb(var(--muted))', fontSize: 10, fontFamily: 'monospace' }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            cursor={{ fill: 'rgb(var(--surface-hover))' }}
            contentStyle={{
              background: 'rgb(var(--surface-raised))',
              border: '1px solid rgb(var(--line))',
              borderRadius: 4,
              fontFamily: 'monospace',
              fontSize: 11,
            }}
          />
          <Bar dataKey="count" radius={[2, 2, 0, 0]}>
            {rows.map((r) => (
              <Cell key={r.range} fill={barColor(r.min)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      {data.unscored > 0 && (
        <div className="mt-1 text-center text-2xs text-faint">{data.unscored} unscored</div>
      )}
    </div>
  );
}
