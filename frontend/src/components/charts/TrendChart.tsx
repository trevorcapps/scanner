import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { Trends } from '@/types';

export function TrendChart({ data }: { data: Trends }) {
  const rows = data.series.map((s) => ({
    ...s,
    day: s.date.slice(5), // MM-DD
  }));

  return (
    <div className="h-52">
      <ResponsiveContainer>
        <AreaChart data={rows} margin={{ top: 4, right: 8, bottom: 0, left: -22 }}>
          <defs>
            <linearGradient id="gVulns" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="rgb(var(--danger))" stopOpacity={0.35} />
              <stop offset="100%" stopColor="rgb(var(--danger))" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gNew" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="rgb(var(--amber))" stopOpacity={0.3} />
              <stop offset="100%" stopColor="rgb(var(--amber))" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgb(var(--line-soft))" vertical={false} />
          <XAxis
            dataKey="day"
            interval="preserveStartEnd"
            minTickGap={24}
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
            contentStyle={{
              background: 'rgb(var(--surface-raised))',
              border: '1px solid rgb(var(--line))',
              borderRadius: 4,
              fontFamily: 'monospace',
              fontSize: 11,
            }}
          />
          <Area
            type="monotone"
            dataKey="vulns_found"
            name="vulns found"
            stroke="rgb(var(--danger))"
            fill="url(#gVulns)"
            strokeWidth={1.5}
          />
          <Area
            type="monotone"
            dataKey="new_vulns"
            name="new vulns"
            stroke="rgb(var(--amber))"
            fill="url(#gNew)"
            strokeWidth={1.5}
          />
          <Area
            type="monotone"
            dataKey="scans"
            name="scans"
            stroke="rgb(var(--blue))"
            fill="transparent"
            strokeWidth={1.5}
            strokeDasharray="3 3"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
