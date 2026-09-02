import { clsx } from 'clsx';
import { useNavigate } from 'react-router-dom';
import type { RiskHeatmap as RiskHeatmapData } from '@/types';

const SEV_BG: Record<string, string> = {
  critical: '237, 128, 117',
  high: '238, 184, 79',
  medium: '123, 147, 255',
  low: '82, 221, 207',
};

export function RiskHeatmap({ data }: { data: RiskHeatmapData }) {
  const nav = useNavigate();
  const max = Math.max(
    1,
    ...data.rows.flatMap((r) => data.severities.map((s) => (r as any)[s] as number)),
  );

  if (data.rows.length === 0) {
    return <div className="py-10 text-center text-2xs text-faint">No classified assets with findings</div>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-separate border-spacing-1 text-xs">
        <thead>
          <tr>
            <th className="text-left" />
            {data.severities.map((s) => (
              <th key={s} className="eyebrow px-1 text-center">
                {s}
              </th>
            ))}
            <th className="eyebrow px-1 text-center">total</th>
          </tr>
        </thead>
        <tbody>
          {data.rows.map((row) => (
            <tr key={row.device_type}>
              <td className="whitespace-nowrap pr-2 font-mono text-2xs text-text-soft">
                {row.device_type}
              </td>
              {data.severities.map((s) => {
                const n = (row as any)[s] as number;
                return (
                  <td key={s}>
                    <button
                      disabled={n === 0}
                      onClick={() =>
                        nav(`/assets?device_type=${encodeURIComponent(row.device_type)}&severity=${s}`)
                      }
                      className={clsx(
                        'flex h-9 w-full items-center justify-center rounded font-mono text-2xs',
                        n === 0 ? 'bg-hover text-faint' : 'text-black/85 hover:ring-1 hover:ring-text',
                      )}
                      style={
                        n === 0
                          ? undefined
                          : { background: `rgba(${SEV_BG[s]}, ${0.25 + 0.6 * (n / max)})` }
                      }
                    >
                      {n || ''}
                    </button>
                  </td>
                );
              })}
              <td className="text-center font-mono text-2xs text-text">{row.total}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
