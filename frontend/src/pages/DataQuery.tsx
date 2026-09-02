import { useState } from 'react';
import { PageHeading, Panel, Badge } from '@/components/ui/primitives';
import { api, ApiError } from '@/lib/api';

interface SqlResult {
  columns: string[];
  rows: unknown[][];
  count: number;
  time_ms: number;
  truncated: boolean;
}

const SAMPLES = [
  'SELECT ip, hostname, device_type, scan_count FROM assets ORDER BY last_seen DESC LIMIT 25',
  "SELECT severity, count(*) FROM vulnerabilities GROUP BY severity",
  'SELECT ip, count(*) AS open_ports FROM scans WHERE state = \'open\' GROUP BY ip ORDER BY open_ports DESC',
  'SELECT status, count(*) FROM scan_jobs GROUP BY status',
];

export default function DataQuery() {
  const [query, setQuery] = useState(SAMPLES[0]);
  const [result, setResult] = useState<SqlResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<string[]>([]);

  const run = async () => {
    const q = query.trim();
    if (!q) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.post<SqlResult>('/api/v1/sql', { query: q });
      setResult(r);
      setHistory((h) => [q, ...h.filter((x) => x !== q)].slice(0, 10));
    } catch (e) {
      setResult(null);
      setError(e instanceof ApiError ? e.message : 'Query failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <PageHeading eyebrow="Direct evidence access" title="Data query" state="Read-only" />

      <Panel bodyClassName="p-0">
        <textarea
          className="w-full resize-y border-b border-line-soft bg-surface px-4 py-3 font-mono text-xs text-text outline-none"
          rows={5}
          spellCheck={false}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run();
          }}
        />
        <div className="flex flex-wrap items-center gap-2 p-3">
          <button className="btn-primary" disabled={busy} onClick={run}>
            {busy ? 'Running…' : 'Run  ⌘↵'}
          </button>
          <select
            className="input w-auto"
            value=""
            onChange={(e) => e.target.value && setQuery(e.target.value)}
          >
            <option value="">samples…</option>
            {SAMPLES.map((s) => (
              <option key={s} value={s}>
                {s.slice(0, 60)}…
              </option>
            ))}
          </select>
          {history.length > 0 && (
            <select
              className="input w-auto"
              value=""
              onChange={(e) => e.target.value && setQuery(e.target.value)}
            >
              <option value="">history…</option>
              {history.map((h, i) => (
                <option key={i} value={h}>
                  {h.slice(0, 60)}
                </option>
              ))}
            </select>
          )}
          {result && (
            <span className="ml-auto flex items-center gap-2 font-mono text-2xs text-muted">
              <Badge>{result.count} rows</Badge>
              <Badge>{result.time_ms} ms</Badge>
              {result.truncated && <Badge className="border-amber/40 text-amber">truncated</Badge>}
            </span>
          )}
        </div>
      </Panel>

      {error && (
        <div className="mt-3 rounded border border-danger/40 bg-danger-bg px-3 py-2 font-mono text-2xs text-danger">
          {error}
        </div>
      )}

      {result && (
        <Panel className="mt-4" bodyClassName="p-0">
          <div className="max-h-[60vh] overflow-auto">
            <table className="w-full border-collapse text-xs">
              <thead className="sticky top-0 bg-raised">
                <tr className="border-b border-line text-left">
                  {result.columns.map((c) => (
                    <th key={c} className="px-3 py-2 font-mono text-2xs uppercase tracking-wider text-muted">
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {result.rows.map((row, i) => (
                  <tr key={i} className="border-b border-line-soft">
                    {row.map((cell, j) => (
                      <td key={j} className="whitespace-nowrap px-3 py-1.5 font-mono text-2xs text-text-soft">
                        {cell === null ? <span className="text-faint">null</span> : String(cell)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}
