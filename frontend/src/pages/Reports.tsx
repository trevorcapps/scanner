import { useState } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { clsx } from 'clsx';
import { PageHeading, Panel, Badge, Spinner } from '@/components/ui/primitives';
import { Modal, Field, FormActions } from '@/components/ui/Modal';
import { useAuth } from '@/hooks/useAuth';
import { useSites } from '@/hooks/useResources';
import {
  useReports,
  useReportSchedules,
  useRiskTrends,
  type ReportFormat,
  type ReportKind,
  type ReportSchedule,
  type ReportScope,
} from '@/hooks/useReports';
import { api } from '@/lib/api';
import { formatDate } from '@/lib/format';
import { toast } from '@/stores/toast';

const KINDS: { v: ReportKind; label: string; hint: string }[] = [
  { v: 'executive', label: 'Executive', hint: 'Summary, KPIs, top findings — for leadership' },
  { v: 'technical', label: 'Technical', hint: 'Adds CVSS distribution + per-host detail' },
  { v: 'full', label: 'Full', hint: 'Everything, every host, every CVE' },
];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export default function Reports() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  return (
    <div className="space-y-4">
      <PageHeading eyebrow="Deliverables" title="Reports" state="Executive & technical" />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <GeneratePanel />
        <TrajectoryPanel isAdmin={isAdmin} />
      </div>
      <HistoryPanel isAdmin={isAdmin} />
      <SchedulesPanel isAdmin={isAdmin} />
    </div>
  );
}

/* ------------------------------------------------------------------ generate */

function ScopePicker({
  scope,
  setScope,
}: {
  scope: ReportScope;
  setScope: (s: ReportScope) => void;
}) {
  const { list: sites } = useSites();
  return (
    <div className="space-y-2">
      <div className="flex gap-1.5">
        {(['environment', 'site', 'filter'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setScope({ type: t })}
            className={clsx(
              'rounded border px-2 py-1 font-mono text-2xs uppercase tracking-wider',
              scope.type === t ? 'border-blue bg-blue/10 text-blue' : 'border-line text-text-soft',
            )}
          >
            {t}
          </button>
        ))}
      </div>

      {scope.type === 'site' && (
        <select
          className="input"
          value={scope.id ?? ''}
          onChange={(e) => setScope({ type: 'site', id: Number(e.target.value) || undefined })}
        >
          <option value="">Select a site…</option>
          {(sites.data ?? []).map((s: { id: number; name: string }) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>
      )}

      {scope.type === 'filter' && (
        <div className="grid gap-2 sm:grid-cols-3">
          <select
            className="input"
            value={scope.min_severity ?? ''}
            onChange={(e) => setScope({ ...scope, min_severity: e.target.value || undefined })}
          >
            <option value="">Any severity</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                ≥ {s}
              </option>
            ))}
          </select>
          <input
            className="input"
            placeholder="device type"
            value={scope.device_type ?? ''}
            onChange={(e) => setScope({ ...scope, device_type: e.target.value || undefined })}
          />
          <input
            className="input"
            placeholder="subnet e.g. 10.0.0.0/24"
            value={scope.subnet ?? ''}
            onChange={(e) => setScope({ ...scope, subnet: e.target.value || undefined })}
          />
        </div>
      )}
    </div>
  );
}

function GeneratePanel() {
  const { generate } = useReports();
  const [kind, setKind] = useState<ReportKind>('executive');
  const [fmt, setFmt] = useState<ReportFormat>('pdf');
  const [scope, setScope] = useState<ReportScope>({ type: 'environment' });

  const run = () => {
    generate.mutate(
      { kind, format: fmt, scope },
      {
        onSuccess: (r) => {
          toast.success('Report generated');
          downloadReport(r.report.id, r.report.title, r.report.format);
        },
        onError: (e) =>
          toast.error(e instanceof Error ? e.message : 'Generation failed'),
      },
    );
  };

  return (
    <Panel title="Generate a report">
      <div className="space-y-3">
        <div>
          <span className="eyebrow mb-1 block">Report type</span>
          <div className="grid grid-cols-3 gap-1.5">
            {KINDS.map((k) => (
              <button
                key={k.v}
                onClick={() => setKind(k.v)}
                className={clsx(
                  'rounded border px-2 py-2 font-mono text-2xs uppercase tracking-wider',
                  kind === k.v ? 'border-blue bg-blue/10 text-blue' : 'border-line text-text-soft',
                )}
              >
                {k.label}
              </button>
            ))}
          </div>
          <p className="mt-1 text-2xs text-faint">{KINDS.find((k) => k.v === kind)?.hint}</p>
        </div>

        <div>
          <span className="eyebrow mb-1 block">Scope</span>
          <ScopePicker scope={scope} setScope={setScope} />
        </div>

        <div>
          <span className="eyebrow mb-1 block">Format</span>
          <div className="flex gap-1.5">
            {(['pdf', 'html'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFmt(f)}
                className={clsx(
                  'rounded border px-3 py-1 font-mono text-2xs uppercase tracking-wider',
                  fmt === f ? 'border-blue bg-blue/10 text-blue' : 'border-line text-text-soft',
                )}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        <button className="btn-primary" onClick={run} disabled={generate.isPending}>
          {generate.isPending ? 'Generating…' : 'Generate & download'}
        </button>
      </div>
    </Panel>
  );
}

/* ---------------------------------------------------------------- trajectory */

function TrajectoryPanel({ isAdmin }: { isAdmin: boolean }) {
  const { data, isLoading } = useRiskTrends(90);
  const [capturing, setCapturing] = useState(false);
  const series = (data?.series ?? []).map((p) => ({ ...p, day: p.date.slice(5) }));

  const capture = async () => {
    setCapturing(true);
    try {
      await api.post('/api/v1/reports/snapshot');
      toast.success('Snapshot captured');
      window.location.reload();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed');
    } finally {
      setCapturing(false);
    }
  };

  return (
    <Panel
      title="Risk trajectory"
      meta={series.length ? `${series.length} day${series.length === 1 ? '' : 's'}` : ''}
      actions={
        isAdmin && (
          <button className="btn px-2 py-1" onClick={capture} disabled={capturing}>
            {capturing ? '…' : 'Snapshot now'}
          </button>
        )
      }
    >
      {isLoading ? (
        <div className="flex h-48 items-center justify-center">
          <Spinner />
        </div>
      ) : series.length < 2 ? (
        <p className="py-10 text-center text-2xs text-faint">
          The trajectory needs at least two daily snapshots. One is captured automatically each day;
          {isAdmin ? ' or use “Snapshot now”.' : ' check back tomorrow.'}
        </p>
      ) : (
        <div className="h-52">
          <ResponsiveContainer>
            <AreaChart data={series} margin={{ top: 4, right: 8, bottom: 0, left: -22 }}>
              <defs>
                <linearGradient id="gCrit" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="rgb(var(--danger))" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="rgb(var(--danger))" stopOpacity={0} />
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
                dataKey="critical"
                name="critical"
                stroke="rgb(var(--danger))"
                fill="url(#gCrit)"
                strokeWidth={1.5}
              />
              <Line type="monotone" dataKey="high" name="high" stroke="rgb(var(--amber))" strokeWidth={1.5} dot={false} />
              <Line
                type="monotone"
                dataKey="exploitable"
                name="exploitable"
                stroke="#000"
                strokeWidth={1.2}
                strokeDasharray="3 3"
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </Panel>
  );
}

/* ------------------------------------------------------------------- history */

async function downloadReport(id: number, title: string, fmt: string) {
  try {
    const res = await fetch(`/api/v1/reports/${id}/download`, { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${title.replace(/[^A-Za-z0-9._-]+/g, '-')}.${fmt}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch {
    toast.error('Download failed');
  }
}

function HistoryPanel({ isAdmin }: { isAdmin: boolean }) {
  const { list, remove } = useReports();
  const reports = list.data?.reports ?? [];

  return (
    <Panel title="Report history" meta={`${reports.length}`}>
      {list.isLoading ? (
        <div className="flex h-24 items-center justify-center">
          <Spinner />
        </div>
      ) : reports.length === 0 ? (
        <p className="py-6 text-center text-2xs text-faint">No reports generated yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-line-soft text-left text-2xs uppercase tracking-wide text-muted">
                <th className="py-1.5 pr-3">Title</th>
                <th className="pr-3">Type</th>
                <th className="pr-3">Format</th>
                <th className="pr-3">Findings</th>
                <th className="pr-3">Size</th>
                <th className="pr-3">Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id} className="border-b border-line-soft last:border-0">
                  <td className="py-1.5 pr-3">{r.title}</td>
                  <td className="pr-3 capitalize">{r.kind}</td>
                  <td className="pr-3 uppercase">{r.format}</td>
                  <td className="pr-3">
                    {r.status === 'failed' ? (
                      <span className="text-danger" title={r.error ?? ''}>
                        failed
                      </span>
                    ) : (
                      <span className="text-muted">
                        {r.summary.by_severity?.critical ?? 0}C / {r.summary.by_severity?.high ?? 0}H ·{' '}
                        {r.summary.unique_cves ?? 0} CVE
                      </span>
                    )}
                  </td>
                  <td className="pr-3 text-muted">{r.size_bytes ? `${Math.round(r.size_bytes / 1024)} KB` : '—'}</td>
                  <td className="pr-3 text-muted">{formatDate(r.created_at)}</td>
                  <td className="flex gap-1.5 py-1.5">
                    {r.status === 'ready' && (
                      <button
                        className="btn px-2 py-0.5 text-2xs"
                        onClick={() => downloadReport(r.id, r.title, r.format)}
                      >
                        Download
                      </button>
                    )}
                    {isAdmin && (
                      <button
                        className="btn-danger px-2 py-0.5 text-2xs"
                        onClick={() =>
                          remove.mutate(r.id, { onSuccess: () => toast.info('Deleted') })
                        }
                      >
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

/* ----------------------------------------------------------------- schedules */

const BLANK_SCHED = {
  id: 0,
  name: '',
  kind: 'executive' as ReportKind,
  format: 'pdf' as ReportFormat,
  scope: { type: 'environment' } as ReportScope,
  cron_expression: '0 8 * * 1',
  recipients: [] as string[],
  enabled: true,
};

function SchedulesPanel({ isAdmin }: { isAdmin: boolean }) {
  const { list, create, update, remove, run } = useReportSchedules();
  const [editing, setEditing] = useState<typeof BLANK_SCHED | null>(null);
  const schedules = list.data?.schedules ?? [];

  const save = (s: typeof BLANK_SCHED) => {
    const body = {
      name: s.name,
      kind: s.kind,
      format: s.format,
      scope: s.scope,
      cron_expression: s.cron_expression,
      recipients: s.recipients,
      enabled: s.enabled,
    };
    const opts = {
      onSuccess: () => {
        toast.success('Saved');
        setEditing(null);
      },
      onError: (e: unknown) => toast.error(e instanceof Error ? e.message : 'Save failed'),
    };
    if (s.id) update.mutate({ id: s.id, body }, opts);
    else create.mutate(body, opts);
  };

  return (
    <Panel
      title="Scheduled delivery"
      meta={`${schedules.length}`}
      actions={
        isAdmin && (
          <button className="btn-primary px-2 py-1" onClick={() => setEditing({ ...BLANK_SCHED })}>
            New schedule
          </button>
        )
      }
    >
      {schedules.length === 0 ? (
        <p className="py-6 text-center text-2xs text-faint">
          No scheduled reports. Configure SMTP under Control, then add a schedule to email reports on a cron.
        </p>
      ) : (
        <div className="space-y-1.5">
          {schedules.map((s) => (
            <ScheduleRow
              key={s.id}
              s={s}
              isAdmin={isAdmin}
              onEdit={() =>
                setEditing({
                  id: s.id,
                  name: s.name,
                  kind: s.kind,
                  format: s.format,
                  scope: s.scope,
                  cron_expression: s.cron_expression,
                  recipients: s.recipients,
                  enabled: s.enabled,
                })
              }
              onRun={() =>
                run.mutate(s.id, {
                  onSuccess: () => toast.info('Ran — check status'),
                })
              }
              onToggle={() =>
                update.mutate({
                  id: s.id,
                  body: {
                    name: s.name,
                    kind: s.kind,
                    format: s.format,
                    scope: s.scope,
                    cron_expression: s.cron_expression,
                    recipients: s.recipients,
                    enabled: !s.enabled,
                  },
                })
              }
              onDelete={() => remove.mutate(s.id, { onSuccess: () => toast.info('Deleted') })}
            />
          ))}
        </div>
      )}

      {editing && (
        <ScheduleModal
          value={editing}
          onChange={setEditing}
          onClose={() => setEditing(null)}
          onSave={() => save(editing)}
        />
      )}
    </Panel>
  );
}

function ScheduleRow({
  s,
  isAdmin,
  onEdit,
  onRun,
  onToggle,
  onDelete,
}: {
  s: ReportSchedule;
  isAdmin: boolean;
  onEdit: () => void;
  onRun: () => void;
  onToggle: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded border border-line-soft px-3 py-2 text-xs">
      <span className={clsx('h-2 w-2 shrink-0 rounded-full', s.enabled ? 'bg-lime' : 'bg-faint')} />
      <span className="font-medium">{s.name}</span>
      <Badge>{s.kind}</Badge>
      <Badge>{s.format.toUpperCase()}</Badge>
      <span className="data text-muted">{s.cron_expression}</span>
      <span className="text-2xs text-muted">
        → {s.recipients.length ? s.recipients.join(', ') : 'no recipients'}
      </span>
      {s.last_status && (
        <span
          className={clsx(
            'text-2xs',
            s.last_status === 'sent' ? 'text-lime' : s.last_status.includes('fail') ? 'text-danger' : 'text-muted',
          )}
          title={s.last_error ?? ''}
        >
          {s.last_status}
        </span>
      )}
      <span className="ml-auto flex gap-1.5">
        {isAdmin && (
          <>
            <button className="btn px-2 py-0.5 text-2xs" onClick={onRun}>
              Run now
            </button>
            <button className="btn px-2 py-0.5 text-2xs" onClick={onToggle}>
              {s.enabled ? 'Disable' : 'Enable'}
            </button>
            <button className="btn px-2 py-0.5 text-2xs" onClick={onEdit}>
              Edit
            </button>
            <button className="btn-danger px-2 py-0.5 text-2xs" onClick={onDelete}>
              Delete
            </button>
          </>
        )}
      </span>
    </div>
  );
}

function ScheduleModal({
  value,
  onChange,
  onClose,
  onSave,
}: {
  value: typeof BLANK_SCHED;
  onChange: (v: typeof BLANK_SCHED) => void;
  onClose: () => void;
  onSave: () => void;
}) {
  const set = <K extends keyof typeof BLANK_SCHED>(k: K, v: (typeof BLANK_SCHED)[K]) =>
    onChange({ ...value, [k]: v });

  return (
    <Modal open onClose={onClose} title={value.id ? 'Edit schedule' : 'New scheduled report'} wide>
      <Field label="Name">
        <input className="input" value={value.name} onChange={(e) => set('name', e.target.value)} />
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Report type">
          <select className="input" value={value.kind} onChange={(e) => set('kind', e.target.value as ReportKind)}>
            {KINDS.map((k) => (
              <option key={k.v} value={k.v}>
                {k.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Format">
          <select
            className="input"
            value={value.format}
            onChange={(e) => set('format', e.target.value as ReportFormat)}
          >
            <option value="pdf">PDF</option>
            <option value="html">HTML</option>
          </select>
        </Field>
      </div>
      <Field label="Scope">
        <ScopePicker scope={value.scope} setScope={(s) => set('scope', s)} />
      </Field>
      <Field label="Cron expression" hint="5-field: min hour dom mon dow — e.g. “0 8 * * 1” = Mondays 08:00 UTC">
        <input
          className="input"
          value={value.cron_expression}
          onChange={(e) => set('cron_expression', e.target.value)}
        />
      </Field>
      <Field label="Recipients" hint="comma-separated email addresses">
        <input
          className="input"
          value={value.recipients.join(', ')}
          onChange={(e) =>
            set(
              'recipients',
              e.target.value
                .split(',')
                .map((x) => x.trim())
                .filter(Boolean),
            )
          }
        />
      </Field>
      <label className="flex items-center gap-2 text-xs text-text-soft">
        <input type="checkbox" checked={value.enabled} onChange={(e) => set('enabled', e.target.checked)} />
        Enabled
      </label>
      <FormActions>
        <button className="btn" onClick={onClose}>
          Cancel
        </button>
        <button className="btn-primary" onClick={onSave} disabled={!value.name.trim()}>
          Save
        </button>
      </FormActions>
    </Modal>
  );
}
