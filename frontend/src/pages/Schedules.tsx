import { useState } from 'react';
import { PageHeading, Spinner, EmptyState, Panel, Badge } from '@/components/ui/primitives';
import { EntityCard } from '@/components/ui/EntityCard';
import { Modal, Field, FormActions } from '@/components/ui/Modal';
import { DataTable, type Column } from '@/components/ui/DataTable';
import { useSchedules, useScanHistory } from '@/hooks/useResources';
import { formatDate } from '@/lib/format';
import { toast } from '@/stores/toast';

interface SchedForm {
  id?: number;
  name: string;
  target: string;
  scan_type: string;
  schedule_type: string;
  schedule_hour: number;
}

const blank = (): SchedForm => ({
  name: '',
  target: '',
  scan_type: 'port',
  schedule_type: 'daily',
  schedule_hour: 2,
});

export default function Schedules() {
  const s = useSchedules();
  const history = useScanHistory();
  const [form, setForm] = useState<SchedForm | null>(null);

  const submit = () => {
    if (!form) return;
    const body = {
      name: form.name.trim() || 'Unnamed Schedule',
      target: form.target.trim(),
      scan_type: form.scan_type,
      schedule_type: form.schedule_type,
      schedule_hour: Number(form.schedule_hour) || 2,
    };
    if (!body.target) {
      toast.error('Target is required');
      return;
    }
    const done = () => {
      toast.success('Schedule saved');
      setForm(null);
    };
    const err = (e: unknown) => toast.error(e instanceof Error ? e.message : 'Failed');
    if (form.id) s.update.mutate({ id: form.id, body }, { onSuccess: done, onError: err });
    else s.create.mutate(body, { onSuccess: done, onError: err });
  };

  const cols: Column<any>[] = [
    { key: 'target', header: 'Target', render: (h) => <span className="data text-text">{h.target}</span> },
    { key: 'scan_type', header: 'Type', render: (h) => <Badge>{h.scan_type}</Badge> },
    { key: 'status', header: 'Status', render: (h) => <Badge>{h.status}</Badge> },
    {
      key: 'found',
      header: 'Found',
      render: (h) => (
        <span className="font-mono text-2xs text-muted">
          {h.hosts_scanned}h · {h.ports_found}p · {h.vulns_found}v
        </span>
      ),
    },
    { key: 'started', header: 'Started', render: (h) => <span className="text-2xs text-muted">{formatDate(h.started_at)}</span> },
  ];

  return (
    <div>
      <PageHeading
        eyebrow="Automated traces"
        title="Schedules"
        actions={
          <button className="btn-primary" onClick={() => setForm(blank())}>
            New schedule
          </button>
        }
      />

      {s.list.isLoading && (
        <div className="flex justify-center py-12">
          <Spinner />
        </div>
      )}
      {s.list.data?.length === 0 && <EmptyState>No schedules configured.</EmptyState>}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {(s.list.data ?? []).map((sc) => (
          <EntityCard
            key={sc.id}
            title={sc.name}
            meta={`${sc.target} · ${sc.scan_type} · ${sc.schedule_type} @ ${sc.schedule_hour ?? 2}:00`}
            status={sc.last_status || (sc.enabled ? 'active' : 'offline')}
            lines={[sc.last_run && `Last: ${formatDate(sc.last_run)}`, sc.next_run && `Next: ${formatDate(sc.next_run)}`]}
            actions={
              <>
                <button
                  className="btn px-2 py-1"
                  onClick={() => s.run.mutate(sc.id, { onSuccess: () => toast.success('Triggered') })}
                >
                  Run now
                </button>
                <button className="btn px-2 py-1" onClick={() => s.toggle.mutate(sc.id)}>
                  {sc.enabled ? 'Disable' : 'Enable'}
                </button>
                <button
                  className="btn px-2 py-1"
                  onClick={() =>
                    setForm({
                      id: sc.id,
                      name: sc.name,
                      target: sc.target,
                      scan_type: sc.scan_type || 'port',
                      schedule_type: sc.schedule_type || 'daily',
                      schedule_hour: sc.schedule_hour ?? 2,
                    })
                  }
                >
                  Edit
                </button>
                <button
                  className="btn-danger px-2 py-1"
                  onClick={() => {
                    if (confirm(`Delete schedule "${sc.name}"?`))
                      s.remove.mutate(sc.id, { onSuccess: () => toast.success('Deleted') });
                  }}
                >
                  Delete
                </button>
              </>
            }
          />
        ))}
      </div>

      <div className="mt-6">
        <Panel title="Execution history" bodyClassName="p-0">
          <DataTable
            columns={cols}
            rows={history.data ?? []}
            rowKey={(h) => String(h.id)}
            loading={history.isLoading}
            empty="No scan history yet."
          />
        </Panel>
      </div>

      <Modal open={!!form} onClose={() => setForm(null)} title={form?.id ? 'Edit schedule' : 'New schedule'}>
        {form && (
          <>
            <Field label="Name">
              <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </Field>
            <Field label="Target" hint="IP, CIDR, or hostname">
              <input
                className="input"
                value={form.target}
                onChange={(e) => setForm({ ...form, target: e.target.value })}
              />
            </Field>
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Scan type">
                <select
                  className="input"
                  value={form.scan_type}
                  onChange={(e) => setForm({ ...form, scan_type: e.target.value })}
                >
                  {['port', 'vuln', 'full'].map((t) => (
                    <option key={t}>{t}</option>
                  ))}
                </select>
              </Field>
              <Field label="Schedule">
                <select
                  className="input"
                  value={form.schedule_type}
                  onChange={(e) => setForm({ ...form, schedule_type: e.target.value })}
                >
                  {['daily', 'weekly', 'monthly'].map((t) => (
                    <option key={t}>{t}</option>
                  ))}
                </select>
              </Field>
              <Field label="Hour (UTC)">
                <input
                  className="input"
                  type="number"
                  min={0}
                  max={23}
                  value={form.schedule_hour}
                  onChange={(e) => setForm({ ...form, schedule_hour: Number(e.target.value) })}
                />
              </Field>
            </div>
            <FormActions>
              <button className="btn" onClick={() => setForm(null)}>
                Cancel
              </button>
              <button className="btn-primary" onClick={submit}>
                Save
              </button>
            </FormActions>
          </>
        )}
      </Modal>
    </div>
  );
}
