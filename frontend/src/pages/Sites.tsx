import { useState } from 'react';
import { PageHeading, Spinner, EmptyState } from '@/components/ui/primitives';
import { EntityCard } from '@/components/ui/EntityCard';
import { Modal, Field, FormActions } from '@/components/ui/Modal';
import { useSites } from '@/hooks/useResources';
import { formatDate } from '@/lib/format';
import { toast } from '@/stores/toast';

interface SiteForm {
  id?: number;
  name: string;
  description: string;
  targets: string;
  excluded_targets: string;
  scan_type: string;
  schedule_type: string;
  schedule_hour: number;
  scan_options: {
    ports: string;
    scan_speed: string;
    host_timeout: number;
    max_hosts: number;
    severity: string;
    rate_limit: number;
  };
}

const blank = (): SiteForm => ({
  name: '',
  description: '',
  targets: '',
  excluded_targets: '',
  scan_type: 'full',
  schedule_type: 'daily',
  schedule_hour: 2,
  scan_options: {
    ports: '',
    scan_speed: 'T3',
    host_timeout: 300,
    max_hosts: 256,
    severity: 'critical,high,medium,low',
    rate_limit: 150,
  },
});

export default function Sites() {
  const sites = useSites();
  const [form, setForm] = useState<SiteForm | null>(null);

  const openEdit = (s: any) => {
    let opts: any = {};
    try {
      opts = JSON.parse(s.scan_options_json || '{}') || {};
    } catch {
      /* */
    }
    setForm({
      id: s.id,
      name: s.name,
      description: s.description || '',
      targets: (s.targets || []).join('\n'),
      excluded_targets: (s.excluded_targets || []).join('\n'),
      scan_type: s.scan_type || 'full',
      schedule_type: s.schedule_type || 'daily',
      schedule_hour: s.schedule_hour ?? 2,
      scan_options: { ...blank().scan_options, ...opts },
    });
  };

  const submit = () => {
    if (!form) return;
    const body = {
      name: form.name.trim(),
      description: form.description.trim(),
      targets: form.targets.split('\n').map((t) => t.trim()).filter(Boolean),
      excluded_targets: form.excluded_targets.split('\n').map((t) => t.trim()).filter(Boolean),
      scan_type: form.scan_type,
      schedule_type: form.schedule_type,
      schedule_hour: Number(form.schedule_hour) || 2,
      scan_options: form.scan_options,
    };
    if (!body.name || body.targets.length === 0) {
      toast.error('Name and at least one target are required');
      return;
    }
    const done = () => {
      toast.success('Site saved');
      setForm(null);
    };
    const err = (e: unknown) => toast.error(e instanceof Error ? e.message : 'Failed');
    if (form.id) sites.update.mutate({ id: form.id, body }, { onSuccess: done, onError: err });
    else sites.create.mutate(body, { onSuccess: done, onError: err });
  };

  return (
    <div>
      <PageHeading
        eyebrow="Scan boundaries"
        title="Sites"
        actions={
          <button className="btn-primary" onClick={() => setForm(blank())}>
            New site
          </button>
        }
      />

      {sites.list.isLoading && (
        <div className="flex justify-center py-12">
          <Spinner />
        </div>
      )}
      {sites.list.data?.length === 0 && <EmptyState>No sites configured.</EmptyState>}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {(sites.list.data ?? []).map((s) => (
          <EntityCard
            key={s.id}
            title={s.name}
            meta={`${s.target_count} target${s.target_count === 1 ? '' : 's'} · ${s.scan_type} · ${s.schedule_type}`}
            status={s.last_status || (s.schedule_enabled ? 'active' : 'offline')}
            lines={[
              s.last_run && `Last: ${formatDate(s.last_run)}`,
              s.next_run && `Next: ${formatDate(s.next_run)}`,
              s.latest_scan &&
                `${s.latest_scan.vulns_found ?? 0} findings · ${s.latest_scan.targets_scanned ?? 0}/${s.latest_scan.targets_total ?? 0} hosts`,
            ]}
            actions={
              <>
                <button
                  className="btn px-2 py-1"
                  onClick={() =>
                    sites.scan.mutate(s.id, {
                      onSuccess: () => toast.success('Site scan queued'),
                      onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed'),
                    })
                  }
                >
                  Run
                </button>
                <button className="btn px-2 py-1" onClick={() => sites.toggle.mutate(s.id)}>
                  {s.schedule_enabled ? 'Disable' : 'Enable'}
                </button>
                <button className="btn px-2 py-1" onClick={() => openEdit(s)}>
                  Edit
                </button>
                <button
                  className="btn-danger px-2 py-1"
                  onClick={() => {
                    if (confirm(`Delete site "${s.name}"?`))
                      sites.remove.mutate(s.id, { onSuccess: () => toast.success('Deleted') });
                  }}
                >
                  Delete
                </button>
              </>
            }
          />
        ))}
      </div>

      <Modal open={!!form} onClose={() => setForm(null)} title={form?.id ? 'Edit site' : 'New site'} wide>
        {form && (
          <>
            <Field label="Name">
              <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </Field>
            <Field label="Description">
              <input
                className="input"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
            </Field>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Targets (one per line)">
                <textarea
                  className="input h-24"
                  value={form.targets}
                  onChange={(e) => setForm({ ...form, targets: e.target.value })}
                />
              </Field>
              <Field label="Exclusions (one per line)">
                <textarea
                  className="input h-24"
                  value={form.excluded_targets}
                  onChange={(e) => setForm({ ...form, excluded_targets: e.target.value })}
                />
              </Field>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Scan type">
                <select
                  className="input"
                  value={form.scan_type}
                  onChange={(e) => setForm({ ...form, scan_type: e.target.value })}
                >
                  {['full', 'port', 'vuln', 'auth'].map((t) => (
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
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label="Port range">
                <input
                  className="input"
                  placeholder="1-1000 · - · 22,80,443"
                  value={form.scan_options.ports}
                  onChange={(e) =>
                    setForm({ ...form, scan_options: { ...form.scan_options, ports: e.target.value } })
                  }
                />
              </Field>
              <Field label="Speed">
                <select
                  className="input"
                  value={form.scan_options.scan_speed}
                  onChange={(e) =>
                    setForm({ ...form, scan_options: { ...form.scan_options, scan_speed: e.target.value } })
                  }
                >
                  {['T2', 'T3', 'T4', 'T5'].map((t) => (
                    <option key={t}>{t}</option>
                  ))}
                </select>
              </Field>
              <Field label="Severity filter">
                <select
                  className="input"
                  value={form.scan_options.severity}
                  onChange={(e) =>
                    setForm({ ...form, scan_options: { ...form.scan_options, severity: e.target.value } })
                  }
                >
                  <option value="critical,high,medium,low">all</option>
                  <option value="critical,high,medium">medium+</option>
                  <option value="critical,high">high+</option>
                  <option value="critical">critical</option>
                </select>
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
