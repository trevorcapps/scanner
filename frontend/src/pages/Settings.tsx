import { useEffect, useState } from 'react';
import { PageHeading, Panel, Badge } from '@/components/ui/primitives';
import { Modal, Field, FormActions } from '@/components/ui/Modal';
import { DEFAULT_SCAN, useUi, type ScanDefaults } from '@/stores/ui';
import { useCredentials, useSettings, useWebhooks } from '@/hooks/useResources';
import { useBranding, useSmtp } from '@/hooks/useReports';
import { getSocket } from '@/lib/socket';
import { formatDate } from '@/lib/format';
import { toast } from '@/stores/toast';

export default function Settings() {
  return (
    <div className="space-y-4">
      <PageHeading eyebrow="Engine policy" title="Control" state="Configuration" />
      <ScanDefaultsPanel />
      <NvdPanel />
      <CredentialsPanel />
      <ReportBrandingPanel />
      <SmtpPanel />
      <WebhooksPanel />
      <ApiPanel />
    </div>
  );
}

function ReportBrandingPanel() {
  const { get, save } = useBranding();
  const [d, setD] = useState({
    report_org_name: '',
    report_logo: '',
    report_accent_color: '#7c3aed',
    report_footer: '',
    report_confidentiality: 'CONFIDENTIAL',
  });
  useEffect(() => {
    if (get.data) setD((p) => ({ ...p, ...get.data }));
  }, [get.data]);

  const onLogo = (file?: File) => {
    if (!file) return;
    if (file.size > 400_000) {
      toast.error('Logo must be under 400 KB');
      return;
    }
    const reader = new FileReader();
    reader.onload = () => setD({ ...d, report_logo: String(reader.result) });
    reader.readAsDataURL(file);
  };

  return (
    <Panel
      title="Report branding"
      actions={
        <button
          className="btn-primary px-2 py-1"
          onClick={() =>
            save.mutate(d, { onSuccess: () => toast.success('Saved'), onError: () => toast.error('Save failed') })
          }
        >
          Save
        </button>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Organisation name">
          <input
            className="input"
            value={d.report_org_name}
            placeholder="Acme Security"
            onChange={(e) => setD({ ...d, report_org_name: e.target.value })}
          />
        </Field>
        <Field label="Accent colour">
          <input
            className="input h-9"
            type="color"
            value={d.report_accent_color || '#7c3aed'}
            onChange={(e) => setD({ ...d, report_accent_color: e.target.value })}
          />
        </Field>
        <Field label="Confidentiality banner" hint="blank to omit">
          <input
            className="input"
            value={d.report_confidentiality}
            onChange={(e) => setD({ ...d, report_confidentiality: e.target.value })}
          />
        </Field>
        <Field label="Footer text" hint="e.g. legal disclaimer">
          <input
            className="input"
            value={d.report_footer}
            onChange={(e) => setD({ ...d, report_footer: e.target.value })}
          />
        </Field>
        <Field label="Logo" hint="PNG/SVG, under 400 KB — embedded in the cover page">
          <div className="flex items-center gap-3">
            <input type="file" accept="image/*" onChange={(e) => onLogo(e.target.files?.[0])} className="text-2xs" />
            {d.report_logo && (
              <>
                <img src={d.report_logo} alt="logo" className="h-8 rounded border border-line-soft bg-white p-1" />
                <button className="btn px-2 py-0.5 text-2xs" onClick={() => setD({ ...d, report_logo: '' })}>
                  Clear
                </button>
              </>
            )}
          </div>
        </Field>
      </div>
    </Panel>
  );
}

function SmtpPanel() {
  const { get, save, test } = useSmtp();
  const [d, setD] = useState({
    smtp_host: '',
    smtp_port: '587',
    smtp_username: '',
    smtp_password: '',
    smtp_from: '',
    smtp_security: 'starttls',
  });
  const [testTo, setTestTo] = useState('');
  useEffect(() => {
    if (get.data)
      setD((p) => ({
        ...p,
        smtp_host: get.data.smtp_host,
        smtp_port: get.data.smtp_port || '587',
        smtp_username: get.data.smtp_username,
        smtp_from: get.data.smtp_from,
        smtp_security: get.data.smtp_security || 'starttls',
      }));
  }, [get.data]);

  return (
    <Panel
      title="Email (SMTP)"
      meta={get.data?.smtp_password_set ? 'password set' : ''}
      actions={
        <button
          className="btn-primary px-2 py-1"
          onClick={() =>
            save.mutate(d, {
              onSuccess: () => {
                toast.success('Saved');
                setD({ ...d, smtp_password: '' });
              },
              onError: () => toast.error('Save failed'),
            })
          }
        >
          Save
        </button>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Host">
          <input className="input" value={d.smtp_host} placeholder="smtp.example.com"
            onChange={(e) => setD({ ...d, smtp_host: e.target.value })} />
        </Field>
        <Field label="Port">
          <input className="input" value={d.smtp_port} onChange={(e) => setD({ ...d, smtp_port: e.target.value })} />
        </Field>
        <Field label="Security">
          <select className="input" value={d.smtp_security} onChange={(e) => setD({ ...d, smtp_security: e.target.value })}>
            <option value="starttls">STARTTLS</option>
            <option value="ssl">SSL/TLS</option>
            <option value="none">None</option>
          </select>
        </Field>
        <Field label="From address">
          <input className="input" value={d.smtp_from} placeholder="artemis@example.com"
            onChange={(e) => setD({ ...d, smtp_from: e.target.value })} />
        </Field>
        <Field label="Username" hint="blank for unauthenticated relays">
          <input className="input" value={d.smtp_username} onChange={(e) => setD({ ...d, smtp_username: e.target.value })} />
        </Field>
        <Field label="Password" hint={get.data?.smtp_password_set ? 'leave blank to keep current' : ''}>
          <input className="input" type="password" value={d.smtp_password}
            onChange={(e) => setD({ ...d, smtp_password: e.target.value })} />
        </Field>
      </div>
      <div className="mt-2 flex items-center gap-2 border-t border-line-soft pt-3">
        <input className="input flex-1" placeholder="you@example.com" value={testTo}
          onChange={(e) => setTestTo(e.target.value)} />
        <button
          className="btn px-3 py-1"
          disabled={!testTo || test.isPending}
          onClick={() =>
            test.mutate(testTo, {
              onSuccess: () => toast.success('Test email sent'),
              onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed'),
            })
          }
        >
          {test.isPending ? 'Sending…' : 'Send test'}
        </button>
      </div>
    </Panel>
  );
}

function ScanDefaultsPanel() {
  const stored = useUi((s) => s.scanDefaults);
  const setStored = useUi((s) => s.setScanDefaults);
  const [d, setD] = useState<ScanDefaults>(stored);
  useEffect(() => setD(stored), [stored]);

  const num = (k: keyof ScanDefaults, v: string) => setD({ ...d, [k]: Number(v) || DEFAULT_SCAN[k] });

  return (
    <Panel
      title="Scan defaults"
      actions={
        <button
          className="btn-primary px-2 py-1"
          onClick={() => {
            setStored(d);
            toast.success('Saved');
          }}
        >
          Save
        </button>
      }
    >
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label="Port range" hint='"-" for all ports'>
          <input className="input" value={d.ports} onChange={(e) => setD({ ...d, ports: e.target.value })} />
        </Field>
        <Field label="Scan speed">
          <select className="input" value={d.scanSpeed} onChange={(e) => setD({ ...d, scanSpeed: e.target.value })}>
            {['T2', 'T3', 'T4', 'T5'].map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </Field>
        <Field label="Host timeout (s)">
          <input className="input" type="number" value={d.hostTimeout} onChange={(e) => num('hostTimeout', e.target.value)} />
        </Field>
        <Field label="Max hosts">
          <input className="input" type="number" value={d.maxHosts} onChange={(e) => num('maxHosts', e.target.value)} />
        </Field>
        <Field label="Vuln timeout (s)">
          <input className="input" type="number" value={d.vulnTimeout} onChange={(e) => num('vulnTimeout', e.target.value)} />
        </Field>
        <Field label="Rate limit (req/s)">
          <input className="input" type="number" value={d.rateLimit} onChange={(e) => num('rateLimit', e.target.value)} />
        </Field>
        <Field label="Severity filter">
          <select className="input" value={d.severity} onChange={(e) => setD({ ...d, severity: e.target.value })}>
            <option value="critical,high,medium,low">all</option>
            <option value="critical,high,medium">medium+</option>
            <option value="critical,high">high+</option>
            <option value="critical">critical</option>
          </select>
        </Field>
        <Field label="Nuclei tags">
          <input className="input" value={d.templates} onChange={(e) => setD({ ...d, templates: e.target.value })} />
        </Field>
        <label className="flex items-center gap-2 self-end pb-3 text-2xs text-text-soft">
          <input type="checkbox" checked={d.vulscan} onChange={(e) => setD({ ...d, vulscan: e.target.checked })} />
          enable vulscan NSE
        </label>
      </div>
    </Panel>
  );
}

function NvdPanel() {
  const { nvdStatus, nvdKey, setNvdKey } = useSettings();
  const [key, setKey] = useState('');
  const [sync, setSync] = useState<{ message: string; percent?: number } | null>(null);

  useEffect(() => {
    const s = getSocket();
    const on = (d: { status?: string; message?: string; percent?: number }) => {
      setSync({ message: d.message || 'Syncing…', percent: d.percent });
      if (d.status === 'complete' || d.status === 'error') {
        setTimeout(() => setSync(null), 4000);
        nvdStatus.refetch();
      }
    };
    s.on('nvd_sync_progress', on);
    return () => {
      s.off('nvd_sync_progress', on);
    };
  }, [nvdStatus]);

  const st = nvdStatus.data ?? {};

  return (
    <Panel title="NVD feed cache">
      <div className="mb-3 flex flex-wrap gap-4 font-mono text-2xs">
        <span>
          <span className="text-muted">CVEs </span>
          <span className="text-text">{(st.total_cves ?? 0).toLocaleString?.() ?? st.total_cves ?? 0}</span>
        </span>
        <span>
          <span className="text-muted">Last sync </span>
          <span className="text-text">{st.last_sync ? formatDate(st.last_sync) : 'never'}</span>
        </span>
      </div>
      <div className="flex flex-wrap gap-2">
        <button className="btn-primary" disabled={!!sync} onClick={() => getSocket().emit('start_nvd_sync', { full: false })}>
          Update (modified feed)
        </button>
        <button
          className="btn"
          disabled={!!sync}
          onClick={() => {
            if (confirm('Full sync downloads every year feed. Continue?'))
              getSocket().emit('start_nvd_sync', { full: true });
          }}
        >
          Full sync
        </button>
      </div>
      {sync && (
        <div className="mt-3">
          <div className="mb-1 font-mono text-2xs text-text-soft">{sync.message}</div>
          <div className="h-1.5 overflow-hidden rounded bg-hover">
            <div className="h-full bg-blue transition-all" style={{ width: `${sync.percent ?? 5}%` }} />
          </div>
        </div>
      )}

      <div className="mt-5 border-t border-line-soft pt-4">
        <Field label="NVD API key" hint={nvdKey.data?.has_key ? `configured (${nvdKey.data.masked})` : 'optional — raises the rate limit'}>
          <div className="flex gap-2">
            <input
              className="input"
              type="password"
              placeholder={nvdKey.data?.has_key ? nvdKey.data.masked : 'Enter NVD API key'}
              value={key}
              onChange={(e) => setKey(e.target.value)}
            />
            <button
              className="btn-primary shrink-0"
              onClick={() =>
                setNvdKey.mutate(key.trim(), {
                  onSuccess: () => {
                    toast.success('Saved');
                    setKey('');
                  },
                })
              }
            >
              Save
            </button>
          </div>
        </Field>
      </div>
    </Panel>
  );
}

function CredentialsPanel() {
  const { list, save, remove } = useCredentials();
  const [form, setForm] = useState<any | null>(null);

  const submit = () => {
    const body: any = {
      name: form.name.trim(),
      cred_type: form.cred_type,
      username: form.username.trim(),
      key_path: form.key_path.trim(),
      password: form.password,
    };
    if (form.id) body.id = form.id;
    save.mutate(body, {
      onSuccess: (d: any) => {
        if (d?.error) toast.error(d.error);
        else {
          toast.success('Credential saved');
          setForm(null);
        }
      },
      onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed'),
    });
  };

  return (
    <Panel
      title="Credentials"
      actions={
        <button
          className="btn-primary px-2 py-1"
          onClick={() => setForm({ cred_type: 'ssh_key', username: 'root', name: '', key_path: '', password: '' })}
        >
          Add
        </button>
      }
    >
      {(list.data?.credentials ?? []).length === 0 && (
        <p className="text-2xs text-faint">No credentials configured.</p>
      )}
      <div className="space-y-1.5">
        {(list.data?.credentials ?? []).map((c) => (
          <div key={c.id} className="flex items-center gap-2 text-xs">
            <span className="data text-text">{c.name}</span>
            <Badge>{c.cred_type}</Badge>
            <span className="text-muted">{c.username}</span>
            <span className="text-2xs text-faint">
              {c.cred_type === 'ssh_key' ? c.key_path : c.password_set ? '••••••' : 'no password'}
            </span>
            <div className="ml-auto flex gap-1">
              <button
                className="btn px-2 py-0.5"
                onClick={() => setForm({ ...c, password: '', key_path: c.key_path || '' })}
              >
                Edit
              </button>
              <button
                className="btn-danger px-2 py-0.5"
                onClick={() => {
                  if (confirm(`Delete "${c.name}"?`))
                    remove.mutate(c.id, { onSuccess: () => toast.success('Deleted') });
                }}
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>

      <Modal open={!!form} onClose={() => setForm(null)} title={form?.id ? 'Edit credential' : 'Add credential'}>
        {form && (
          <>
            <Field label="Name">
              <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </Field>
            <Field label="Type">
              <select
                className="input"
                value={form.cred_type}
                onChange={(e) => setForm({ ...form, cred_type: e.target.value })}
              >
                <option value="ssh_key">SSH key</option>
                <option value="ssh_password">SSH password</option>
              </select>
            </Field>
            <Field label="Username">
              <input className="input" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
            </Field>
            {form.cred_type === 'ssh_key' ? (
              <Field label="Key path">
                <input className="input" value={form.key_path} onChange={(e) => setForm({ ...form, key_path: e.target.value })} />
              </Field>
            ) : (
              <Field label="Password" hint={form.id ? 'leave blank to keep existing' : undefined}>
                <input
                  className="input"
                  type="password"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                />
              </Field>
            )}
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
    </Panel>
  );
}

function WebhooksPanel() {
  const { list, create, remove, test } = useWebhooks();
  const [url, setUrl] = useState('');
  const [events, setEvents] = useState<string[]>([]);
  const available = (list.data?.available_events ?? []).filter((e) => e !== 'ping');

  const add = () => {
    if (!url.startsWith('http')) {
      toast.error('URL must be http(s)');
      return;
    }
    create.mutate(
      { url: url.trim(), events },
      {
        onSuccess: (d) => {
          toast.success('Webhook created');
          setUrl('');
          setEvents([]);
          if ((d as { secret?: string })?.secret)
            toast.info(`Secret (shown once): ${(d as { secret: string }).secret}`);
        },
        onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed'),
      },
    );
  };

  return (
    <Panel title="Webhooks" meta="signed X-Artemis-Signature">
      <div className="mb-3 flex flex-wrap items-end gap-2">
        <input
          className="input max-w-sm flex-1"
          placeholder="https://example.com/artemis-hook"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button className="btn-primary" onClick={add}>
          Add
        </button>
      </div>
      <div className="mb-4 flex flex-wrap gap-2">
        {available.map((e) => (
          <label key={e} className="flex items-center gap-1 font-mono text-2xs text-text-soft">
            <input
              type="checkbox"
              checked={events.includes(e)}
              onChange={(ev) =>
                setEvents(ev.target.checked ? [...events, e] : events.filter((x) => x !== e))
              }
            />
            {e}
          </label>
        ))}
        <span className="text-2xs text-faint">none checked = all events</span>
      </div>

      {(list.data?.webhooks ?? []).length === 0 && <p className="text-2xs text-faint">No webhooks.</p>}
      <div className="space-y-1.5">
        {(list.data?.webhooks ?? []).map((w) => (
          <div key={w.id} className="flex items-center gap-2 text-xs">
            <span className="truncate text-text-soft">{w.url}</span>
            <span className="text-2xs text-muted">{(w.events ?? []).join(', ') || 'all'}</span>
            {w.last_status && <Badge>{w.last_status}</Badge>}
            <div className="ml-auto flex gap-1">
              <button
                className="btn px-2 py-0.5"
                onClick={() =>
                  test.mutate(w.id, { onSuccess: () => toast.info('Test ping queued') })
                }
              >
                Test
              </button>
              <button
                className="btn-danger px-2 py-0.5"
                onClick={() => {
                  if (confirm('Delete webhook?')) remove.mutate(w.id, { onSuccess: () => toast.success('Deleted') });
                }}
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function ApiPanel() {
  return (
    <Panel title="API">
      <p className="mb-3 text-xs text-text-soft">
        Browse the REST API. Authenticate with a bearer token or an <code>X-API-Key</code>.
      </p>
      <div className="flex gap-2">
        <a className="btn" href="/api/v1/docs" target="_blank" rel="noopener">
          Open API docs
        </a>
        <a className="btn" href="/api/v1/openapi.json" target="_blank" rel="noopener">
          openapi.json
        </a>
        <a className="btn" href="/classic" target="_blank" rel="noopener">
          Classic UI
        </a>
      </div>
    </Panel>
  );
}
