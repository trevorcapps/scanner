import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Modal } from '@/components/ui/Modal';
import { EmptyState, PageHeading, Panel, Spinner, StatusDot } from '@/components/ui/primitives';
import { api } from '@/lib/api';
import { formatDate } from '@/lib/format';
import { toast } from '@/stores/toast';
import type { AssetSummary } from '@/types';

interface Starter {
  id: string;
  description?: string;
  platform?: string;
  version?: number;
}

interface Content {
  id: number;
  digest: string;
  kind: string;
  filename?: string | null;
  size_bytes: number;
  syntax_ok: boolean;
  created_at: string;
}

interface AgentSummary {
  id: number;
  ip: string;
  hostname?: string | null;
  status: string;
  capabilities?: string[];
}

interface AutomationJob {
  id: string;
  status: string;
  target: string;
  created_at: string;
  completed_at?: string | null;
  error_message?: string | null;
}

interface JobEvent {
  seq: number;
  kind: string;
  message?: string | null;
  level?: string | null;
  created_at: string;
}

const DEFAULT_PLAYBOOK = `- hosts: targets
  gather_facts: false
  tasks:
    - name: Verify Ansible execution
      ansible.builtin.command: /usr/bin/true
`;

export default function Automation() {
  const qc = useQueryClient();
  const [playbook, setPlaybook] = useState('');
  const [filename, setFilename] = useState('site.yml');
  const [variables, setVariables] = useState('');
  const [selectedTargets, setSelectedTargets] = useState<number[]>([]);
  const [selectedCredentials, setSelectedCredentials] = useState<number[]>([]);
  const [selectedContent, setSelectedContent] = useState('');
  const [selectedStarter, setSelectedStarter] = useState('');
  const [eventsJob, setEventsJob] = useState<string | null>(null);

  const assets = useQuery({
    queryKey: ['automation-assets'],
    queryFn: () => api.get<{ assets: AssetSummary[] }>('/api/v1/assets'),
  });
  const agents = useQuery({
    queryKey: ['automation-agents'],
    queryFn: () => api.get<AgentSummary[]>('/api/v1/agents'),
    refetchInterval: 20_000,
  });
  const content = useQuery({
    queryKey: ['automation-content'],
    queryFn: () => api.get<{ content: Content[] }>('/api/v1/automation/content?limit=100'),
  });
  const starters = useQuery({
    queryKey: ['automation-starters'],
    queryFn: () => api.get<{ starters: Starter[] }>('/api/v1/automation/starters'),
  });
  const credentials = useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.get<{ credentials: Array<{ id: number; name: string; cred_type: string; username: string }> }>('/api/v1/credentials'),
  });
  const jobs = useQuery({
    queryKey: ['automation-jobs'],
    queryFn: () => api.get<{ jobs: AutomationJob[] }>('/api/v1/jobs?type=ansible_run&limit=25'),
    refetchInterval: 5_000,
  });
  const starterBody = useQuery({
    queryKey: ['automation-starter', selectedStarter],
    queryFn: () => api.get<{ starter: Starter & { body: string } }>(`/api/v1/automation/starters/${selectedStarter}`),
    enabled: !!selectedStarter,
  });
  const events = useQuery({
    queryKey: ['automation-job-events', eventsJob],
    queryFn: () => api.get<{ events: JobEvent[]; job: AutomationJob }>(`/api/v1/jobs/${eventsJob}/events`),
    enabled: !!eventsJob,
    refetchInterval: 3_000,
  });
  useEffect(() => {
    const body = starterBody.data?.starter.body;
    if (selectedStarter && body && !playbook) setPlaybook(body);
  }, [selectedStarter, starterBody.data?.starter.body, playbook]);

  const launch = useMutation({
    mutationFn: async (checkMode: boolean) => {
      const body: Record<string, unknown> = {
        targets: { asset_ids: selectedTargets },
        variables: parseVariables(variables),
        credential_refs: selectedCredentials,
        check_mode: checkMode,
      };
      if (selectedContent) body.content_id = Number(selectedContent);
      else {
        const raw = playbook.trim() || (selectedStarter ? (starterBody.data?.starter.body ?? '').trim() : '');
        if (!raw) throw new Error('Provide a playbook or select saved content');
        body.content = raw;
        body.filename = filename.trim() || 'site.yml';
      }
      return api.post<{ job: AutomationJob }>('/api/v1/automation/runs', body);
    },
    onSuccess: (_, checkMode) => {
      toast.success(checkMode ? 'Check run queued' : 'Playbook queued');
      qc.invalidateQueries({ queryKey: ['automation-content'] });
      qc.invalidateQueries({ queryKey: ['automation-jobs'] });
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : 'Could not launch playbook'),
  });
  const save = useMutation({
    mutationFn: () => {
      const raw = playbook.trim() || (selectedStarter ? (starterBody.data?.starter.body ?? '').trim() : '');
      if (!raw) throw new Error('Provide a playbook before saving');
      return api.post<{ content: Content }>('/api/v1/automation/content', {
        content: raw,
        filename: filename.trim() || 'site.yml',
      });
    },
    onSuccess: (result) => {
      toast.success('Playbook saved');
      setSelectedContent(String(result.content.id));
      setSelectedStarter('');
      qc.invalidateQueries({ queryKey: ['automation-content'] });
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : 'Could not save playbook'),
  });
  const cancel = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/jobs/${id}/cancel`),
    onSuccess: () => {
      toast.success('Cancellation requested');
      qc.invalidateQueries({ queryKey: ['automation-jobs'] });
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : 'Could not cancel job'),
  });

  const agentByIp = new Map((agents.data ?? []).map((agent) => [agent.ip, agent]));
  const toggleTarget = (id: number) =>
    setSelectedTargets((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
  const selectStarter = (id: string) => {
    setSelectedStarter(id);
    setSelectedContent('');
    if (id) setPlaybook('');
  };
  const selectContent = (id: string) => {
    setSelectedContent(id);
    setSelectedStarter('');
  };
  const onFile = (file: File | undefined) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setPlaybook(String(reader.result ?? ''));
      setFilename(file.name);
      setSelectedContent('');
      setSelectedStarter('');
    };
    reader.readAsText(file);
  };

  if (assets.isLoading || agents.isLoading || content.isLoading || starters.isLoading || credentials.isLoading) {
    return <div><PageHeading eyebrow="Controlled execution" title="Ansible automation" /><div className="flex justify-center py-16"><Spinner /></div></div>;
  }

  return (
    <div>
      <PageHeading
        eyebrow="Controlled execution"
        title="Ansible automation"
        state="PLAYBOOKS"
        actions={<button className="btn" onClick={() => void Promise.all([assets.refetch(), agents.refetch(), content.refetch(), starters.refetch(), jobs.refetch()])}>Refresh</button>}
      />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(320px,0.9fr)]">
        <Panel title="Playbook editor" meta="validate / launch">
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block">
              <span className="eyebrow mb-1 block">Starter playbook</span>
              <select className="input" value={selectedStarter} onChange={(e) => selectStarter(e.target.value)}>
                <option value="">Choose a starter</option>
                {(starters.data?.starters ?? []).map((starter) => <option key={starter.id} value={starter.id}>{starter.id}</option>)}
              </select>
            </label>
            <label className="block">
              <span className="eyebrow mb-1 block">Saved content</span>
              <select className="input" value={selectedContent} onChange={(e) => selectContent(e.target.value)}>
                <option value="">New playbook</option>
                {(content.data?.content ?? []).map((item) => <option key={item.id} value={item.id}>{item.filename || item.kind} · {item.digest.slice(0, 12)}</option>)}
              </select>
            </label>
          </div>
          <label className="mt-3 block">
            <span className="eyebrow mb-1 block">Load YAML file</span>
            <input className="input" type="file" accept=".yml,.yaml,.json,text/yaml,application/x-yaml" onChange={(e) => onFile(e.target.files?.[0])} />
          </label>
          <label className="mt-3 block">
            <span className="eyebrow mb-1 block">Playbook YAML</span>
            <textarea
              className="input min-h-[320px] resize-y font-mono text-xs leading-relaxed"
              spellCheck={false}
              placeholder={DEFAULT_PLAYBOOK}
              value={selectedContent ? '' : (playbook || (starterBody.data?.starter.body ?? ''))}
              disabled={!!selectedContent}
              onChange={(e) => setPlaybook(e.target.value)}
            />
            <span className="mt-1 block text-2xs text-faint">Use <code>hosts: targets</code>. Agent-local runs execute on the selected agent's localhost.</span>
          </label>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <label className="block"><span className="eyebrow mb-1 block">Filename</span><input className="input" value={filename} disabled={!!selectedContent} onChange={(e) => setFilename(e.target.value)} /></label>
            <label className="block"><span className="eyebrow mb-1 block">Extra variables (JSON)</span><textarea className="input min-h-[70px] resize-y font-mono text-xs" spellCheck={false} placeholder='{"key": "value"}' value={variables} onChange={(e) => setVariables(e.target.value)} /></label>
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-2">
            <button className="btn" disabled={launch.isPending || save.isPending} onClick={() => launch.mutate(true)}>Check mode</button>
            <button className="btn" disabled={launch.isPending || save.isPending} onClick={() => save.mutate()}>Save content</button>
            <button className="btn-primary" disabled={launch.isPending || save.isPending} onClick={() => launch.mutate(false)}>{launch.isPending ? 'Submitting…' : 'Run playbook'}</button>
            {selectedContent && <span className="text-2xs text-muted">Saved content selected; it will be launched by ID.</span>}
          </div>
        </Panel>

        <Panel title="Target fleet" meta={`${selectedTargets.length} selected`}>
          <p className="mb-3 rounded border border-amber/40 bg-amber/10 px-2.5 py-2 text-2xs text-amber">Multiple assets use the controller executor today. A single asset with an <code>ansible_local</code> agent runs outbound-only.</p>
          <div className="mb-2 flex gap-2"><button className="btn px-2 py-1" onClick={() => setSelectedTargets((assets.data?.assets ?? []).flatMap((asset) => asset.id ? [asset.id] : []))}>Select all</button><button className="btn px-2 py-1" onClick={() => setSelectedTargets([])}>Clear</button></div>
          <div className="max-h-[390px] overflow-y-auto rounded border border-line-soft">
            {(assets.data?.assets ?? []).map((asset) => {
              if (asset.id == null) return null;
              const agent = agentByIp.get(asset.ip);
              const local = agent?.capabilities?.includes('ansible_local');
              return <label key={asset.id} className="flex cursor-pointer items-center gap-2 border-b border-line-soft px-2.5 py-2 last:border-0 hover:bg-hover">
                <input type="checkbox" checked={selectedTargets.includes(asset.id)} onChange={() => toggleTarget(asset.id!)} />
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-text">{asset.hostname || asset.ip}<span className="ml-1 text-2xs text-muted">{asset.hostname ? `(${asset.ip})` : ''}</span></span>
                <span className="flex items-center gap-1 text-2xs text-muted"><StatusDot status={agent?.status ?? 'controller'} />{local ? 'AGENT LOCAL' : (agent?.status ?? 'CONTROLLER').toUpperCase()}</span>
              </label>;
            })}
            {!(assets.data?.assets ?? []).length && <EmptyState>No eligible assets.</EmptyState>}
          </div>
          <label className="mt-4 block"><span className="eyebrow mb-1 block">SSH credential references</span><select className="input min-h-[100px]" multiple value={selectedCredentials.map(String)} onChange={(e) => setSelectedCredentials(Array.from(e.target.selectedOptions, (option) => Number(option.value)))}>{(credentials.data?.credentials ?? []).map((credential) => <option key={credential.id} value={credential.id}>{credential.name} ({credential.cred_type} / {credential.username})</option>)}</select><span className="mt-1 block text-2xs text-faint">Secrets are resolved just-in-time and are not stored in playbook content.</span></label>
        </Panel>
      </div>

      <Panel className="mt-4" title="Recent runs" meta="job history" bodyClassName="p-0">
        <div className="overflow-x-auto"><table className="w-full border-collapse text-xs"><thead><tr className="border-b border-line text-left"><th className="px-3 py-2 font-mono text-2xs uppercase tracking-wider text-muted">Created</th><th className="px-3 py-2 font-mono text-2xs uppercase tracking-wider text-muted">Target</th><th className="px-3 py-2 font-mono text-2xs uppercase tracking-wider text-muted">Status</th><th className="px-3 py-2 font-mono text-2xs uppercase tracking-wider text-muted">Actions</th></tr></thead><tbody>
          {(jobs.data?.jobs ?? []).map((job) => { const terminal = ['success', 'failed', 'cancelled', 'expired'].includes(job.status); return <tr key={job.id} className="border-b border-line-soft"><td className="px-3 py-2 text-2xs text-muted">{formatDate(job.created_at)}</td><td className="px-3 py-2 font-mono text-xs text-text">{job.target}</td><td className="px-3 py-2"><span className="inline-flex items-center gap-1.5 font-mono text-2xs uppercase text-text-soft"><StatusDot status={job.status} />{job.status}</span>{job.error_message && <div className="mt-1 text-2xs text-danger">{job.error_message}</div>}</td><td className="px-3 py-2"><div className="flex gap-1.5"><button className="btn px-2 py-1" onClick={() => setEventsJob(job.id)}>Events</button>{!terminal && <button className="btn-danger px-2 py-1" disabled={cancel.isPending} onClick={() => cancel.mutate(job.id)}>Cancel</button>}</div></td></tr>; })}
          {!(jobs.data?.jobs ?? []).length && <tr><td colSpan={4}><EmptyState>No Ansible runs yet.</EmptyState></td></tr>}
        </tbody></table></div>
      </Panel>

      <Modal open={!!eventsJob} onClose={() => setEventsJob(null)} title="Job events" wide>
        {events.isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
        {events.data && <div className="space-y-1 rounded border border-line-soft bg-surface px-3 py-2 font-mono text-2xs">{events.data.events.length ? events.data.events.map((event) => <div key={event.seq} className="border-b border-line-soft py-1.5 last:border-0"><span className="mr-2 text-faint">{formatDate(event.created_at)}</span><span className={event.level === 'error' ? 'text-danger' : 'text-text-soft'}>{event.message || event.kind}</span></div>) : <EmptyState>No events recorded.</EmptyState>}</div>}
      </Modal>
    </div>
  );
}

function parseVariables(value: string): Record<string, unknown> {
  if (!value.trim()) return {};
  const parsed: unknown = JSON.parse(value);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('Extra variables must be a JSON object');
  return parsed as Record<string, unknown>;
}
