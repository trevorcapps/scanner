import { useEffect, useMemo, useRef, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { useNavigate } from 'react-router-dom';
import { SEVERITY_COLOR } from '@/lib/format';
import type { Topology, TopologyNode } from '@/types';

interface GNode extends TopologyNode {
  val?: number;
  color?: string;
}

export function TopologyGraph({ data }: { data: Topology }) {
  const nav = useNavigate();
  const wrapRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 600, h: 380 });

  useEffect(() => {
    if (!wrapRef.current) return;
    const ro = new ResizeObserver(([e]) => {
      setSize({ w: e.contentRect.width, h: e.contentRect.height });
    });
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, []);

  const graph = useMemo(() => {
    const nodes: GNode[] = data.nodes.map((n) => {
      if (n.type === 'root') return { ...n, val: 8, color: 'rgb(var(--text-soft))' };
      if (n.type === 'subnet') return { ...n, val: 4, color: 'rgb(var(--blue))' };
      return {
        ...n,
        val: 1 + Math.min(6, (n.port_count ?? 0) / 3),
        color: n.worst_severity ? SEVERITY_COLOR[n.worst_severity] : 'rgb(var(--muted))',
      };
    });
    return { nodes, links: data.links.map((l) => ({ ...l })) };
  }, [data]);

  return (
    <div ref={wrapRef} className="h-[380px] w-full overflow-hidden rounded bg-surface">
      <ForceGraph2D
        graphData={graph}
        width={size.w}
        height={size.h}
        backgroundColor="rgba(0,0,0,0)"
        nodeRelSize={4}
        nodeVal={(n: GNode) => n.val ?? 1}
        nodeColor={(n: GNode) => n.color ?? 'rgb(var(--muted))'}
        nodeLabel={(n: GNode) => {
          const g = n;
          if (g.type === 'asset') {
            return `${g.hostname || g.ip} · ${g.device_type} · ${g.port_count} ports${
              g.vuln_total ? ` · ${g.vuln_total} vulns` : ''
            }`;
          }
          return g.label;
        }}
        linkColor={() => 'rgb(var(--line))'}
        linkWidth={0.6}
        cooldownTicks={80}
        onNodeClick={(n: GNode) => {
          const g = n;
          if (g.type === 'asset' && g.ip) nav(`/assets?q=${encodeURIComponent(g.ip)}`);
          if (g.type === 'subnet') nav(`/assets?q=${encodeURIComponent(g.label.replace('.0/24', '.'))}`);
        }}
      />
    </div>
  );
}
