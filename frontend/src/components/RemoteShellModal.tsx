import { useEffect, useRef, useState } from 'react';
import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';

import { api } from '@/lib/api';
import type { AgentShellSession } from '@/types';


function encodeText(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}


function decodeBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}


export function RemoteShellModal({
  session,
  targetLabel,
  onClose,
}: {
  session: AgentShellSession | null;
  targetLabel: string;
  onClose: () => void;
}) {
  const hostRef = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState<string>(session?.status ?? 'requested');

  useEffect(() => {
    setStatus(session?.status ?? 'requested');
  }, [session]);

  useEffect(() => {
    if (!session || !hostRef.current) return;
    let cancelled = false;
    let pollTimer: number | undefined;
    let inputTimer: number | undefined;
    let inputBuffer = '';
    let after = 0;
    let finalState = '';

    const terminal = new Terminal({
      cursorBlink: true,
      convertEol: false,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
      fontSize: 13,
      scrollback: 5000,
      theme: {
        background: '#0a0b0d',
        foreground: '#eef0f4',
        cursor: '#9de75b',
        selectionBackground: '#3b4666',
      },
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(hostRef.current);
    fit.fit();
    terminal.focus();
    terminal.writeln('\x1b[36mARTEMIS remote PTY — awaiting agent…\x1b[0m');

    const flushInput = () => {
      if (!inputBuffer || cancelled || finalState) return;
      const data = inputBuffer;
      inputBuffer = '';
      void api.post(`/api/v1/agent-shell-sessions/${session.id}/input`, { data: encodeText(data) })
        .catch((error: unknown) => {
          if (!cancelled) setStatus(error instanceof Error ? error.message : 'input transport error');
        });
    };
    const inputDisposable = terminal.onData((data) => {
      inputBuffer += data;
      window.clearTimeout(inputTimer);
      inputTimer = window.setTimeout(flushInput, 25);
    });

    let resizeTimer: number | undefined;
    const sendResize = () => {
      if (cancelled) return;
      void api.post(`/api/v1/agent-shell-sessions/${session.id}/resize`, {
        cols: terminal.cols,
        rows: terminal.rows,
      }).catch((error: unknown) => {
        if (!cancelled) setStatus(error instanceof Error ? error.message : 'resize transport error');
      });
    };
    const observer = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        return;
      }
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(sendResize, 100);
    });
    observer.observe(hostRef.current);

    const poll = async () => {
      try {
        const data = await api.get<{
          output: Array<{ id: number; data: string }>;
          session: AgentShellSession;
        }>(`/api/v1/agent-shell-sessions/${session.id}/output?after=${after}`);
        if (cancelled) return;
        for (const chunk of data.output) {
          terminal.write(decodeBytes(chunk.data));
          after = Math.max(after, chunk.id);
        }
        setStatus(data.session.status);
        if (['closed', 'failed', 'expired'].includes(data.session.status)) {
          if (finalState !== data.session.status) {
            terminal.writeln(
              `\r\n\x1b[33m[session ${data.session.status}` +
              `${data.session.exit_code != null ? `, exit ${data.session.exit_code}` : ''}]\x1b[0m`,
            );
            if (data.session.error_message) terminal.writeln(`\x1b[31m${data.session.error_message}\x1b[0m`);
            finalState = data.session.status;
          }
          return;
        }
      } catch (error) {
        if (!cancelled) setStatus(error instanceof Error ? error.message : 'connection error');
      }
      if (!cancelled) pollTimer = window.setTimeout(poll, 250);
    };
    void poll();

    const stopEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') event.stopImmediatePropagation();
    };
    window.addEventListener('keydown', stopEscape, true);

    return () => {
      cancelled = true;
      window.clearTimeout(pollTimer);
      window.clearTimeout(inputTimer);
      window.clearTimeout(resizeTimer);
      observer.disconnect();
      inputDisposable.dispose();
      terminal.dispose();
      window.removeEventListener('keydown', stopEscape, true);
    };
  }, [session]);

  if (!session) return null;

  const close = async () => {
    try {
      await api.del(`/api/v1/agent-shell-sessions/${session.id}`);
      onClose();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'could not close session');
    }
  };

  return (
    <div className="fixed inset-0 z-[90] flex items-center justify-center bg-black/70 p-4">
      <div className="flex h-[80vh] w-full max-w-6xl flex-col overflow-hidden rounded border border-line bg-[#0a0b0d] shadow-2xl">
        <header className="flex items-center justify-between border-b border-line px-4 py-2">
          <div>
            <div className="font-mono text-xs text-text">Remote shell · {targetLabel}</div>
            <div className="font-mono text-2xs text-muted">
              agent {session.agent_id} · {status} · expires {new Date(session.expires_at).toLocaleTimeString()}
            </div>
          </div>
          <button className="btn-danger" onClick={() => void close()}>Close session</button>
        </header>
        <div ref={hostRef} className="min-h-0 flex-1 p-2" />
      </div>
    </div>
  );
}
