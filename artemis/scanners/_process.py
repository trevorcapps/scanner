"""Run an external scanner in its own process group with cooperative cancel.

Every scanner subprocess (nmap, nuclei, fingerprint helpers) is launched with
``start_new_session=True`` so the whole tree can be signalled. On cancel or
timeout: SIGTERM the group, wait briefly, then SIGKILL. Partial output collected
so far is returned to the caller, which marks the evidence partial.
"""

import logging
import os
import signal
import subprocess
import time

logger = logging.getLogger(__name__)


class ProcessCancelled(RuntimeError):
    def __init__(self, partial_output=''):
        super().__init__('process cancelled')
        self.partial_output = partial_output


class ProcessTimeout(RuntimeError):
    def __init__(self, partial_output=''):
        super().__init__('process timed out')
        self.partial_output = partial_output


def _kill_group(proc, grace=5):
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        proc.terminate()
    deadline = time.monotonic() + grace
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.1)
    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.wait(timeout=5)


def run_streaming(cmd, *, cancel_check=None, timeout=None, line_callback=None,
                  poll_interval=0.5, env=None):
    """Run ``cmd``, streaming stdout lines to ``line_callback``.

    Returns (returncode, collected_stdout). Raises ProcessCancelled /
    ProcessTimeout (each carrying the partial output) on early termination.
    """
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
            env=env,
        )
    except FileNotFoundError as exc:
        raise FileNotFoundError(f'{cmd[0]} is not installed or not on PATH') from exc

    collected = []
    start = time.monotonic()
    os.set_blocking(proc.stdout.fileno(), False)

    try:
        while True:
            if cancel_check and cancel_check():
                _kill_group(proc)
                raise ProcessCancelled(''.join(collected))
            if timeout is not None and time.monotonic() - start > timeout:
                _kill_group(proc)
                raise ProcessTimeout(''.join(collected))

            line = proc.stdout.readline()
            if line:
                collected.append(line)
                if line_callback:
                    try:
                        line_callback(line.rstrip())
                    except Exception:  # noqa: BLE001
                        pass
                continue

            if proc.poll() is not None:
                # drain anything buffered after exit
                rest = proc.stdout.read() or ''
                collected.append(rest)
                if rest and line_callback:
                    for extra in rest.splitlines():
                        line_callback(extra)
                break
            time.sleep(poll_interval)
        return proc.returncode, ''.join(collected)
    finally:
        if proc.poll() is None:
            _kill_group(proc)
        try:
            proc.stdout.close()
        except Exception:  # noqa: BLE001
            pass
