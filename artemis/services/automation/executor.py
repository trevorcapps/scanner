"""The AutomationExecutor boundary (decision D11).

Artemis remains the source of truth for fleet identity, authorization, job
history, and operator experience. An executor only *runs content and streams
events*. The embedded Ansible Runner implementation is the default and only
initial backend; the interface is kept clean enough to add an AWX adapter later
without touching callers.
"""

import abc
import json
import logging
import os
import shutil
import tempfile

logger = logging.getLogger(__name__)


class ExecutorUnavailable(RuntimeError):
    pass


class AutomationExecutor(abc.ABC):
    name = 'base'

    @abc.abstractmethod
    def available(self):
        """True when this executor can run content right now."""

    @abc.abstractmethod
    def run(self, *, playbook_body, inventory, variables, private_data_dir,
            event_handler, cancel_check=None, check_mode=False, options=None):
        """Execute one playbook. Returns a dict:
        {status, stats: {ok, changed, failed, unreachable, skipped}, rc}.
        ``event_handler(event: dict)`` is called for every structured event."""


class NullExecutor(AutomationExecutor):
    """Used when ansible-runner is not installed."""

    name = 'null'

    def available(self):
        return False

    def run(self, **_kwargs):
        raise ExecutorUnavailable(
            'Ansible Runner is not installed (pip install "artemis-scanner[automation]")'
        )


class RunnerExecutor(AutomationExecutor):
    name = 'ansible-runner'

    def available(self):
        try:
            import ansible_runner  # noqa: F401
            return shutil.which('ansible-playbook') is not None
        except Exception:  # noqa: BLE001
            return False

    def run(self, *, playbook_body, inventory, variables, private_data_dir,
            event_handler, cancel_check=None, check_mode=False, options=None):
        import ansible_runner

        options = options or {}
        project = os.path.join(private_data_dir, 'project')
        env_dir = os.path.join(private_data_dir, 'env')
        os.makedirs(project, exist_ok=True)
        os.makedirs(env_dir, exist_ok=True)

        playbook_path = os.path.join(project, 'playbook.yml')
        with open(playbook_path, 'w') as fh:
            fh.write(playbook_body)
        with open(os.path.join(private_data_dir, 'inventory'), 'w') as fh:
            fh.write(inventory)
        with open(os.path.join(env_dir, 'extravars'), 'w') as fh:
            json.dump(variables or {}, fh)

        stats = {'ok': 0, 'changed': 0, 'failed': 0, 'unreachable': 0, 'skipped': 0}

        def _handle(event):
            event_handler(event)
            data = event.get('event_data', {}) or {}
            if event.get('event') == 'playbook_on_stats':
                for key in stats:
                    stats[key] = sum((data.get(key) or {}).values())

        cmdline = ['--check'] if check_mode else []
        if options.get('diff'):
            cmdline.append('--diff')
        if options.get('serial'):
            cmdline += ['--forks', str(options.get('forks', 5))]

        runner = ansible_runner.run(
            private_data_dir=private_data_dir,
            playbook='playbook.yml',
            inventory=os.path.join(private_data_dir, 'inventory'),
            extravars=variables or {},
            cmdline=' '.join(cmdline) or None,
            event_handler=_handle,
            cancel_callback=cancel_check or (lambda: False),
            quiet=True,
        )
        return {'status': runner.status, 'rc': runner.rc, 'stats': stats}


_EXECUTOR = None


def get_executor():
    global _EXECUTOR
    if _EXECUTOR is None:
        candidate = RunnerExecutor()
        _EXECUTOR = candidate if candidate.available() else NullExecutor()
        logger.info('automation executor: %s', _EXECUTOR.name)
    return _EXECUTOR


def reset_executor():
    global _EXECUTOR
    _EXECUTOR = None


def set_executor(executor):
    """Test hook."""
    global _EXECUTOR
    _EXECUTOR = executor


class TempDataDir:
    """Rootless, resource-limited private data directory for one run."""

    def __init__(self, base=None):
        self.base = base
        self.path = None

    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix='artemis-ansible-', dir=self.base)
        os.chmod(self.path, 0o700)
        return self.path

    def __exit__(self, *exc):
        if self.path and os.path.isdir(self.path):
            shutil.rmtree(self.path, ignore_errors=True)
        return False
