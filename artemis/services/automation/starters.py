"""Built-in, versioned starter playbooks (P5-E).

Each starter is registered by id + version and its body ships in the package.
Launching one just feeds its content through the normal content pipeline (so it
is content-addressed and validated like anything else).
"""

import os

_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                    'automation_playbooks')

STARTERS = {
    'linux-fact-refresh': {'version': 1, 'file': 'linux_fact_refresh.yml',
                           'platform': 'linux', 'description': 'Gather facts and summarize OS + packages'},
    'linux-update-preview': {'version': 1, 'file': 'linux_update_preview.yml',
                             'platform': 'linux', 'description': 'List pending updates without applying'},
    'linux-package-update': {'version': 1, 'file': 'linux_package_update.yml',
                             'platform': 'linux', 'description': 'Batched OS package update (serial rollout)'},
    'linux-controlled-reboot': {'version': 1, 'file': 'linux_controlled_reboot.yml',
                                'platform': 'linux', 'description': 'Reboot with return-to-service validation'},
    'linux-service-control': {'version': 1, 'file': 'linux_service_control.yml',
                              'platform': 'linux', 'description': 'Start / stop / restart a systemd unit'},
    'diagnostic-bundle': {'version': 1, 'file': 'diagnostic_bundle.yml',
                          'platform': 'linux', 'description': 'Collect a bounded diagnostic snapshot'},
    'macos-fact-refresh': {'version': 1, 'file': 'macos_fact_refresh.yml',
                           'platform': 'macos', 'description': 'macOS facts + software-update / Homebrew status'},
}


def list_starters():
    return [{'id': sid, **{k: v for k, v in meta.items() if k != 'file'}}
            for sid, meta in STARTERS.items()]


def get_starter_body(starter_id):
    meta = STARTERS.get(starter_id)
    if not meta:
        return None
    with open(os.path.join(_DIR, meta['file'])) as fh:
        return fh.read()
