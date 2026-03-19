#!/usr/bin/env python3
"""Artemis entry point — run with: python run.py"""

import os

from artemis import create_app
from artemis.extensions import socketio

app = create_app()

if __name__ == '__main__':
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5005))
    socketio.run(app, host=host, port=port, debug=debug)
