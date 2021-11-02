#!/usr/bin/env python3

from . import routes
from . import onion_request
from .web import app

import coloredlogs
coloredlogs.install(level=config.LOG_LEVEL, milliseconds=True, isatty=True)
