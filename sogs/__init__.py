#!/usr/bin/env python3

from . import config
import coloredlogs

coloredlogs.install(level=config.LOG_LEVEL, milliseconds=True, isatty=True)

from . import db
from . import routes
from . import onion_request
from . import legacy_routes
from .web import app
from . import cleanup
