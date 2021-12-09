import configparser
import os
import re
import logging
import coloredlogs

from .web import app

# Set up colored logging; we come back to set the level once we know it
coloredlogs.install(level='NOTSET', milliseconds=True, isatty=True)

# Default config settings; most of these are configurable via config.ini (see it for details).
DB_PATH = 'sogs.db'
DB_SCHEMA_FILE = 'schema.sql'
KEY_FILE = 'key_x25519'
URL_BASE = 'http://example.net'
HTTP_SHOW_RECENT = True
OMQ_LISTEN = 'tcp://*:22028'
OMQ_INTERNAL = 'ipc://./omq.sock'
LOG_LEVEL = 'WARNING'
UPLOAD_DEFAULT_EXPIRY_DAYS = 15
UPLOAD_FILENAME_MAX = 60
UPLOAD_FILENAME_KEEP_PREFIX = 40
UPLOAD_FILENAME_KEEP_SUFFIX = 17
UPLOAD_FILE_MAX_SIZE = 6_000_000
UPLOAD_FILENAME_BAD = re.compile(r"[^\w+\-.'()@\[\]]+")
ROOM_ACTIVE_PRUNE_THRESHOLD = 60
ROOM_DEFAULT_ACTIVE_THRESHOLD = 7
MESSAGE_HISTORY_PRUNE_THRESHOLD = 30
IMPORT_ADJUST_MS = 0
BAD_WORDS_FILE = 'badwords.txt' if os.path.exists('badwords.txt') else None


def load_config():
    if 'SOGS_CONFIG' in os.environ:
        conf_ini = os.environ['SOGS_CONFIG']
        if conf_ini and not os.path.exists(conf_ini):
            raise RuntimeError(f"SOGS_CONFIG={conf_ini} specified, but path does not exist!")
    else:
        conf_ini = 'sogs.ini'
        if not os.path.exists(conf_ini):
            app.logger.info("sogs.ini does not exist; using all config defaults")
            conf_ini = None

    if not conf_ini:
        return

    app.logger.info(f"Loading config from {conf_ini}")
    cp = configparser.ConfigParser()
    cp.read(conf_ini)

    # Set log level up first (we'll set it again below, mainly to log it if we have debug logging
    # enabled).
    if 'log' in cp.sections() and 'level' in cp['log']:
        app.logger.setLevel(cp['log']['level'])

    # Map of: section => { param => ('GLOBAL', test lambda, value lambda) }
    # global is the string name of the global variable to set
    # test lambda returns True/False for validation (if None/omitted, accept anything)
    # value lambda extracts the value (if None/omitted use str value as-is)
    setting_map = {
        'db': {'url': ('DB_PATH', lambda x: x.startswith('sqlite:///'), lambda x: x[10:])},
        'crypto': {'key_file': ('KEY_FILE',)},
        'net': {
            'base_url': ('URL_BASE', lambda x: re.search('^https?://.', x)),
            'omq_listen': (
                'OMQ_LISTEN',
                lambda x: all(re.search('^(?:tcp|ipc)://.', y) for y in x.splitlines() if len(y)),
                lambda x: [y for y in x.splitlines() if len(y)],
            ),
            'omq_internal': ('OMQ_INTERNAL', lambda x: re.search('^(?:tcp|ipc)://.', x)),
            'http_show_recent': (
                'HTTP_SHOW_RECENT',
                lambda x: x in ('yes', 'no'),
                lambda x: x == 'yes',
            ),
        },
        'files': {
            'expiry': ('UPLOAD_DEFAULT_EXPIRY_DAYS', None, float),
            'max_size': ('UPLOAD_FILE_MAX_SIZE', None, int),
        },
        'rooms': {
            'active_threshold': ('ROOM_DEFAULT_ACTIVE_THRESHOLD', None, float),
            'active_prune_threshold': ('ROOM_ACTIVE_PRUNE_THRESHOLD', None, float),
        },
        'messages': {
            'history_prune_threshold': ('MESSAGE_HISTORY_PRUNE_THRESHOLD', None, float),
            'bad_words': ('BAD_WORDS_FILE', os.path.exists),
        },
        'log': {'level': ('LOG_LEVEL',)},
    }

    for s in cp.sections():
        if s not in setting_map:
            app.logger.warning(f"Ignoring unknown section [{s}] in {conf_ini}")
            continue
        for opt in cp[s]:
            if opt not in setting_map[s]:
                app.logger.warning(f"Ignoring unknown config setting [{s}].{opt} in {conf_ini}")
                continue

            value = cp[s][opt]
            conf = setting_map[s][opt]

            assert isinstance(conf, tuple) and 1 <= len(conf) <= 3
            assert conf[0] in globals()

            app.logger.debug(f"Loaded config setting [{s}].{opt}={value}")

            if len(conf) >= 2 and conf[1]:
                if not conf[1](value):
                    raise RuntimeError(f"Invalid value [{s}].{opt}={value} in {conf_ini}")

            if len(conf) >= 3 and conf[2]:
                value = conf[2](value)

            app.logger.debug(f"Set config.{conf[0]} = {value}")
            globals()[conf[0]] = value


try:
    load_config()
    app.logger.setLevel(LOG_LEVEL)
except Exception as e:
    app.logger.critical(f"Failed to load config: {e}")
    raise
