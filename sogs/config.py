import configparser
import os
import re
import logging
import coloredlogs

logger = logging.getLogger("config")

# Set up colored logging; we come back to set the level once we know it
coloredlogs.install(milliseconds=True, isatty=True, logger=logger)

# Default config settings; most of these are configurable via config.ini (see it for details).
DB_URL = 'sqlite:///sogs.db'
KEY_FILE = 'key_x25519'
URL_BASE = 'http://example.net'
HTTP_SHOW_INDEX = True
HTTP_SHOW_RECENT = True
OMQ_LISTEN = 'tcp://*:22028'
OMQ_INTERNAL = 'ipc://./omq.sock'
LOG_LEVEL = 'WARNING'
DM_EXPIRY_DAYS = 15
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
PROFANITY_FILTER = False
PROFANITY_SILENT = True
PROFANITY_CUSTOM = None
REQUIRE_BLIND_KEYS = False
TEMPLATE_PATH = 'templates'
STATIC_PATH = 'static'
UPLOAD_PATH = 'uploads'

# Will be true if we're running as a uwsgi app, false otherwise; used where we need to do things
# only in one case or another (e.g. database initialization only via app mode).
RUNNING_AS_APP = False
try:
    import uwsgi  # noqa: F401

    RUNNING_AS_APP = True
except ImportError:
    pass


def load_config():
    if 'SOGS_CONFIG' in os.environ:
        conf_ini = os.environ['SOGS_CONFIG']
        if conf_ini and not os.path.exists(conf_ini):
            raise RuntimeError(f"SOGS_CONFIG={conf_ini} specified, but path does not exist!")
    else:
        conf_ini = 'sogs.ini'
        if not os.path.exists(conf_ini):
            logger.info("sogs.ini does not exist; using all config defaults")
            conf_ini = None

    if not conf_ini:
        return

    logger.info(f"Loading config from {conf_ini}")
    cp = configparser.ConfigParser()
    cp.read(conf_ini)

    # Set log level up first (we'll set it again below, mainly to log it if we have debug logging
    # enabled).
    if 'log' in cp.sections() and 'level' in cp['log']:
        logger.setLevel(cp['log']['level'])

    def path_exists(path):
        return not path or os.path.exists(path)

    def val_or_none(v):
        return v or None

    truthy = ('y', 'yes', 'Y', 'Yes', 'true', 'True', 'on', 'On', '1')
    falsey = ('n', 'no', 'N', 'No', 'false', 'False', 'off', 'Off', '0')
    booly = truthy + falsey

    def bool_opt(name):
        return (name, lambda x: x in booly, lambda x: x in truthy)

    # Map of: section => { param => ('GLOBAL', test lambda, value lambda) }
    # global is the string name of the global variable to set
    # test lambda returns True/False for validation (if None/omitted, accept anything)
    # value lambda extracts the value (if None/omitted use str value as-is)
    setting_map = {
        'db': {
            'url': ('DB_URL', lambda x: x.startswith('sqlite:///') or x.startswith('postgresql'))
        },
        'crypto': {'key_file': ('KEY_FILE',)},
        'net': {
            'base_url': ('URL_BASE', lambda x: re.search('^https?://.', x)),
            'omq_listen': (
                'OMQ_LISTEN',
                lambda x: all(re.search('^(?:tcp|ipc)://.', y) for y in x.splitlines() if len(y)),
                lambda x: [y for y in x.splitlines() if len(y)],
            ),
            'omq_internal': ('OMQ_INTERNAL', lambda x: re.search('^(?:tcp|ipc)://.', x)),
            'http_show_index': bool_opt('HTTP_SHOW_INDEX'),
            'http_show_recent': bool_opt('HTTP_SHOW_RECENT'),
        },
        'files': {
            'expiry': ('UPLOAD_DEFAULT_EXPIRY_DAYS', None, float),
            'max_size': ('UPLOAD_FILE_MAX_SIZE', None, int),
            'uploads_dir': ('UPLOAD_PATH', path_exists, val_or_none),
        },
        'rooms': {
            'active_threshold': ('ROOM_DEFAULT_ACTIVE_THRESHOLD', None, float),
            'active_prune_threshold': ('ROOM_ACTIVE_PRUNE_THRESHOLD', None, float),
        },
        'direct_messages': {'expiry': ('DM_EXPIRY_DAYS', None, float)},
        'users': {'require_blind_keys': bool_opt('REQUIRE_BLIND_KEYS')},
        'messages': {
            'history_prune_threshold': ('MESSAGE_HISTORY_PRUNE_THRESHOLD', None, float),
            'profanity_filter': bool_opt('PROFANITY_FILTER'),
            'profanity_silent': bool_opt('PROFANITY_SILENT'),
            'profanity_custom': ('PROFANITY_CUSTOM', path_exists, val_or_none),
        },
        'web': {
            'template_path': ('TEMPLATE_PATH', path_exists, val_or_none),
            'static_path': ('STATIC_PATH', path_exists, val_or_none),
        },
        'log': {'level': ('LOG_LEVEL',)},
    }

    for s in cp.sections():
        if s not in setting_map:
            logger.warning(f"Ignoring unknown section [{s}] in {conf_ini}")
            continue
        for opt in cp[s]:
            if opt not in setting_map[s]:
                logger.warning(f"Ignoring unknown config setting [{s}].{opt} in {conf_ini}")
                continue

            value = cp[s][opt]
            conf = setting_map[s][opt]

            assert isinstance(conf, tuple) and 1 <= len(conf) <= 3
            assert conf[0] in globals()

            logger.debug(f"Loaded config setting [{s}].{opt}={value}")

            if len(conf) >= 2 and conf[1]:
                if not conf[1](value):
                    raise RuntimeError(f"Invalid value [{s}].{opt}={value} in {conf_ini}")

            if len(conf) >= 3 and conf[2]:
                value = conf[2](value)

            logger.debug(f"Set config.{conf[0]} = {value}")
            globals()[conf[0]] = value


try:
    load_config()
except Exception as e:
    logger.critical(f"Failed to load config: {e}")
    raise
