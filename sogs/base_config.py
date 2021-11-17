import logging
import re

# STOP: Do not make changes to this file!  This file contains defaults for the open group server and
# is intended to be replaced on upgrade.  If you want to override any changes you should instead set
# the variable you care about in `config.py`, which overrides values specified here.

# The paths we use for storage; if relative these are in the current working directory of the server
# process running sogs.
DB_PATH = 'sogs.db'
DB_SCHEMA_FILE = 'schema.sql'
KEY_FILE = 'key_x25519'

# Base url for generating links.  Can be http, https, and may or may not include a port.  Note if
# using https that you need to set up proper HTTPS certificates, for example using certbot to obtain
# a free Let's Encrypt certificate.
URL_BASE = 'http://example.net'

# The log level.
LOG_LEVEL = logging.WARNING

# Default upload expiry time, in days.
UPLOAD_DEFAULT_EXPIRY_DAYS = 15

# We truncate filenames if the sanitized name (not including the initial 'ID_') is longer than this.
UPLOAD_FILENAME_MAX = 60

# When a filename exceeds UPLOAD_FILENAME_MAX, we keep this many characters from the beginning,
# append "...", and then append enough from the end (i.e. max - this - 3) to hit the _MAX value.
UPLOAD_FILENAME_KEEP_PREFIX = 40
UPLOAD_FILENAME_KEEP_SUFFIX = 17

# Maximum size of a file upload that we accept, in bytes.  Note that onion requests have a hard
# limit of 10MB for a fully-wrapped request, and that Session uploads with base64 encoding,
# so this is deliberately set conservatively below that limit.
UPLOAD_FILE_MAX_SIZE = 6_000_000

# Regex that matches *invalid* characters in a user-supplied filename (if any); any matches of this
# regex get replaced with a single _ when writing the file to disk.  The default is intended to
# strip out enough so that the filename is storable portably on modern OS filesystems.
UPLOAD_FILENAME_BAD = re.compile(r"[^\w+\-.'()@\[\]]+")

# How long without activity before we drop user-room activity info, in days.
ROOM_ACTIVE_PRUNE_THRESHOLD = 60

# The default user activity cutoff that is used to report a room's current "active users" count; the
# unit is in days.
ROOM_DEFAULT_ACTIVE_THRESHOLD = 7

# How long we keep message edit/deletion history, in days.
MESSAGE_HISTORY_PRUNE_THRESHOLD = 30

# dev import testing option, to be removed in the future
IMPORT_ADJUST_MS = 0

# file containing "bad" words for filtration.  This feature in temporary and will be removed once
# more robust bot/spam filtering is available.
BAD_WORDS_FILE = 'badwords.txt'
