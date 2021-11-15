import logging
import re

DB_PATH = 'sogs.db'
DB_SCHEMA_FILE = 'schema.sql'

SEED_FILE = 'sogs-seed.bin'

# base url for generating links
URL_BASE = 'http://51.79.57.234:8000'

LOG_LEVEL = logging.DEBUG

# Default upload expiry, in days
UPLOAD_DEFAULT_EXPIRY_DAYS = 15

#  We truncate filenames if the sanitized name (not including the initial 'ID_') is longer than
#  this.
UPLOAD_FILENAME_MAX = 60

# When a filename exceeds _MAX, we keep this much from the beginning, append ..., and then append
# enough from the end (i.e. max - this - 3) to hit the _MAX value.
UPLOAD_FILENAME_KEEP_PREFIX = 40
UPLOAD_FILENAME_KEEP_SUFFIX = 17

# Maximum size of a file upload that we accept, in bytes.  Note that onion requests have a hard
# limit of 10MB for a fully-wrapped request, and that Session uploads with base64 encoding,
# so this is deliberately set conservatively below that limit.
UPLOAD_FILE_MAX_SIZE = 6_000_000

# Regex that matches *invalid* characters in a user-supplied filename (if any); any matches of this
# regex get replaced with a single _ when writing the file to disk.
UPLOAD_FILENAME_BAD = re.compile(r"[^\w+\-.'()@\[\]]+")

# How long without activity before we drop user-room activity info, in days
ROOM_ACTIVE_PRUNE_THRESHOLD = 60

# The default user activity cutoff that is used to report a room's current "active users" count; the
# unit is in days.
ROOM_DEFAULT_ACTIVE_THRESHOLD = 7

# How long we keep message edit/deletion history, in days
MESSAGE_HISTORY_PRUNE_THRESHOLD = 30


# file containing "bad" words for filtration
BAD_WORDS_FILE = 'badwords.txt'
