from .utils import message_body
from . import config
import os


def should_drop_message_with_body(body):
    body = message_body(body)
    """return true if we should drop a message given its body"""
    if os.path.exists(config.BAD_WORDS_FILE):
        with open(config.BAD_WORDS_FILE, 'r') as f:
            for line in f:
                word = line.rstrip()
                if word in body:
                    return True
    return False
