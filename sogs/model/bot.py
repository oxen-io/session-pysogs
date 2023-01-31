from __future__ import annotations

from .. import crypto, db, config
from ..db import query
from ..web import app
from .exc import NoSuchUser, BadPermission
from sogs.model.user import User
from .exc import (InvalidData)

from typing import Optional, List
import time
import contextlib


class Bot:
    """
    Class representing a simple bot to manage open group server

    Object Properties:
        id - database primary key for user row
        session_id - jex encoded session_id of the bot
        banned - default to false
        global_admin - default to true for bot
        global_moderator - default to true for bot
        visible_mod - default to true for bot
    """

    def __init__(
        self,
        row = None,
        *,
        id: Optional[int] = None,
        session_id: Optional[int] = None) -> None:

        # immutable attributes
        self._banned = False
        self._global_admin = False
        self._global_moderator = False
        self._visible_mod = False

        # operational attributes
        self.current_message = None
        self.nlp_model = None
        self.language = "English"
        self.word_blacklist = ['placeholderlist', 'until', 'we', 'decide', 'naughty', 'words']


    def __setattr__(self, __name: str, __value) -> None:
        if __name in ['_banned', '_global_admin', '_global_moderator', '_visible_mod']:
            raise AttributeError("Cannot modify bots")
        else:
            setattr(self, __name, __value)

    def __delattr__(self, __name: str) -> None:
        if __name in ['_banned', '_global_admin', '_global_moderator', '_visible_mod']:
            raise AttributeError("Cannot modify bots")
        else:
            delattr(self, __name)

    def receive_message(self,  
        user: User,
        data: bytes,
        sig: bytes,
        *,
        files: List[int] = []):

        if data is None or sig is None or len(sig) != 64:
            raise InvalidData()

        