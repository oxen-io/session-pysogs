from __future__ import annotations
from .. import config, crypto, session_pb2 as protobuf
import random

from .. import crypto, config
from ..db import query
from ..hashing import blake2b
from nacl.signing import SigningKey
from .exc import PostRejected
from sogs.model.user import User
from sogs.model.room import Room, alphabet_filter_patterns
from sogs.model.post import Post

import time


class SimpleFilter:
    """
    Class representing a simple word filter searching for naughty words

    Object Properties:
        bot - bot this filter is servicing
        current_message - reference to current data being analyzed
    """

    def __init__(self):
        self.current_message: Post = None

    def filtering(self):
        settings = {
            'profanity_filter': config.PROFANITY_FILTER,
            'profanity_silent': config.PROFANITY_SILENT,
            'alphabet_filters': config.ALPHABET_FILTERS,
            'alphabet_silent': config.ALPHABET_SILENT,
        }
        if self.token in config.ROOM_OVERRIDES:
            for k in (
                'profanity_filter',
                'profanity_silent',
                'alphabet_filters',
                'alphabet_silent',
            ):
                if k in config.ROOM_OVERRIDES[self.token]:
                    settings[k] = config.ROOM_OVERRIDES[self.token][k]
        return settings

    def filter_should_reply(self, filter_type, filter_lang, room: Room):
        """If the settings say we should reply to a filter, this returns a tuple of

        (profile name, message format, whisper)

        where profile name is the name we should use in the reply, message format is a string with
        substitutions ready, and whisper is True/False depending on whether it should be whispered
        to the user (True) or public (False).

        If we shouldn't reply this returns (None, None, None)
        """

        if not config.FILTER_SETTINGS:
            return (None, None, None)

        reply_format = None
        profile_name = 'SOGS'
        public = False

        # Precedences from least to most specific so that we load values from least specific first
        # then overwrite them if we find a value in a more specific section
        room_precedence = ('*', room.token)
        filter_precedence = ('*', filter_type, filter_lang) if filter_lang else ('*', filter_type)

        for r in room_precedence:
            s1 = config.FILTER_SETTINGS.get(r)
            if s1 is None:
                continue
            for f in filter_precedence:
                settings = s1.get(f)
                if settings is None:
                    continue

                rf = settings.get('reply')
                pn = settings.get('profile_name')
                pb = settings.get('public')
                if rf is not None:
                    reply_format = random.choice(rf)
                if pn is not None:
                    profile_name = pn
                if pb is not None:
                    public = pb

        return (reply_format, profile_name, public)

    def read_message(self, user: User, data: bytes, room: Room):
        """
        Checks a message for disallowed alphabets and profanity (if the profanity
        filter is enabled).

        - Returns None if this message passes (i.e. didn't trigger any filter, or is
          being posted by an admin to whom the filters don't apply).

        - Returns a callback if the message fails but should be silently accepted.  The callback
          should be called (with no arguments) *after* the filtered message is inserted into the db.

        - Throws PostRejected if the message should be rejected (and rejection passed back to the
          user)
        """

        if not data:
            raise ValueError('No message data passed to filter')

        self.current_message = Post(raw=data)

        if not config.FILTER_MODS and self.check_moderator(user):
            return None

        filt = self.filtering()
        alphabets = filt['alphabet_filters']
        for lang, pattern in alphabet_filter_patterns:
            if lang not in alphabets:
                continue

            if not pattern.search(self.current_message().text):
                continue

            # Filter it!
            filter_type, filter_lang = 'alphabet', lang
            break

        if not filter_type and filt['profanity_filter']:
            import better_profanity

            for part in (self.current_message().text, self.current_message().username):
                if better_profanity.profanity.contains_profanity(part):
                    filter_type = 'profanity'
                    break

        if not filter_type:
            return None

        silent = filt[filter_type + '_silent']

        msg_fmt, prof_name, pub = self.filter_should_reply(filter_type, filter_lang)
        if msg_fmt:
            pbmsg = protobuf.Content()
            body = msg_fmt.format(
                profile_name=(
                    user.session_id
                    if self.current_message().username is None
                    else self.current_message().username
                ),
                profile_at="@" + user.session_id,
                room_name=self.name,
                room_token=self.token,
            ).encode()
            pbmsg.dataMessage.body = body
            pbmsg.dataMessage.timestamp = int(time.time() * 1000)
            pbmsg.dataMessage.profile.displayName = prof_name

            # Add two bytes padding so that session doesn't get confused by a lack of padding
            pbmsg = pbmsg.SerializeToString() + b'\x80\x00'

            # Make a fake signing key based on prof_name and the server privkey (so that different
            # names use different keys; otherwise the bot names overwrite each other in Session
            # clients when a later message has a new profile name).
            global filter_privkeys
            if prof_name in room.filter_privkeys:
                signingkey = filter_privkeys[prof_name]
            else:
                signingkey = SigningKey(
                    blake2b(
                        prof_name.encode() + crypto.server_signkey.encode(), key=b'sogsfiltering'
                    )
                )
                filter_privkeys[prof_name] = signingkey

            sig = signingkey.sign(pbmsg).signature
            server_fake_user = User(
                session_id='15' + signingkey.verify_key.encode().hex(), autovivify=True, touch=False
            )

            def insert_reply():
                query(
                    """
                    INSERT INTO messages
                        (room, "user", data, data_size, signature, whisper)
                        VALUES
                        (:r, :u, :data, :data_size, :signature, :whisper)
                    """,
                    r=room.id,
                    u=server_fake_user.id,
                    data=pbmsg[:-2],
                    data_size=len(pbmsg),
                    signature=sig,
                    whisper=None if pub else user.id,
                )

            if filt[filter_type + '_silent']:
                # Defer the insertion until after the filtered row gets inserted
                return insert_reply
            else:
                insert_reply()

        elif silent:
            return lambda: None

        # TODO: can we send back some error code that makes Session not retry?
        raise PostRejected(f"filtration rejected message ({filter_type})")
