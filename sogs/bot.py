import oxenmq
from oxenc import bt_deserialize, bt_serialize
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey
import nacl.bindings as sodium
from datetime import timedelta
from time import time
from sogs.model.post import Post


class Bot:

    FILTER_ACCEPT = "OK"
    FILTER_REJECT = "REJECT"
    FILTER_REJECT_SILENT = "SILENT"
    FILTER_RESPONSES = (FILTER_ACCEPT, FILTER_REJECT, FILTER_REJECT_SILENT)

    def __init__(self, sogs_address, sogs_pubkey, privkey, pubkey, display_name, *args):
        if privkey is None or pubkey is None:
            raise Exception("SOGS Bot must have x25519 keys")

        self.display_name = display_name
        self.privkey = privkey
        self.pubkey = pubkey
        self.sogs_address = sogs_address
        self.sogs_pubkey = sogs_pubkey
        self.x_priv = sodium.crypto_sign_ed25519_sk_to_curve25519(self.privkey + self.pubkey)
        self.x_pub = sodium.crypto_sign_ed25519_pk_to_curve25519(self.pubkey)
        print(f"x_pub: {self.x_pub.hex()}")
        self.omq = oxenmq.OxenMQ(
            privkey=self.x_priv, pubkey=self.x_pub, log_level=oxenmq.LogLevel.debug
        )

        # FIXME: do we *care* to blind bots, or would it be useful/preferable to be able to identify
        #        bots on multiple SOGS as the same?
        from session_util import blinding

        blind25_keypair = blinding.blind25_key_pair(privkey, sogs_pubkey)
        self.blind25_pub = blind25_keypair.pubkey
        self.blind25_priv = blind25_keypair.privkey
        blind15_keypair = blinding.blind15_key_pair(privkey, sogs_pubkey)
        self.blind15_pub = blind15_keypair.pubkey
        self.blind15_priv = blind15_keypair.privkey

        self.session_id = '15' + self.blind15_pub.hex()

        self.last_post_time = 0

        cat = self.omq.add_category("bot", access_level=oxenmq.AuthLevel.none)
        cat.add_request_command("filter_message", self.filter_message)
        cat.add_command("message_posted", self.message_posted)
        cat.add_command("reaction_posted", self.reaction_posted)

        self.pre_slash_handlers = {}
        self.post_slash_handlers = {}
        cat.add_request_command("pre_message_command", self.pre_message_command)
        cat.add_request_command("post_message_command", self.post_message_command)

        self.request_read_handler = None
        cat.add_request_command("request_read", self.request_read)

        self.running = False

    def finish_init(self):
        pre_commands = list(self.pre_slash_handlers.keys())
        post_commands = self.post_slash_handlers.keys()
        if self.request_read_handler:
            pre_commands.append('/request_read')
        if len(pre_commands):
            print(f"calling register_pre_command with commands: {pre_commands}")
            self.omq.send(
                self.conn, "bot.register_pre_commands", bt_serialize({'commands': pre_commands})
            )
        if len(post_commands):
            print(f"calling register_post_command with commands: {post_commands}")
            self.omq.send(
                self.conn,
                "bot.register_post_commands",
                bt_serialize({'commands': list(post_commands)}),
            )

    def say_hello(self):
        try:
            resp = bt_deserialize(
                self.omq.request_future(
                    self.conn,
                    "bot.hello",
                    bt_serialize(self.session_id),
                    request_timeout=timedelta(seconds=1),
                ).get()[0]
            )
            if resp == b'OK':
                return
            elif resp == b"REGISTER":
                self.finish_init()
                self.running = True
                return

            print(f"Bot hello error from sogs: {resp}")
        except Exception as e:
            print(f"Exception in bot hello: {e}")

    def run(self):
        self.omq.start()
        self.conn = self.omq.connect_remote(oxenmq.Address(self.sogs_address, self.sogs_pubkey))

        self.say_hello()

        # FIXME: there's definitely a better way to do this, but if SOGS restarts and
        #        we reconnect, this makes SOGS recognize our omq connection as this bot.
        count = 0
        while True:
            count += 1
            if count % 60 == 0:
                self.say_hello()
            from time import sleep

            sleep(1)

    def register_request_read_handler(self, handler):
        """
        If a user attempts to read a room but has only "access" to the room, this will be called
        (if registered).

        Currently SOGS does nothing with the response from this request, but responding signals
        the bot is done handling it.  This is so SOGS waits to respond to that user until e.g.
        the bot has had the chance to whisper the user (so the user will see the whisper right away).
        Any return value from the handler will be ignored until SOGS has use for it.
        """
        self.request_read_handler = handler

        # if not running, finish_init() will do this once connected
        if self.running:
            self.omq.send(
                self.conn, f"bot.register_pre_commands", bt_serialize({"commands": [command]})
            )

    def handle_message_command(self, m: oxenmq.Message, pre_command: bool):
        req = bt_deserialize(m.dataview()[0])
        msg = Post(raw=req[b"message_data"])

        command_parts = msg.text.split(' ')
        if not command_parts:
            # shouldn't be possible, but false just to signal it happened
            return bt_serialize(False)

        command = command_parts[0]
        command_container = self.pre_slash_handlers if pre_command else self.post_slash_handlers

        if not command in command_container:
            return bt_serialize(True)

        try:
            retval = command_container[command](req, command_parts)
            if not isinstance(retval, bool):
                print("command handlers must return True or False")
                return bt_serialize(True)
            return bt_serialize(retval)
        except Exception as e:
            print(f"Exception handling slash command: {e}")
            return bt_serialize(True)

    def pre_message_command(self, m: oxenmq.Message):
        return self.handle_message_command(m, True)

    def post_message_command(self, m: oxenmq.Message):
        return self.handle_message_command(m, False)

    def request_read(self, m: oxenmq.Message):
        req = bt_deserialize(m.dataview()[0])
        # this should not be called by sogs if we didn't register it...
        if not self.request_read_handler:
            return bt_serialize(False)
        try:
            self.request_read_handler(req)
        except Exception as e:
            print(f"Exception in request_read handler: {e}")
        return bt_serialize(True)

    def register_command(self, command, handler, pre_command: bool):
        """
        Registers a slash command with sogs.  `handler` will be invoked with the arguments
        from sogs as a dictionary, including "command": command.
        sogs sends commands before database insertion and after.  Use pre_message/post_message to
        indicate which you want to handle.
        Return True from your handler if sogs may continue to the next bot and/or the next step
        in message handling, False if you handled the command and it should be considered finished
        or if you wanted to handle it but there was an error and sogs should discard it.
        """
        if pre_command:
            self.pre_slash_handlers[command] = handler
        else:
            self.post_slash_handlers[command] = handler

        # if not running, finish_init() will do this once connected
        if self.running:
            command_type = "pre_commands" if pre_command else "post_commands"
            self.omq.send(
                self.conn, f"bot.register{command_type}", bt_serialize({"commands": [command]})
            )

    def register_pre_command(self, command, handler):
        self.register_command(command, handler, True)

    def register_post_command(self, command, handler):
        self.register_command(command, handler, False)

    def filter_message(self, m: oxenmq.Message):
        print(f"filter_message called")
        try:
            request = bt_deserialize(m.dataview()[0])
            resp = self.filter(request)
            if resp not in self.FILTER_RESPONSES:
                print(f"Bot.filter() must return one of {FILTER_RESPONSES}")
                return bt_serialize("REJECT")
            print(f"filter_message returning '{resp}' as filter response")
            return bt_serialize(resp)
        except Exception as e:
            print(f"Exception filtering message: {e}")
            return bt_serialize("REJECT")

    def filter(self, request):
        """
        Users may override this function for custom filtering, or supply a callable filter object

        This function must return one of FILTER_ACCEPT, FILTER_REJECT, or FILTER_REJECT_SILENT
        """
        return self.FILTER_ACCEPT

    """
    Call this from your filter() override when you want to reply to a user message,
    e.g. "hey no swearing here"
    """

    def reply(
        self,
        room_name,
        room_token,
        user_session_id,
        message_data,
        username,
        *args,
        reply_settings=None,
    ):
        from random import choice

        if not reply_settings:
            print("Bot.reply called with no reply_settings")
            return

        rf = choice(reply_settings[0])
        reply_name = reply_settings[
            1
        ]  # not used, but kept here for now to save confusion about config loading
        public = reply_settings[2]

        body = rf.format(
            profile_name=(user_session_id.decode('ascii') if username is None else username),
            profile_at="@" + user_session_id.decode('ascii'),
            room_name=room_name.decode('utf-8'),
            room_token=room_token,
        ).encode()

        self.post_message(
            room_token, body, whisper_target="" if public else user_session_id.decode('ascii')
        )

    def set_user_room_permissions(
        self,
        *,
        room_token=None,
        room_id=None,
        user_session_id=None,
        user_id=None,
        sec_from_now=None,
        **perms,
    ):
        if sec_from_now:
            if not isinstance(sec_from_now, int):
                print("future permissions must be set an integer number of seconds from now.")
                return

            if not 0 < sec_from_now < 1_000_000_000:
                print("future permissions must not be set *that* far in the future or past...")
                return

            for k in ('accessible', 'read', 'write', 'upload'):
                if k in perms and perms[k] is None:
                    print("Setting permissions to 'None' is invalid for future permission changes.")
                    return

        if not room_token and not room_id:
            print("room identifier (token or id) required for permissions changes.")
            return
        if not user_session_id and not user_id:
            print("user identifier (session_id or id) required for permissions changes.")
            return

        req = {}
        if room_token:
            req['room_token'] = room_token
        else:
            req['room_id'] = room_id
        if user_session_id:
            req['user_session_id'] = user_session_id
        else:
            req['user_id'] = user_id

        for key in ('accessible', 'read', 'write', 'upload'):
            if key in perms:
                if not isinstance(perms[key], bool) and perms[key] is not None:
                    print(f"Invalid permission change {key} -> {perms[key]}")
                    return
                req[key] = perms[key]

        print(f"req: {req}")
        if sec_from_now:
            req['in'] = sec_from_now

        return self.omq.request_future(
            self.conn,
            "bot.set_user_room_permissions",
            bt_serialize(req),
            request_timeout=timedelta(seconds=1),
        ).get()[0]

    def delete_message(self, msg_id: int):
        """
        Tells sogs to delete the specified message.
        The message must have been created by this bot.
        """
        self.omq.send(self.conn, "bot.delete_message", bt_serialize({'msg_id': msg_id}))

    def post_message(self, room_token, body, *args, whisper_target=None, no_bots=False, files=None):
        from sogs import session_pb2 as protobuf
        from time import time

        t = int(time() * 1000)
        if t == self.last_post_time:
            t += 1
        self.last_post_time = t

        pbmsg = protobuf.Content()
        pbmsg.dataMessage.body = body
        pbmsg.dataMessage.timestamp = t
        pbmsg.dataMessage.profile.displayName = self.display_name

        file_ids = None
        if files:
            file_ids = []
            for metadata in files:
                file_ids.append(metadata["id"])
                attachment = pbmsg.dataMessage.attachments.add()
                for key in metadata:
                    old = getattr(attachment, key) # should raise exception if not present
                    setattr(attachment, key, metadata[key])

        # Add two bytes padding so that Session doesn't get confused by a lack of padding
        # FIXME: is this necessary?  The message doesn't seem to be inserted padded as-such,
        #        nor sent directly as a reply.  Does Session expect this padding for the signature?
        pbmsg = pbmsg.SerializeToString() + b'\x80\x00'

        # FIXME: make this use 25-blinding when Session is ready
        from session_util.blinding import blind15_sign

        sig = blind15_sign(self.privkey, self.sogs_pubkey, pbmsg)

        return self.inject_message(
            room_token, self.session_id, pbmsg, sig, whisper_target=whisper_target, no_bots=no_bots, files=file_ids
        )

    # This can be used either to post a message from the bot *or* to re-inject a now-approved user message
    # Pass whisper_target=session_id if the message is a whisper to a user
    # Pass whisper_mods="yes" if the message is a mod whisper
    def inject_message(
        self,
        room_token,
        session_id,
        message,
        sig,
        *args,
        whisper_target=None,
        whisper_mods=False,
        no_bots=False,
        files=None,
    ):
        req = {
            "room_token": room_token,
            "session_id": session_id,
            "message": message,
            "sig": sig,
            "whisper_mods": whisper_mods,
        }

        if whisper_target:
            req["whisper_target"] = whisper_target

        if no_bots:
            req["no_bots"] = True

        if files:
            req["files"] = files

        resp = bt_deserialize(
            self.omq.request_future(
                self.conn, "bot.message", bt_serialize(req), request_timeout=timedelta(seconds=1)
            ).get()[0]
        )
        if not b'msg_id' in resp:
            return None
        msg_id = resp[b'msg_id']
        print(f"message injected, id: {msg_id}")
        return msg_id

    def post_reactions(self, room_token, msg_id, *reactions):
        req = {"room_token": room_token, "msg_id": msg_id, "reactions": reactions}
        print(f"post_reactions request: {req}")
        return bt_deserialize(
            self.omq.request_future(
                self.conn,
                "bot.post_reactions",
                bt_serialize(req),
                request_timeout=timedelta(seconds=1),
            ).get()[0]
        )

    def upload_file(self, file_path, room_token, display_filename=None):
        try:
            from os import path
            filename = display_filename if display_filename else path.basename(file_path)


            from pathlib import Path
            file_contents = Path(file_path).read_bytes()

            req = {"filename": filename, "file_contents": file_contents, "room_token": room_token}

            resp = bt_deserialize(
                self.omq.request_future(
                    self.conn,
                    "bot.upload_file",
                    bt_serialize(req),
                    request_timeout=timedelta(seconds=3),
                ).get()[0]
            )

            if not (b"file_id" in resp and b"url" in resp):
                print(f"file_id or url missing from sogs response to upload_file")
                return None

            metadata = {}
            metadata["fileName"] = filename
            metadata["id"] = resp[b"file_id"]
            metadata["url"] = resp[b"url"].decode("utf-8")
            metadata["size"] = len(file_contents)

            import magic
            mime = magic.from_file(file_path, mime=True)
            metadata["contentType"] = mime
            if mime.startswith("image"):
                from exif import Image
                img = Image(file_contents)
                if img.has_exif:
                    metadata["width"] = img.pixel_x_dimension
                    metadata["height"] = img.pixel_y_dimension

            return metadata

        except Exception as e:
            print(f"upload_file exception: {e}")
            return None

    def message_posted(self, m: oxenmq.Message):
        print(f"message_posted called")
        try:
            msg = bt_deserialize(m.dataview()[0])
            print(f"message: {msg}")
        except Exception as e:
            print(f"Exception: {e}")

    def reaction_posted(self, m: oxenmq.Message):
        print(f"reaction_posted called")
        try:
            reaction = bt_deserialize(m.dataview()[0])
            print(f"reaction: {reaction}")
        except Exception as e:
            print(f"Exception: {e}")


def profanity_check(*args):
    import better_profanity

    for part in args:
        if better_profanity.profanity.contains_profanity(part):
            print(f"Profanity detected in message part: \"{part}\"")
            return True

    return False


class SogsFilterBot(Bot):
    import re

    # Character ranges for different filters.  This is ordered because some are subsets of each other
    # (e.g. persian is a subset of the arabic character range).
    alphabet_filter_patterns = [
        (
            'persian',
            re.compile(
                r'[\u0621-\u0628\u062a-\u063a\u0641-\u0642\u0644-\u0648\u064e-\u0651\u0655'
                r'\u067e\u0686\u0698\u06a9\u06af\u06be\u06cc]'
            ),
        ),
        (
            'arabic',
            re.compile(r'[\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff\ufb50-\ufdff\ufe70-\ufefe]'),
        ),
        ('cyrillic', re.compile(r'[\u0400-\u04ff]')),
        ('debug', re.compile(r'debug alphabet test')),
    ]

    """
    Handles profanity filtering and alphabet detection/direction (replacing the functionality
            which was previously built into SOGS directly).

    Pass config_file=path_to_sogs.ini or config_file=True to load config from
    environment SOGS_CONFIG variable or 'sogs.ini' in pwd

    Pass reply_name to override the default Session display name of this bot (SOGSBot)
    """

    def __init__(self, privkey, pubkey, *args, display_name="SOGSBot", config_file=None):

        self.room_settings = {}
        self.filter_mods = False

        if isinstance(config_file, str):
            import os

            os.environ['SOGS_CONFIG'] = config_file

        from sogs import config

        self.config = config
        from sogs.crypto import server_pubkey_bytes

        sogs_pubkey = server_pubkey_bytes
        sogs_address = config.OMQ_LISTEN[0].replace('*', '127.0.0.1')
        self.from_sogs_config = True
        self.load_sogs_settings()

        Bot.__init__(self, sogs_address, sogs_pubkey, privkey, pubkey, display_name)

    def load_sogs_settings(self):
        self.filter_mods = self.config.FILTER_MODS
        settings = {
            'profanity_filter': self.config.PROFANITY_FILTER,
            'profanity_silent': self.config.PROFANITY_SILENT,
            'alphabet_filters': self.config.ALPHABET_FILTERS,
            'alphabet_silent': self.config.ALPHABET_SILENT,
            'reply_settings': None,
        }
        self.room_settings['*'] = {}
        for k in self.config.FILTER_SETTINGS:
            if (
                'profanity' in self.config.FILTER_SETTINGS[k]
                or '*' in self.config.FILTER_SETTINGS[k]
            ):
                self.room_settings[k] = {}

        for k in settings:
            for room in self.room_settings:
                self.room_settings[room][k] = settings[k]

        print(f"overrides:\n{self.config.ROOM_OVERRIDES}\n")
        for room_token in self.config.ROOM_OVERRIDES:
            self.room_settings[room_token] = {}
            for k in settings:
                self.room_settings[room_token][k] = settings[k]
            for k in (
                'profanity_filter',
                'profanity_silent',
                'alphabet_filters',
                'alphabet_silent',
            ):
                if k in self.config.ROOM_OVERRIDES[room_token]:
                    self.room_settings[room_token][k] = self.config.ROOM_OVERRIDES[room_token][k]

        print(self.room_settings)

    def get_reply_settings(self, room_token, *args, filter_type='profanity', filter_lang=None):
        if not self.config.FILTER_SETTINGS:
            return None

        reply_format = None
        profile_name = 'SOGS'
        public = False

        # Precedences from least to most specific so that we load values from least specific first
        # then overwrite them if we find a value in a more specific section
        room_precedence = ('*', room_token)
        filter_precedence = ('*', filter_type, filter_lang) if filter_lang else ('*', filter_type)

        for r in room_precedence:
            s1 = self.config.FILTER_SETTINGS.get(r)
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
                    reply_format = rf
                if pn is not None:
                    profile_name = pn
                if pb is not None:
                    public = pb

        if reply_format is None:
            return None

        return (reply_format, profile_name, public)

    def filter(self, request):
        # is_mod should be "mod" but is empty if not, so just check len
        if request[b"is_mod"] and not self.filter_mods:
            return self.FILTER_ACCEPT

        if request[b"message_id"] != -1:
            print("message filter request is an edit")

        room_token = request[b"room_token"].decode('utf-8')
        print(f"filtering for room_token: {room_token}")
        if room_token in self.room_settings:
            settings = self.room_settings[room_token]
            print("filter using room-specific settings")
        else:
            settings = self.room_settings['*']
            print("filter using global settings")

        if not (settings['profanity_filter'] or settings['alphabet_filters']):
            return self.FILTER_ACCEPT

        msg = Post(raw=request[b"message_data"])

        prof_result = self.FILTER_ACCEPT
        if settings['profanity_filter'] and profanity_check(msg.text, msg.username):
            reply_settings = self.get_reply_settings(room_token, filter_type='profanity')
            if reply_settings:
                print(f"replying with format: {reply_settings}")
                self.reply(
                    request[b"room_name"],
                    request[b"room_token"],
                    request[b"session_id"],
                    request[b"message_data"],
                    msg.username,
                    reply_settings=reply_settings,
                )
            prof_result = (
                self.FILTER_REJECT_SILENT if settings['profanity_silent'] else self.FILTER_REJECT
            )

        if not settings['alphabet_filters']:
            return prof_result

        alpha_result = self.FILTER_ACCEPT
        for lang, pattern in self.alphabet_filter_patterns:
            if lang not in settings['alphabet_filters']:
                continue

            if not pattern.search(msg.text):
                continue

            # Filter it!
            filter_type, filter_lang = 'alphabet', lang
            reply_settings = self.get_reply_settings(
                request[b"room_token"], filter_type=filter_type, filter_lang=filter_lang
            )
            if reply_settings:
                print(f"replying with format: {reply_settings}")
                self.reply(
                    request[b"room_name"],
                    request[b"room_token"],
                    request[b"session_id"],
                    request[b"message_data"],
                    msg.username,
                    reply_settings=reply_settings,
                )

            alpha_result = (
                self.FILTER_REJECT_SILENT if settings['alphabet_silent'] else self.FILTER_REJECT
            )

            break

        if alpha_result == self.FILTER_REJECT or prof_result == self.FILTER_REJECT:
            # Example of re-injecting the message later if some other approval process succeeds:
            # msg_id = self.inject_message(room_token, user_session_id, message_data, sig, whisper_target = whisper_target, whisper_mods = whisper_mods)
            return self.FILTER_REJECT
        elif alpha_result == self.FILTER_REJECT_SILENT or prof_result == self.FILTER_REJECT_SILENT:
            return self.FILTER_REJECT_SILENT

        return self.FILTER_ACCEPT


class SlashTestBot(Bot):

    def __init__(self, sogs_address, sogs_pubkey, privkey, pubkey, display_name, *args):

        Bot.__init__(self, sogs_address, sogs_pubkey, privkey, pubkey, display_name)
        self.register_pre_command('/test', self.handle_pre_slash)
        self.register_post_command('/test', self.handle_post_slash)
        self.register_pre_command('/test_handled', self.handle_pre_slash)
        self.register_post_command('/test_handled', self.handle_post_slash)
        self.register_pre_command('/get_file', self.handle_get_file)

    def handle_pre_slash(self, request, command_parts):
        print(f"slash pre-insertion command: {command_parts}")
        if command_parts[0] == '/test_handled':
            return False
        return True

    def handle_post_slash(self, request, command_parts):
        print(f"slash post-insertion command: {command_parts}")
        if command_parts[0] == '/test_handled':
            return False
        return True

    def handle_get_file(self, request, command_parts):
        print(f"/get_file pre-insertion command: {command_parts}")

        room_token = request[b'room_token']
        print(f"room_token for file upload: {room_token}")

        file_meta = self.upload_file("test.jpg", room_token)

        if not file_meta:
            print("file upload failed...")
            return False

        print(f"file upload success, file_meta: {file_meta}")

        msg_id = self.post_message(
            room_token,
            "Please work ffs!",
            no_bots=False,
            files=[file_meta,],
        )

        print(f"Success, msg_id = {msg_id}")

        return False


class PermissionBot(Bot):

    def __init__(
        self,
        sogs_address,
        sogs_pubkey,
        privkey,
        pubkey,
        display_name,
        *args,
        yes_reaction="\N{THUMBS UP SIGN}",
        no_reaction="\N{THUMBS DOWN SIGN}",
        retry_timeout=120,
        write_timeout=120,
    ):

        self.yes_reaction = yes_reaction
        self.no_reaction = no_reaction
        self.pending_requests = {}  # map {session_id : {room_token : msg_id } }
        self.retry_jail = {}
        self.retry_timeout = retry_timeout
        self.write_timeout = write_timeout

        Bot.__init__(self, sogs_address, sogs_pubkey, privkey, pubkey, display_name)
        self.register_request_read_handler(self.handle_request_read)

    def handle_request_read(self, req):
        room_token = req[b'room_token']
        session_id = req[b'session_id']
        if session_id in self.retry_jail:
            if time() > self.retry_jail[session_id]:
                del self.retry_jail[session_id]
            else:
                return bt_serialize("JAIL")

        if session_id in self.pending_requests and room_token in self.pending_requests[session_id]:
            return bt_serialize("OK")
        print(f"request_read from {session_id}, id={req[b'user_id']}, room={room_token}")
        msg_id = self.post_message(
            room_token,
            "Please react with a thumbs up to agree to the room rules.",
            whisper_target=session_id,
            no_bots=True,
        )
        if msg_id:
            react_resp = self.post_reactions(
                room_token, msg_id, self.yes_reaction, self.no_reaction
            )
            if b'error' in react_resp:
                print(f"Error adding reactions to whisper: {react_resp[b'error']}")
                return bt_serialize("ERROR")
            if session_id not in self.pending_requests:
                self.pending_requests[session_id] = dict()
            self.pending_requests[session_id][room_token] = msg_id

        return bt_serialize("OK")

    def reaction_posted(self, m: oxenmq.Message):
        req = bt_deserialize(m.dataview()[0])
        print(f"reaction_posted, req = {req}")
        msg_id = req[b'msg_id']
        session_id = req[b'session_id']
        room_token = req[b'room_token']
        if (
            session_id in self.pending_requests
            and room_token in self.pending_requests[session_id]
            and msg_id == self.pending_requests[session_id][room_token]
        ):
            print(f"reaction_posted, correct session_id, room, and msg_id")
            reaction = req[b'reaction'].decode('utf-8')
            if reaction == self.yes_reaction:
                print(f"Granting read permissions to {session_id} for room with token {room_token}")
                self.set_user_room_permissions(
                    room_token=room_token, user_session_id=session_id, sec_from_now=None, read=True
                )
                self.set_user_room_permissions(
                    room_token=room_token, user_session_id=session_id, sec_from_now=120, write=True
                )
                self.post_message(
                    room_token,
                    f"You may read now.  Study up, and you may learn to write in {self.write_timeout} seconds.",
                    whisper_target=session_id,
                    no_bots=True,
                )
            else:
                self.post_message(
                    room_token,
                    f"You chose...poorly.  You may try again in {self.retry_timeout} seconds with a new prompt.",
                    whisper_target=session_id,
                    no_bots=True,
                )
                self.retry_jail[session_id] = time() + self.retry_timeout
            self.delete_message(msg_id)
            del self.pending_requests[session_id][room_token]
            if len(self.pending_requests[session_id]) == 0:
                del self.pending_requests[session_id]


if __name__ == '__main__':

    """
    These are test keys for convenience and if they make it into production *anywhere*, that means
    that someone did something really dumb.
    """
    # server_key_hex = b"3689294e4e49dac8842746ae7011477610e846f30a4f30bedac684fb20f28f65"
    server_key_hex = b'0bac1f7b4ec1fbe61f89d6ef95504859622eba175ffe3c50050a94b14f755359'
    bot_privkey_hex = b'489327e8db1e9f6e05c4ad4d75b8bef6aeb8ad78ae6b3d4a74b96455b7438e79'

    from nacl.public import PublicKey

    server_key = PublicKey(HexEncoder.decode(server_key_hex))
    server_key_bytes = server_key.encode()

    privkey = SigningKey(HexEncoder.decode(bot_privkey_hex))
    print(f"privkey: {privkey.encode(HexEncoder)}")
    privkey_bytes = privkey.encode()
    pubkey_bytes = privkey.verify_key.encode()
    print(f"pubkey: {privkey.verify_key.encode(HexEncoder)}")
    # bot = TestBot("tcp://127.0.0.1:43210", server_key_bytes, privkey_bytes, pubkey_bytes)
    # bot = SogsFilterBot(privkey_bytes, pubkey_bytes, config_file='sogs.ini')
    # bot = PermissionBot("tcp://127.0.0.1:43210", server_key_bytes, privkey_bytes, pubkey_bytes, "Permissions Bot")
    bot = SlashTestBot(
        "tcp://127.0.0.1:43210", server_key_bytes, privkey_bytes, pubkey_bytes, "Slash Bot"
    )

    bot.run()
