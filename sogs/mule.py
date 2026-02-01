import traceback
import oxenmq
from oxenc import bt_deserialize, bt_serialize
import time
from datetime import timedelta
import functools
from nacl.encoding import HexEncoder

from .web import app
from . import cleanup
from . import config
from . import omq as o
from . import db
from .db import query
from .model.user import User
from .model.room import Room
from .model.exc import NoSuchRoom, NoSuchUser
from .model.post import Post

# This is the uwsgi "mule" that handles things not related to serving HTTP requests:
# - it holds the oxenmq instance (with its own interface into sogs)
# - it handles cleanup jobs (e.g. periodic deletions)

# holds bot_id -> bot omq connection for connected bots
bot_conns = {}

# holds oxenmq ConnectionID -> metadata (bot_id, bot session_id, etc.)
bot_conn_info = {}

# holds command -> bot_id for commands registered by bots
# key includes the prefix (default slash, may make configurable)
bot_pre_commands = {}
bot_post_commands = {}


# not changing the keys, since this is just for fixing the values if they
# need to be str and not bytes
def bytestring_fixup(d, keys):
    for k in keys:
        if k in d:
            d[k] = d[k].decode('utf-8')

def log_exceptions(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            app.logger.error(f"{f.__name__} raised exception: {e}")
            raise

    return wrapper


def needs_app_context(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        with app.app_context():
            return f(*args, **kwargs)

    return wrapper


def run():
    try:
        app.logger.info("OxenMQ mule started.")

        while True:
            time.sleep(1)

    except Exception:
        app.logger.error("mule died via exception:\n{}".format(traceback.format_exc()))


@needs_app_context
def allow_conn(addr, pk, sn):
    with db.transaction():

        row = query("SELECT id FROM bots WHERE auth_key = :key", key=pk).first()

        if row:
            app.logger.debug(f"Bot connected: {HexEncoder.encode(pk)}")
            return oxenmq.AuthLevel.basic

    app.logger.warning(f"No bot found with key: {HexEncoder.encode(pk)}")
    # TODO: user recognition auth
    return oxenmq.AuthLevel.denied


def admin_conn(addr, pk, sn):
    return oxenmq.AuthLevel.admin


def inproc_fail(connid, reason):
    raise RuntimeError(f"Couldn't connect mule to itself: {reason}")


@needs_app_context
@log_exceptions
def get_relevant_bots(where_clause, *args, room_id=None, room_token=None):
    bot_ids = {}
    with db.transaction():
        query_str = "SELECT id, required FROM bots WHERE global = 1 AND " + where_clause
        rows = query(query_str)
        for row in rows:
            required = False
            if row['required'] and row['required'] == 1:
                required = True
            bot_ids[row['id']] = required

        if room_token and not room_id:
            id_row = query("SELECT id FROM rooms WHERE token = :token", token=room_token).first()
            if id_row is None:
                app.logger.warning(
                    f"filtering message for inexistent room with token: \"{room_token}\"??"
                )
                m.reply(bt_serialize("The room destination for the message does not exist."))
                return None
            room_id = id_row['id']

        query_str = "SELECT bot, required FROM room_bots WHERE room = :room_id AND " + where_clause
        rows = query(query_str, room_id=room_id)
        for row in rows:
            required = False
            if row['required'] and row['required'] == 1:
                required = True
            if row['id'] in bot_ids:
                required = required or bot_ids[row['id']]
            bot_ids[row['id']] = required

    return bot_ids


# Commands from SOGS/uwsgi


@needs_app_context
@log_exceptions
def message_request(m: oxenmq.Message):
    """
    Called by SOGS when a user sends or edits a message
    TODO: handle edits
    """
    app.logger.debug("message_request called on mule")

    responded = False
    try:
        command = ""
        request = bt_deserialize(m.dataview()[0])
        bytestring_fixup(request, b"alt_id")

        filter_resp = bot_filter_message(m.data(), request)
        if filter_resp == "REJECT":
            return bt_serialize({"error": "Message rejected by filter bot(s)"})
        elif filter_resp == "SILENT":
            request[b"filtered"] = True

        msg = Post(raw=request[b"message_data"])

        # TODO: make the trigger character configurable
        if msg.text.startswith('/'):
            app.logger.debug(f"Processing slash command, pre-command phase")

            command = msg.text.split(' ')[0]

        if command:
            if not bot_pre_message_commands(m.data(), request, command):
                return bt_serialize({"ok": True})

        # TODO: pre-insertion bot command, e.g. not a command and passed all filters,
        #       but for some other reason we don't want to insert it (or not yet).

        # TODO: handle edit message
        room = Room(id=request[b"room_id"])
        msg_id = room.insert_message(request)
        responded = True
        # manually reply so we don't hold up the worker longer than necessary
        m.reply(bt_serialize({"ok": True, "msg_id": msg_id}))

        bot_post_message_commands(m.data(), request, command)
        on_message_posted(msg_id)

        return
    except Exception as e:
        app.logger.warning(f"Exception handling new/edited message from sogs: {e}")
        if not responded:
            return bt_serialize({"error": f"{e}"})


@needs_app_context
@log_exceptions
def request_read(m: oxenmq.Message):
    """
    This is a request rather than a command so that sogs waits for it to finish
    before answering the read request that triggered it.  This lets a bot add a
    whisper to the user, if desired, which sogs will deliver.
    """
    command = '/request_read'
    retval = bt_serialize("OK")  # always, for now
    if command not in bot_pre_commands:
        return retval
    if len(bot_pre_commands[command]) != 1:
        return retval

    bot_id = list(bot_pre_commands[command])[0]
    if bot_id not in bot_conns:
        return retval

    try:
        app.logger.debug(f"Giving command 'request_read' to bot (id={bot_id})")
        resp = o.omq.request_future(
            bot_conns[bot_id], "bot.request_read", m.data(), request_timeout=timedelta(seconds=1)
        ).get()
    except TimeoutError as e:
        app.logger.warning(f"Timeout from bot (id={bot_id}) handling request_read")
        pass
    except Exception:
        # TODO: Should this fail the whole command?
        pass

    return retval


@log_exceptions
def reaction_posted(m: oxenmq.Message):
    on_reaction_posted(m)


@log_exceptions
def messages_deleted(m: oxenmq.Message):
    ids = bt_deserialize(m.data()[0])
    app.logger.debug(f"FIXME: mule -- message delete stub, deleted messages: {ids}")


@log_exceptions
def message_edited(m: oxenmq.Message):
    app.logger.debug("FIXME: mule -- message edited stub")


# Commands *to* Bots


@log_exceptions
def bot_filter_message(data, deserialized_data):
    bot_ids = {}
    bot_ids = get_relevant_bots("approver = 1", room_id=deserialized_data[b"room_id"])

    if not bot_ids:
        return "OK"

    app.logger.debug(f"Requesting message approval from {len(bot_ids)} bots.")

    for bot_id in bot_ids:
        if bot_ids[bot_id] and bot_id not in bot_conns:
            return "REJECT"

    pending_requests = []
    for bot_id in bot_ids:
        # not-required bot is not connected, skip
        if not bot_id in bot_conns:
            continue

        r = o.omq.request_future(
            bot_conns[bot_id], "bot.filter_message", data, timeout=timedelta(seconds=1)
        )
        if not r:
            return "REJECT"
        pending_requests.append(r)

    silent = False
    for pending in pending_requests:
        try:
            response = pending.get()
            if (not response) or (not len(response) == 1):
                return "REJECT"
            resp_text = bt_deserialize(response[0])
            if resp_text == b"OK":
                continue
            elif resp_text == b"SILENT":
                silent = True
                continue
            else:
                return "REJECT"
        except Exception as e:
            app.logger.warning(f"Bot filter exception: {e}")
            return "REJECT"

    return "SILENT" if silent else "OK"


@needs_app_context
@log_exceptions
def bot_message_commands(data, deserialized_data, command, pre_command: bool):
    """
    pass command to bots registered for that command, in order.
    Bot returns True if we should continue handling the message, i.e. either that bot ignored it
    or that bot errored/thinks the command should not be handled further.
    If all bots return True, this function returns True (to indicate to continue handling), else
    return False.
    If no bots are registered to handle the command, return True (NOTE: not sure on this)

    For now, "/request_read" and "/request_write" will be special commands which, rather than
    passing a user's message to the bot, will pass session_id, user.id, room.id, room.token
    As these are special, they are handled elsewhere, not in this function
    """

    commands_container = bot_pre_commands if pre_command else bot_post_commands
    command_type = "pre_message_command" if pre_command else "post_message_command"

    if command not in commands_container:
        # FIXME: Should we (silently?) drop messages which start with '/' but aren't registered commands?
        return True

    for bot_id in commands_container[command]:
        if bot_id not in bot_conns:
            app.logger.warning(
                f"Bot (id={bot_id}) registered to handle {command_type} {command} but no longer in bot_conns, somehow."
            )
            continue
        try:
            app.logger.debug(f"Giving {command_type} {command} to bot (id={bot_id})")
            resp = o.omq.request_future(
                bot_conns[bot_id],
                f"bot.{command_type}",
                data,
                request_timeout=timedelta(seconds=0.2),
            ).get()
        except TimeoutError as e:
            app.logger.warning(f"Timeout from bot (id={bot_id}) handling {command_type} {command}")
            if pre_command:
                return False
        except Exception as e:
            app.logger.warning(
                f"Error from bot (id={bot_id}) handling {command_type} {command}, error: {e}"
            )
            if pre_command:
                return False

        should_continue = bt_deserialize(resp[0])
        app.logger.debug(f"{command_type} {command} response from bot: {should_continue}")
        if pre_command and not should_continue:
            return False

    return True


def bot_pre_message_commands(data, deserialized_data, command):
    return bot_message_commands(data, deserialized_data, command, True)


def bot_post_message_commands(data, deserialized_data, command):
    return bot_message_commands(data, deserialized_data, command, False)


def setup_omq():
    omq = o.omq

    app.logger.debug("Mule setting up omq")
    if isinstance(config.OMQ_LISTEN, list):
        listen = config.OMQ_LISTEN
    elif config.OMQ_LISTEN is None:
        listen = []
    else:
        listen = [config.OMQ_LISTEN]
    for addr in listen:
        omq.listen(addr, curve=True, allow_connection=allow_conn)
        app.logger.info(f"OxenMQ listening on {addr}")

    # Internal socket for workers to talk to us:
    omq.listen(config.OMQ_INTERNAL, curve=False, allow_connection=admin_conn)

    # Periodic database cleanup timer:
    omq.add_timer(cleanup.cleanup, timedelta(seconds=cleanup.INTERVAL))

    # Commands other workers can send to us, e.g. for notifications of activity for us to know about
    bot = omq.add_category("bot", access_level=oxenmq.AuthLevel.basic)
    bot.add_request_command("hello", bot_hello)
    bot.add_command("register_pre_commands", bot_register_pre_command)
    bot.add_command("register_post_commands", bot_register_post_command)
    bot.add_command("delete_message", bot_delete_message)
    bot.add_request_command("post_reactions", bot_post_reactions)
    bot.add_request_command("message", bot_insert_message)
    bot.add_request_command("upload_file", bot_upload_file)
    bot.add_request_command("set_user_room_permissions", bot_set_user_room_permissions)
    worker = omq.add_category("worker", access_level=oxenmq.AuthLevel.admin)
    worker.add_request_command("message_request", message_request)
    worker.add_request_command("request_read", request_read)
    worker.add_command("messages_deleted", messages_deleted)
    worker.add_command("message_edited", message_edited)
    worker.add_command("reaction_posted", reaction_posted)

    app.logger.debug("Mule starting omq")
    omq.start()

    # Connect mule to itself so that if something the mule does wants to send something to the mule
    # it will work.  (And so be careful not to recurse!)
    app.logger.debug("Mule connecting to self")
    o.mule_conn = omq.connect_inproc(on_success=None, on_failure=inproc_fail)


@needs_app_context
@log_exceptions
def bot_hello(m: oxenmq.Message):
    app.logger.debug(f"bot.hello called with key: {m.conn.pubkey}")

    new_bot_conn = False
    with db.transaction():

        row = query("SELECT id FROM bots WHERE auth_key = :key", key=m.conn.pubkey).first()

        if row is None:
            # TODO: would like to close conn in this case, but oxenmq only allows close on outgoing conns.
            app.logger.warning(f"No bot found with key: {m.conn.pubkey}")
            return bt_serialize("NoSuchBot")

        bot_conns[row['id']] = m.conn
        if not m.conn in bot_conn_info:
            new_bot_conn = True
            bot_conn_info[m.conn] = {}
        bot_conn_info[m.conn]['bot_id'] = row['id']

        try:
            if len(m.dataview()):
                session_id = bt_deserialize(m.dataview()[0]).decode('ascii')
                u = User(session_id=session_id, autovivify=True)
                # TODO: handle bot permissions and setup better
                admin_user = User(id=0)
                u.set_moderator(added_by=admin_user, visible=True)
                bot_conn_info[m.conn]['user'] = u
        except Exception as e:
            app.logger.warning(f"Bot with id {row['id']} tried to register bad session_id.")
            del bot_conns[row['id']]
            del bot_conn_info[m.conn]
            return bt_serialize("Bad session_id")

    new_str = "new " if new_bot_conn else ""
    app.logger.debug(f"Added {new_str}bot connection for known key: {m.conn.pubkey}")

    # inform the bot that as far as we know this is a new connection from it, it should
    # re-register commands as desired
    if new_bot_conn:
        return bt_serialize("REGISTER")

    return bt_serialize("OK")


@needs_app_context
@log_exceptions
def bot_register_command(m: oxenmq.Message, pre_command: bool):
    if not m.conn in bot_conn_info or not 'bot_id' in bot_conn_info[m.conn]:
        # bot hasn't said hello yet, the jerk!
        return

    command_type = "pre_command" if pre_command else "post_command"
    commands_container = bot_pre_commands if pre_command else bot_post_commands

    req = bt_deserialize(m.dataview()[0])
    commands = req[b'commands']
    app.logger.debug(f"register_{command_type}, commands: {commands}")
    for command in commands:
        app.logger.debug(
            f"trying to add {command_type} {command} for bot {bot_conn_info[m.conn]['bot_id']}"
        )
        if not command.startswith(b'/'):
            return

        command = command.decode('utf-8')
        app.logger.debug(
            f"adding {command_type} {command} for bot {bot_conn_info[m.conn]['bot_id']}"
        )
        if not command in commands_container:
            commands_container[command] = set()
        commands_container[command].add(bot_conn_info[m.conn]['bot_id'])


def bot_register_pre_command(m: oxenmq.Message):
    bot_register_command(m, True)


def bot_register_post_command(m: oxenmq.Message):
    bot_register_command(m, False)


@needs_app_context
@log_exceptions
def bot_get_user_permissions(m: oxenmq.Message):
    pass


@needs_app_context
@log_exceptions
def bot_set_user_room_permissions(m: oxenmq.Message):
    """
    Limited to access/read/write for now
    arguments:
        - room_id / room_token
        - user_id / user_session_id
        - accessible/read/write = -1,0,1 (-1 is actively remove override in room for user)
    user room permissions will be changed as specified; omitting access/read/write means
    leave that value unchanged.
    """
    if not bot_conn_info[m.conn]['user']:
        return bt_serialize("Must call 'hello' with bot session_id at least once")

    req = bt_deserialize(m.dataview()[0])
    try:
        if b'room_id' in req:
            room = Room(id=req[b'room_id'])
        elif b'room_token' in req:
            room = Room(token=req[b'room_token'].decode('ascii'))
        else:
            return bt_serialize("Must specify a room for user permissions change.")
        if b'user_id' in req:
            user = User(id=req[b'user_id'], autovivify=False)
        elif b'user_session_id' in req:
            user = User(session_id=req[b'user_session_id'].decode('ascii'))
        else:
            return bt_serialize("Must specify a user for user permissions change.")
        new_perms = {}
        for key in (b'accessible', b'read', b'write'):
            if key in req:
                k = key.decode('ascii')
                new_perms[k] = req[key]
                if new_perms[k] == -1:
                    new_perms[k] = None
        if b'in' in req:
            set_at = time.time() + req[b'in']
            room.add_future_permission(
                user, mod=bot_conn_info[m.conn]['user'], at=set_at, **new_perms
            )
        else:
            room.set_permissions(user, mod=bot_conn_info[m.conn]['user'], **new_perms)

    except NoSuchRoom as e:
        return bt_serialize("NoSuchRoom")
    except NoSuchUser as e:
        return bt_serialize("NoSuchUser")
    except Exception as e:
        app.logger.warning(f"Exception in bot set perms: {e}")
        return bt_serialize("An error occurred with changing permissions.")

    return bt_serialize("OK")


@needs_app_context
@log_exceptions
def bot_delete_message(m: oxenmq.Message):
    """
    For now, bots can only delete messages they created.
    """
    if not m.conn in bot_conn_info or not 'user' in bot_conn_info[m.conn]:
        return
    req = bt_deserialize(m.dataview()[0])
    msg_id = req[b'msg_id']
    with db.transaction():
        rowcount = query(
            """DELETE FROM message_details WHERE id = :msg_id AND "user" = :user""",
            msg_id=msg_id,
            user=bot_conn_info[m.conn]['user'].id,
        )
        if rowcount:
            app.logger.warning(f"Deleted message with id {msg_id}")
        else:
            app.logger.warning(f"(apparently?) failed to delete message with id {msg_id}")


@needs_app_context
@log_exceptions
def bot_insert_message(m: oxenmq.Message):
    req = bt_deserialize(m.dataview()[0])

    # TODO: confirm bot sessid is 25-blinded of bot omq auth key?
    sender = User(session_id=req[b'session_id'].decode('ascii'), autovivify=True, touch=False)
    whisper_target = None
    if b'whisper_target' in req:
        try:
            whisper_target = User(
                session_id=req[b'whisper_target'].decode('ascii'), autovivify=False
            )
        except Exception:
            # invalid whisper target, bot messed up?
            app.logger.warning(f"Bot attempted to whisper an inexistent user...")
            return bt_serialize({'error': "NoSuchUser"})

    whisper_mods = req[b'whisper_mods']
    with db.transaction():
        try:
            room = Room(token=req[b"room_token"].decode("ascii"))
        except Exception:
            app.logger.warning(f"Bot attempted to post message to inexistent room...")
            return bt_serialize({'error': "NoSuchRoom"})

        sig = req[b'sig']
        msg = req[b'message']
        bot_str = sender.session_id + f" ({sender.using_id})"
        whisper_target_str = ''
        if whisper_target:
            whisper_target_str = whisper_target.session_id + f" ({whisper_target.using_id})"
        app.logger.debug(f"Posting message from bot: {bot_str}")
        app.logger.debug(f"signature: {sig}")
        app.logger.debug(f"Whisper target: {whisper_target_str}")
        p = Post(raw=msg)
        app.logger.debug(f"message text: {p.text}")
        app.logger.debug(f"message username: {p.username}")

        message_args = {
            b"room_id": room.id,
            b"room_token": room.token,
            b"room_name": room.name,
            b"user_id": sender.id,
            b"session_id": sender.session_id,
            b"message_data": msg,
            b"data_size": len(msg),
            b"sig": sig,
            b"filtered": False,
            b"is_mod": room.check_moderator(sender),
            b"whisper_mods": whisper_mods,
        }
        if whisper_target:
            message_args[b"whisper_to"] = whisper_target.id
        if sender.alt_id:
            message_args[b"alt_id"] = sender.using_id


        msg_id = room.insert_message(message_args)

        if b"files" in req:
            app.logger.debug(f"associating files {req[b'files']} with msg {msg_id}")
            room._own_files(msg_id, req[b"files"], sender)

        if not b'no_bots' in req:
            on_message_posted(msg_id)

        return bt_serialize({'msg_id': msg_id})


@needs_app_context
@log_exceptions
def bot_upload_file(m: oxenmq.Message):
    if not m.conn in bot_conn_info or not 'user' in bot_conn_info[m.conn]:
        return

    req = bt_deserialize(m.dataview()[0])

    with db.transaction():
        try:
            room = Room(token=req[b"room_token"].decode("ascii"))
        except Exception as e:
            app.logger.warning(f"Bot attempted to upload file to inexistent room...")
            return bt_serialize({'error': "NoSuchRoom"})

        # just passing this as bytes(req[b'file_contents']) was complaining about the type...?
        content = bytes(req[b'file_contents'])
        file_id = room.upload_file(content, bot_conn_info[m.conn]['user'], filename=req[b'filename'].decode('utf-8'), lifetime=3600.0)

        url = f"{config.URL_BASE}/{room.token}/file/{file_id}"
        return bt_serialize({'file_id': file_id, "url": url})

@needs_app_context
@log_exceptions
def on_message_posted(msg_id):
    app.logger.warn(f"Calling on_message_posted with id={msg_id}")
    msg = None
    for row in query(
        f"""
        SELECT message_details.*, uroom.token AS room_token FROM message_details
        JOIN rooms uroom ON message_details.room = uroom.id
        WHERE message_details.id = :msg_id
        """,
        msg_id=msg_id,
    ):
        app.logger.warn("Message details:")
        for key in row.keys():
            app.logger.warn(f"{key}: {row[key]}")
        msg = {x: row[x] for x in row.keys()}

    if msg is None:
        return

    for key in msg.keys():
        if msg[key] is None:
            msg[key] = ""
    msg['posted'] = str(msg['posted'])

    bot_ids = get_relevant_bots("subscribe = 1", room_id=msg['room'])
    serialized = bt_serialize(msg)
    for bot_id in bot_ids.keys():
        o.omq.send(bot_conns[bot_id], "bot.message_posted", serialized)


@needs_app_context
@log_exceptions
def bot_post_reactions(m: oxenmq.Message):
    """
    Post one or more reactions from this bot to a single message.
    """
    try:
        req = bt_deserialize(m.dataview()[0])
        for key in (b'room_token', b'msg_id', b'reactions'):
            if not key in req:
                return bt_serialize({'error': f"missing parameter {key}"})

        room = Room(token=req[b'room_token'].decode('ascii'))
        for reaction in req[b'reactions']:
            app.logger.debug(f"bot_post_reactions, posting reaction to room")
            room.add_reaction(
                bot_conn_info[m.conn]['user'],
                req[b'msg_id'],
                reaction.decode('utf-8'),
                send_to_bots=False,
            )
    except NoSuchRoom as e:
        app.logger.warning(f"Error: {e}")
        return bt_serialize({'error': 'NoSuchRoom'})
    except Exception as e:
        app.logger.warning(f"Error: {e}")
        return bt_serialize({'error': 'Something getting wrong'})
    return bt_serialize({'status': 'OK'})


# TODO: this should be usable for reaction added/removed, not just added
@needs_app_context
@log_exceptions
def on_reaction_posted(m: oxenmq.Message):
    msg_dict = bt_deserialize(m.dataview()[0])
    app.logger.warn(f"on_reaction_posted, reaction:\n{msg_dict}")
    bot_ids = get_relevant_bots("subscribe = 1", room_id=msg_dict[b'room_id'])
    for bot_id in bot_ids.keys():
        app.logger.warn(f"Sending reaction to bot {bot_id}")
        o.omq.send(bot_conns[bot_id], "bot.reaction_posted", m.data())


# NOTE: this should be a list of IDs; if the bot cares, it will have stored them.
#       or can fetch them
@needs_app_context
@log_exceptions
def on_messages_deleted(m: oxenmq.Message):
    pass
