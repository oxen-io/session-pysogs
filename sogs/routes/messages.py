from .. import http, utils
from . import auth

from flask import abort, jsonify, g, Blueprint, request

# Room message retrieving/submitting endpoints


messages = Blueprint('messages', __name__)


_query_limit_doc = """# Query Parameters

The request takes an optional `limit` query parameter indicating the number of messages to
return (up to 256).  If omitted, 100 messages are returned."""


@messages.get("/room/<Room:room>/messages/since/<int:seqno>")
@auth.read_required
def messages_since(room, seqno):
    f"""
    Retrieves message *updates* from a room.  This is the main message polling endpoint in SOGS.

    This endpoint retrieves new, edited, and deleted messages posted to this room since the given
    message sequence counter.  Returns `limit` messages at a time (100 if no limit is given).
    Returned messages include any new messages, updates to existing messages (i.e.  edits), and
    message deletions made to the room since the given update id.  Messages are returned in "update"
    order, that is, in the order in which the change was applied to the room, from oldest the
    newest.

    # URL Parameters

    - `seqno` — the integer `seqno` value of the most recent message retrieves from this room.  To
      retrieve from the beginning of the room's message history use a value of 0 (the first room
      post will always be >= 1).

    {_query_limit_doc}

    # Return value

    On success this returns a JSON array of message update objects.  Each element is an object as
    would be returned by [the single message retrieval endpoint](#get-roomroommessagemsg_id), except
    that updates for *deleted* messages are also included with the `"data"` key set to `null` and
    the `"signature"` key omitted.

    The endpoint always returns `limit` (or 100, if unspecified) message updates if they are
    available, so that a caller can determine whether it needs to issue additional room updates by
    seeing whether the returned value contains `limit` update: if this returns fewer than `limit`
    then there are currently no additional message updates.

    # Error status codes

    403 Forbidden — if the invoking user does not have read access to the room.
    """
    if g.user:
        g.user.update_room_activity(room)

    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)

    return utils.jsonify_with_base64(room.get_messages_for(g.user, limit=limit, sequence=seqno))


@messages.get("/room/<Room:room>/messages/before/<int:msg_id>")
@auth.read_required
def messages_before(room, msg_id):
    f"""
    Retrieves messages from the room preceding a given id.

    This endpoint is intended to be used with `.../recent` to allow a client to retrieve the most
    recent messages and then walk backwards through batches of ever-older messages. As with
    `.../recent`, messages are returned in order from most recent to least recent.

    As with `.../recent`, this endpoint does not include deleted messages and always returns the
    current version, for edited messages.

    # URL Parameters

    - `msg_id` a numeric integer ID; the messages immediately *before* this ID are returned.

    {_query_limit_doc}

    # Return value

    On success this returns a 200 status code with a body consisting of a JSON array of the message
    details.  Each message is the object that would be returned by [the single message retrieval
    endpoint](#get-roomroommessagemsg_id).  Messages are sorted from newest to oldest.

    # Error status codes

    - 403 Forbidden — if the invoking user does not have read access to the room.
    """
    if g.user:
        g.user.update_room_activity(room)

    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)

    return utils.jsonify_with_base64(room.get_messages_for(g.user, limit=limit, before=msg_id))


@messages.get("/room/<Room:room>/messages/recent")
@auth.read_required
def messages_recent(room):
    f"""
    Retrieves recent messages posted to this room.

    Returns the most recent `limit` messages (100 if no limit is given).  This only returns extant
    messages, and always returns the latest versions: that is, deleted message indicators and
    pre-editing versions of messages are not returned. Messages are returned in order from most
    recent to least recent.

    # URL Parameters

    {_query_limit_doc}

    # Return value

    On success this returns a 200 status code with a body consisting of a JSON array of the message
    details.  Each message is the object that would be returned by [the single message retrieval
    endpoint](#get-roomroommessagemsg_id).

    # Error status codes

    - 403 Forbidden — if the invoking user does not have read access to the room.
    """
    if g.user:
        g.user.update_room_activity(room)

    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)

    return utils.jsonify_with_base64(room.get_messages_for(g.user, limit=limit, recent=True))


@messages.get("/room/<Room:room>/message/<int:msg_id>")
@auth.read_required
def message_single(room, msg_id):
    """
    Returns a single message by ID.

    # URL Parameters

    - `msg_id` the numeric integer ID of the message to retrieve.

    # Return value

    On success this returns a 200 status code with a JSON body containing an object with keys:

    - `id` — The numeric message id.
    - `session_id` — The session ID of the user who posted this message. Omitted in contexts where
      the information isn't available or isn't useful or available, such as in the confirmation of
      submitting a post.
    - `posted` — The unix timestamp (float) when the message was posted to the server.
    - `edited` — Unix timestamp of the last edit to this message.  This field is omitted if the
      messages has never been edited.
    - `seqno` — This message's event sequence number in the room; this number is set to the room's
      current monotonic sequence counter (*not* a timestamp!) when this message is first posted and
      whenever the message is edited or deleted.  Thus an update to this value for the same message
      indicates an update or deletion has occurred.

        Note that this sequence number is used for event tracking, *not* message ordering.  For
        example, an edit will increase this value so that polling clients will receive the edit, but
        the edit itself should change the content but not re-position the message.

    - `whisper` — If true then this message is a whisper, either directed at the retrieving user, or
      sent to all moderators (and the retrieving user is a moderator).
    - `whisper_mods` — If true then this message is a whisper visible to all moderators.  If false
      then this message is a whisper meant only for a specific user (and not all mods).  Omitted
      when the message is not either type of whisper.
    - `whisper_to` — The Session ID of the recipient of this whisper.  Omitted if the message is not
      a whisper, or if the whisper is for all mods without a specific recipient.
    - `data` — The actual message content, serialized as per Session.  For message bodies returned
      in a [`.../since` request](#get-roomroommessagessinceseqno) this field will be `null` if this
      message is an update for a deleted message.
    - `signature` — An Ed25519 signature of the data contained in `data`.  If `session_id` is a
      blinded ID (`15...`) then this is signed using the private key associated with the public
      Ed25519 key in the blinded session ID.  For unblinded IDs (`05...`) the signature is
      verifiable using the XEd25519-specified converted pubkey of the Session ID.  If `data` is null
      this field (i.e. for a deletion update) this field is omitted.

    # Error status codes

    - 403 Forbidden — returned if the invoking user does not have read access to the room.

    - 404 Not Found — returned if the message does not exist or is not visible to this user.  For
      example, attempting to access a whisper meant for someone else, or attempting to access a
      deleted message will return this not found error code.
    """

    if g.user:
        g.user.update_room_activity(room)

    msgs = room.get_messages_for(g.user, single=msg_id)
    if not msgs:
        abort(http.NOT_FOUND)

    return utils.jsonify_with_base64(msgs[0])


@messages.post("/room/<Room:room>/message")
@auth.user_required
def post_message(room):
    """
    Posts a new message to a room.

    The method takes a JSON request body containing the details to be added to the room.

    # JSON parameters

    ## Required fields:

    - `data` — (required) the serialized message body, encoded in base64.
    - `signature` — (required) a 64-byte Ed25519 signature of the message body, signed by the
      current user's keys, encoded in base64 (i.e. 88 base64 chars).

    ## Optional fields:

    - `whisper_to` — Takes a Session ID; if present this indicates that this message is a whisper
      that should only be shown to the given user.  Note that only moderators may set this flag.

    - `whisper_mods` — Boolean.  If true, then this message will be visible to moderators but not
      ordinary users.  If this *and* `whisper_to` are used together then the message will be visible
      to the given user *and* any room moderators.  (This can be used, for instance, to issue a
      warning to a user that only the user and other mods can see).  Note that only moderators may
      set this flag.

    - `files` — Array of file IDs of new files uploaded as attachments of this post.  This is
      required to preserve uploads for the default expiry period (15 days, unless otherwise
      configured by the SOGS administrator).  Uploaded files that are not attached to a post will
      be deleted much sooner.

        If any of the given file ids are already associated with another message then the
        association is ignored (i.e. the files remain associated with the original message).

        When submitting a [message *edit*](#put-roomroommessagemsg_id) this field must contain the
        IDs of any newly uploaded files that are part of the edit.  Existing attachment IDs may also
        be included, but are not required.

    # Return value

    On success this returns a status **201** (Created), *not* the default 200 (OK) returned by most
    endpoints.  The request body is json containing the post details, as would be returned from
    the [GET /room/ROOM/message/ID](#get-roomroommessagemsg_id) endpoint.

    # Error status codes

    - 403 Forbidden — if the invoking user does not have write permission to the room.
    """
    req = request.json

    # TODO: files tracking

    msg = room.add_post(
        g.user,
        data=utils.decode_base64(req.get('data')),
        sig=utils.decode_base64(req.get('signature')),
        whisper_to=req.get('whisper_to'),
        whisper_mods=bool(req.get('whisper_mods')),
    )

    return utils.jsonify_with_base64(msg), http.CREATED


@messages.put("/room/<Room:room>/message/<int:msg_id>")
@auth.user_required
def edit_message(room, msg_id):
    """
    Edits a message, replacing its existing content with new content and a new signature.

    This edit may only be initiated by the creator of the post, and the poster must *currently* have
    write permissions in the room

    # URL Parameters

    - `msg_id` the numeric integer ID of the message to edit.

    # JSON parameters

    The request takes a JSON object containing the following keys:

    - `data` — (required)
    - `signature` — (required)
    - `files` — (optional)

    See [the message creation endpoint](#post-roomroommessage) for parameter descriptions.  Other
    parameters accepted by the original post endpoint (such as `whisper_to`) cannot be changed in an
    edit.

    # Return value

    On success this return a status code 200 with an empty JSON object as the body.

    # Error status codes

    - 403 Forbidden — if the invoking user does not have permission to edit the post (i.e. because
      they are not the original author or no longer have posting permission).
    """
    req = request.json

    # TODO: files tracking

    room.edit_post(
        g.user,
        msg_id,
        data=utils.decode_base64(req.get('data')),
        sig=utils.decode_base64(req.get('signature')),
    )

    return jsonify({})


@messages.post("/room/<Room:room>/pin/<int:msg_id>")
def message_pin(room, msg_id):
    """
    Adds a pinned message to this room.

    Note that existing pinned messages are *not* removed: the new message is added to the pinned
    message list.  (If you want to remove existing pins then build a sequence request that first
    calls .../unpin/all).

    The user must have admin (not just moderator) permissions in the room in order to pin messages.

    Pinned messages that are already pinned will be re-pinned (that is, their pin timestamp and
    pinning admin user will be updated).  Because pinned messages are returned in pinning-order this
    allows admins to order multiple pinned messages in a room by re-pinning (via this endpoint) in
    the order in which pinned messages should be displayed.

    # URL Parameters

    - `msg_id` — The message ID of a post in this room that should be pinned.  The message must not
      be deleted or a whisper.

    # JSON parameters

    Takes a JSON object as the request body.  Currently empty (but that may change in the future).

    # Return value

    On success returns a 200 status code and returns an empty JSON object as response.

    # Error status codes

    - 403 Forbidden — returned if the invoking user does not have admin permission in this room.

    - 404 Not Found — returned if the given post was not found in this room or is ineligible for
      pinning (e.g. a whisper or deleted post).
    """
    room.pin(msg_id, g.user)
    return jsonify({})


@messages.post("/room/<Room:room>/unpin/<int:msg_id>")
def message_unpin(room, msg_id):
    """
    Remove a message from this room's pinned message list.

    The user must have admin (not just moderator) permissions in the room.

    # URL Parameters

    - `msg_id` — The message ID of a pinned post in this room that should be unpinned.  If the
      message ID is not currently pinned then this endpoint does nothing.

    # JSON parameters

    Takes a JSON object as the request body.  Currently empty (but that may change in the future).

    # Return value

    On success returns a 200 status code and returns an empty JSON object as response body.

    # Error status codes

    - 403 Forbidden — returned if the invoking user does not have admin permission in this room.
    """
    room.unpin(msg_id, g.user)
    return jsonify({})


@messages.post("/room/<Room:room>/unpin/all")
def message_unpin_all(room):
    """
    Removes *all* pinned messages from this room.

    The user must have admin (not just moderator) permissions in the room.

    # JSON parameters

    Takes an empty JSON object as the request body.

    # Return value

    On success returns a 200 status code with an empty JSON object as response body.  All pinned
    messages have been removed.

    # Error status codes

    - 403 Forbidden — returned if the invoking user does not have admin permission in this room.
    """
    room.unpin_all(g.user)
    return jsonify({})
