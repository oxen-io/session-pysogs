from .. import http, utils
from . import auth

from flask import abort, jsonify, g, Blueprint, request

# Room message retrieving/submitting endpoints


messages = Blueprint('messages', __name__)


def qs_reactors():
    return utils.get_int_param('reactors', 4, min=0, max=20, truncate=True)


@messages.get("/room/<Room:room>/messages/since/<int:seqno>")
@auth.accessible_required
def messages_since(room, seqno):
    """
    Retrieves message *updates* from a room.  This is the main message polling endpoint in SOGS.

    This endpoint retrieves new, edited, and deleted messages or message reactions posted to this
    room since the given message sequence counter.  Returns `limit` messages at a time (100 if no
    limit is given).  Returned messages include any new messages, updates to existing messages (i.e.
    edits), and message deletions made to the room since the given update id.  Messages are returned
    in "update" order, that is, in the order in which the change was applied to the room, from
    oldest the newest.

    # URL Parameters

    - `seqno` — the integer `seqno` value of the most recent message or reaction retrieved from this
      room via this endpoint.  To retrieve from the beginning of the room's message history use a
      value of 0 (the first room post will always be >= 1).

    # Query Parameters

    - `limit` — if specified this indicates the number of messages to return (up to 256).  If
      omitted, 100 messages are returned.

    - `t` — string indicating the types of updates that the client supports, thus allowing the
      client to opt-out of update types that it does not yet support.  Each letter of the string is
      a flag; flags may be specified in any order, and are case-sensistive.  Unknown flags are
      ignored by SOGS (to allow for backwards compatibility). Current flags:

      - `r` — include message reaction updates

      Note that flags may be removed in the future, once a given feature is supported by all known
      clients.

    - `reactors` — maximum number of reactors to return for emoji reactions.  Can be set to a value
      from 0 to 20; the default, if omitted, is 4.  If 0 then the `"reactors"` field (see below) is
      omitted entirely.

    # Return value

    On success this returns a JSON array of message update objects.  There are, currently, two types
    of updates:

    - a message row, returning the most recent version of the message (as would be returned by [the
      single message retrieval endpoint](#get-roomroommessagemsg_id)).  This is used for new
      messages, for edited messages, and for deletions.  In the case of a deletion, the `"data"`
      element will be set to null, the `"signature"` key will be omitted, and an extra element
      `"deleted"` will be set to `true`.

      This message type can be definitively identified by the presence of a `"data"` key (which can
      be null, but will still be present).

    - message reaction details when a message has had changes to its reactions.  (Requires using the
      `t=r` query parameters).  This consists of an object containing the message id (`"id"` key)
      and the `"reactions"` key, as would be returned by the single message retrieval endpoint, but
      without any of the other message data.

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

    flags = request.args.get('t', '')

    return utils.jsonify_with_base64(
        room.get_messages_for(
            g.user,
            limit=limit,
            sequence=seqno,
            reaction_updates='r' in flags,
            reactor_limit=qs_reactors(),
        )
    )


@messages.get("/room/<Room:room>/messages/before/<int:msg_id>")
@auth.accessible_required
def messages_before(room, msg_id):
    """
    Retrieves messages from the room preceding a given id.

    This endpoint is intended to be used with `.../recent` to allow a client to retrieve the most
    recent messages and then walk backwards through batches of ever-older messages. As with
    `.../recent`, messages are returned in order from most recent to least recent.

    As with `.../recent`, this endpoint does not include deleted messages and always returns the
    current version, for edited messages.

    # URL Parameters

    - `msg_id` a numeric integer ID; the messages immediately *before* this ID are returned.

    # Query Parameters

    - `limit` — maximum number of messages to return; defaults to 100, maximum is 256.

    - `reactors` — how many reactors to include in message reaction data.  Defaults to 4.

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

    return utils.jsonify_with_base64(
        room.get_messages_for(g.user, limit=limit, before=msg_id, reactor_limit=qs_reactors())
    )


@messages.get("/room/<Room:room>/messages/recent")
@auth.accessible_required
def messages_recent(room):
    """
    Retrieves recent messages posted to this room.

    Returns the most recent `limit` messages (100 if no limit is given).  This only returns extant
    messages, and always returns the latest versions: that is, deleted message indicators and
    pre-editing versions of messages are not returned. Messages are returned in order from most
    recent to least recent.

    # URL Parameters

    # Query Parameters

    - `limit` — maximum number of messages to return; defaults to 100, maximum is 256.

    - `reactors` — how many reactors to include in message reaction data.  Defaults to 4.

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

    return utils.jsonify_with_base64(
        room.get_messages_for(g.user, limit=limit, recent=True, reactor_limit=qs_reactors())
    )


@messages.get("/room/<Room:room>/message/<int:msg_id>")
@auth.read_required
def message_single(room, msg_id):
    """
    Returns a single message by ID.

    # URL Parameters

    - `msg_id` the numeric integer ID of the message to retrieve.

    # Query Parameters

    - `reactors` — optional parameter that controls how many reactor session IDs to include in the
      `"reactions"` field.  Can be 0 to 20; the default, if omitted, is 4.  If 0 then the
      `"reactors"` key will be omitted entirely from the `"reactions"` field.

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
    - `reactions` — A dict of reaction information for this message; the returned information is
      always current (i.e. requesting the same thing more than once can give different reaction
      information if reaction changes occur between requests).  Note that, when polling for message
      updates including reactions, *only* this key and `id` will be included in the response for
      reactions-only updates.

      This dict contains keys:

      - `"index"` — contains the order sequence of the reactions indicating the order in which the
        reactions are meant to be displayed (i.e. the first-reaction-added order).  The value is
        numeric, from 0 to N-1 for the N reactions returned.
      - `"count"` — the total number of the given reaction, e.g. 27 if 27 different users have added
        the given reaction.
      - `"reactors"` — the session IDs of the first *N* users to use this reaction.  `N` can be
        controlled using the `reactors` query string parameter.  If `reactors` is 0 then this field
        is omitted entirely.
      - `"you"` — will be present and set to true if the user making the request has applied the
        given reaction.  Omitted if the user has not (or if the request does not have a user).

      For example, one reaction detail (with the default reactors size) might consist of:

      ```json
      {
        "id": 147176,
        "seqno": 5717578,
        "reactions": {
          "👍": {
            "index": 1,
            "count": 150,
            "reactors": [
              "058328640343b91c03d393b8dc6ce15c8f93b191ff78054b6ae2c8030e2680b4d6",
              "05d782a81448199aea940f496cc70dc644c269e5979e472536ea03a067bf46d54a",
              "05233432db6edcd320a06b550d4dcf1a06cc486c58f8017a565f6f7dc0fc8b9512",
              "05ca519a397a1aa8a7a1515ff433dd2784cbcbb31c358b1a6e97fb758ceab44dca"
            ],
            "you": true
          },
          "👎": {
            "index": 0,
            "count": 27,
            "reactors": [
              "05ca519a397a1aa8a7a1515ff433dd2784cbcbb31c358b1a6e97fb758ceab44dca",
              "055297c3dc032bef33a21dcb1b76265c8319e53ed0867accd3c274c25ae33c1731",
              "05986c4e7fec0ac1a3a544d84367b2e995f85a6356be8d082724781a9ff699ac7a",
              "0537f1727302b70be32fc371523097bcdbc3e681f947a68ef5e3ea1365a689666a"
            ]
          },
          "🍆": {
            "index": 2,
            "count": 1,
            "reactors": [
              "051234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            ],
            "you": true
          }
        }
      }
      ```

    # Error status codes

    - 403 Forbidden — returned if the invoking user does not have read access to the room.

    - 404 Not Found — returned if the message does not exist or is not visible to this user.  For
      example, attempting to access a whisper meant for someone else, or attempting to access a
      deleted message will return this not found error code.
    """

    if g.user:
        g.user.update_room_activity(room)

    msgs = room.get_messages_for(g.user, single=msg_id, reactor_limit=qs_reactors())
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

    msg = room.add_post(
        g.user,
        data=utils.decode_base64(req.get('data')),
        sig=utils.decode_base64(req.get('signature')),
        whisper_to=req.get('whisper_to'),
        whisper_mods=bool(req.get('whisper_mods')),
        files=[int(x) for x in req.get('files', [])],
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

    room.edit_post(
        g.user,
        msg_id,
        data=utils.decode_base64(req.get('data')),
        sig=utils.decode_base64(req.get('signature')),
        files=[int(x) for x in req.get('files', [])],
    )

    return jsonify({})


@messages.delete("/room/<Room:room>/message/<int:msg_id>")
@auth.user_required
def remove_message(room, msg_id):
    """
    Remove a message by its message id

    # URL Parameters

    - `msg_id` — The message ID of a post in this room that should be deleted.

    # Return value

    On success returns a 200 status code and returns an empty JSON object as response.

    # Error status codes

    - 403 Forbidden — returned if the invoking user does not have admin permission in this room.

    - 404 Not Found — returned if the given post was not found in this room.

    """
    if not room.check_permission(g.user, write=True):
        abort(http.FORBIDDEN)
    if not room.delete_posts([msg_id], deleter=g.user):
        abort(http.NOT_FOUND)
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

    On success returns a 200 status code and returns a JSON object as response containing keys:

    - `info_updates` -- the new info_updates value of the room; a client can use this to avoid
      race conditions with room info polling that might not yet include the updated value(s).

    # Error status codes

    - 403 Forbidden — returned if the invoking user does not have admin permission in this room.

    - 404 Not Found — returned if the given post was not found in this room or is ineligible for
      pinning (e.g. a whisper or deleted post).
    """
    room.pin(msg_id, g.user)
    return jsonify({"info_updates": room.info_updates})


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

    On success returns a 200 status code and returns an JSON object as response body containing
    keys:

    - `unpinned` - boolean value indicating whether the message was pinned and has now been unpinned
      (true), or was already unpinned (false).
    - `info_updates` - the new info_updates value for the room.  This value will only change if the
      given message was actually pinned (i.e. it does not increment when `unpinned` is false).

    # Error status codes

    - 403 Forbidden — returned if the invoking user does not have admin permission in this room.
    """
    count = room.unpin(msg_id, g.user)
    return jsonify({"unpinned": count > 0, "info_updates": room.info_updates})


@messages.post("/room/<Room:room>/unpin/all")
def message_unpin_all(room):
    """
    Removes *all* pinned messages from this room.

    The user must have admin (not just moderator) permissions in the room.

    # JSON parameters

    Takes an empty JSON object as the request body.

    # Return value

    On success returns a 200 status code with an JSON object as response body containing keys:

    - `unpinned` - count of how many pinned messages were removed.
    - `info_updates` - new `info_updates` property for the room.  This value is only incremented by
      this operation if at least one message was found and unpinned (i.e. if `unpinned > 0`).

    # Error status codes

    - 403 Forbidden — returned if the invoking user does not have admin permission in this room.
    """
    count = room.unpin_all(g.user)
    return jsonify({"unpinned": count, "info_updates": room.info_updates})


@messages.put("/room/<Room:room>/reaction/<int:msg_id>/<path:reaction>")
@auth.user_required
@auth.accessible_required
def message_react(room, msg_id, reaction):
    """
    Adds a reaction to the given message in this room.  The user must have read access in the room.

    Reactions are short strings of 1-12 unicode codepoints, typically emoji (or character sequences
    to produce an emoji variant, such as 👨🏿‍🦰, which is composed of 4 unicode "characters"
    but usually renders as a single emoji "Man: Dark Skin Tone, Red Hair").

    # URL Parameters

    - `msg_id` — The message ID on which the reaction should be applied.  The message must be in
      this room, must not be deleted, and must be a regular message (i.e. not a whisper).

    - `reaction` — The reaction to be added, as a UTF-8 string. When making a direct HTTP request it
      is strongly recommended to use a URL-encoded UTF-8 byte sequence (e.g. `%f0%9f%8d%86` for
      `🍆`); many HTTP libraries will do this encoding automatically.  When making an onion request
      you can use the UTF-8 value directly in the path if that is simpler than URL-encoding.  Note
      that regardless of whether URL-encoding is used or not, the X-SOGS-Signature value must sign
      the unencoded value (i.e. `🍆` not `%f0%9f%8d%86`).

    # JSON parameters

    Takes an empty JSON object as the request body.  All values in the object are reserved for
    possible future use.

    # Return value

    On success returns a 200 status code and a JSON object response body with keys:

    - `"added"` — boolean value indicating whether the reaction was added (true) or already present
      (false).
    - `"seqno"` — the message's new seqno value.  This can be used to identify stale reaction
      updates when polling and reactions can race: if an in-progress poll returns a reaction update
      for the message with a seqno less than this value then the client can know that that reaction
      update won't yet have the reaction added here.

    # Error status codes

    - 403 Forbidden — returned if the user doesn't have read permission in the room.
    - 404 Not Found — returned if the given post does not exist
    - 400 Bad Request — if the input does not contain a valid reaction

    Note that it is *not* an error to attempt to add a reaction that the user has already added
    (instead in such a case the success response return value includes `"added": false`).
    """

    added, seqno = room.add_reaction(g.user, msg_id, reaction)
    return jsonify({"added": added, "seqno": seqno})


@messages.delete("/room/<Room:room>/reaction/<int:msg_id>/<path:reaction>")
@auth.user_required
@auth.read_required
def message_unreact(room, msg_id, reaction):
    """
    Removes a reaction from a post this room.  The user must have read access in the room.  This
    only removes the user's own reaction but does not affect the reactions of other users.

    # URL Parameters

    - `msg_id` — The message ID from which the reaction should be removed.  The message must be in
      this room, must not be deleted, and must be a regular message (i.e. not a whisper).

    - `reaction` — The UTF-8 reaction string.  See the PUT endpoint for encoding information.

    # Return value

    On success returns a 200 status code and a JSON object response body with keys:

    - `"removed"` — boolean value indicating whether the reaction was removed (true) or was not
      present to begin with (false).
    - `"seqno"` — the message's new seqno value.  (See description in the put reaction endpoint).

    # Error status codes

    - 403 Forbidden — returned if the user doesn't have read permission in the room.
    - 404 Not Found — returned if the given post does not exist
    - 400 Bad Request — if the input does not contain a valid reaction

    Note that it is *not* an error to attempt to remove a reaction that does not exist (instead in
    such a case the success response return value includes `"removed": false`).
    """
    removed, seqno = room.delete_reaction(g.user, msg_id, reaction)
    return jsonify({"removed": removed, "seqno": seqno})


@messages.delete("/room/<Room:room>/reactions/<int:msg_id>/<path:reaction>")
@messages.delete("/room/<Room:room>/reactions/<int:msg_id>")
@auth.mod_required
def message_delete_reactions(room, msg_id, reaction=None):
    """
    Removes all reactions of all users from a post in this room.  The calling must have moderator
    permissions in the room.  This endpoint can either remove a single reaction (e.g. remove all 🍆
    reactions) by specifying it after the message id (following a /), or remove *all* reactions from
    the post by not including the `/<reaction>` suffix of the URL.

    # URL Parameters

    - `msg_id` — The message ID from which the reactions should be removed.  The message must be in
      this room, must not be deleted, and must be a regular message (i.e. not a whisper).

    - `reaction` — The optional UTF-8 reaction string. If specified then all reactions of this type
      are removed; if omitted then *all* reactions are removed from the post.  See the PUT endpoint
      for encoding information.

    # Return value

    On success returns a 200 status code and a JSON object response body with keys:

    - `"removed"` — the total number of reactions that were deleted.
    - `"seqno"` — the message's new seqno value.  (See description in the put reaction endpoint).

    # Error status codes

    - 403 Forbidden — if not a moderator
    - 404 Not Found — if the referenced post does not exist or is not a regular message
    - 400 Bad Request — if the input does not contain a valid reaction *or* `"all": true`.
    """
    removed, seqno = room.delete_all_reactions(g.user, msg_id, reaction)
    return jsonify({"removed": removed, "seqno": seqno})


@messages.get("/room/<Room:room>/reactors/<int:msg_id>/<path:reaction>")
@auth.read_required
def message_get_reactors(room, msg_id, reaction):
    """
    Returns the list of all reactors who have added a particular reaction to a particular message.

    # URL Parameters

    - `msg_id` — The message ID in this room for which reactions are being queried.  The message
      must be in this room, must not be deleted, and must be a regular message (i.e. not a whisper).

    - `reaction` — The UTF-8 reaction string.  See the PUT endpoint for encoding information.

    # Query Parameters

    - `limit` — if specified this indicates the maximum number of reactor IDs to return.  If omitted
      or specified as <= 0 then there is no limit.

    # Return value

    On success returns a 200 status code with a body consisting of a JSON list of [session ID,
    timestamp] pairs containing the users who added this reaction, and the unix timestamp at which
    they added the reaction.

    # Error status codes

    - 403 Forbidden — if the caller does not have read access to the room
    - 404 Not Found — if the referenced post does not exist or is not a regular message
    - 400 Bad Request — if the `reaction` value is not a valid reaction
    """

    limit = utils.get_int_param('limit', 0)
    if limit <= 0:
        limit = None
    return jsonify(room.get_reactors(msg_id, reaction, g.user, limit=limit))
