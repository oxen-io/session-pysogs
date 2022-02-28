from .. import db, http, utils
from ..model import room as mroom
from ..model.exc import NoSuchUser
from ..model.user import User
from ..model.message import Message
from ..web import app
from . import auth

from flask import abort, jsonify, g, Blueprint, request, Response

# User-related routes


users = Blueprint('users', __name__)


def extract_rooms_or_global(req, admin=True):
    """
    Extracts the rooms / global parameters from the request body checking them for validity and
    expanding them as appropriate.

    Throws a flask abort on failure, returns (rooms, global) which will be either ([list of Rooms],
    None) for a room operation or (None, True) for a global operation.

    admin specifies whether we require admin permission (if True) or just moderator permission,
    either in all rooms specified, or globally.  (Similarly it affects what `rooms=['*']` expands
    to).
    """

    if not isinstance(req, dict):
        app.logger.warning(f"Invalid request: expected a JSON object body, not {type(req)}")
        abort(http.BAD_REQUEST)

    room_tokens, global_ = req.get('rooms'), req.get('global', False)

    if room_tokens and not isinstance(room_tokens, list):
        app.logger.warning("Invalid request: rooms must be a list")
        abort(http.BAD_REQUEST)

    if room_tokens and global_:
        app.logger.warning("Invalid moderator request: cannot specify both 'rooms' and 'global'")
        abort(http.BAD_REQUEST)

    if not room_tokens and not global_:
        app.logger.warning("Invalid moderator request: neither 'rooms' nor 'global' specified")
        abort(http.BAD_REQUEST)

    if room_tokens:
        if len(room_tokens) > 1 and '*' in room_tokens:
            app.logger.warning("Invalid moderator request: room '*' must be the only rooms value")
            abort(http.BAD_REQUEST)

        if room_tokens == ['*']:
            room_tokens = None

        try:
            rooms = mroom.get_rooms_with_permission(
                g.user, tokens=room_tokens, moderator=True, admin=True if admin else None
            )
        except Exception as e:
            # This is almost certainly a bad room token passed in:
            app.logger.warning(f"Cannot get rooms for adding a moderator: {e}")
            abort(http.NOT_FOUND)

        if room_tokens:
            if len(rooms) != len(room_tokens):
                abort(http.FORBIDDEN)
        elif not rooms:
            abort(http.FORBIDDEN)

        return (rooms, None)

    if not g.user.global_moderator or (admin and not g.user.global_admin):
        abort(http.FORBIDDEN)

    return (None, True)


def _serialize_message(msg):
    return {
        "id": msg.id,
        "posted_at": msg.posted_at,
        "expires_at": msg.expires_at,
        "message": utils.encode_base64(msg.data),
        "sender": msg.sender.session_id,
    }


@users.get("/inbox")
@auth.user_required
def get_inbox():
    """
    Retrieves all of the user's current messages (up to `limit`).

    # Query Parameters

    The request takes an optional `limit` query parameter indicating the number of messages to
    return (up to 256).  If omitted, at most 100 messages are returned.

    # Return value

    Returns a JSON array of up to `limit` (default 100) messages, with oldest messages first.  Each
    element is a JSON object with keys:

    - `id` — the unique integer message id.
    - `posted_at` — unix timestamp (float) when the message was received by SOGS.
    - `expires_at` — unix timestamp (float) when SOGS will expire and delete the message.
    - `message` — the encrypted message body.
    - `sender` — the (blinded) Session ID of the sender of the message.

    # Encryption details

    SOGS itself does not have the ability to decrypt the message contents and thus cannot enforce
    any particular content; the following, however, is strongly recommended for Session client
    interoperability:

    Alice has master Session Ed25519 keypair a, A and blinded keypair ka, kA.

    Bob has master Session Ed25519 keypair b, B and blinded keypair kb, kB.

    Alice wants to send a message to Bob, knowing only kB (i.e. the blinded Session ID after
    stripping the 0x15 prefix).

    Alice constructs a message using Session protobuf encoding, then concatenates her *unblinded*
    pubkey, A, to this message:

    MSG || A

    Alice then constructs an encryption key:

    E = H(a * kB || kA || kB)

    where H(.) is 32-byte BLAKE2b, and the `*` denotes unclamped Ed25519 scalar*point multiplication
    (e.g. libsodium's `crypto_scalarmult_ed25519_noclamp`).

    The `MSG || A` plaintext value is then encrypted using XChaCha20-Poly1305 (e.g. using
    libsodium's `crypto_aead_xchacha20poly1305_ietf_encrypt` function), using a secure-random
    24-byte nonce, no additional data, and encryption key `E`.

    The final data message is then constructed as:

    0x00 || CIPHERTEXT || NONCE

    where 0x00 is a version byte (allowing for future alternative encryption formats) and the rest
    are bytes.

    Finally this is base64-encoded when send to/retrieved from the SOGS.

    # Decryption

    Decryption proceeds by reversing the steps above:

    1. base64-decode the value.

    2. Grab the version byte from the front and the 24-byte nonce from the back of the value.

        a) if the version byte is not 0x00 abort because this message is from someone using a
        different encryption protocol.

    3. Construct the encryption key by calculating:

            E = H(b * kA || kA || kB)

        where kA is the sender's de-prefixed blinded Session ID, b is the user's master Ed25519 key,
        and kB is the user's blinded Ed25519 for this SOGS server.

    4. Decrypt the remaining ciphertext using the nonce.

    5. Unpack the plaintext value into MSG and the sender's `A` value (i.e. the last 32 bytes).

    6. Derive the sender's actual Session ID by converting `A` from an ed25519 pubkey to an
       curve25519 pubkey and prepending 0x05.  (E.g. using libsodium's
       `crypto_sign_ed25519_pk_to_curve25519` on `A`, then adding the 05 prefix to the front).

    This then leaves the receiving client with the true Session ID of the sender, and the message
    body (encoded according to typical Session message protobuf encoding).
    """
    if not g.user.is_blinded:
        abort(http.FORBIDDEN)
    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)
    return jsonify([_serialize_message(msg) for msg in Message.to(user=g.user, limit=limit)])


@users.get("/inbox/since/<int:msgid>")
@auth.user_required
def poll_inbox(msgid):
    """
    Polls for any DMs received since the given id.

    # URL Parameters

    - `msgid` — the numeric message ID of the last received message.  (Newer messages will always
      have a higher ID).

    # Query Parameters

    The request takes an optional `limit` query parameter indicating the number of messages to
    return (up to 256).  If omitted, at most 100 messages are returned.

    # Return value

    This method, on success, returns *either* a 200 (OK) status code with a list of 1 or more new
    messages, or else returns a 304 (Not Modified) response with an empty body to indicate that
    there are no messages for this user newer than the given ID.

    If there are messages this returns a JSON array of up to `limit` (default 100) messages, with
    oldest messages first.  Each element is exactly as described in the [all messages](#GET-inbox)
    endpoint.
    """
    if not g.user.is_blinded:
        abort(http.FORBIDDEN)

    limit = utils.get_int_param('limit', 100, min=1, max=256, truncate=True)
    msgs = [_serialize_message(msg) for msg in Message.to(user=g.user, since=msgid, limit=limit)]
    if len(msgs) > 0:
        return jsonify(msgs)
    return Response('', status=http.NOT_MODIFIED)


@users.post("/inbox/<BlindSessionID:sid>")
@auth.user_required
def send_inbox(sid):
    """
    Delivers a direct message to a user via their blinded Session ID.

    The body of this request is a JSON object containing a `message` key with a value of the
    encrypted-then-base64-encoded message to deliver.

    Message encryption is described in the [`GET` /inbox](#GET-inbox) endpoint.

    # Return value

    On successful deposit of the message a 201 (Created) status code is returned.  The body will be
    a JSON object containing an `expires_at` key indicating the unix timestamp of when the message
    expires.

    # Error status codes

    400 Bad Request — if no message is provided.

    404 Not Found — if the given Session ID does not exist on this server, either because they have
    never accessed the server, or because they have been permanently banned.
    """
    try:
        recip_user = User(session_id=sid, autovivify=False)
    except NoSuchUser:
        abort(http.NOT_FOUND)

    if recip_user.banned:
        abort(http.NOT_FOUND)

    req = request.json
    message = req.get('message')
    if message is None:
        app.logger.warning("No message provided")
        abort(http.BAD_REQUEST)

    with db.transaction():
        msg = Message(data=utils.decode_base64(message), recip=recip_user, sender=g.user)
    return jsonify({"expires_at": msg.expires_at}), http.CREATED


@users.post("/user/<SessionID:sid>/moderator")
@auth.user_required
def set_mod(sid):
    """
    Appoints or removes a moderator or admin.

    This endpoint is used to appoint or remove moderator/admin permissions either for specific rooms
    or for server-wide global moderator permissions.

    Admins/moderators of rooms can only be appointed or removed by a user who has admin permissions
    in the room (including global admins).  Global admins/moderators may only be appointed by a
    global admin.

    # Body Parameters

    Takes a JSON object as body with the following keys:

    - `rooms` — List of one or more room tokens to which the moderator status should be applied. The
      invoking user must be an admin of all of the given rooms.

        This may be set to the single-element list ["*"] to add or remove the moderator from all
        rooms in which the current user has admin permissions (the call will succeed if the calling
        user is an admin in at least one channel).

        Exclusive of `global`.

    - `global` — boolean value: if true then apply the change at the server-wide global level: the
      user will be added/removed as a global moderator.  The invoking user must be a global admin in
      order to control global mods/admins.

        Exclusive of `rooms`.

    - `moderator` — optional boolean value indicating that this user should have moderator
      permissions added (`true`), removed (`false`), or left alone (omitted or `null`).  At least
      one non-null value of `moderator` or `admin` must be provided.

    - `visible` — boolean specifying whether the moderator/admin should be made publicly visible as
      a moderator/admin of the room(s) (if `true`) or hidden (`false`).  Hidden moderators/admins
      still have all the same permissions as visible moderators/admins, but are visible only to
      other moderators/admins; regular users in the room will not know their moderator status.

        The default behaviour if this field is omitted (or `null`) is to make the moderator visible
        when adding as a room moderator/admin, and hidden if adding as a global moderator/admin.

    - `admin` — boolean value indicating that this user should have admin permissions added
      (`true`), removed (`false`), or left alone (omitted or `null`).  Note that granting admin
      permission automatically includes granting moderator permission, and thus it is an error to
      use `admin=true` with `moderator=false`.

    The request must include exactly one non-null value of `rooms` and `global`, and at least one
    non-null value of `moderator` and `admin`.

    Different combinations of `moderator` and `admin` true/false/omitted values interact as follows
    (note that an omitted value and an explicit `null` value are equivalent):

    - `admin=true` — Adds admin permissions (and, implicitly, moderator permissions).
    - `admin=true`, `moderator=true` — Same as above (adds admin permission).
    - `admin=false`, `moderator=true` — Removes admin permission, if present, and assigns moderator
      permission.  This both demotes an admin to a moderator, and promotes a non-moderator to a
      moderator.
    - `admin=false`, — Removes admin permission, if present, but leaves moderator permissions alone.
      This effectively "demotes" the user from admin to moderator, but will not promote a
      non-moderator/admin to a moderator.
    - `moderator=true` — Adds moderator permissions.  If admin permission is already present, it
      remains in effect.
    - `moderator=false` — Removes moderator **and admin** permissions, if present.
    - `moderator=false`, `admin=false` — Same as above (removes both).
    - `admin=true`, `moderator=false` — Error: because admin implies moderator, this is impossible
      to fulfill.
    - both null — Error: at least one must have a non-null value.

    If an admin or moderator has both global and room-specific moderation permissions then their
    actual moderator status will be taken as the greater of the two.  That is, they will have room
    admin permissions if listed as an admin of *either* the room or global server.

    Visibility, however, is determined by the room-specific visibility setting, regardless of the
    global setting.  (So, for example, a hidden global admin with moderator powers in a room will
    appears as a visible admin of the room, and a global visible admin listed as a room hidden
    moderator will be effectively a hidden admin of the room).

    # Return value

    On success returns a 200 status code with an empty JSON object as body.

    # Error status codes

    400 Bad Request — if invalid parameters (or parameter combinations) are provided, such as an
    empty room list, or not specifying either moderator or admin parameters.

    403 Forbidden — if the invoking user does not have admin access to all of the given `rooms` (or,
    for a global moderator request, is not a global admin).

    404 Not Found — if one or more of the given `rooms` tokens do not exist.
    """

    user = User(session_id=sid)

    req = request.json

    rooms, global_mod = extract_rooms_or_global(req)

    mod, admin, visible = (
        None if arg is None else bool(arg)
        for arg in (req.get('moderator'), req.get('admin'), req.get('visible'))
    )

    # Filter out any invalid or redundant arguments:
    if (admin, mod) == (None, None):
        app.logger.warning(
            "Invalid moderator request: at least one of admin/moderator must be specified"
        )
        abort(http.BAD_REQUEST)
    elif (admin, mod) == (True, False):
        app.logger.warning("Invalid moderator call: admin=True, moderator=False is impossible")
        abort(http.BAD_REQUEST)
    elif (admin, mod) == (True, True):
        mod = None  # admin already implies mod so we can ignore it
    elif (admin, mod) == (False, False):
        admin = None  # ¬mod implies ¬admin so we can ignore it

    # We now have one of these cases:
    # (True, None) -- adds admin
    # (None, True) -- adds mod
    # (None, False) -- removes mod/admin
    # (False, True) -- removes admin, adds mod
    # (False, None) -- removes admin

    if rooms:
        if visible is None:
            visible = True

        with db.transaction():
            for room in rooms:
                if (admin, mod) in ((True, None), (None, True)):
                    room.set_moderator(user, added_by=g.user, admin=admin, visible=visible)
                elif (admin, mod) == (None, False):
                    room.remove_moderator(user, removed_by=g.user)
                elif (admin, mod) == (False, None):
                    room.remove_moderator(user, removed_by=g.user, remove_admin_only=True)
                elif (admin, mod) == (False, True):
                    room.remove_moderator(user, removed_by=g.user, remove_admin_only=True)
                    room.set_moderator(user, added_by=g.user, admin=False, visible=visible)
                else:
                    app.logger.error("Internal error: unhandled mod/admin room case")
                    raise RuntimeError("Internal error: unhandled mod/admin room case")

    else:  # global mod
        if visible is None:
            visible = False

        if (admin, mod) in ((True, None), (None, True)):
            user.set_moderator(added_by=g.user, admin=admin, visible=visible)
        elif (admin, mod) == (None, False):
            user.remove_moderator(removed_by=g.user)
        elif (admin, mod) == (False, None):
            user.remove_moderator(removed_by=g.user, remove_admin_only=True)
        elif (admin, mod) == (False, True):
            with db.transaction():
                user.remove_moderator(removed_by=g.user, remove_admin_only=True)
                user.set_moderator(added_by=g.user, admin=bool(admin), visible=visible)

    return jsonify({})


@users.post("/user/<SessionID:sid>/ban")
@auth.user_required
def ban_user(sid):
    """
    Applies a ban of a user from specific rooms, or from the server globally.

    The invoking user must have moderator (or admin) permission in all given rooms when specifying
    `rooms`, and must be a global server moderator (or admin) if using the `global` parameter.

    # Body Parameters

    Takes a JSON object as body with the following keys:

    - `rooms` — List of one or more room tokens from which the user should be banned. The
      invoking user must be a moderator of all of the given rooms.

        This may be set to the single-element list ["*"] to ban the user from all rooms in which the
        invoking user has moderator permissions (the call will succeed if the calling user is a
        moderator in at least one channel).

        Exclusive of `global`.

    - `global` — boolean value: if true then apply the ban at the server-wide global level: the user
      will be banned from the server entirely—not merely from all rooms, but also from calling any
      other server request.  The invoking user must be a global moderator in order to add a global
      ban.

        Exclusive of `rooms`.

    - `timeout` — optional numeric value specifying a time limit on the ban, in seconds.  The
      applied ban will expire and be removed after the given interval.  If omitted (or `null`) then
      the ban is permanent.

        If this endpoint is called multiple times then the `timeout` of the last call takes effect.
        For example, a permanent ban can be replaced with a time-limited ban by calling the endpoint
        again with a `timeout` value, and vice versa.

    The request must include exactly one non-null value of `rooms` and `global`.

    The user's messages are not deleted by this request.  In order to ban and delete all messages
    use the [`/sequence`](#post-sequence) endpoint to bundle a `/user/.../ban` with a
    [`/user/.../deleteMessages`](#post-usersiddeleteMessages) request.

    # Return value

    On success returns a 200 status code with an empty JSON object as body.

    # Error status codes

    400 Bad Request — if invalid parameters (or parameter combinations) are provided, such as an
    empty room list.

    403 Forbidden — if the invoking user does not have moderator access to all of the given `rooms`
    (or, for a global moderator request, is not a global moderator).

    404 Not Found — if one or more of the given `rooms` tokens do not exist.
    """

    user = User(session_id=sid)
    req = request.json
    rooms, global_ban = extract_rooms_or_global(req, admin=False)

    timeout = req.get('timeout')
    if timeout is not None and not isinstance(timeout, int) and not isinstance(timeout, float):
        app.logger.warning("Invalid ban request: timeout must be numeric")
        abort(http.BAD_REQUEST)

    if rooms:
        with db.transaction():
            for room in rooms:
                room.ban_user(to_ban=user, mod=g.user, timeout=timeout)
    else:
        user.ban(banned_by=g.user, timeout=timeout)

    return {}


@users.post("/user/<SessionID:sid>/unban")
@auth.user_required
def unban_user(sid):
    """
    Removes a user ban from specific rooms, or from the server globally.

    The invoking user must have moderator (or admin) permission in all given rooms when specifying
    `rooms`, and must be a global server moderator (or admin) if using the `global` parameter.

    # Body Parameters

    Takes a JSON object as body with the following keys:

    - `rooms` — List of one or more room tokens from which the ban should be removed. The invoking
      user must be a moderator of all of the given rooms.

        This may be set to the single-element list ["*"] to unban the user from all rooms in which
        the invoking user has moderator permissions (the call will succeed if the calling user is a
        moderator in at least one channel).

        Exclusive of `global`.

    - `global` — boolean value: if true then remove a server-wide global ban.

        Exclusive of `rooms`.

    The request must include exactly one non-null value of `rooms` and `global`.

    Note that room and global bans are independent: if a user is banned globally *and* has a
    room-specific ban then removing the global ban does not remove the room specific ban, and
    removing the room-specific ban does not remove the global ban.  (To fully unban a user globally
    and from all rooms, submit a sequence request with a global unban followed by a `"rooms": ["*"]`
    unban).

    # Return value

    On success returns a 200 status code with an empty JSON object as body.

    # Error status codes

    400 Bad Request — if invalid parameters (or parameter combinations) are provided, such as an
    empty room list.

    403 Forbidden — if the invoking user does not have moderator access to all of the given `rooms`
    (or, for a global moderator request, is not a global moderator).

    404 Not Found — if one or more of the given `rooms` tokens do not exist.
    """

    user = User(session_id=sid)
    rooms, global_ban = extract_rooms_or_global(request.json, admin=False)

    if rooms:
        with db.transaction():
            for room in rooms:
                room.unban_user(to_unban=user, mod=g.user)
    else:
        user.unban(unbanned_by=g.user)

    return {}
