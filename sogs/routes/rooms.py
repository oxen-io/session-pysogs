from .. import config, db, http
from ..model import room as mroom
from ..web import app
from . import auth

from flask import abort, jsonify, g, Blueprint, request

# Room-related routes, excluding retrieving/posting messages


rooms = Blueprint('rooms', __name__)


def get_room_info(room):
    mods, admins, h_mods, h_admins = room.get_mods(g.user)

    rr = {
        'token': room.token,
        'name': room.name,
        'info_updates': room.info_updates,
        'message_sequence': room.message_sequence,
        'created': room.created,
        'active_users': room.active_users(),
        'active_users_cutoff': int(config.ROOM_DEFAULT_ACTIVE_THRESHOLD * 86400),
        'moderators': mods,
        'admins': admins,
        'read': room.check_read(g.user),
        'write': room.check_write(g.user),
        'upload': room.check_upload(g.user),
    }

    if room.description is not None:
        rr['description'] = room.description

    if room.image_id is not None:
        rr['image_id'] = room.image_id

    pinned = room.pinned_messages
    if pinned:
        rr['pinned_messages'] = pinned

    if h_mods:
        rr['hidden_moderators'] = h_mods
    if h_admins:
        rr['hidden_admins'] = h_admins

    if room.check_moderator(g.user):
        rr['moderator'] = True
        rr['default_read'] = room.default_read
        rr['default_accessible'] = room.default_accessible
        rr['default_write'] = room.default_write
        rr['default_upload'] = room.default_upload
    if room.check_admin(g.user):
        rr['admin'] = True
    if g.user:
        if g.user.global_moderator:
            rr['global_moderator'] = True
        if g.user.global_admin:
            rr['global_admin'] = True

    return rr


@rooms.get("/room/<Room:room>")
@auth.accessible_required
def get_one_room(room):
    """
    Returns the details of a single room.

    # Return value

    A JSON object with keys:

    - `token` — The room token as used in a URL, e.g. `"sudoku"`.
    - `name` — The room name typically shown to users, e.g. `"Sodoku Solvers"`.
    - `description` — Text description of the room, e.g. `"All the best sodoku discussion!"`.
    - `info_updates` — Monotonic integer counter that increases whenever the room's metadata changes
    - `message_sequence` — Monotonic room post counter that increases each time a message is posted,
      edited, or deleted in this room.  (Note that changes to this field do *not* imply an update
      the room's `info_updates` value, nor vice versa).
    - `created` — Unix timestamp (as a float) of the room creation time.  Note that unlike earlier
      versions of SOGS, this is a proper seconds-since-epoch unix timestamp, not a javascript-style
      millisecond value.
    - `active_users` — Number of recently active users in the room over a recent time period (as
      given in the `active_users_cutoff` value).  Users are considered "active" if they have
      accessed the room (checking for new messages, etc.) at least once in the given period.
      **Note:** changes to this field do *not* update the room's `info_updates` value.
    - `active_users_cutoff` — The length of time (in seconds) of the `active_users` period.
      Defaults to a week (604800), but the open group administrator can configure it.
    - `image_id` — File ID of an uploaded file containing the room's image.  Omitted if there is no
      image.
    - `pinned_messages` — Array of pinned message information (omitted entirely if there are no
      pinned messages).  Each array element is an object with keys:
        * `id` — The numeric message id.
        * `pinned_at` — The unix timestamp when the message was pinned.
        * `pinned_by` — The session ID of the admin who pinned this message (which is not
          necessarily the same as the author of the message).
    - `moderators` — Array of Session IDs of the room's publicly viewable moderators.  This does not
      include room administrators nor hidden moderators.
    - `admins` — Array of Session IDs of the room's publicly viewable moderators.  This does not
      include room moderator nor hidden admins.
    - `hidden_moderators` — Array of Session IDs of the room's publicly hidden moderators.  This
      field is only included if the requesting user has moderator or admin permissions, and is
      omitted if empty.
    - `hidden_admins` — Array of Session IDs of the room's publicly hidden admins.  This field is
      only included if the requesting user has moderator or admin permissions, and is omitted if
      empty.
    - `default_read`, `default_accessible`, `default_write`, `default_upload` — These four boolean
      fields indicate whether new users have read, access, write, and upload permissions,
      respectively, in the room.  They are included in the response only if the requesting user has
      moderator or admin permissions.
    - `read`, `write`, `upload` — These three boolean flags indicate whether the **current** user
      has permission to read messages, write messages, or upload files to this room, respectively.
      (Accessibility is not included as being able to access the room information at all implies the
      room is accessible).
    - `moderator` — True if the current user has moderator permissions in the room, omitted
      otherwise.
    - `admin` — True if the current user has admin permissions in the room, omitted otherwise.  This
      is *not* exclusive of `moderator`: that is, an admin will have both `admin` and `moderator`
      set to true.
    - `global_moderator` — True if the current user is a global moderator.  This is not exclusive of
      `moderator`: a global moderator will have both flags set.
    - `global_admin` — True if the current user is a global admin.  This is *not* exclusive of
      `global_moderator`/`moderator`/`admin`: that is, a global admin will have all four set to
      true.

    # Access permissions

    The four access permissions control what a user can do in a room.  Users can have specific
    overrides (either true or false) applied for each room by moderators; if there are no such
    override then a user receives the room's `default_*` permission (e.g. `default_read`).  The
    meaning of each permission is as follows:

    - `read` — this allows a user to read messages posted in the room.
    - `write` — this allows users to post messages to the room.
    - `upload` — this allows users to upload attachments to the room (but only if `write` is also
      set).
    - `access` — this flag controls only applies when a user does *not* have `read` access: if this
      is true (which is the default for new rooms) then the user can still see information about the
      room such as its name, description, and user count, but cannot access the messages themselves.
      If this is *false* then the user does not have any access to the room at all and will receive
      a 404 Not Found error if attempting to access it (the same thing they would see if the room
      didn't exist).  This is provided to allow for "secret" rooms that only invited users may
      access (by setting both `default_accessible` and `default_write` to false).

    # Error status codes

    - 403 Forbidden — Returned if the current user does not have permission to access the room,
      e.g. because they are banned or the room permissions otherwise restrict access.

    - 404 Not Found — Returned if the room does not exist, or is configured as inaccessible (and
      this user doesn't have access).
    """
    return jsonify(get_room_info(room))


@rooms.get("/rooms")
def get_rooms():
    """
    Returns a list of available rooms on the server.

    Rooms to which the user does not have access (e.g. because they are banned, or the room has
    restricted access permissions) are not included.

    # Return value

    Returns a json list of the rooms.  Each room is an JSON object as would be returned by [the
    single-room version](#get-roomroom) of this call.
    """
    return jsonify([get_room_info(room=r) for r in mroom.get_accessible_rooms(g.user)])


BAD_NAME_CHARS = {c: None for c in range(32)}
BAD_DESCRIPTION_CHARS = {c: None for c in range(32) if not (0x09 <= c <= 0x0A)}


@rooms.put("/room/<Room:room>")
@auth.admin_required
def update_room(room):
    """
    Updates room details/settings.

    This request takes a JSON object as request body containing the room details to update.  Any
    field can be omitted to leave it at its current value.  The invoking user must have admin
    permissions in the room to call this method.

    Supported fields are:

    - `name` — New user-displayed single-line name/title of this room.  UTF-8 encoded; newlines,
      tabs and other control characters (i.e. all codepoints below \u0020) will be stripped out.
    - `description` — Long description to show to users, typically in smaller text below the room
      name.  UTF-8 encoded, and permits newlines, tabs; other control characters below \u0020 will
      be stripped out.  Can be `null` or an empty string to remove the description entirely.
    - `default_read`, `default_accessible`, `default_write`, `default_upload` — if specified these
      update the room's default read, access, write, and upload permissions for ordinary users (i.e.
      users who do not have any other user-specific permission applied).  See the description of
      Access permissions in the (room information)[#get-roomroom] endpoint for details.

    # Return value

    On success this endpoint returns a 200 status code and an empty json object (`{}`) as the body.

    # Error status codes

    - 403 Forbidden — if the invoking user does not have administrator access to the room.
    """

    req = request.json

    with db.transaction():
        did = False
        if 'name' in req:
            n = req['name']
            if not isinstance(n, str):
                app.logger.warning(f"Room update with invalid name: {type(n)} != str")
                abort(http.BAD_REQUEST)
            room.name = n.translate(BAD_NAME_CHARS)
            did = True
        if 'description' in req:
            d = req['description']
            if not (d is None or isinstance(d, str)):
                app.logger.warning(f"Room update: invalid description: {type(d)} is not str, null")
                abort(http.BAD_REQUEST)
            if d is not None:
                d = d.translate(BAD_DESCRIPTION_CHARS)
                if len(d) == 0:
                    d = None

            room.description = d
            did = True
        read, accessible, write, upload = (
            req.get('default_' + x) for x in ('read', 'accessible', 'write', 'upload')
        )
        for val in (read, accessible, write, upload):
            if not (val is None or isinstance(val, bool) or isinstance(val, int)):
                app.logger.warning(
                    "Room update: default_read/accessible/write/upload must be bool, not "
                    f"{type(val)}"
                )
                abort(http.BAD_REQUEST)

        if read is not None:
            room.default_read = bool(read)
            did = True
        if accessible is not None:
            room.default_accessible = bool(accessible)
            did = True
        if write is not None:
            room.default_write = bool(write)
            did = True
        if upload is not None:
            room.default_upload = bool(upload)
            did = True

        if not did:
            app.logger.warning("Room update: must include at least one field to update")
            abort(http.BAD_REQUEST)

    return jsonify({})


@rooms.get("/room/<Room:room>/pollInfo/<int:info_updated>")
@auth.read_required
def poll_room_info(room, info_updated):
    """
    Polls a room for metadata updates.

    The endpoint polls room metadata for this room, always including the instantaneous room details
    (such as the user's permission and current number of active users), and including the full room
    metadata if the room's info_updated counter has changed from the provided value.

    # URL Parameters

    - `info_updated` — The client's currently cached `info_updates` value for the room.  The full
      room metadata is returned in the response if and only if the room's last update count does not
      equal the given value.

    # Return value

    On success this returns the results of polling the room for updated information.  This endpoint
    always returns ephemeral data, such as the number of active users and the current user's
    permissions, and will include the full room details if and only if it has changed (i.e.
    info_updates does not match) from the `info_updated` value provided by the requestor.

    Note that the `details` field is only present and populated if the room's `info_updates` counter
    differs from the provided `info_updated` value; otherwise the values are unchanged and so it is
    omitted.

    The return value is a JSON object containing the following subset of values of [the full room
    details](#get-roomroom):

    - `token`
    - `active_users`
    - `read`, `write`, `upload`
    - `moderator`, `admin`, `global_moderator`, `global_admin`
    - `default_read`, `default_accessible`, `default_write`, `default_upload`

    If the room metadata has changed then the following is also included:

    - `details` — The full room metadata (as would be returned by the [`/rooms/ROOM`
      endpoint](#get-roomroom)).

    The intention is that this endpoint allows a client to know that it doesn't need to worry about
    updating the room image or pinned messages whenever the `details` field is not included in the
    response.

    # Error status codes

    - 403 Forbidden — if the invoking user does not have access to the room.
    """
    if g.user:
        g.user.update_room_activity(room)

    result = {
        'token': room.token,
        'active_users': room.active_users(),
        'read': room.check_read(g.user),
        'write': room.check_write(g.user),
        'upload': room.check_upload(g.user),
    }

    if room.info_updates != info_updated:
        result['details'] = get_room_info(room)

    if room.check_moderator(g.user):
        result['moderator'] = True
        result['default_read'] = room.default_read
        result['default_accessible'] = room.default_accessible
        result['default_write'] = room.default_write
        result['default_upload'] = room.default_upload
    if room.check_admin(g.user):
        result['admin'] = True
    if g.user:
        if g.user.global_moderator:
            result['global_moderator'] = True
        if g.user.global_admin:
            result['global_admin'] = True

    return jsonify(result)
