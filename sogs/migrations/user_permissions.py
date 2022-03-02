import logging
from .exc import DatabaseUpgradeRequired


def migrate(conn, *, check_only):
    """
    Recreates the user_permissions view if it doesn't exist; this is the common code for both
    room_accessible and seqno_etc as both drop the view (when migrating) to be recreated here.
    """

    from .. import db

    if 'user_permissions' in db.metadata.tables:
        return False

    logging.warning("DB migration: recreating user_permissions view")
    if check_only:
        raise DatabaseUpgradeRequired("Recreate user_permissions view")

    sqlite = db.engine.name == "sqlite"
    conn.execute(
        f"""
CREATE VIEW user_permissions AS
SELECT
    rooms.id AS room,
    users.id AS {'user' if sqlite else '"user"'},
    users.session_id,
    CASE WHEN users.banned THEN TRUE ELSE COALESCE(user_permission_overrides.banned, FALSE) END AS banned,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.read, rooms.read) END AS read,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.accessible, rooms.accessible) END AS accessible,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.write, rooms.write) END AS write,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.upload, rooms.upload) END AS upload,
    CASE WHEN users.moderator THEN TRUE ELSE COALESCE(user_permission_overrides.moderator, FALSE) END AS moderator,
    CASE WHEN users.admin THEN TRUE ELSE COALESCE(user_permission_overrides.admin, FALSE) END AS admin,
    -- room_moderator will be TRUE if the user is specifically listed as a moderator of the room
    COALESCE(user_permission_overrides.moderator OR user_permission_overrides.admin, FALSE) AS room_moderator,
    -- global_moderator will be TRUE if the user is a global moderator/admin (note that this is
    -- *not* exclusive of room_moderator: a moderator/admin could be listed in both).
    COALESCE(users.moderator OR users.admin, FALSE) as global_moderator,
    -- visible_mod will be TRUE if this mod is a publicly viewable moderator of the room
    CASE
        WHEN user_permission_overrides.moderator OR user_permission_overrides.admin THEN user_permission_overrides.visible_mod
        WHEN users.moderator OR users.admin THEN users.visible_mod
        ELSE FALSE
    END AS visible_mod
FROM
    users {'JOIN' if sqlite else 'CROSS JOIN'} rooms LEFT OUTER JOIN user_permission_overrides ON
        (users.id = user_permission_overrides.{'user' if sqlite else '"user"'} AND rooms.id = user_permission_overrides.room)
"""  # noqa E501
    )

    return True
