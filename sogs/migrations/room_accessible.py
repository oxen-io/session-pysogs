import logging


def migrate(conn):
    """Add the room.accessible permission flag, and associated column/view changes"""

    from .. import db

    if 'accessible' in db.metadata.tables['rooms'].c:
        return False

    logging.warning("DB migration: adding 'accessible' room permission columns")

    conn.execute("ALTER TABLE rooms ADD COLUMN accessible BOOLEAN NOT NULL DEFAULT TRUE")
    conn.execute("ALTER TABLE user_permission_overrides ADD COLUMN accessible BOOLEAN")
    conn.execute("DROP TRIGGER IF EXISTS user_perms_empty_cleanup")
    conn.execute("DROP VIEW IF EXISTS user_permissions")

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
    if sqlite:
        conn.execute(
            """
CREATE TRIGGER user_perms_empty_cleanup AFTER UPDATE ON user_permission_overrides
FOR EACH ROW WHEN NOT (NEW.banned OR NEW.moderator OR NEW.admin)
    AND COALESCE(NEW.accessible, NEW.read, NEW.write, NEW.upload) IS NULL
BEGIN
    DELETE from user_permission_overrides WHERE room = NEW.room AND user = NEW.user;
END
"""
        )

    else:
        conn.execute(
            """
CREATE TRIGGER user_perms_empty_cleanup AFTER UPDATE ON user_permission_overrides
FOR EACH ROW WHEN (NOT (NEW.banned OR NEW.moderator OR NEW.admin)
    AND COALESCE(NEW.accessible, NEW.read, NEW.write, NEW.upload) IS NULL)
EXECUTE PROCEDURE trigger_user_perms_empty_cleanup();
"""
        )

    return True
