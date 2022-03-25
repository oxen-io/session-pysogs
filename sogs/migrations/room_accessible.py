import logging
from .exc import DatabaseUpgradeRequired


def migrate(conn, *, check_only):
    """Add the room.accessible permission flag, and associated column/view changes"""

    from .. import db

    if 'accessible' in db.metadata.tables['rooms'].c:
        return False

    logging.warning("DB migration: adding 'accessible' room permission columns")
    if check_only:
        raise DatabaseUpgradeRequired("Add accessible room permission columns")

    conn.execute("ALTER TABLE rooms ADD COLUMN accessible BOOLEAN NOT NULL DEFAULT TRUE")
    conn.execute("ALTER TABLE user_permission_overrides ADD COLUMN accessible BOOLEAN")

    # Gets recreated in the user_permissions migration:
    conn.execute("DROP VIEW IF EXISTS user_permissions")

    if db.engine.name == "sqlite":
        conn.execute("DROP TRIGGER IF EXISTS user_perms_empty_cleanup")
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
DROP TRIGGER IF EXISTS user_perms_empty_cleanup ON user_permission_overrides;

CREATE TRIGGER user_perms_empty_cleanup AFTER UPDATE ON user_permission_overrides
FOR EACH ROW WHEN (NOT (NEW.banned OR NEW.moderator OR NEW.admin)
    AND COALESCE(NEW.accessible, NEW.read, NEW.write, NEW.upload) IS NULL)
EXECUTE PROCEDURE trigger_user_perms_empty_cleanup();
"""
        )

    return True
