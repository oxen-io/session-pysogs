from .exc import DatabaseUpgradeRequired


def migrate(conn, *, check_only):

    from .. import db

    if db.engine.name == "sqlite":
        exists = conn.execute(
            """
            SELECT COUNT(*) FROM sqlite_master
            WHERE type = 'trigger' AND name = 'message_details_deleter'
            """
        ).first()[0]
        if exists:
            return False

        elif check_only:
            raise DatabaseUpgradeRequired("message_details delete trigger")

        conn.execute(
            """
CREATE TRIGGER message_details_deleter INSTEAD OF DELETE ON message_details
FOR EACH ROW WHEN OLD.data IS NOT NULL
BEGIN
    UPDATE messages SET data = NULL, data_size = NULL, signature = NULL
        WHERE id = OLD.id;
END
"""
        )
        return True

    return False
