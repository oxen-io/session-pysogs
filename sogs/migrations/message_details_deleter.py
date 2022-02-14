def migrate(conn):

    from .. import db

    if db.engine.name == "sqlite":
        conn.execute(
            """
CREATE TRIGGER IF NOT EXISTS message_details_deleter INSTEAD OF DELETE ON message_details
FOR EACH ROW WHEN OLD.data IS NOT NULL
BEGIN
    UPDATE messages SET data = NULL, data_size = NULL, signature = NULL
        WHERE id = OLD.id;
END
"""
        )

    return False  # No need to refresh metadata even if we added the trigger above.
