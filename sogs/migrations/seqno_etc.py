import logging
from .exc import DatabaseUpgradeRequired


def migrate(conn, *, check_only):
    """
    Rename rooms.updates/messages.updated to rooms.message_sequence/messages.seqno for better
    disambiguation with rooms.info_updates.

    This also does various other changes/fixes that came at the same time as the column rename:

    - remove "updated" from and add "pinned_by"/"pinned_at" to pinned_messages
    - recreate the pinned_messages table and triggers because we need several changes:
        - add trigger to unpin a message when the message is deleted
        - remove "updates" (now message_sequence) updates from room metadata update trigger
        - add AFTER UPDATE trigger to properly update room metadata counter when re-pinning an
          existing pinned message
    - fix user_permissions view to return true for read/write/upload to true for moderators
    """

    from .. import db

    if 'seqno' in db.metadata.tables['messages'].c:
        return False

    if check_only:
        raise DatabaseUpgradeRequired("sequence column renames & pinned_messages table")

    # We can't insert the required pinned_messages because we don't have the pinned_by user, but
    # that isn't a big deal since we didn't have any endpoints for pinned messsages before this
    # anyway, so we just recreate the whole thing (along with triggers which we also need to
    # update/fix)
    logging.warning("Recreating pinned_messages table")
    conn.execute("DROP TABLE pinned_messages")
    if db.engine.name == 'sqlite':
        conn.execute(
            """
CREATE TABLE pinned_messages (
    room INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    pinned_by INTEGER NOT NULL REFERENCES users(id),
    pinned_at FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch when pinned */
    PRIMARY KEY(room, message)
)
"""  # noqa: E501
        )
        conn.execute(
            """
CREATE TRIGGER messages_after_delete AFTER UPDATE OF data ON messages
FOR EACH ROW WHEN NEW.data IS NULL AND OLD.data IS NOT NULL
BEGIN
    -- Unpin if we deleted a pinned message:
    DELETE FROM pinned_messages WHERE message = OLD.id;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER room_metadata_pinned_add AFTER INSERT ON pinned_messages
FOR EACH ROW
BEGIN
    UPDATE rooms SET info_updates = info_updates + 1 WHERE id = NEW.room;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER room_metadata_pinned_update AFTER UPDATE ON pinned_messages
FOR EACH ROW
BEGIN
    UPDATE rooms SET info_updates = info_updates + 1 WHERE id = NEW.room;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER room_metadata_pinned_remove AFTER DELETE ON pinned_messages
FOR EACH ROW
BEGIN
    UPDATE rooms SET info_updates = info_updates + 1 WHERE id = OLD.room;
END
"""
        )

    else:  # postgresql
        logging.warning("Recreating pinned_messages table")
        conn.execute(
            """
CREATE TABLE pinned_messages (
    room BIGINT NOT NULL REFERENCES rooms ON DELETE CASCADE,
    message BIGINT NOT NULL REFERENCES messages ON DELETE CASCADE,
    pinned_by BIGINT NOT NULL REFERENCES users,
    pinned_at FLOAT NOT NULL DEFAULT (extract(epoch from now())),
    PRIMARY KEY(room, message)
);


-- Trigger to handle required updates after a message gets deleted (in the SOGS context: that is,
-- has data set to NULL)
CREATE OR REPLACE FUNCTION trigger_messages_after_delete()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$BEGIN
    -- Unpin if we deleted a pinned message:
    DELETE FROM pinned_messages WHERE message = OLD.id;
    RETURN NULL;
END;$$;
CREATE TRIGGER messages_after_delete AFTER UPDATE OF data ON messages
FOR EACH ROW WHEN (NEW.data IS NULL AND OLD.data IS NOT NULL)
EXECUTE PROCEDURE trigger_messages_after_delete();

CREATE TRIGGER room_metadata_pinned_add AFTER INSERT OR UPDATE ON pinned_messages
FOR EACH ROW
EXECUTE PROCEDURE trigger_room_metadata_info_update_new();

CREATE TRIGGER room_metadata_pinned_remove AFTER DELETE ON pinned_messages
FOR EACH ROW
EXECUTE PROCEDURE trigger_room_metadata_info_update_old();
"""
        )

    logging.warning("Applying message_sequence renames")
    conn.execute("ALTER TABLE rooms RENAME COLUMN updates TO message_sequence")

    # The message_views migration will create these for us, and we need to drop them because:
    # 1) postgresql doesn't rename the view's output columns to match the new table column
    # 2) sqlite breaks if attempting the rename a column that is referenced in a view-of-a-view
    conn.execute("DROP VIEW message_metadata")
    conn.execute("DROP VIEW message_details")

    conn.execute("ALTER TABLE messages RENAME COLUMN updated TO seqno")

    # Gets recreated in the user_permissions migration:
    logging.warning("Dropping user_permissions view")
    conn.execute("DROP VIEW IF EXISTS user_permissions")

    return True
