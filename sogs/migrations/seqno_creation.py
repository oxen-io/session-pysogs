import logging
from .exc import DatabaseUpgradeRequired


def migrate(conn, *, check_only):
    """
    Adds a seqno_creation column to track the seqno when a message was created so that we can skip
    deleted messages entirely (i.e. omit the tombstone) when polling from a seqno before the message
    was created.
    """

    from .. import db

    if 'seqno_creation' in db.metadata.tables['messages'].c:
        return False

    if check_only:
        raise DatabaseUpgradeRequired("message creation seqno")

    logging.warning("Adding messages.seqno_creation column")
    if db.engine.name == 'sqlite':
        conn.execute("ALTER TABLE messages ADD COLUMN seqno_creation INTEGER NOT NULL DEFAULT 0")
        conn.execute("DROP TRIGGER IF EXISTS messages_insert_counter")
        conn.execute(
            """
CREATE TRIGGER messages_insert_counter AFTER INSERT ON messages
FOR EACH ROW
BEGIN
    UPDATE rooms SET message_sequence = message_sequence + 1 WHERE id = NEW.room;
    UPDATE messages SET seqno_data = (SELECT message_sequence FROM rooms WHERE id = NEW.room) WHERE id = NEW.id;
    UPDATE messages SET seqno_creation = seqno_data WHERE id = NEW.id;
END
"""  # noqa: E501
        )
    else:  # postgresql
        conn.execute(
            """
ALTER TABLE messages ADD COLUMN seqno_creation BIGINT NOT NULL DEFAULT 0;

CREATE OR REPLACE FUNCTION trigger_messages_insert_counter()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$
DECLARE
    new_seqno BIGINT := increment_room_sequence(NEW.room);
BEGIN
    UPDATE messages SET seqno_data = new_seqno, seqno_creation = new_seqno WHERE id = NEW.id;
    RETURN NULL;
END;$$;
DROP TRIGGER IF EXISTS messages_insert_counter ON messages;
CREATE TRIGGER messages_insert_counter AFTER INSERT ON messages
FOR EACH ROW EXECUTE PROCEDURE trigger_messages_insert_counter();
"""
        )

    # Drop these to be recreated (with the no column) in the message_views migration.
    conn.execute("DROP VIEW IF EXISTS message_metadata")
    conn.execute("DROP VIEW IF EXISTS message_details")

    return True
