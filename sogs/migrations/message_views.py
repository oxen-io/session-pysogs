import logging
from .exc import DatabaseUpgradeRequired


def migrate(conn, *, check_only):
    from .. import db

    if 'message_metadata' in db.metadata.tables and all(
        x in db.metadata.tables['message_metadata'].c
        for x in ('whisper_to', 'whisper_mods', 'filtered', 'seqno', 'seqno_data')
    ):
        return False

    logging.warning("DB migration: recreating message_metadata/message_details views")
    if check_only:
        raise DatabaseUpgradeRequired("message views need to be recreated")

    conn.execute("DROP VIEW IF EXISTS message_metadata")
    conn.execute("DROP VIEW IF EXISTS message_details")

    if db.engine.name == "sqlite":
        conn.execute("DROP TRIGGER IF EXISTS message_details_deleter")
        conn.execute(
            """
CREATE VIEW message_details AS
SELECT messages.*, uposter.session_id, uwhisper.session_id AS whisper_to
    FROM messages
        JOIN users uposter ON messages."user" = uposter.id
        LEFT JOIN users uwhisper ON messages.whisper = uwhisper.id
"""
        )
        conn.execute(
            """
CREATE TRIGGER message_details_deleter INSTEAD OF DELETE ON message_details
FOR EACH ROW WHEN OLD.data IS NOT NULL
BEGIN
    UPDATE messages SET data = NULL, data_size = NULL, signature = NULL
        WHERE id = OLD.id;
    DELETE FROM reactions WHERE message = OLD.id;
END
"""
        )
        conn.execute(
            """
CREATE VIEW message_metadata AS
SELECT id, room, "user", session_id, posted, edited, seqno, seqno_data, seqno_reactions,
        filtered, whisper_to, whisper_mods,
        length(data) AS data_unpadded, data_size, length(signature) as signature_length
    FROM message_details
"""
        )

    else:  # postgresql
        conn.execute(
            """
-- Effectively the same as `messages` except that it also includes the `session_id` from the users
-- table of the user who posted it, and the session id of the whisper recipient (as `whisper_to`) if
-- a directed whisper.
CREATE VIEW message_details AS
SELECT messages.*, uposter.session_id, uwhisper.session_id AS whisper_to
    FROM messages
        JOIN users uposter ON messages.user = uposter.id
        LEFT JOIN users uwhisper ON messages.whisper = uwhisper.id;

-- Delete trigger on message_details which lets us use a DELETE that gets transformed into an UPDATE
-- that sets data, size, signature to NULL on the matched messages.
CREATE OR REPLACE FUNCTION trigger_message_details_deleter()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$BEGIN
    IF OLD.data IS NOT NULL THEN
        UPDATE messages SET data = NULL, data_size = NULL, signature = NULL
            WHERE id = OLD.id;
        DELETE FROM reactions WHERE message = OLD.id;
    END IF;
    RETURN NULL;
END;$$;
DROP TRIGGER IF EXISTS message_details_deleter ON message_details;
CREATE TRIGGER message_details_deleter INSTEAD OF DELETE ON message_details
FOR EACH ROW
EXECUTE PROCEDURE trigger_message_details_deleter();

-- View of `messages` that is useful for manually inspecting table contents by only returning the
-- length (rather than raw bytes) for data/signature.
CREATE VIEW message_metadata AS
SELECT id, room, "user", session_id, posted, edited, seqno, seqno_data, seqno_reactions,
        filtered, whisper_to, whisper_mods,
        length(data) AS data_unpadded, data_size, length(signature) as signature_length
    FROM message_details;
            """
        )

    return True
