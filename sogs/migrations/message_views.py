import logging


def migrate(conn):
    from .. import db

    if db.engine.name == "sqlite":
        if any(
            x not in db.metadata.tables['message_metadata'].c for x in ('whisper_to', 'filtered')
        ):
            logging.warning("DB migration: replacing message_metadata/message_details views")
            conn.execute("DROP VIEW IF EXISTS message_metadata")
            conn.execute("DROP VIEW IF EXISTS message_details")
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
END
"""
            )
            conn.execute(
                """
CREATE VIEW message_metadata AS
SELECT id, room, "user", session_id, posted, edited, seqno, filtered, whisper_to,
        length(data) AS data_unpadded, data_size, length(signature) as signature_length
    FROM message_details
"""
            )

            return True

    # else: don't worry about this for postgresql because initial pg support had the fix

    return False
