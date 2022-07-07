from .exc import DatabaseUpgradeRequired
import logging


def migrate(conn, *, check_only):

    from .. import db

    if 'reactions' in db.metadata.tables:
        return False

    logging.warning("DB migration: adding reactions updates")
    if check_only:
        raise DatabaseUpgradeRequired("Add reactions support")

    if db.engine.name == "sqlite":
        conn.execute("ALTER TABLE messages ADD COLUMN seqno_data INTEGER NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE messages ADD COLUMN seqno_reactions INTEGER NOT NULL DEFAULT 0")
        conn.execute("UPDATE messages SET seqno_data = seqno")
        conn.execute("DROP TRIGGER IF EXISTS messages_insert_counter")
        conn.execute(
            """
CREATE TRIGGER messages_insert_counter AFTER INSERT ON messages
FOR EACH ROW
BEGIN
    UPDATE rooms SET message_sequence = message_sequence + 1 WHERE id = NEW.room;
    UPDATE messages SET seqno_data = (SELECT message_sequence FROM rooms WHERE id = NEW.room)
        WHERE id = NEW.id;
END
"""
        )
        conn.execute("DROP TRIGGER IF EXISTS messages_insert_history")
        conn.execute(
            """
CREATE TRIGGER messages_insert_history AFTER UPDATE OF data ON messages
FOR EACH ROW WHEN NEW.data IS NOT OLD.data
BEGIN
    INSERT INTO message_history (message, data, signature) VALUES (NEW.id, OLD.data, OLD.signature);
    UPDATE rooms SET message_sequence = message_sequence + 1 WHERE id = NEW.room;
    UPDATE messages SET
        seqno_data = (SELECT message_sequence FROM rooms WHERE id = NEW.room),
        edited = (julianday('now') - 2440587.5)*86400.0
    WHERE id = NEW.id;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER messages_seqno_updater_ins AFTER INSERT ON messages
FOR EACH ROW
BEGIN
    UPDATE messages SET seqno = max(seqno_data, seqno_reactions) WHERE id = NEW.id;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER messages_seqno_updater_upd AFTER UPDATE OF seqno_data, seqno_reactions ON messages
FOR EACH ROW
BEGIN
    UPDATE messages SET seqno = max(seqno_data, seqno_reactions) WHERE id = NEW.id;
END
"""
        )
        conn.execute(
            """
CREATE TABLE reactions (
    message INTEGER NOT NULL REFERENCES messages ON DELETE CASCADE,
    reaction TEXT NOT NULL,
    "user" INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    at FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    PRIMARY KEY(message, reaction, "user")
)
"""
        )
        conn.execute("CREATE INDEX reactions_at ON reactions(message, reaction, at)")
        conn.execute('CREATE INDEX reactions_user ON reactions("user", message)')
        conn.execute(
            """
CREATE VIEW first_reactors AS
SELECT *, rank() OVER (PARTITION BY message, reaction ORDER BY at) AS _order
FROM reactions
"""
        )
        conn.execute(
            """
CREATE TRIGGER reactions_insert_seqno AFTER INSERT ON reactions
FOR EACH ROW
BEGIN
    UPDATE rooms SET message_sequence = message_sequence + 1
        WHERE id = (SELECT room FROM messages WHERE id = NEW.message);
    UPDATE messages SET seqno_reactions = (
        SELECT message_sequence FROM rooms JOIN messages ON messages.room = rooms.id
            WHERE messages.id = NEW.message)
        WHERE id = NEW.message;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER reactions_update_seqno AFTER UPDATE ON reactions
FOR EACH ROW
BEGIN
    UPDATE rooms SET message_sequence = message_sequence + 1
        WHERE id = (SELECT room FROM messages WHERE id = NEW.message);
    UPDATE messages SET seqno_reactions = (
        SELECT message_sequence FROM rooms JOIN messages ON messages.room = rooms.id
            WHERE messages.id = NEW.message)
        WHERE id = NEW.message;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER reactions_update_seqno_msg AFTER UPDATE ON reactions
FOR EACH ROW WHEN NEW.message != OLD.message
BEGIN
    UPDATE rooms SET message_sequence = message_sequence + 1
        WHERE id = (SELECT room FROM messages WHERE id = OLD.message);
    UPDATE messages SET seqno_reactions = (
        SELECT message_sequence FROM rooms JOIN messages ON messages.room = rooms.id
            WHERE messages.id = OLD.message)
        WHERE id = OLD.message;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER reactions_delete_seqno AFTER DELETE ON reactions
FOR EACH ROW
BEGIN
    UPDATE rooms SET message_sequence = message_sequence + 1
        WHERE id = (SELECT room FROM messages WHERE id = OLD.message);
    UPDATE messages SET seqno_reactions = (
        SELECT message_sequence FROM rooms JOIN messages ON messages.room = rooms.id
            WHERE messages.id = OLD.message)
        WHERE id = OLD.message;
END
"""
        )

    else:  # postgresql
        conn.execute(
            """
ALTER TABLE messages ADD COLUMN seqno_data INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN seqno_reactions INTEGER NOT NULL DEFAULT 0;
UPDATE messages SET seqno_data = seqno;

CREATE OR REPLACE FUNCTION increment_room_sequence(room_id BIGINT)
RETURNS BIGINT LANGUAGE PLPGSQL AS $$
DECLARE
    new_seqno BIGINT;
BEGIN
    UPDATE rooms SET message_sequence = message_sequence + 1 WHERE id = room_id
        RETURNING message_sequence INTO STRICT new_seqno;
    RETURN new_seqno;
END;$$;

-- Trigger to increment a room's `message_sequence` counter and assign it to the message's `seqno`
-- field for new messages.
CREATE OR REPLACE FUNCTION trigger_messages_insert_counter()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$BEGIN
    UPDATE messages SET seqno_data = increment_room_sequence(NEW.room) WHERE id = NEW.id;
    RETURN NULL;
END;$$;
DROP TRIGGER IF EXISTS messages_insert_counter ON messages;
CREATE TRIGGER messages_insert_counter AFTER INSERT ON messages
FOR EACH ROW EXECUTE PROCEDURE trigger_messages_insert_counter();

CREATE OR REPLACE FUNCTION trigger_messages_insert_history()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$BEGIN
    INSERT INTO message_history (message, data, signature) VALUES (NEW.id, OLD.data, OLD.signature);
    UPDATE messages SET
        seqno_data = increment_room_sequence(NEW.room),
        edited = (extract(epoch from now()))
    WHERE id = NEW.id;
    RETURN NULL;
END;$$;
DROP TRIGGER IF EXISTS messages_insert_history ON messages;
CREATE TRIGGER messages_insert_history AFTER UPDATE OF data ON messages
FOR EACH ROW WHEN (NEW.data IS DISTINCT FROM OLD.data)
EXECUTE PROCEDURE trigger_messages_insert_history();

-- Trigger to update seqno when any of the seqno_* indicators is updated, so that updating can
-- update just the seqno_whatever and have the master seqno get updated automatically.
CREATE OR REPLACE FUNCTION trigger_messages_seqno()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$BEGIN
    UPDATE messages SET seqno = GREATEST(seqno_data, seqno_reactions)
        WHERE id = NEW.id;
    RETURN NULL;
END;$$;
DROP TRIGGER IF EXISTS messages_seqno_updater ON messages;
CREATE TRIGGER messages_seqno_updater
AFTER INSERT OR UPDATE OF seqno_data, seqno_reactions ON messages
FOR EACH ROW EXECUTE PROCEDURE trigger_messages_seqno();


-- Reactions
CREATE TABLE reactions (
    message BIGINT NOT NULL REFERENCES messages ON DELETE CASCADE,
    reaction TEXT NOT NULL,
    "user" BIGINT NOT NULL REFERENCES users ON DELETE CASCADE,
    at FLOAT NOT NULL DEFAULT (extract(epoch from now())),
    PRIMARY KEY(message, reaction, "user")
);
CREATE INDEX reactions_at ON reactions(message, reaction, at);
CREATE INDEX reactions_user ON reactions("user", message);

-- View used to select the first n reactors (using `WHERE _order <= 5`).
CREATE VIEW first_reactors AS
SELECT *, rank() OVER (PARTITION BY message, reaction ORDER BY at) AS _order
FROM reactions;


CREATE OR REPLACE FUNCTION trigger_reactions_seqno_insert()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$
DECLARE
    room_id BIGINT;
BEGIN
    SELECT room INTO STRICT room_id FROM messages WHERE id = NEW.message;
    UPDATE messages SET seqno_reactions = increment_room_sequence(room_id)
        WHERE id = NEW.message;
    RETURN NULL;
END;$$;
CREATE OR REPLACE FUNCTION trigger_reactions_seqno_delete()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$
DECLARE
    room_id BIGINT;
BEGIN
    SELECT room INTO STRICT room_id FROM messages WHERE id = OLD.message;
    UPDATE messages SET seqno_reactions = increment_room_sequence(room_id)
        WHERE id = OLD.message;
    RETURN NULL;
END;$$;
CREATE TRIGGER reactions_insert_seqno AFTER INSERT OR UPDATE ON reactions
FOR EACH ROW EXECUTE PROCEDURE trigger_reactions_seqno_insert();
CREATE TRIGGER reactions_delete_seqno AFTER DELETE OR UPDATE ON reactions
FOR EACH ROW EXECUTE PROCEDURE trigger_reactions_seqno_delete();
"""
        )

    return True
