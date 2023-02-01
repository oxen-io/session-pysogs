from .exc import DatabaseUpgradeRequired
import logging


def migrate(conn, *, check_only):
    from .. import db

    if 'user_reactions' in db.metadata.tables:
        return False

    logging.warning("DB migration: adding reactions updates")
    if check_only:
        raise DatabaseUpgradeRequired("Add reactions support")

    if db.engine.name == "sqlite":
        if 'seqno_data' not in db.metadata.tables['messages'].c:
            conn.execute("ALTER TABLE messages ADD COLUMN seqno_data INTEGER NOT NULL DEFAULT 0")
            conn.execute(
                "ALTER TABLE messages ADD COLUMN seqno_reactions INTEGER NOT NULL DEFAULT 0"
            )
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
        conn.execute("DROP TABLE IF EXISTS reactions")
        conn.execute("DROP TABLE IF EXISTS user_reactions")
        conn.execute(
            """
CREATE TABLE reactions (
    id INTEGER NOT NULL PRIMARY KEY,
    message INTEGER NOT NULL REFERENCES messages ON DELETE CASCADE,
    reaction TEXT NOT NULL
)
"""
        )
        conn.execute("CREATE UNIQUE INDEX reactions_message ON reactions (message, reaction)")
        conn.execute(
            """
CREATE TABLE user_reactions (
    reaction INTEGER NOT NULL REFERENCES reactions,
    "user" INTEGER NOT NULL REFERENCES users ON DELETE CASCADE,
    at FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */
    PRIMARY KEY(reaction, "user")
)
"""
        )
        conn.execute("CREATE INDEX user_reactions_at ON user_reactions(reaction, at)")
        conn.execute("DROP VIEW IF EXISTS message_reactions")
        conn.execute(
            """
CREATE VIEW message_reactions AS
SELECT reactions.*, user_reactions.user, user_reactions.at
FROM reactions JOIN user_reactions ON user_reactions.reaction = reactions.id
"""
        )
        conn.execute(
            """
CREATE TRIGGER message_reactions_insert INSTEAD OF INSERT ON message_reactions
FOR EACH ROW
BEGIN
    INSERT INTO reactions (message, reaction) VALUES (NEW.message, NEW.reaction)
        ON CONFLICT (message, reaction) DO NOTHING;
    INSERT INTO user_reactions (reaction, "user") VALUES (
        (SELECT id FROM reactions WHERE message = NEW.message AND reaction = NEW.reaction),
        NEW."user");
END
"""
        )
        conn.execute(
            """
CREATE VIEW first_reactors AS
SELECT *, rank() OVER (PARTITION BY reaction ORDER BY at) AS _order
FROM user_reactions
"""
        )
        conn.execute(
            """
CREATE TRIGGER reactions_no_update BEFORE UPDATE ON reactions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'reactions is not UPDATEable');
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER user_reactions_insert_seqno AFTER INSERT ON user_reactions
FOR EACH ROW
BEGIN
    UPDATE rooms SET message_sequence = message_sequence + 1
        WHERE id = (SELECT room FROM messages WHERE id = (SELECT message FROM reactions WHERE id = NEW.reaction));
    UPDATE messages SET seqno_reactions = (
            SELECT message_sequence FROM rooms JOIN messages ON messages.room = rooms.id
            WHERE messages.id = (SELECT message FROM reactions WHERE id = NEW.reaction)
        )
        WHERE id = (SELECT message FROM reactions WHERE id = NEW.reaction);
END
"""  # noqa: E501
        )
        conn.execute(
            """
CREATE TRIGGER user_reactions_no_update BEFORE UPDATE ON user_reactions
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'user_reactions is not UPDATEable');
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER reactions_delete_seqno BEFORE DELETE ON user_reactions
FOR EACH ROW
BEGIN
    UPDATE rooms SET message_sequence = message_sequence + 1
        WHERE id = (SELECT room FROM messages WHERE id = (SELECT message FROM reactions WHERE id = OLD.reaction));
    UPDATE messages SET seqno_reactions = (
            SELECT message_sequence FROM rooms JOIN messages ON messages.room = rooms.id
            WHERE messages.id = (SELECT message FROM reactions WHERE id = OLD.reaction)
        )
        WHERE id = (SELECT message FROM reactions WHERE id = OLD.reaction);
END
"""  # noqa: E501
        )
        conn.execute(
            """
CREATE TRIGGER reactions_cleanup_empty AFTER DELETE ON user_reactions
FOR EACH ROW
BEGIN
    DELETE FROM reactions WHERE id = OLD.reaction
        AND NOT EXISTS(SELECT * FROM user_reactions WHERE reaction = reactions.id);
END
"""
        )

    else:  # postgresql
        if 'seqno_data' not in db.metadata.tables['messages'].c:
            conn.execute(
                """
ALTER TABLE messages ADD COLUMN seqno_data INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN seqno_reactions INTEGER NOT NULL DEFAULT 0;
UPDATE messages SET seqno_data = seqno;
"""
            )

        conn.execute(
            """

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
DROP TABLE IF EXISTS reactions CASCADE;
CREATE TABLE reactions (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    message BIGINT NOT NULL REFERENCES messages ON DELETE CASCADE,
    reaction TEXT NOT NULL
);
CREATE UNIQUE INDEX reactions_message ON reactions (message, reaction);

DROP TABLE IF EXISTS user_reactions CASCADE;
CREATE TABLE user_reactions (
    reaction BIGINT NOT NULL REFERENCES reactions ON DELETE CASCADE,
    "user" BIGINT NOT NULL REFERENCES users ON DELETE CASCADE,
    at FLOAT NOT NULL DEFAULT (extract(epoch from now())),
    PRIMARY KEY(reaction, "user")
);
CREATE INDEX user_reactions_at ON user_reactions(reaction, at);

CREATE VIEW message_reactions AS
SELECT reactions.*, user_reactions.user, user_reactions.at
FROM reactions JOIN user_reactions ON user_reactions.reaction = reactions.id;


CREATE OR REPLACE FUNCTION trigger_message_reactions_insert()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$BEGIN
    INSERT INTO reactions (message, reaction) VALUES (NEW.message, NEW.reaction)
        ON CONFLICT (message, reaction) DO NOTHING;
    INSERT INTO user_reactions (reaction, "user") VALUES (
        (SELECT id FROM reactions WHERE message = NEW.message AND reaction = NEW.reaction),
        NEW."user");
    RETURN NULL;
END;$$;
DROP TRIGGER IF EXISTS message_reactions_insert ON message_reactions;
CREATE TRIGGER message_reactions_insert INSTEAD OF INSERT ON message_reactions
FOR EACH ROW
EXECUTE PROCEDURE trigger_message_reactions_insert();



-- View used to select the first n reactors (using `WHERE _order <= 5`).
CREATE VIEW first_reactors AS
SELECT *, rank() OVER (PARTITION BY reaction ORDER BY at) AS _order
FROM user_reactions;


CREATE OR REPLACE FUNCTION trigger_reactions_no_update()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$BEGIN
    RAISE 'reactions/user_reactions tables are not UPDATEable';
END;$$;
DROP TRIGGER IF EXISTS reactions_no_update ON reactions;
CREATE TRIGGER reactions_no_update BEFORE UPDATE ON reactions
FOR EACH STATEMENT
EXECUTE PROCEDURE trigger_reactions_no_update();
DROP TRIGGER IF EXISTS user_reactions_no_update ON user_reactions;
CREATE TRIGGER user_reactions_no_update BEFORE UPDATE ON user_reactions
FOR EACH STATEMENT
EXECUTE PROCEDURE trigger_reactions_no_update();


CREATE OR REPLACE FUNCTION trigger_user_reactions_seqno_insert()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$
DECLARE
    msg_id BIGINT;
    room_id BIGINT;
BEGIN
    SELECT message INTO STRICT msg_id FROM reactions WHERE id = NEW.reaction;
    SELECT room INTO STRICT room_id FROM messages WHERE id = msg_id;
    UPDATE messages SET seqno_reactions = increment_room_sequence(room_id)
        WHERE id = msg_id;
    RETURN NULL;
END;$$;
DROP TRIGGER IF EXISTS user_reactions_insert_seqno ON user_reactions;
CREATE TRIGGER user_reactions_insert_seqno AFTER INSERT ON user_reactions
FOR EACH ROW EXECUTE PROCEDURE trigger_user_reactions_seqno_insert();

CREATE OR REPLACE FUNCTION trigger_user_reactions_seqno_delete()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$
DECLARE
    msg_id BIGINT;
    room_id BIGINT;
BEGIN
    SELECT message INTO STRICT msg_id FROM reactions WHERE id = OLD.reaction;
    SELECT room INTO STRICT room_id FROM messages WHERE id = msg_id;
    UPDATE messages SET seqno_reactions = increment_room_sequence(room_id)
        WHERE id = msg_id;
    RETURN OLD;
END;$$;
DROP TRIGGER IF EXISTS user_reactions_delete_seqno ON user_reactions;
CREATE TRIGGER user_reactions_delete_seqno BEFORE DELETE ON user_reactions
FOR EACH ROW EXECUTE PROCEDURE trigger_user_reactions_seqno_delete();

-- Trigger to delete the reactions row when we delete the last referencing user reaction
CREATE OR REPLACE FUNCTION trigger_reactions_clear_empty()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$BEGIN
    DELETE FROM reactions WHERE id = OLD.reaction
        AND NOT EXISTS(SELECT * FROM user_reactions WHERE reaction = reactions.id);
    RETURN NULL;
END;$$;
DROP TRIGGER IF EXISTS reactions_clear_empty ON user_reactions;
CREATE TRIGGER reactions_clear_empty AFTER DELETE ON user_reactions
FOR EACH ROW
EXECUTE PROCEDURE trigger_reactions_clear_empty();

"""
        )

    return True
