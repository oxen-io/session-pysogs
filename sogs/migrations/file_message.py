from .exc import DatabaseUpgradeRequired
import logging


def migrate(conn, *, check_only):
    from .. import db

    fix_fk = False
    if 'message' in db.metadata.tables['files'].c:
        if db.engine.name == "sqlite" and db.metadata.tables['files'].c['message'].references(
            db.metadata.tables['rooms'].c['id']
        ):
            fix_fk = True
        else:
            return False

    logging.warning("DB migration: adding message/file association")
    if check_only:
        raise DatabaseUpgradeRequired("Add message/file association")

    if db.engine.name == "sqlite" and fix_fk:
        # Prior versions of this script created the column referencing rooms(id) instead of
        # messages; we need to rewrite the schema to fix it.  This schema updating feel janky, but
        # is the officially documented method (https://www.sqlite.org/lang_altertable.html)
        conn.execute("UPDATE files SET message = NULL")
        schema_ver = conn.execute("PRAGMA schema_version").first()[0]
        files_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'files'"
        ).first()[0]
        broken = 'message INTEGER REFERENCES rooms(id)'
        fixed = 'message INTEGER REFERENCES messages(id)'
        if broken not in files_sql:
            raise RuntimeError(
                "Didn't find expected schema in files table; cannot proceed with upgrade!"
            )
        files_sql = files_sql.replace(broken, fixed)
        conn.execute("PRAGMA writable_schema=ON")
        conn.execute(
            "UPDATE sqlite_master SET sql = ? WHERE type = 'table' AND name = 'files'", (files_sql,)
        )
        conn.execute(f"PRAGMA schema_version={schema_ver+1}")
        conn.execute("PRAGMA writable_schema=OFF")

    elif db.engine.name == "sqlite":
        conn.execute(
            "ALTER TABLE files ADD COLUMN message INTEGER REFERENCES messages(id)"
            " ON DELETE SET NULL"
        )
        conn.execute("CREATE INDEX files_message ON files(message)")
        conn.execute("DROP TRIGGER IF EXISTS messages_after_delete")
        conn.execute(
            """
CREATE TRIGGER messages_after_delete AFTER UPDATE OF data ON messages
FOR EACH ROW WHEN NEW.data IS NULL AND OLD.data IS NOT NULL
BEGIN
    -- Unpin if we deleted a pinned message:
    DELETE FROM pinned_messages WHERE message = OLD.id;
    -- Expire the post's attachments immediately:
    UPDATE files SET expiry = 0.0 WHERE message = OLD.id;
END
"""
        )
        conn.execute("DROP TRIGGER IF EXISTS room_metadata_pinned_add")
        conn.execute("DROP TRIGGER IF EXISTS room_metadata_pinned_update")
        conn.execute("DROP TRIGGER IF EXISTS room_metadata_pinned_remove")
        conn.execute(
            """
CREATE TRIGGER room_metadata_pinned_add AFTER INSERT ON pinned_messages
FOR EACH ROW
BEGIN
    UPDATE rooms SET info_updates = info_updates + 1 WHERE id = NEW.room;
    UPDATE files SET expiry = NULL WHERE message = NEW.message;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER room_metadata_pinned_update AFTER UPDATE ON pinned_messages
FOR EACH ROW
BEGIN
    UPDATE rooms SET info_updates = info_updates + 1 WHERE id = NEW.room;
    UPDATE files SET expiry = NULL WHERE message = NEW.message;
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER room_metadata_pinned_remove AFTER DELETE ON pinned_messages
FOR EACH ROW
BEGIN
    UPDATE rooms SET info_updates = info_updates + 1 WHERE id = OLD.room;
    UPDATE files SET expiry = uploaded + 15.0 * 86400.0 WHERE message = OLD.message;
END
"""
        )

    else:
        conn.execute(
            """
ALTER TABLE files ADD COLUMN message BIGINT REFERENCES messages ON DELETE SET NULL;

CREATE INDEX files_message ON files(message);

DROP TRIGGER IF EXISTS messages_after_delete ON messages;
CREATE OR REPLACE FUNCTION trigger_messages_after_delete()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$BEGIN
    -- Unpin if we deleted a pinned message:
    DELETE FROM pinned_messages WHERE message = OLD.id;
    -- Expire the posts attachments immediately:
    UPDATE files SET expiry = 0.0 WHERE message = OLD.id;
    RETURN NULL;
END;$$;
CREATE TRIGGER messages_after_delete AFTER UPDATE OF data ON messages
FOR EACH ROW WHEN (NEW.data IS NULL AND OLD.data IS NOT NULL)
EXECUTE PROCEDURE trigger_messages_after_delete();


DROP TRIGGER IF EXISTS room_metadata_pinned_add ON pinned_messages;
DROP TRIGGER IF EXISTS room_metadata_pinned_remove ON pinned_messages;

CREATE OR REPLACE FUNCTION trigger_room_metadata_pinned_add()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$BEGIN
    UPDATE rooms SET info_updates = info_updates + 1 WHERE id = NEW.room;
    UPDATE files SET expiry = NULL WHERE message = NEW.message;
    RETURN NULL;
END;$$;
CREATE TRIGGER room_metadata_pinned_add AFTER INSERT OR UPDATE ON pinned_messages
FOR EACH ROW
EXECUTE PROCEDURE trigger_room_metadata_pinned_add();

CREATE OR REPLACE FUNCTION trigger_room_metadata_pinned_remove()
RETURNS TRIGGER LANGUAGE PLPGSQL AS $$BEGIN
    UPDATE rooms SET info_updates = info_updates + 1 WHERE id = OLD.room;
    UPDATE files SET expiry = uploaded + 15.0*86400.0 WHERE message = OLD.message;
    RETURN NULL;
END;$$;
CREATE TRIGGER room_metadata_pinned_remove AFTER DELETE ON pinned_messages
FOR EACH ROW
EXECUTE PROCEDURE trigger_room_metadata_pinned_remove();
"""
        )

    return True
