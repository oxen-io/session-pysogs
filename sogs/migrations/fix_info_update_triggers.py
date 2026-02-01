import logging
from .exc import DatabaseUpgradeRequired


def migrate(conn, *, check_only):
    from .. import db

    # Room info_updates triggers for global mods didn't fire for invisible global mods/admins, but
    # should (so that other mods/admins notice the change).
    has_bad_trigger = db.query(
        (
            """
        SELECT COUNT(*) FROM sqlite_master
            WHERE type = 'trigger' AND name = :trigger
            AND LOWER(sql) LIKE :bad
        """
            if db.engine.name == "sqlite"
            else """
        SELECT COUNT(*) FROM information_schema.triggers
            WHERE trigger_name = :trigger
            AND LOWER(action_condition) LIKE :bad
        """
        ),
        trigger='room_metadata_global_mods_insert',
        bad='% new.visible_mod%',
        dbconn=conn,
    ).first()[0]

    if not has_bad_trigger:
        return False

    logging.warning("DB migration: fixing global hidden mod room triggers")
    if check_only:
        raise DatabaseUpgradeRequired("global hidden mod room triggers need to be recreated")

    if db.engine.name == "sqlite":
        conn.execute("DROP TRIGGER IF EXISTS room_metadata_global_mods_insert")
        conn.execute("DROP TRIGGER IF EXISTS room_metadata_global_mods_update")
        conn.execute("DROP TRIGGER IF EXISTS room_metadata_global_mods_delete")
        conn.execute(
            """
CREATE TRIGGER room_metadata_global_mods_insert AFTER INSERT ON users
FOR EACH ROW WHEN (NEW.admin OR NEW.moderator)
BEGIN
    UPDATE rooms SET info_updates = info_updates + 1; -- WHERE everything!
END
"""
        )
        conn.execute(
            """
CREATE TRIGGER room_metadata_global_mods_update AFTER UPDATE ON users
FOR EACH ROW WHEN (NEW.moderator != OLD.moderator OR NEW.admin != OLD.admin OR NEW.visible_mod != OLD.visible_mod)
BEGIN
    UPDATE rooms SET info_updates = info_updates + 1; -- WHERE everything!
END
"""  # noqa: E501
        )
        conn.execute(
            """
CREATE TRIGGER room_metadata_global_mods_delete AFTER DELETE ON users
FOR EACH ROW WHEN (OLD.moderator OR OLD.admin)
BEGIN
    UPDATE rooms SET info_updates = info_updates + 1; -- WHERE everything!
END
"""
        )

    else:  # postgresql
        conn.execute(
            """
DROP TRIGGER IF EXISTS room_metadata_global_mods_insert ON users;
DROP TRIGGER IF EXISTS room_metadata_global_mods_update ON users;
DROP TRIGGER IF EXISTS room_metadata_global_mods_delete ON users;

CREATE TRIGGER room_metadata_global_mods_insert AFTER INSERT ON users
FOR EACH ROW WHEN (NEW.admin OR NEW.moderator)
EXECUTE PROCEDURE trigger_room_metadata_info_update_all();

CREATE TRIGGER room_metadata_global_mods_update AFTER UPDATE OF moderator, admin, visible_mod ON users
FOR EACH ROW WHEN (NEW.moderator != OLD.moderator OR NEW.admin != OLD.admin OR NEW.visible_mod != OLD.visible_mod)
EXECUTE PROCEDURE trigger_room_metadata_info_update_all();

CREATE TRIGGER room_metadata_global_mods_delete AFTER DELETE ON users
FOR EACH ROW WHEN (OLD.moderator OR OLD.admin)
EXECUTE PROCEDURE trigger_room_metadata_info_update_all();
"""  # noqa: E501
        )

    return True
